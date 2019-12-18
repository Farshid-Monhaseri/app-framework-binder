/*
 * Copyright (C) 2015-2019 "IoT.bzh"
 * Author José Bollo <jose.bollo@iot.bzh>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define _GNU_SOURCE

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>

#include <json-c/json.h>
#include <afb/afb-event-x2-itf.h>
#include <afb/afb-event-x1.h>

#include "afb-evt.h"
#include "afb-hook.h"
#include "verbose.h"
#include "jobs.h"
#include "uuid.h"

struct afb_evt_watch;

/*
 * Structure for event listeners
 */
struct afb_evt_listener {

	/* chaining listeners */
	struct afb_evt_listener *next;

	/* interface for callbacks */
	const struct afb_evt_itf *itf;

	/* closure for the callback */
	void *closure;

	/* head of the list of events listened */
	struct afb_evt_watch *watchs;

	/* rwlock of the listener */
	pthread_rwlock_t rwlock;

	/* count of reference to the listener */
	uint16_t refcount;
};

/*
 * Structure for describing events
 */
struct afb_evtid {

	/* interface */
	struct afb_event_x2 eventid;

	/* next event */
	struct afb_evtid *next;

	/* head of the list of listeners watching the event */
	struct afb_evt_watch *watchs;

	/* rwlock of the event */
	pthread_rwlock_t rwlock;

#if WITH_AFB_HOOK
	/* hooking */
	int hookflags;
#endif

	/* refcount */
	uint16_t refcount;

	/* id of the event */
	uint16_t id;

	/* fullname of the event */
	char fullname[];
};

/*
 * Structure for associating events and listeners
 */
struct afb_evt_watch {

	/* the evtid */
	struct afb_evtid *evtid;

	/* link to the next watcher for the same evtid */
	struct afb_evt_watch *next_by_evtid;

	/* the listener */
	struct afb_evt_listener *listener;

	/* link to the next watcher for the same listener */
	struct afb_evt_watch *next_by_listener;
};

/*
 * structure for job of broadcasting events
 */
struct job_broadcast
{
	/** object atached to the event */
	struct json_object *object;

	/** the uuid of the event */
	uuid_binary_t  uuid;

	/** remaining hop */
	uint8_t hop;

	/** name of the event to broadcast */
	char event[];
};

/*
 * structure for job of broadcasting or pushing events
 */
struct job_evtid
{
	/** the event to broadcast */
	struct afb_evtid *evtid;

	/** object atached to the event */
	struct json_object *object;
};

/* the interface for events */
static struct afb_event_x2_itf afb_evt_event_x2_itf = {
	.broadcast = (void*)afb_evt_evtid_broadcast,
	.push = (void*)afb_evt_evtid_push,
	.unref = (void*)afb_evt_evtid_unref,
	.name = (void*)afb_evt_evtid_name,
	.addref = (void*)afb_evt_evtid_addref
};

#if WITH_AFB_HOOK
/* the interface for events */
static struct afb_event_x2_itf afb_evt_hooked_event_x2_itf = {
	.broadcast = (void*)afb_evt_evtid_hooked_broadcast,
	.push = (void*)afb_evt_evtid_hooked_push,
	.unref = (void*)afb_evt_evtid_hooked_unref,
	.name = (void*)afb_evt_evtid_hooked_name,
	.addref = (void*)afb_evt_evtid_hooked_addref
};
#endif

/* job groups for events push/broadcast */
#define BROADCAST_JOB_GROUP  (&afb_evt_event_x2_itf)
#define PUSH_JOB_GROUP       (&afb_evt_event_x2_itf)

/* head of the list of listeners */
static pthread_rwlock_t listeners_rwlock = PTHREAD_RWLOCK_INITIALIZER;
static struct afb_evt_listener *listeners = NULL;

/* handling id of events */
static pthread_rwlock_t events_rwlock = PTHREAD_RWLOCK_INITIALIZER;
static struct afb_evtid *evtids = NULL;
static uint16_t event_genid = 0;
static uint16_t event_count = 0;

/* head of uniqueness of events */
#if !defined(EVENT_BROADCAST_HOP_MAX)
#  define EVENT_BROADCAST_HOP_MAX  10
#endif
#if !defined(EVENT_BROADCAST_MEMORY_COUNT)
#  define EVENT_BROADCAST_MEMORY_COUNT  8
#endif

#if EVENT_BROADCAST_MEMORY_COUNT
static struct {
	pthread_mutex_t mutex;
	uint8_t base;
	uint8_t count;
	uuid_binary_t uuids[EVENT_BROADCAST_MEMORY_COUNT];
} uniqueness = {
	.mutex = PTHREAD_MUTEX_INITIALIZER,
	.base = 0,
	.count = 0
};
#endif

/*
 * Create structure for job of broadcasting string 'event' with 'object'
 * Returns the created structure or NULL if out of memory
 */
static struct job_broadcast *make_job_broadcast(const char *event, struct json_object *object, const uuid_binary_t uuid, uint8_t hop)
{
	size_t sz = 1 + strlen(event);
	struct job_broadcast *jb = malloc(sz + sizeof *jb);
	if (jb) {
		jb->object = object;
		memcpy(jb->uuid, uuid, sizeof jb->uuid);
		jb->hop = hop;
		memcpy(jb->event, event, sz);
	}
	return jb;
}

/*
 * Destroy structure 'jb' for job of broadcasting string events
 */
static void destroy_job_broadcast(struct job_broadcast *jb)
{
	json_object_put(jb->object);
	free(jb);
}

/*
 * Create structure for job of broadcasting or pushing 'evtid' with 'object'
 * Returns the created structure or NULL if out of memory
 */
static struct job_evtid *make_job_evtid(struct afb_evtid *evtid, struct json_object *object)
{
	struct job_evtid *je = malloc(sizeof *je);
	if (je) {
		je->evtid = afb_evt_evtid_addref(evtid);
		je->object = object;
	}
	return je;
}

/*
 * Destroy structure for job of broadcasting or pushing evtid
 */
static void destroy_job_evtid(struct job_evtid *je)
{
	afb_evt_evtid_unref(je->evtid);
	json_object_put(je->object);
	free(je);
}

/*
 * Broadcasts the 'event' of 'id' with its 'object'
 */
static void broadcast(struct job_broadcast *jb)
{
	struct afb_evt_listener *listener;

	pthread_rwlock_rdlock(&listeners_rwlock);
	listener = listeners;
	while(listener) {
		if (listener->itf->broadcast != NULL)
			listener->itf->broadcast(listener->closure, jb->event, json_object_get(jb->object), jb->uuid, jb->hop);
		listener = listener->next;
	}
	pthread_rwlock_unlock(&listeners_rwlock);
}

/*
 * Jobs callback for broadcasting string asynchronously
 */
static void broadcast_job(int signum, void *closure)
{
	struct job_broadcast *jb = closure;

	if (signum == 0)
		broadcast(jb);
	destroy_job_broadcast(jb);
}

/*
 * Broadcasts the string 'event' with its 'object'
 */
static int unhooked_broadcast(const char *event, struct json_object *object, const uuid_binary_t uuid, uint8_t hop)
{
	uuid_binary_t local_uuid;
	struct job_broadcast *jb;
	int rc;
#if EVENT_BROADCAST_MEMORY_COUNT
	int iter, count;
#endif

	/* check if lately sent */
	if (!uuid) {
		uuid_new_binary(local_uuid);
		uuid = local_uuid;
		hop = EVENT_BROADCAST_HOP_MAX;
#if EVENT_BROADCAST_MEMORY_COUNT
		pthread_mutex_lock(&uniqueness.mutex);
	} else {
		pthread_mutex_lock(&uniqueness.mutex);
		iter = (int)uniqueness.base;
		count = (int)uniqueness.count;
		while (count) {
			if (0 == memcmp(uuid, uniqueness.uuids[iter], sizeof(uuid_binary_t))) {
				pthread_mutex_unlock(&uniqueness.mutex);
				return 0;
			}
			if (++iter == EVENT_BROADCAST_MEMORY_COUNT)
				iter = 0;
			count--;
		}
	}
	iter = (int)uniqueness.base;
	if (uniqueness.count < EVENT_BROADCAST_MEMORY_COUNT)
		iter += (int)(uniqueness.count++);
	else if (++uniqueness.base == EVENT_BROADCAST_MEMORY_COUNT)
		uniqueness.base = 0;
	memcpy(uniqueness.uuids[iter], uuid, sizeof(uuid_binary_t));
	pthread_mutex_unlock(&uniqueness.mutex);
#else
	}
#endif

	/* create the structure for the job */
	jb = make_job_broadcast(event, object, uuid, hop);
	if (jb == NULL) {
		ERROR("Cant't create broadcast string job item for %s(%s)",
			event, json_object_to_json_string(object));
		json_object_put(object);
		return -1;
	}

	/* queue the job */
	rc = jobs_queue(BROADCAST_JOB_GROUP, 0, broadcast_job, jb);
	if (rc) {
		ERROR("cant't queue broadcast string job item for %s(%s)",
			event, json_object_to_json_string(object));
		destroy_job_broadcast(jb);
	}
	return rc;
}

/*
 * Broadcasts the event 'evtid' with its 'object'
 * 'object' is released (like json_object_put)
 * Returns the count of listener that received the event.
 */
int afb_evt_evtid_broadcast(struct afb_evtid *evtid, struct json_object *object)
{
	return unhooked_broadcast(evtid->fullname, object, NULL, 0);
}

#if WITH_AFB_HOOK
/*
 * Broadcasts the event 'evtid' with its 'object'
 * 'object' is released (like json_object_put)
 * Returns the count of listener that received the event.
 */
int afb_evt_evtid_hooked_broadcast(struct afb_evtid *evtid, struct json_object *object)
{
	int result;

	json_object_get(object);

	if (evtid->hookflags & afb_hook_flag_evt_broadcast_before)
		afb_hook_evt_broadcast_before(evtid->fullname, evtid->id, object);

	result = afb_evt_evtid_broadcast(evtid, object);

	if (evtid->hookflags & afb_hook_flag_evt_broadcast_after)
		afb_hook_evt_broadcast_after(evtid->fullname, evtid->id, object, result);

	json_object_put(object);

	return result;
}
#endif

int afb_evt_rebroadcast(const char *event, struct json_object *object, const uuid_binary_t uuid, uint8_t hop)
{
	int result;

#if WITH_AFB_HOOK
	json_object_get(object);
	afb_hook_evt_broadcast_before(event, 0, object);
#endif

	result = unhooked_broadcast(event, object, uuid, hop);

#if WITH_AFB_HOOK
	afb_hook_evt_broadcast_after(event, 0, object, result);
	json_object_put(object);
#endif
	return result;
}

/*
 * Broadcasts the 'event' with its 'object'
 * 'object' is released (like json_object_put)
 * Returns the count of listener having receive the event.
 */
int afb_evt_broadcast(const char *event, struct json_object *object)
{
	return afb_evt_rebroadcast(event, object, NULL, 0);
}

/*
 * Pushes the event 'evtid' with 'obj' to its listeners
 * Returns the count of listener that received the event.
 */
static void push_evtid(struct afb_evtid *evtid, struct json_object *object)
{
	struct afb_evt_watch *watch;
	struct afb_evt_listener *listener;

	pthread_rwlock_rdlock(&evtid->rwlock);
	watch = evtid->watchs;
	while(watch) {
		listener = watch->listener;
		assert(listener->itf->push != NULL);
		listener->itf->push(listener->closure, evtid->fullname, evtid->id, json_object_get(object));
		watch = watch->next_by_evtid;
	}
	pthread_rwlock_unlock(&evtid->rwlock);
}

/*
 * Jobs callback for pushing evtid asynchronously
 */
static void push_job_evtid(int signum, void *closure)
{
	struct job_evtid *je = closure;

	if (signum == 0)
		push_evtid(je->evtid, je->object);
	destroy_job_evtid(je);
}

/*
 * Pushes the event 'evtid' with 'obj' to its listeners
 * 'obj' is released (like json_object_put)
 * Returns 1 if at least one listener exists or 0 if no listener exists or
 * -1 in case of error and the event can't be delivered
 */
int afb_evt_evtid_push(struct afb_evtid *evtid, struct json_object *object)
{
	struct job_evtid *je;
	int rc;

	if (!evtid->watchs)
		return 0;

	je = make_job_evtid(evtid, object);
	if (je == NULL) {
		ERROR("Cant't create push evtid job item for %s(%s)",
			evtid->fullname, json_object_to_json_string(object));
		json_object_put(object);
		return -1;
	}

	rc = jobs_queue(PUSH_JOB_GROUP, 0, push_job_evtid, je);
	if (rc == 0)
		rc = 1;
	else {
		ERROR("cant't queue push evtid job item for %s(%s)",
			evtid->fullname, json_object_to_json_string(object));
		destroy_job_evtid(je);
	}

	return rc;
}

#if WITH_AFB_HOOK
/*
 * Pushes the event 'evtid' with 'obj' to its listeners
 * 'obj' is released (like json_object_put)
 * Emits calls to hooks.
 * Returns the count of listener taht received the event.
 */
int afb_evt_evtid_hooked_push(struct afb_evtid *evtid, struct json_object *obj)
{

	int result;

	/* lease the object */
	json_object_get(obj);

	/* hook before push */
	if (evtid->hookflags & afb_hook_flag_evt_push_before)
		afb_hook_evt_push_before(evtid->fullname, evtid->id, obj);

	/* push */
	result = afb_evt_evtid_push(evtid, obj);

	/* hook after push */
	if (evtid->hookflags & afb_hook_flag_evt_push_after)
		afb_hook_evt_push_after(evtid->fullname, evtid->id, obj, result);

	/* release the object */
	json_object_put(obj);
	return result;
}
#endif

static void unwatch(struct afb_evt_listener *listener, struct afb_evtid *evtid, int remove)
{
	/* notify listener if needed */
	if (remove && listener->itf->remove != NULL)
		listener->itf->remove(listener->closure, evtid->fullname, evtid->id);
}

static void evtid_unwatch(struct afb_evtid *evtid, struct afb_evt_listener *listener, struct afb_evt_watch *watch, int remove)
{
	struct afb_evt_watch **prv;

	/* notify listener if needed */
	unwatch(listener, evtid, remove);

	/* unlink the watch for its event */
	pthread_rwlock_wrlock(&listener->rwlock);
	prv = &listener->watchs;
	while(*prv) {
		if (*prv == watch) {
			*prv = watch->next_by_listener;
			break;
		}
		prv = &(*prv)->next_by_listener;
	}
	pthread_rwlock_unlock(&listener->rwlock);

	/* recycle memory */
	free(watch);
}

static void listener_unwatch(struct afb_evt_listener *listener, struct afb_evtid *evtid, struct afb_evt_watch *watch, int remove)
{
	struct afb_evt_watch **prv;

	/* notify listener if needed */
	unwatch(listener, evtid, remove);

	/* unlink the watch for its event */
	pthread_rwlock_wrlock(&evtid->rwlock);
	prv = &evtid->watchs;
	while(*prv) {
		if (*prv == watch) {
			*prv = watch->next_by_evtid;
			break;
		}
		prv = &(*prv)->next_by_evtid;
	}
	pthread_rwlock_unlock(&evtid->rwlock);

	/* recycle memory */
	free(watch);
}

/*
 * Creates an event of name 'fullname' and returns it or NULL on error.
 */
struct afb_evtid *afb_evt_evtid_create(const char *fullname)
{
	size_t len;
	struct afb_evtid *evtid, *oevt;
	uint16_t id;

	/* allocates the event */
	len = strlen(fullname);
	evtid = malloc(len + 1 + sizeof * evtid);
	if (evtid == NULL)
		goto error;

	/* allocates the id */
	pthread_rwlock_wrlock(&events_rwlock);
	if (event_count == UINT16_MAX) {
		pthread_rwlock_unlock(&events_rwlock);
		free(evtid);
		ERROR("Can't create more events");
		return NULL;
	}
	event_count++;
	do {
		/* TODO add a guard (counting number of event created) */
		id = ++event_genid;
		if (!id)
			id = event_genid = 1;
		oevt = evtids;
		while(oevt != NULL && oevt->id != id)
			oevt = oevt->next;
	} while (oevt != NULL);

	/* initialize the event */
	memcpy(evtid->fullname, fullname, len + 1);
	evtid->next = evtids;
	evtid->refcount = 1;
	evtid->watchs = NULL;
	evtid->id = id;
	pthread_rwlock_init(&evtid->rwlock, NULL);
	evtids = evtid;
#if WITH_AFB_HOOK
	evtid->hookflags = afb_hook_flags_evt(evtid->fullname);
	evtid->eventid.itf = evtid->hookflags ? &afb_evt_hooked_event_x2_itf : &afb_evt_event_x2_itf;
	if (evtid->hookflags & afb_hook_flag_evt_create)
		afb_hook_evt_create(evtid->fullname, evtid->id);
#else
	evtid->eventid.itf = &afb_evt_event_x2_itf;
#endif
	pthread_rwlock_unlock(&events_rwlock);

	/* returns the event */
	return evtid;
error:
	return NULL;
}

/*
 * Creates an event of name 'prefix'/'name' and returns it or NULL on error.
 */
struct afb_evtid *afb_evt_evtid_create2(const char *prefix, const char *name)
{
	size_t prelen, postlen;
	char *fullname;

	/* makes the event fullname */
	prelen = strlen(prefix);
	postlen = strlen(name);
	fullname = alloca(prelen + postlen + 2);
	memcpy(fullname, prefix, prelen);
	fullname[prelen] = '/';
	memcpy(fullname + prelen + 1, name, postlen + 1);

	/* create the event */
	return afb_evt_evtid_create(fullname);
}

/*
 * increment the reference count of the event 'evtid'
 */
struct afb_evtid *afb_evt_evtid_addref(struct afb_evtid *evtid)
{
	__atomic_add_fetch(&evtid->refcount, 1, __ATOMIC_RELAXED);
	return evtid;
}

#if WITH_AFB_HOOK
/*
 * increment the reference count of the event 'evtid'
 */
struct afb_evtid *afb_evt_evtid_hooked_addref(struct afb_evtid *evtid)
{
	if (evtid->hookflags & afb_hook_flag_evt_addref)
		afb_hook_evt_addref(evtid->fullname, evtid->id);
	return afb_evt_evtid_addref(evtid);
}
#endif

/*
 * decrement the reference count of the event 'evtid'
 * and destroy it when the count reachs zero
 */
void afb_evt_evtid_unref(struct afb_evtid *evtid)
{
	struct afb_evtid **prv, *oev;
	struct afb_evt_watch *watch, *nwatch;

	if (!__atomic_sub_fetch(&evtid->refcount, 1, __ATOMIC_RELAXED)) {
		/* unlinks the event if valid! */
		pthread_rwlock_wrlock(&events_rwlock);
		prv = &evtids;
		for(;;) {
			oev = *prv;
			if (oev == evtid)
				break;
			if (!oev) {
				ERROR("unexpected event");
				pthread_rwlock_unlock(&events_rwlock);
				return;
			}
			prv = &oev->next;
		}
		event_count--;
		*prv = evtid->next;
		pthread_rwlock_unlock(&events_rwlock);

		/* removes all watchers */
		pthread_rwlock_wrlock(&evtid->rwlock);
		watch = evtid->watchs;
		evtid->watchs = NULL;
		pthread_rwlock_unlock(&evtid->rwlock);
		while(watch) {
			nwatch = watch->next_by_evtid;
			evtid_unwatch(evtid, watch->listener, watch, 1);
			watch = nwatch;
		}

		/* free */
		pthread_rwlock_destroy(&evtid->rwlock);
		free(evtid);
	}
}

#if WITH_AFB_HOOK
/*
 * decrement the reference count of the event 'evtid'
 * and destroy it when the count reachs zero
 */
void afb_evt_evtid_hooked_unref(struct afb_evtid *evtid)
{
	if (evtid->hookflags & afb_hook_flag_evt_unref)
		afb_hook_evt_unref(evtid->fullname, evtid->id);
	afb_evt_evtid_unref(evtid);
}
#endif

/*
 * Returns the true name of the 'event'
 */
const char *afb_evt_evtid_fullname(struct afb_evtid *evtid)
{
	return evtid->fullname;
}

/*
 * Returns the name of the 'event'
 */
const char *afb_evt_evtid_name(struct afb_evtid *evtid)
{
	const char *name = strchr(evtid->fullname, '/');
	return name ? name + 1 : evtid->fullname;
}

#if WITH_AFB_HOOK
/*
 * Returns the name associated to the event 'evtid'.
 */
const char *afb_evt_evtid_hooked_name(struct afb_evtid *evtid)
{
	const char *result = afb_evt_evtid_name(evtid);
	if (evtid->hookflags & afb_hook_flag_evt_name)
		afb_hook_evt_name(evtid->fullname, evtid->id, result);
	return result;
}
#endif

/*
 * Returns the id of the 'event'
 */
uint16_t afb_evt_evtid_id(struct afb_evtid *evtid)
{
	return evtid->id;
}

/*
 * Returns an instance of the listener defined by the 'send' callback
 * and the 'closure'.
 * Returns NULL in case of memory depletion.
 */
struct afb_evt_listener *afb_evt_listener_create(const struct afb_evt_itf *itf, void *closure)
{
	struct afb_evt_listener *listener;

	/* search if an instance already exists */
	pthread_rwlock_wrlock(&listeners_rwlock);
	listener = listeners;
	while (listener != NULL) {
		if (listener->itf == itf && listener->closure == closure) {
			listener = afb_evt_listener_addref(listener);
			goto found;
		}
		listener = listener->next;
	}

	/* allocates */
	listener = calloc(1, sizeof *listener);
	if (listener != NULL) {
		/* init */
		listener->itf = itf;
		listener->closure = closure;
		listener->watchs = NULL;
		listener->refcount = 1;
		pthread_rwlock_init(&listener->rwlock, NULL);
		listener->next = listeners;
		listeners = listener;
	}
 found:
	pthread_rwlock_unlock(&listeners_rwlock);
	return listener;
}

/*
 * Increases the reference count of 'listener' and returns it
 */
struct afb_evt_listener *afb_evt_listener_addref(struct afb_evt_listener *listener)
{
	__atomic_add_fetch(&listener->refcount, 1, __ATOMIC_RELAXED);
	return listener;
}

/*
 * Decreases the reference count of the 'listener' and destroys it
 * when no more used.
 */
void afb_evt_listener_unref(struct afb_evt_listener *listener)
{
	struct afb_evt_listener **prv, *olis;

	if (listener && !__atomic_sub_fetch(&listener->refcount, 1, __ATOMIC_RELAXED)) {

		/* unlink the listener */
		pthread_rwlock_wrlock(&listeners_rwlock);
		prv = &listeners;
		for(;;) {
			olis = *prv;
			if (olis == listener)
				break;
			if (!olis) {
				ERROR("unexpected listener");
				pthread_rwlock_unlock(&listeners_rwlock);
				return;
			}
			prv = &olis->next;
		}
		*prv = listener->next;
		pthread_rwlock_unlock(&listeners_rwlock);

		/* remove the watchers */
		afb_evt_listener_unwatch_all(listener, 0);

		/* free the listener */
		pthread_rwlock_destroy(&listener->rwlock);
		free(listener);
	}
}

/*
 * Makes the 'listener' watching 'evtid'
 * Returns 0 in case of success or else -1.
 */
int afb_evt_listener_watch_evt(struct afb_evt_listener *listener, struct afb_evtid *evtid)
{
	struct afb_evt_watch *watch;

	/* check parameter */
	if (listener->itf->push == NULL) {
		errno = EINVAL;
		return -1;
	}

	/* search the existing watch for the listener */
	pthread_rwlock_wrlock(&listener->rwlock);
	watch = listener->watchs;
	while(watch != NULL) {
		if (watch->evtid == evtid)
			goto end;
		watch = watch->next_by_listener;
	}

	/* not found, allocate a new */
	watch = malloc(sizeof *watch);
	if (watch == NULL) {
		pthread_rwlock_unlock(&listener->rwlock);
		errno = ENOMEM;
		return -1;
	}

	/* initialise and link */
	watch->evtid = evtid;
	watch->listener = listener;
	watch->next_by_listener = listener->watchs;
	listener->watchs = watch;
	pthread_rwlock_wrlock(&evtid->rwlock);
	watch->next_by_evtid = evtid->watchs;
	evtid->watchs = watch;
	pthread_rwlock_unlock(&evtid->rwlock);

	if (listener->itf->add != NULL)
		listener->itf->add(listener->closure, evtid->fullname, evtid->id);
end:
	pthread_rwlock_unlock(&listener->rwlock);
	return 0;
}

/*
 * Avoids the 'listener' to watch 'evtid'
 * Returns 0 in case of success or else -1.
 */
int afb_evt_listener_unwatch_evt(struct afb_evt_listener *listener, struct afb_evtid *evtid)
{
	struct afb_evt_watch *watch, **pwatch;

	/* search the existing watch */
	pthread_rwlock_wrlock(&listener->rwlock);
	pwatch = &listener->watchs;
	for (;;) {
		watch = *pwatch;
		if (!watch) {
			pthread_rwlock_unlock(&listener->rwlock);
			errno = ENOENT;
			return -1;
		}
		if (evtid == watch->evtid) {
			*pwatch = watch->next_by_listener;
			pthread_rwlock_unlock(&listener->rwlock);
			listener_unwatch(listener, evtid, watch, 1);
			return 0;
		}
		pwatch = &watch->next_by_listener;
	}
}

/*
 * Avoids the 'listener' to watch 'eventid'
 * Returns 0 in case of success or else -1.
 */
int afb_evt_listener_unwatch_id(struct afb_evt_listener *listener, uint16_t eventid)
{
	struct afb_evt_watch *watch, **pwatch;
	struct afb_evtid *evtid;

	/* search the existing watch */
	pthread_rwlock_wrlock(&listener->rwlock);
	pwatch = &listener->watchs;
	for (;;) {
		watch = *pwatch;
		if (!watch) {
			pthread_rwlock_unlock(&listener->rwlock);
			errno = ENOENT;
			return -1;
		}
		evtid = watch->evtid;
		if (evtid->id == eventid) {
			*pwatch = watch->next_by_listener;
			pthread_rwlock_unlock(&listener->rwlock);
			listener_unwatch(listener, evtid, watch, 1);
			return 0;
		}
		pwatch = &watch->next_by_listener;
	}
}

/*
 * Avoids the 'listener' to watch any event, calling the callback
 * 'remove' of the interface if 'remoe' is not zero.
 */
void afb_evt_listener_unwatch_all(struct afb_evt_listener *listener, int remove)
{
	struct afb_evt_watch *watch, *nwatch;

	/* search the existing watch */
	pthread_rwlock_wrlock(&listener->rwlock);
	watch = listener->watchs;
	listener->watchs = NULL;
	pthread_rwlock_unlock(&listener->rwlock);
	while(watch) {
		nwatch = watch->next_by_listener;
		listener_unwatch(listener, watch->evtid, watch, remove);
		watch = nwatch;
	}
}

#if WITH_AFB_HOOK
/*
 * update the hooks for events
 */
void afb_evt_update_hooks()
{
	struct afb_evtid *evtid;

	pthread_rwlock_rdlock(&events_rwlock);
	for (evtid = evtids ; evtid ; evtid = evtid->next) {
		evtid->hookflags = afb_hook_flags_evt(evtid->fullname);
		evtid->eventid.itf = evtid->hookflags ? &afb_evt_hooked_event_x2_itf : &afb_evt_event_x2_itf;
	}
	pthread_rwlock_unlock(&events_rwlock);
}
#endif

inline struct afb_evtid *afb_evt_event_x2_to_evtid(struct afb_event_x2 *eventid)
{
	return (struct afb_evtid*)eventid;
}

inline struct afb_event_x2 *afb_evt_event_x2_from_evtid(struct afb_evtid *evtid)
{
	return &evtid->eventid;
}

/*
 * Creates an event of 'fullname' and returns it.
 * Returns an event with closure==NULL in case of error.
 */
struct afb_event_x2 *afb_evt_event_x2_create(const char *fullname)
{
	return afb_evt_event_x2_from_evtid(afb_evt_evtid_create(fullname));
}

/*
 * Creates an event of name 'prefix'/'name' and returns it.
 * Returns an event with closure==NULL in case of error.
 */
struct afb_event_x2 *afb_evt_event_x2_create2(const char *prefix, const char *name)
{
	return afb_evt_event_x2_from_evtid(afb_evt_evtid_create2(prefix, name));
}

/*
 * Returns the fullname of the 'eventid'
 */
const char *afb_evt_event_x2_fullname(struct afb_event_x2 *eventid)
{
	struct afb_evtid *evtid = afb_evt_event_x2_to_evtid(eventid);
	return evtid ? evtid->fullname : NULL;
}

/*
 * Returns the id of the 'eventid'
 */
uint16_t afb_evt_event_x2_id(struct afb_event_x2 *eventid)
{
	struct afb_evtid *evtid = afb_evt_event_x2_to_evtid(eventid);
	return evtid ? evtid->id : 0;
}

/*
 * Makes the 'listener' watching 'eventid'
 * Returns 0 in case of success or else -1.
 */
int afb_evt_listener_watch_x2(struct afb_evt_listener *listener, struct afb_event_x2 *eventid)
{
	struct afb_evtid *evtid = afb_evt_event_x2_to_evtid(eventid);

	/* check parameter */
	if (!evtid) {
		errno = EINVAL;
		return -1;
	}

	/* search the existing watch for the listener */
	return afb_evt_listener_watch_evt(listener, evtid);
}

/*
 * Avoids the 'listener' to watch 'eventid'
 * Returns 0 in case of success or else -1.
 */
int afb_evt_listener_unwatch_x2(struct afb_evt_listener *listener, struct afb_event_x2 *eventid)
{
	struct afb_evtid *evtid = afb_evt_event_x2_to_evtid(eventid);

	/* check parameter */
	if (!evtid) {
		errno = EINVAL;
		return -1;
	}

	/* search the existing watch */
	return afb_evt_listener_unwatch_evt(listener, evtid);
}

int afb_evt_event_x2_push(struct afb_event_x2 *eventid, struct json_object *object)
#if WITH_AFB_HOOK
{
	struct afb_evtid *evtid = afb_evt_event_x2_to_evtid(eventid);
	if (evtid)
		return afb_evt_evtid_hooked_push(evtid, object);
	json_object_put(object);
	return 0;
}
#else
	__attribute__((alias("afb_evt_event_x2_unhooked_push")));
#endif

int afb_evt_event_x2_unhooked_push(struct afb_event_x2 *eventid, struct json_object *object)
{
	struct afb_evtid *evtid = afb_evt_event_x2_to_evtid(eventid);
	if (evtid)
		return afb_evt_evtid_push(evtid, object);
	json_object_put(object);
	return 0;
}

#if WITH_LEGACY_BINDING_V1 || WITH_LEGACY_BINDING_V2
struct afb_event_x1 afb_evt_event_from_evtid(struct afb_evtid *evtid)
{
	return evtid
#if WITH_AFB_HOOK
		? (struct afb_event_x1){ .itf = &afb_evt_hooked_event_x2_itf, .closure = &evtid->eventid }
#else
		? (struct afb_event_x1){ .itf = &afb_evt_event_x2_itf, .closure = &evtid->eventid }
#endif
		: (struct afb_event_x1){ .itf = NULL, .closure = NULL };
}
#endif

void afb_evt_event_x2_unref(struct afb_event_x2 *eventid)
{
	struct afb_evtid *evtid = afb_evt_event_x2_to_evtid(eventid);
	if (evtid)
		afb_evt_evtid_unref(evtid);
}

struct afb_event_x2 *afb_evt_event_x2_addref(struct afb_event_x2 *eventid)
{
	struct afb_evtid *evtid = afb_evt_event_x2_to_evtid(eventid);
	if (evtid)
		afb_evt_evtid_addref(evtid);
	return eventid;
}

