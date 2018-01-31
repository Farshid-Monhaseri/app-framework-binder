/*
 * Copyright (C) 2015, 2016, 2017 "IoT.bzh"
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
#include <afb/afb-eventid-itf.h>
#include <afb/afb-event.h>

#include "afb-evt.h"
#include "afb-hook.h"
#include "verbose.h"

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

	/* mutex of the listener */
	pthread_mutex_t mutex;

	/* count of reference to the listener */
	int refcount;
};

/*
 * Structure for describing events
 */
struct afb_evtid {

	/* interface */
	struct afb_eventid eventid;

	/* next event */
	struct afb_evtid *next;

	/* head of the list of listeners watching the event */
	struct afb_evt_watch *watchs;

	/* mutex of the event */
	pthread_mutex_t mutex;

	/* hooking */
	int hookflags;

	/* refcount */
	int refcount;

	/* id of the event */
	int id;

	/* fullname of the event */
	char fullname[1];
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

	/* activity */
	unsigned activity;
};

/* the interface for events */
static struct afb_eventid_itf afb_evt_eventid_itf = {
	.broadcast = (void*)afb_evt_evtid_broadcast,
	.push = (void*)afb_evt_evtid_push,
	.unref = (void*)afb_evt_evtid_unref,
	.name = (void*)afb_evt_evtid_name,
	.addref = (void*)afb_evt_evtid_addref
};

/* the interface for events */
static struct afb_eventid_itf afb_evt_hooked_eventid_itf = {
	.broadcast = (void*)afb_evt_evtid_hooked_broadcast,
	.push = (void*)afb_evt_evtid_hooked_push,
	.unref = (void*)afb_evt_evtid_hooked_unref,
	.name = (void*)afb_evt_evtid_hooked_name,
	.addref = (void*)afb_evt_evtid_hooked_addref
};

/* head of the list of listeners */
static pthread_mutex_t listeners_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct afb_evt_listener *listeners = NULL;

/* handling id of events */
static pthread_mutex_t events_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct afb_evtid *evtids = NULL;
static int event_id_counter = 0;
static int event_id_wrapped = 0;

/*
 * Broadcasts the 'event' of 'id' with its 'obj'
 * 'obj' is released (like json_object_put)
 * Returns the count of listener having receive the event.
 */
static int broadcast(const char *event, struct json_object *obj, int id)
{
	int result;
	struct afb_evt_listener *listener;

	result = 0;
	pthread_mutex_lock(&listeners_mutex);
	listener = listeners;
	while(listener) {
		if (listener->itf->broadcast != NULL) {
			listener->itf->broadcast(listener->closure, event, id, json_object_get(obj));
			result++;
		}
		listener = listener->next;
	}
	pthread_mutex_unlock(&listeners_mutex);
	json_object_put(obj);
	return result;
}

/*
 * Broadcasts the 'event' of 'id' with its 'obj'
 * 'obj' is released (like json_object_put)
 * calls hooks if hookflags isn't 0
 * Returns the count of listener having receive the event.
 */
static int hooked_broadcast(const char *event, struct json_object *obj, int id, int hookflags)
{
	int result;

	json_object_get(obj);

	if (hookflags & afb_hook_flag_evt_broadcast_before)
		afb_hook_evt_broadcast_before(event, id, obj);

	result = broadcast(event, obj, id);

	if (hookflags & afb_hook_flag_evt_broadcast_after)
		afb_hook_evt_broadcast_after(event, id, obj, result);

	json_object_put(obj);

	return result;
}

/*
 * Broadcasts the event 'evtid' with its 'object'
 * 'object' is released (like json_object_put)
 * Returns the count of listener that received the event.
 */
int afb_evt_evtid_broadcast(struct afb_evtid *evtid, struct json_object *object)
{
	return broadcast(evtid->fullname, object, evtid->id);
}

/*
 * Broadcasts the event 'evtid' with its 'object'
 * 'object' is released (like json_object_put)
 * Returns the count of listener that received the event.
 */
int afb_evt_evtid_hooked_broadcast(struct afb_evtid *evtid, struct json_object *object)
{
	return hooked_broadcast(evtid->fullname, object, evtid->id, evtid->hookflags);
}

/*
 * Broadcasts the 'event' with its 'object'
 * 'object' is released (like json_object_put)
 * Returns the count of listener having receive the event.
 */
int afb_evt_broadcast(const char *event, struct json_object *object)
{
	return hooked_broadcast(event, object, 0, -1);
}

/*
 * Pushes the event 'evtid' with 'obj' to its listeners
 * 'obj' is released (like json_object_put)
 * Returns the count of listener that received the event.
 */
int afb_evt_evtid_push(struct afb_evtid *evtid, struct json_object *obj)
{
	int result;
	struct afb_evt_watch *watch;
	struct afb_evt_listener *listener;

	result = 0;
	pthread_mutex_lock(&evtid->mutex);
	watch = evtid->watchs;
	while(watch) {
		listener = watch->listener;
		assert(listener->itf->push != NULL);
		if (watch->activity != 0) {
			listener->itf->push(listener->closure, evtid->fullname, evtid->id, json_object_get(obj));
			result++;
		}
		watch = watch->next_by_evtid;
	}
	pthread_mutex_unlock(&evtid->mutex);
	json_object_put(obj);
	return result;
}

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

/*
 * remove the 'watch'
 */
static void remove_watch(struct afb_evt_watch *watch)
{
	struct afb_evt_watch **prv;
	struct afb_evtid *evtid;
	struct afb_evt_listener *listener;

	/* notify listener if needed */
	evtid = watch->evtid;
	listener = watch->listener;
	if (watch->activity != 0 && listener->itf->remove != NULL)
		listener->itf->remove(listener->closure, evtid->fullname, evtid->id);

	/* unlink the watch for its event */
	prv = &evtid->watchs;
	while(*prv != watch)
		prv = &(*prv)->next_by_evtid;
	*prv = watch->next_by_evtid;

	/* unlink the watch for its listener */
	prv = &listener->watchs;
	while(*prv != watch)
		prv = &(*prv)->next_by_listener;
	*prv = watch->next_by_listener;

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

	/* allocates the event */
	len = strlen(fullname);
	evtid = malloc(len + sizeof * evtid);
	if (evtid == NULL)
		goto error;

	/* allocates the id */
	pthread_mutex_lock(&events_mutex);
	do {
		if (++event_id_counter < 0) {
			event_id_wrapped = 1;
			event_id_counter = 1024; /* heuristic: small numbers are not destroyed */
		}
		if (!event_id_wrapped)
			break;
		oevt = evtids;
		while(oevt != NULL && oevt->id != event_id_counter)
			oevt = oevt->next;
	} while (oevt != NULL);

	/* initialize the event */
	memcpy(evtid->fullname, fullname, len + 1);
	evtid->next = evtids;
	evtid->watchs = NULL;
	evtid->id = event_id_counter;
	pthread_mutex_init(&evtid->mutex, NULL);
	evtids = evtid;
	evtid->hookflags = afb_hook_flags_evt(evtid->fullname);
	evtid->eventid.itf = evtid->hookflags ? &afb_evt_hooked_eventid_itf : &afb_evt_eventid_itf;
	if (evtid->hookflags & afb_hook_flag_evt_create)
		afb_hook_evt_create(evtid->fullname, evtid->id);
	pthread_mutex_unlock(&events_mutex);

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

/*
 * increment the reference count of the event 'evtid'
 */
struct afb_evtid *afb_evt_evtid_hooked_addref(struct afb_evtid *evtid)
{
	if (evtid->hookflags & afb_hook_flag_evt_addref)
		afb_hook_evt_addref(evtid->fullname, evtid->id);
	return afb_evt_evtid_addref(evtid);
}

/*
 * decrement the reference count of the event 'evtid'
 * and destroy it when the count reachs zero
 */
void afb_evt_evtid_unref(struct afb_evtid *evtid)
{
	int found;
	struct afb_evtid **prv;
	struct afb_evt_listener *listener;

	if (!__atomic_sub_fetch(&evtid->refcount, 1, __ATOMIC_RELAXED)) {
		/* unlinks the event if valid! */
		pthread_mutex_lock(&events_mutex);
		found = 0;
		prv = &evtids;
		while (*prv && !(found = (*prv == evtid)))
			prv = &(*prv)->next;
		if (found)
			*prv = evtid->next;
		pthread_mutex_unlock(&events_mutex);

		/* destroys the event */
		if (!found)
			ERROR("event not found");
		else {
			/* removes all watchers */
			while(evtid->watchs != NULL) {
				listener = evtid->watchs->listener;
				pthread_mutex_lock(&listener->mutex);
				pthread_mutex_lock(&evtid->mutex);
				remove_watch(evtid->watchs);
				pthread_mutex_unlock(&evtid->mutex);
				pthread_mutex_unlock(&listener->mutex);
			}

			/* free */
			pthread_mutex_destroy(&evtid->mutex);
			free(evtid);
		}
	}
}

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

/*
 * Returns the id of the 'event'
 */
int afb_evt_evtid_id(struct afb_evtid *evtid)
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
	pthread_mutex_lock(&listeners_mutex);
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
		pthread_mutex_init(&listener->mutex, NULL);
		listener->next = listeners;
		listeners = listener;
	}
 found:
	pthread_mutex_unlock(&listeners_mutex);
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
	struct afb_evt_listener **prv;
	struct afb_evtid *evtid;

	if (!__atomic_sub_fetch(&listener->refcount, 1, __ATOMIC_RELAXED)) {

		/* unlink the listener */
		pthread_mutex_lock(&listeners_mutex);
		prv = &listeners;
		while (*prv != listener)
			prv = &(*prv)->next;
		*prv = listener->next;
		pthread_mutex_unlock(&listeners_mutex);

		/* remove the watchers */
		pthread_mutex_lock(&listener->mutex);
		while (listener->watchs != NULL) {
			evtid = listener->watchs->evtid;
			pthread_mutex_lock(&evtid->mutex);
			remove_watch(listener->watchs);
			pthread_mutex_unlock(&evtid->mutex);
		}
		pthread_mutex_unlock(&listener->mutex);

		/* free the listener */
		pthread_mutex_destroy(&listener->mutex);
		free(listener);
	}
}

/*
 * Makes the 'listener' watching 'evtid'
 * Returns 0 in case of success or else -1.
 */
int afb_evt_watch_add_evtid(struct afb_evt_listener *listener, struct afb_evtid *evtid)
{
	struct afb_evt_watch *watch;

	/* check parameter */
	if (listener->itf->push == NULL) {
		errno = EINVAL;
		return -1;
	}

	/* search the existing watch for the listener */
	pthread_mutex_lock(&listener->mutex);
	watch = listener->watchs;
	while(watch != NULL) {
		if (watch->evtid == evtid)
			goto found;
		watch = watch->next_by_listener;
	}

	/* not found, allocate a new */
	watch = malloc(sizeof *watch);
	if (watch == NULL) {
		pthread_mutex_unlock(&listener->mutex);
		errno = ENOMEM;
		return -1;
	}

	/* initialise and link */
	watch->evtid = evtid;
	watch->activity = 0;
	watch->listener = listener;
	watch->next_by_listener = listener->watchs;
	listener->watchs = watch;
	pthread_mutex_lock(&evtid->mutex);
	watch->next_by_evtid = evtid->watchs;
	evtid->watchs = watch;
	pthread_mutex_unlock(&evtid->mutex);

found:
	if (watch->activity == 0 && listener->itf->add != NULL)
		listener->itf->add(listener->closure, evtid->fullname, evtid->id);
	watch->activity++;
	pthread_mutex_unlock(&listener->mutex);

	return 0;
}

/*
 * Avoids the 'listener' to watch 'evtid'
 * Returns 0 in case of success or else -1.
 */
int afb_evt_watch_sub_evtid(struct afb_evt_listener *listener, struct afb_evtid *evtid)
{
	struct afb_evt_watch *watch;

	/* search the existing watch */
	pthread_mutex_lock(&listener->mutex);
	watch = listener->watchs;
	while(watch != NULL) {
		if (watch->evtid == evtid) {
			if (watch->activity != 0) {
				watch->activity--;
				if (watch->activity == 0 && listener->itf->remove != NULL)
					listener->itf->remove(listener->closure, evtid->fullname, evtid->id);
			}
			pthread_mutex_unlock(&listener->mutex);
			return 0;
		}
		watch = watch->next_by_listener;
	}
	pthread_mutex_unlock(&listener->mutex);
	errno = ENOENT;
	return -1;
}

/*
 * update the hooks for events
 */
void afb_evt_update_hooks()
{
	struct afb_evtid *evtid;

	pthread_mutex_lock(&events_mutex);
	for (evtid = evtids ; evtid ; evtid = evtid->next) {
		evtid->hookflags = afb_hook_flags_evt(evtid->fullname);
		evtid->eventid.itf = evtid->hookflags ? &afb_evt_hooked_eventid_itf : &afb_evt_eventid_itf;
	}
	pthread_mutex_unlock(&events_mutex);
}

inline struct afb_evtid *afb_evt_eventid_to_evtid(struct afb_eventid *eventid)
{
	return (struct afb_evtid*)eventid;
}

inline struct afb_eventid *afb_evt_eventid_from_evtid(struct afb_evtid *evtid)
{
	return &evtid->eventid;
}

/*
 * Creates an event of 'fullname' and returns it.
 * Returns an event with closure==NULL in case of error.
 */
struct afb_eventid *afb_evt_eventid_create(const char *fullname)
{
	return afb_evt_eventid_from_evtid(afb_evt_evtid_create(fullname));
}

/*
 * Creates an event of name 'prefix'/'name' and returns it.
 * Returns an event with closure==NULL in case of error.
 */
struct afb_eventid *afb_evt_eventid_create2(const char *prefix, const char *name)
{
	return afb_evt_eventid_from_evtid(afb_evt_evtid_create2(prefix, name));
}

/*
 * Returns the fullname of the 'eventid'
 */
const char *afb_evt_eventid_fullname(struct afb_eventid *eventid)
{
	struct afb_evtid *evtid = afb_evt_eventid_to_evtid(eventid);
	return evtid ? evtid->fullname : NULL;
}

/*
 * Returns the id of the 'eventid'
 */
int afb_evt_eventid_id(struct afb_eventid *eventid)
{
	struct afb_evtid *evtid = afb_evt_eventid_to_evtid(eventid);
	return evtid ? evtid->id : 0;
}

/*
 * Makes the 'listener' watching 'eventid'
 * Returns 0 in case of success or else -1.
 */
int afb_evt_eventid_add_watch(struct afb_evt_listener *listener, struct afb_eventid *eventid)
{
	struct afb_evtid *evtid = afb_evt_eventid_to_evtid(eventid);

	/* check parameter */
	if (!evtid) {
		errno = EINVAL;
		return -1;
	}

	/* search the existing watch for the listener */
	return afb_evt_watch_add_evtid(listener, evtid);
}

/*
 * Avoids the 'listener' to watch 'eventid'
 * Returns 0 in case of success or else -1.
 */
int afb_evt_eventid_remove_watch(struct afb_evt_listener *listener, struct afb_eventid *eventid)
{
	struct afb_evtid *evtid = afb_evt_eventid_to_evtid(eventid);

	/* check parameter */
	if (!evtid) {
		errno = EINVAL;
		return -1;
	}

	/* search the existing watch */
	return afb_evt_watch_sub_evtid(listener, evtid);
}

int afb_evt_eventid_push(struct afb_eventid *eventid, struct json_object *object)
{
	struct afb_evtid *evtid = afb_evt_eventid_to_evtid(eventid);
	if (evtid)
		return afb_evt_evtid_hooked_push(evtid, object);
	json_object_put(object);
	return 0;
}

int afb_evt_eventid_unhooked_push(struct afb_eventid *eventid, struct json_object *object)
{
	struct afb_evtid *evtid = afb_evt_eventid_to_evtid(eventid);
	if (evtid)
		return afb_evt_evtid_push(evtid, object);
	json_object_put(object);
	return 0;
}

struct afb_event afb_evt_event_from_evtid(struct afb_evtid *evtid)
{
	return evtid
		? (struct afb_event){ .itf = &afb_evt_hooked_eventid_itf, .closure = &evtid->eventid }
		: (struct afb_event){ .itf = NULL, .closure = NULL };
}

void afb_evt_eventid_unref(struct afb_eventid *eventid)
{
	struct afb_evtid *evtid = afb_evt_eventid_to_evtid(eventid);
	if (evtid)
		afb_evt_evtid_unref(evtid);
}

struct afb_eventid *afb_evt_eventid_addref(struct afb_eventid *eventid)
{
	struct afb_evtid *evtid = afb_evt_eventid_to_evtid(eventid);
	if (evtid)
		afb_evt_evtid_addref(evtid);
	return eventid;
}

