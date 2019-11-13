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

#if WITH_DBUS_TRANSPARENCY

#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include <systemd/sd-bus.h>
#include <json-c/json.h>
#if !defined(JSON_C_TO_STRING_NOSLASHESCAPE)
#define JSON_C_TO_STRING_NOSLASHESCAPE 0
#endif

#include <afb/afb-event-x2.h>

#include "afb-session.h"
#include "afb-msg-json.h"
#include "afb-api.h"
#include "afb-apiset.h"
#include "afb-api-dbus.h"
#include "afb-context.h"
#include "afb-cred.h"
#include "afb-evt.h"
#include "afb-xreq.h"

#include "verbose.h"
#include "systemd.h"
#include "jobs.h"

static const char DEFAULT_PATH_PREFIX[] = "/org/agl/afb/api/";

struct dbus_memo;
struct dbus_event;
struct origin;

/*
 * The path given are of the form
 *     system:/org/agl/afb/api/...
 * or
 *     user:/org/agl/afb/api/...
 */
struct api_dbus
{
	struct sd_bus *sdbus;	/* the bus */
	char *path;		/* path of the object for the API */
	char *name;		/* name/interface of the object */
	char *api;		/* api name of the interface */
	union {
		struct {
			struct sd_bus_slot *slot_broadcast;
			struct sd_bus_slot *slot_event;
			struct dbus_event *events;
			struct dbus_memo *memos;
		} client;
		struct {
			struct sd_bus_slot *slot_call;
			struct afb_evt_listener *listener; /* listener for broadcasted events */
			struct origin *origins;
			struct afb_apiset *apiset;
		} server;
	};
};

/******************* common part **********************************/

/*
 * create a structure api_dbus connected on either the system
 * bus if 'system' is not null or on the user bus. The connection
 * is established for either emiting/receiving on 'path' being of length
 * 'pathlen'.
 */
static struct api_dbus *make_api_dbus_3(int system, const char *path, size_t pathlen)
{
	struct api_dbus *api;
	struct sd_bus *sdbus;
	char *ptr;

	/* allocates the structure */
	api = calloc(1, sizeof *api + 1 + pathlen + pathlen);
	if (api == NULL) {
		errno = ENOMEM;
		goto error;
	}

	/* init the structure's strings */

	/* path is copied after the struct */
	api->path = (void*)(api+1);
	strcpy(api->path, path);

	/* api name is at the end of the path */
	api->api = strrchr(api->path, '/');
	if (api->api == NULL) {
		errno = EINVAL;
		goto error2;
	}
	api->api++;
	if (!afb_api_is_valid_name(api->api)) {
		errno = EINVAL;
		goto error2;
	}

	/* the name/interface is copied after the path */
	api->name = &api->path[pathlen + 1];
	strcpy(api->name, &path[1]);
	ptr = strchr(api->name, '/');
	while(ptr != NULL) {
		*ptr = '.';
		ptr = strchr(ptr, '/');
	}

	/* choose the bus */
	jobs_acquire_event_manager();
	sdbus = (system ? systemd_get_system_bus : systemd_get_user_bus)();
	if (sdbus == NULL)
		goto error2;

	api->sdbus = sdbus;
	return api;

error2:
	free(api);
error:
	return NULL;
}

/*
 * create a structure api_dbus connected on either the system
 * bus if 'system' is not null or on the user bus. The connection
 * is established for either emiting/receiving on 'path'.
 * If 'path' is not absolute, it is prefixed with DEFAULT_PATH_PREFIX.
 */
static struct api_dbus *make_api_dbus_2(int system, const char *path)
{
	size_t len;
	char *ptr;

	/* check the length of the path */
	len = strlen(path);
	if (len == 0) {
		errno = EINVAL;
		return NULL;
	}

	/* if the path is absolute, creation now */
	if (path[0] == '/')
		return make_api_dbus_3(system, path, len);

	/* compute the path prefixed with DEFAULT_PATH_PREFIX */
	assert(strlen(DEFAULT_PATH_PREFIX) > 0);
	assert(DEFAULT_PATH_PREFIX[strlen(DEFAULT_PATH_PREFIX) - 1] == '/');
	len += strlen(DEFAULT_PATH_PREFIX);
	ptr = alloca(len + 1);
	strcpy(stpcpy(ptr, DEFAULT_PATH_PREFIX), path);

	/* creation for prefixed path */
	return make_api_dbus_3(system, ptr, len);
}

/*
 * create a structure api_dbus connected either emiting/receiving
 * on 'path'.
 * The path can be prefixed with "system:" or "user:" to select
 * either the user or the system D-Bus. If none is set then user's
 * bus is selected.
 * If remaining 'path' is not absolute, it is prefixed with
 * DEFAULT_PATH_PREFIX.
 */
static struct api_dbus *make_api_dbus(const char *path)
{
	const char *ptr;
	size_t preflen;

	/* retrieves the prefix "scheme-like" part */
	ptr = strchr(path, ':');
	if (ptr == NULL)
		return make_api_dbus_2(0, path);

	/* check the prefix part */
	preflen = (size_t)(ptr - path);
	if (strncmp(path, "system", preflen) == 0)
		return make_api_dbus_2(1, ptr + 1);

	if (strncmp(path, "user", preflen) == 0)
		return make_api_dbus_2(0, ptr + 1);

	/* TODO: connect to a foreign D-Bus? */
	errno = EINVAL;
	return NULL;
}

static void destroy_api_dbus(struct api_dbus *api)
{
	free(api);
}

/******************* client part **********************************/

/*
 * structure for recording query data
 */
struct dbus_memo {
	struct dbus_memo *next;		/* the next memo */
	struct api_dbus *api;		/* the dbus api */
	struct afb_xreq *xreq;		/* the request */
	uint64_t msgid;			/* the message identifier */
};

struct dbus_event
{
	struct dbus_event *next;
	struct afb_event_x2 *event;
	int id;
	int refcount;
};

/* allocates and init the memorizing data */
static struct dbus_memo *api_dbus_client_memo_make(struct api_dbus *api, struct afb_xreq *xreq)
{
	struct dbus_memo *memo;

	memo = malloc(sizeof *memo);
	if (memo != NULL) {
		afb_xreq_unhooked_addref(xreq);
		memo->xreq = xreq;
		memo->msgid = 0;
		memo->api = api;
		memo->next = api->client.memos;
		api->client.memos = memo;
	}
	return memo;
}

/* free and release the memorizing data */
static void api_dbus_client_memo_destroy(struct dbus_memo *memo)
{
	struct dbus_memo **prv;

	prv = &memo->api->client.memos;
	while (*prv != NULL) {
		if (*prv == memo) {
			*prv = memo->next;
			break;
		}
		prv = &(*prv)->next;
	}

	afb_xreq_unhooked_unref(memo->xreq);
	free(memo);
}

/* search a memorized request */
static struct dbus_memo *api_dbus_client_memo_search(struct api_dbus *api, uint64_t msgid)
{
	struct dbus_memo *memo;

	memo = api->client.memos;
	while (memo != NULL && memo->msgid != msgid)
		memo = memo->next;

	return memo;
}

/* callback when received answer */
static int api_dbus_client_on_reply(sd_bus_message *message, void *userdata, sd_bus_error *ret_error)
{
	int rc;
	struct dbus_memo *memo;
	const char *json, *error, *info;
	struct json_object *object;
	enum json_tokener_error jerr;

	/* retrieve the recorded data */
	memo = userdata;

	/* get the answer */
	rc = sd_bus_message_read(message, "sss", &json, &error, &info);
	if (rc < 0) {
		/* failing to have the answer */
		afb_xreq_reply(memo->xreq, NULL, "error", "dbus error");
	} else {
		/* report the answer */
		if (!*json)
			object = NULL;
		else {
			object = json_tokener_parse_verbose(json, &jerr);
			if (jerr != json_tokener_success)
				object = json_object_new_string(json);
		}
		afb_xreq_reply(memo->xreq, object, *error ? error : NULL, *info ? info : NULL);
	}
	api_dbus_client_memo_destroy(memo);
	return 1;
}

/* on call, propagate it to the dbus service */
static void api_dbus_client_call(void *closure, struct afb_xreq *xreq)
{
	struct api_dbus *api = closure;
	size_t size;
	int rc;
	struct dbus_memo *memo;
	struct sd_bus_message *msg;
	const char *creds;

	/* create the recording data */
	memo = api_dbus_client_memo_make(api, xreq);
	if (memo == NULL) {
		afb_xreq_reply(memo->xreq, NULL, "error", "out of memory");
		return;
	}

	/* creates the message */
	msg = NULL;
	rc = sd_bus_message_new_method_call(api->sdbus, &msg, api->name, api->path, api->name, xreq->request.called_verb);
	if (rc < 0)
		goto error;

	creds = xreq_on_behalf_cred_export(xreq);
	rc = sd_bus_message_append(msg, "ssus",
			afb_xreq_raw(xreq, &size),
			afb_session_uuid(xreq->context.session),
			(uint32_t)xreq->context.flags,
			creds ?: "");
	if (rc < 0)
		goto error;

	/* makes the call */
	rc = sd_bus_call_async(api->sdbus, NULL, msg, api_dbus_client_on_reply, memo, (uint64_t)-1);
	if (rc < 0)
		goto error;

	rc = sd_bus_message_get_cookie(msg, &memo->msgid);
	if (rc >= 0)
		goto end;

error:
	/* if there was an error report it directly */
	errno = -rc;
	afb_xreq_reply(memo->xreq, NULL, "error", "dbus error");
	api_dbus_client_memo_destroy(memo);
end:
	sd_bus_message_unref(msg);
}

/* receives broadcasted events */
static int api_dbus_client_on_broadcast_event(sd_bus_message *m, void *userdata, sd_bus_error *ret_error)
{
	struct json_object *object;
	const char *event, *data;
	const unsigned char *uuid;
	size_t szuuid;
	uint8_t hop;
	enum json_tokener_error jerr;

	int rc = sd_bus_message_read(m, "ssayy", &event, &data, &uuid, &szuuid, &hop);
	if (rc < 0)
		ERROR("unreadable broadcasted event");
	else {
		object = json_tokener_parse_verbose(data, &jerr);
		if (jerr != json_tokener_success)
			object = json_object_new_string(data);
		afb_evt_rebroadcast(event, object, uuid, hop);
	}
	return 1;
}

/* search the eventid */
static struct dbus_event *api_dbus_client_event_search(struct api_dbus *api, int id, const char *name)
{
	struct dbus_event *ev;

	ev = api->client.events;
	while (ev != NULL && (ev->id != id || 0 != strcmp(afb_evt_event_x2_fullname(ev->event), name)))
		ev = ev->next;

	return ev;
}

/* adds an eventid */
static void api_dbus_client_event_create(struct api_dbus *api, int id, const char *name)
{
	struct dbus_event *ev;

	/* check conflicts */
	ev = api_dbus_client_event_search(api, id, name);
	if (ev != NULL) {
		ev->refcount++;
		return;
	}

	/* no conflict, try to add it */
	ev = malloc(sizeof *ev);
	if (ev != NULL) {
		ev->event = afb_evt_event_x2_create(name);
		if (ev->event == NULL)
			free(ev);
		else {
			ev->refcount = 1;
			ev->id = id;
			ev->next = api->client.events;
			api->client.events = ev;
			return;
		}
	}
	ERROR("can't create event %s, out of memory", name);
}

/* removes an eventid */
static void api_dbus_client_event_drop(struct api_dbus *api, int id, const char *name)
{
	struct dbus_event *ev, **prv;

	/* retrieves the event */
	ev = api_dbus_client_event_search(api, id, name);
	if (ev == NULL) {
		ERROR("event %s not found", name);
		return;
	}

	/* decrease the reference count */
	if (--ev->refcount)
		return;

	/* unlinks the event */
	prv = &api->client.events;
	while (*prv != ev)
		prv = &(*prv)->next;
	*prv = ev->next;

	/* destroys the event */
	afb_evt_event_x2_unref(ev->event);
	free(ev);
}

/* pushs an event */
static void api_dbus_client_event_push(struct api_dbus *api, int id, const char *name, const char *data)
{
	struct json_object *object;
	struct dbus_event *ev;
	enum json_tokener_error jerr;

	/* retrieves the event */
	ev = api_dbus_client_event_search(api, id, name);
	if (ev == NULL) {
		ERROR("event %s not found", name);
		return;
	}

	/* destroys the event */
	object = json_tokener_parse_verbose(data, &jerr);
	if (jerr != json_tokener_success)
		object = json_object_new_string(data);
	afb_evt_event_x2_push(ev->event, object);
}

/* subscribes an event */
static void api_dbus_client_event_subscribe(struct api_dbus *api, int id, const char *name, uint64_t msgid)
{
	int rc;
	struct dbus_event *ev;
	struct dbus_memo *memo;

	/* retrieves the event */
	ev = api_dbus_client_event_search(api, id, name);
	if (ev == NULL) {
		ERROR("event %s not found", name);
		return;
	}

	/* retrieves the memo */
	memo = api_dbus_client_memo_search(api, msgid);
	if (memo == NULL) {
		ERROR("message not found");
		return;
	}

	/* subscribe the request to the event */
	rc = afb_xreq_subscribe(memo->xreq, ev->event);
	if (rc < 0)
		ERROR("can't subscribe: %m");
}

/* unsubscribes an event */
static void api_dbus_client_event_unsubscribe(struct api_dbus *api, int id, const char *name, uint64_t msgid)
{
	int rc;
	struct dbus_event *ev;
	struct dbus_memo *memo;

	/* retrieves the event */
	ev = api_dbus_client_event_search(api, id, name);
	if (ev == NULL) {
		ERROR("event %s not found", name);
		return;
	}

	/* retrieves the memo */
	memo = api_dbus_client_memo_search(api, msgid);
	if (memo == NULL) {
		ERROR("message not found");
		return;
	}

	/* unsubscribe the request from the event */
	rc = afb_xreq_unsubscribe(memo->xreq, ev->event);
	if (rc < 0)
		ERROR("can't unsubscribe: %m");
}

/* receives calls for event */
static int api_dbus_client_on_manage_event(sd_bus_message *m, void *userdata, sd_bus_error *ret_error)
{
	const char *eventname, *data;
	int rc;
	int32_t eventid;
	uint8_t order;
	struct api_dbus *api;
	uint64_t msgid;

	/* check if expected message */
	api = userdata;
	if (0 != strcmp(api->name, sd_bus_message_get_interface(m)))
		return 0; /* not the expected interface */
	if (0 != strcmp("event", sd_bus_message_get_member(m)))
		return 0; /* not the expected member */
	if (sd_bus_message_get_expect_reply(m))
		return 0; /* not the expected type of message */

	/* reads the message */
	rc = sd_bus_message_read(m, "yisst", &order, &eventid, &eventname, &data, &msgid);
	if (rc < 0) {
		ERROR("unreadable event");
		return 1;
	}

	/* what is the order ? */
	switch ((char)order) {
	case '+': /* creates the event */
		api_dbus_client_event_create(api, eventid, eventname);
		break;
	case '-': /* drops the event */
		api_dbus_client_event_drop(api, eventid, eventname);
		break;
	case '!': /* pushs the event */
		api_dbus_client_event_push(api, eventid, eventname, data);
		break;
	case 'S': /* subscribe event for a request */
		api_dbus_client_event_subscribe(api, eventid, eventname, msgid);
		break;
	case 'U': /* unsubscribe event for a request */
		api_dbus_client_event_unsubscribe(api, eventid, eventname, msgid);
		break;
	default:
		/* unexpected order */
		ERROR("unexpected order '%c' received", (char)order);
		break;
	}
	return 1;
}

static struct afb_api_itf dbus_api_itf = {
	.call = api_dbus_client_call
};

/* adds a afb-dbus-service client api */
int afb_api_dbus_add_client(const char *path, struct afb_apiset *declare_set, struct afb_apiset *call_set)
{
	int rc;
	struct api_dbus *api;
	struct afb_api_item afb_api;
	char *match;

	/* create the dbus client api */
	api = make_api_dbus(path);
	if (api == NULL)
		goto error;

	/* connect to broadcasted events */
	rc = asprintf(&match, "type='signal',path='%s',interface='%s',member='broadcast'", api->path, api->name);
	if (rc < 0) {
		errno = ENOMEM;
		ERROR("out of memory");
		goto error;
	}
	rc = sd_bus_add_match(api->sdbus, &api->client.slot_broadcast, match, api_dbus_client_on_broadcast_event, api);
	free(match);
	if (rc < 0) {
		errno = -rc;
		ERROR("can't add dbus match %s for %s", api->path, api->name);
		goto error;
	}

	/* connect to event management */
	rc = sd_bus_add_object(api->sdbus, &api->client.slot_event, api->path, api_dbus_client_on_manage_event, api);
	if (rc < 0) {
		errno = -rc;
		ERROR("can't add dbus object %s for %s", api->path, api->name);
		goto error;
	}

	/* record it as an API */
	afb_api.closure = api;
	afb_api.itf = &dbus_api_itf;
	afb_api.group = NULL;
	if (afb_apiset_add(declare_set, api->api, afb_api) < 0)
		goto error2;

	return 0;

error2:
	destroy_api_dbus(api);
error:
	return -1;
}

/******************* event structures for server part **********************************/

static void afb_api_dbus_server_event_add(void *closure, const char *event, int eventid);
static void afb_api_dbus_server_event_remove(void *closure, const char *event, int eventid);
static void afb_api_dbus_server_event_push(void *closure, const char *event, int eventid, struct json_object *object);
static void afb_api_dbus_server_event_broadcast(void *closure, const char *event, struct json_object *object, const uuid_binary_t uuid, uint8_t hop);

/* the interface for events broadcasting */
static const struct afb_evt_itf evt_broadcast_itf = {
	.broadcast = afb_api_dbus_server_event_broadcast,
};

/* the interface for events pushing */
static const struct afb_evt_itf evt_push_itf = {
	.push = afb_api_dbus_server_event_push,
	.add = afb_api_dbus_server_event_add,
	.remove = afb_api_dbus_server_event_remove
};

/******************* origin description part for server *****************************/

struct origin
{
	/* link to next different origin */
	struct origin *next;

	/* the server dbus-api */
	struct api_dbus *api;

	/* count of references */
	int refcount;

	/* credentials of the origin */
	struct afb_cred *cred;

	/* the origin */
	char name[];
};

/* get the credentials for the message */
static void init_origin_creds(struct origin *origin)
{
	int rc;
	sd_bus_creds *c;
	uid_t uid;
	gid_t gid;
	pid_t pid;
	const char *context;

	rc = sd_bus_get_name_creds(origin->api->sdbus, origin->name,
			SD_BUS_CREDS_PID|SD_BUS_CREDS_UID|SD_BUS_CREDS_GID|SD_BUS_CREDS_SELINUX_CONTEXT,
			&c);
	if (rc < 0)
		origin->cred = NULL;
	else {
		afb_cred_unref(origin->cred);
		sd_bus_creds_get_uid(c, &uid);
		sd_bus_creds_get_gid(c, &gid);
		sd_bus_creds_get_pid(c, &pid);
		sd_bus_creds_get_selinux_context(c, &context);
		origin->cred = afb_cred_create(uid, gid, pid, context);
		sd_bus_creds_unref(c);
	}
}

static struct origin *afb_api_dbus_server_origin_get(struct api_dbus *api, const char *sender)
{
	struct origin *origin;

	/* searchs for an existing origin */
	origin = api->server.origins;
	while (origin != NULL) {
		if (0 == strcmp(origin->name, sender)) {
			origin->refcount++;
			return origin;
		}
		origin = origin->next;
	}

	/* not found, create it */
	origin = malloc(strlen(sender) + 1 + sizeof *origin);
	if (origin == NULL)
		errno = ENOMEM;
	else {
		origin->api = api;
		origin->refcount = 1;
		strcpy(origin->name, sender);
		init_origin_creds(origin);
		origin->next = api->server.origins;
		api->server.origins = origin;
	}
	return origin;
}

static void afb_api_dbus_server_origin_unref(struct origin *origin)
{
	if (!--origin->refcount) {
		struct origin **prv;

		prv = &origin->api->server.origins;
		while(*prv != origin)
			prv = &(*prv)->next;
		*prv = origin->next;
		afb_cred_unref(origin->cred);
		free(origin);
	}
}

struct listener
{
	/* link to next different origin */
	struct origin *origin;

	/* the listener of events */
	struct afb_evt_listener *listener;
};

static void afb_api_dbus_server_listener_free(struct listener *listener)
{
	afb_evt_listener_unref(listener->listener);
	afb_api_dbus_server_origin_unref(listener->origin);
	free(listener);
}

static struct listener *afb_api_dbus_server_listener_get(struct api_dbus *api, const char *sender, struct afb_session *session)
{
	int rc;
	struct listener *listener;
	struct origin *origin;

	/* get the origin */
	origin = afb_api_dbus_server_origin_get(api, sender);
	if (origin == NULL)
		return NULL;

	/* retrieves the stored listener */
	listener = afb_session_get_cookie(session, origin);
	if (listener != NULL) {
		/* found */
		afb_api_dbus_server_origin_unref(origin);
		return listener;
	}

	/* creates the listener */
	listener = malloc(sizeof *listener);
	if (listener == NULL)
		errno = ENOMEM;
	else {
		listener->origin = origin;
		listener->listener = afb_evt_listener_create(&evt_push_itf, origin);
		if (listener->listener != NULL) {
			rc = afb_session_set_cookie(session, origin, listener, (void*)afb_api_dbus_server_listener_free);
			if (rc == 0)
				return listener;
			afb_evt_listener_unref(listener->listener);
		}
		free(listener);
	}
	afb_api_dbus_server_origin_unref(origin);
	return NULL;
}

/******************* dbus request part for server *****************/

/**
 * Structure for a dbus request
 */
struct dbus_req {
	struct afb_xreq xreq;		/**< the xreq of the request */
	sd_bus_message *message;	/**< the incoming request message */
	const char *request;		/**< the readen request as string */
	struct json_object *json;	/**< the readen request as object */
	struct listener *listener;	/**< the listener for events */
};

/* decrement the reference count of the request and free/release it on falling to null */
static void dbus_req_destroy(struct afb_xreq *xreq)
{
	struct dbus_req *dreq = CONTAINER_OF_XREQ(struct dbus_req, xreq);

	afb_context_disconnect(&dreq->xreq.context);
	json_object_put(dreq->json);
	sd_bus_message_unref(dreq->message);
	free(dreq);
}

/* get the object of the request */
static struct json_object *dbus_req_json(struct afb_xreq *xreq)
{
	struct dbus_req *dreq = CONTAINER_OF_XREQ(struct dbus_req, xreq);

	return dreq->json;
}

void dbus_req_raw_reply(struct afb_xreq *xreq, struct json_object *obj, const char *error, const char *info)
{
	struct dbus_req *dreq = CONTAINER_OF_XREQ(struct dbus_req, xreq);
	int rc;

	rc = sd_bus_reply_method_return(dreq->message, "sss",
		obj ? json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN|JSON_C_TO_STRING_NOSLASHESCAPE) : "",
		error ? : "",
		info ? : "");
	if (rc < 0)
		ERROR("sending the reply failed");
}

static void afb_api_dbus_server_event_send(struct origin *origin, char order, const char *event, int eventid, const char *data, uint64_t msgid);

static int dbus_req_subscribe(struct afb_xreq *xreq, struct afb_event_x2 *event)
{
	struct dbus_req *dreq = CONTAINER_OF_XREQ(struct dbus_req, xreq);
	uint64_t msgid;
	int rc;

	rc = afb_evt_event_x2_add_watch(dreq->listener->listener, event);
	sd_bus_message_get_cookie(dreq->message, &msgid);
	afb_api_dbus_server_event_send(dreq->listener->origin, 'S', afb_evt_event_x2_fullname(event), afb_evt_event_x2_id(event), "", msgid);
	return rc;
}

static int dbus_req_unsubscribe(struct afb_xreq *xreq, struct afb_event_x2 *event)
{
	struct dbus_req *dreq = CONTAINER_OF_XREQ(struct dbus_req, xreq);
	uint64_t msgid;
	int rc;

	sd_bus_message_get_cookie(dreq->message, &msgid);
	afb_api_dbus_server_event_send(dreq->listener->origin, 'U', afb_evt_event_x2_fullname(event), afb_evt_event_x2_id(event), "", msgid);
	rc = afb_evt_event_x2_remove_watch(dreq->listener->listener, event);
	return rc;
}

const struct afb_xreq_query_itf afb_api_dbus_xreq_itf = {
	.json = dbus_req_json,
	.reply = dbus_req_raw_reply,
	.unref = dbus_req_destroy,
	.subscribe = dbus_req_subscribe,
	.unsubscribe = dbus_req_unsubscribe,
};

/******************* server part **********************************/

static void afb_api_dbus_server_event_send(struct origin *origin, char order, const char *event, int eventid, const char *data, uint64_t msgid)
{
	int rc;
	struct api_dbus *api;
	struct sd_bus_message *msg;

	api = origin->api;
	msg = NULL;

	rc = sd_bus_message_new_method_call(api->sdbus, &msg, origin->name, api->path, api->name, "event");
	if (rc < 0)
		goto error;

	rc = sd_bus_message_append(msg, "yisst", (uint8_t)order, (int32_t)eventid, event, data, msgid);
	if (rc < 0)
		goto error;

	rc = sd_bus_send(api->sdbus, msg, NULL); /* NULL for cookie implies no expected reply */
	if (rc >= 0)
		goto end;

error:
	ERROR("error while send event %c%s(%d) to %s", order, event, eventid, origin->name);
end:
	sd_bus_message_unref(msg);
}

static void afb_api_dbus_server_event_add(void *closure, const char *event, int eventid)
{
	afb_api_dbus_server_event_send(closure, '+', event, eventid, "", 0);
}

static void afb_api_dbus_server_event_remove(void *closure, const char *event, int eventid)
{
	afb_api_dbus_server_event_send(closure, '-', event, eventid, "", 0);
}

static void afb_api_dbus_server_event_push(void *closure, const char *event, int eventid, struct json_object *object)
{
	const char *data = json_object_to_json_string_ext(object, JSON_C_TO_STRING_PLAIN|JSON_C_TO_STRING_NOSLASHESCAPE);
	afb_api_dbus_server_event_send(closure, '!', event, eventid, data, 0);
	json_object_put(object);
}

static void afb_api_dbus_server_event_broadcast(void *closure, const char *event, struct json_object *object, const uuid_binary_t uuid, uint8_t hop)
{
	int rc;
	struct api_dbus *api;

	api = closure;
	rc = sd_bus_emit_signal(api->sdbus, api->path, api->name, "broadcast",
			"ssayy", event, json_object_to_json_string_ext(object, JSON_C_TO_STRING_PLAIN|JSON_C_TO_STRING_NOSLASHESCAPE),
			uuid, UUID_BINARY_LENGTH, hop);
	if (rc < 0)
		ERROR("error while broadcasting event %s", event);
	json_object_put(object);
}

/* called when the object for the service is called */
static int api_dbus_server_on_object_called(sd_bus_message *message, void *userdata, sd_bus_error *ret_error)
{
	int rc;
	const char *method;
	const char *uuid;
	const char *creds;
	struct dbus_req *dreq;
	struct api_dbus *api = userdata;
	uint32_t flags;
	struct afb_session *session;
	struct listener *listener;
	enum json_tokener_error jerr;

	/* check the interface */
	if (strcmp(sd_bus_message_get_interface(message), api->name) != 0)
		return 0;

	/* get the method */
	method = sd_bus_message_get_member(message);

	/* create the request */
	dreq = calloc(1 , sizeof *dreq);
	if (dreq == NULL)
		goto out_of_memory;

	/* get the data */
	rc = sd_bus_message_read(message, "ssus", &dreq->request, &uuid, &flags, &creds);
	if (rc < 0) {
		sd_bus_reply_method_errorf(message, SD_BUS_ERROR_INVALID_SIGNATURE, "invalid signature");
		goto error;
	}

	/* connect to the context */
	afb_xreq_init(&dreq->xreq, &afb_api_dbus_xreq_itf);
	if (afb_context_connect(&dreq->xreq.context, uuid, NULL) < 0)
		goto out_of_memory;
	session = dreq->xreq.context.session;

	/* get the listener */
	listener = afb_api_dbus_server_listener_get(api, sd_bus_message_get_sender(message), session);
	if (listener == NULL)
		goto out_of_memory;

	/* fulfill the request and emit it */
	dreq->xreq.context.flags = flags;
	dreq->xreq.cred = afb_cred_mixed_on_behalf_import(listener->origin->cred, uuid, creds && creds[0] ? creds : NULL);
	dreq->message = sd_bus_message_ref(message);
	dreq->json = json_tokener_parse_verbose(dreq->request, &jerr);
	if (jerr != json_tokener_success) {
		/* lazy error detection of json request. Is it to improve? */
		dreq->json = json_object_new_string(dreq->request);
	}
	dreq->listener = listener;
	dreq->xreq.request.called_api = api->api;
	dreq->xreq.request.called_verb = method;
	afb_xreq_process(&dreq->xreq, api->server.apiset);
	return 1;

out_of_memory:
	sd_bus_reply_method_errorf(message, SD_BUS_ERROR_NO_MEMORY, "out of memory");
error:
	free(dreq);
	return 1;
}

/* create the service */
int afb_api_dbus_add_server(const char *path, struct afb_apiset *declare_set, struct afb_apiset *call_set)
{
	int rc;
	struct api_dbus *api;

	/* get the dbus api object connected */
	api = make_api_dbus(path);
	if (api == NULL)
		goto error;

	/* request the service object name */
	rc = sd_bus_request_name(api->sdbus, api->name, 0);
	if (rc < 0) {
		errno = -rc;
		ERROR("can't register name %s", api->name);
		goto error2;
	}

	/* connect the service to the dbus object */
	rc = sd_bus_add_object(api->sdbus, &api->server.slot_call, api->path, api_dbus_server_on_object_called, api);
	if (rc < 0) {
		errno = -rc;
		ERROR("can't add dbus object %s for %s", api->path, api->name);
		goto error3;
	}
	INFO("afb service over dbus installed, name %s, path %s", api->name, api->path);

	api->server.listener = afb_evt_listener_create(&evt_broadcast_itf, api);
	api->server.apiset = afb_apiset_addref(call_set);
	return 0;
error3:
	sd_bus_release_name(api->sdbus, api->name);
error2:
	destroy_api_dbus(api);
error:
	return -1;
}

#endif

