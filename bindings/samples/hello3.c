/*
 * Copyright (C) 2015-2019 "IoT.bzh"
 * Author "Fulup Ar Foll"
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
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <fcntl.h>
#include <math.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <json-c/json.h>

#define AFB_BINDING_VERSION 3
#include <afb/afb-binding.h>

#if !defined(APINAME)
#define APINAME "hello"
#endif

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

/**************************************************************************/

struct event
{
	struct event *next;
	afb_event_t event;
	char tag[1];
};

static struct event *events = 0;

/* searchs the event of tag */
static struct event *event_get(const char *tag)
{
	struct event *e = events;
	while(e && strcmp(e->tag, tag))
		e = e->next;
	return e;
}

/* deletes the event of tag */
static int event_del(const char *tag)
{
	struct event *e, **p;

	/* check exists */
	e = event_get(tag);
	if (!e) return -1;

	/* unlink */
	p = &events;
	while(*p != e) p = &(*p)->next;
	*p = e->next;

	/* destroys */
	afb_event_unref(e->event);
	free(e);
	return 0;
}

/* creates the event of tag */
static int event_add(const char *tag, const char *name)
{
	struct event *e;

	/* check valid tag */
	e = event_get(tag);
	if (e) return -1;

	/* creation */
	e = malloc(strlen(tag) + sizeof *e);
	if (!e) return -1;
	strcpy(e->tag, tag);

	/* make the event */
	e->event = afb_daemon_make_event(name);
	if (!e->event) { free(e); return -1; }

	/* link */
	e->next = events;
	events = e;
	return 0;
}

static int event_subscribe(afb_req_t request, const char *tag)
{
	struct event *e;
	e = event_get(tag);
	return e ? afb_req_subscribe(request, e->event) : -1;
}

static int event_unsubscribe(afb_req_t request, const char *tag)
{
	struct event *e;
	e = event_get(tag);
	return e ? afb_req_unsubscribe(request, e->event) : -1;
}

static int event_push(struct json_object *args, const char *tag)
{
	struct event *e;
	e = event_get(tag);
	return e ? afb_event_push(e->event, json_object_get(args)) : -1;
}

static int event_broadcast(struct json_object *args, const char *tag)
{
	struct event *e;
	e = event_get(tag);
	return e ? afb_event_broadcast(e->event, json_object_get(args)) : -1;
}

/**************************************************************************/

struct api
{
	struct api *next;
	afb_api_t api;
	char name[1];
};

static struct api *apis = 0;

/* search the api of name */
static struct api *searchapi(const char *name, struct api ***previous)
{
	struct api *a, **p = &apis;
	while((a = *p) && strcmp(a->name, name))
		p = &a->next;
	if (previous)
		*previous = p;
	return a;
}

/**************************************************************************/

// Sample Generic Ping Debug API
static void ping(afb_req_t request, json_object *jresp, const char *tag)
{
	static int pingcount = 0;
	json_object *query = afb_req_json(request);
	afb_req_success_f(request, jresp, "Ping Binder Daemon tag=%s count=%d query=%s", tag, ++pingcount, json_object_to_json_string(query));
}

static void pingSample (afb_req_t request)
{
	ping(request, json_object_new_string ("Some String"), "pingSample");
}

static void pingFail (afb_req_t request)
{
	afb_req_fail(request, "failed", "Ping Binder Daemon fails");
}

static void pingNull (afb_req_t request)
{
	ping(request, NULL, "pingNull");
}

static void pingBug (afb_req_t request)
{
	ping(NULL, NULL, "pingBug");
}

static void pingEvent(afb_req_t request)
{
	json_object *query = afb_req_json(request);
	afb_daemon_broadcast_event("event", json_object_get(query));
	ping(request, json_object_get(query), "event");
}


// For samples https://linuxprograms.wordpress.com/2010/05/20/json-c-libjson-tutorial/
static void pingJson (afb_req_t request) {
    json_object *jresp, *embed;

    jresp = json_object_new_object();
    json_object_object_add(jresp, "myString", json_object_new_string ("Some String"));
    json_object_object_add(jresp, "myInt", json_object_new_int (1234));

    embed  = json_object_new_object();
    json_object_object_add(embed, "subObjString", json_object_new_string ("Some String"));
    json_object_object_add(embed, "subObjInt", json_object_new_int (5678));

    json_object_object_add(jresp,"eobj", embed);

    ping(request, jresp, "pingJson");
}

static void subcallcb (void *prequest, int status, json_object *object, afb_req_t request)
{
	if (status < 0)
		afb_req_fail(request, "failed", json_object_to_json_string(object));
	else
		afb_req_success(request, json_object_get(object), NULL);
}

static void subcall (afb_req_t request)
{
	const char *api = afb_req_value(request, "api");
	const char *verb = afb_req_value(request, "verb");
	const char *args = afb_req_value(request, "args");
	json_object *object = api && verb && args ? json_tokener_parse(args) : NULL;

	if (object == NULL)
		afb_req_fail(request, "failed", "bad arguments");
	else
		afb_req_subcall_legacy(request, api, verb, object, subcallcb, NULL);
}

static void subcallreqcb (void *prequest, int status, json_object *object, afb_req_t request)
{
	if (status < 0)
		afb_req_fail(request, "failed", json_object_to_json_string(object));
	else
		afb_req_success(request, json_object_get(object), NULL);
}

static void subcallreq (afb_req_t request)
{
	const char *api = afb_req_value(request, "api");
	const char *verb = afb_req_value(request, "verb");
	const char *args = afb_req_value(request, "args");
	json_object *object = api && verb && args ? json_tokener_parse(args) : NULL;

	if (object == NULL)
		afb_req_fail(request, "failed", "bad arguments");
	else
		afb_req_subcall_legacy(request, api, verb, object, subcallreqcb, NULL);
}

static void subcallsync (afb_req_t request)
{
	int rc;
	const char *api = afb_req_value(request, "api");
	const char *verb = afb_req_value(request, "verb");
	const char *args = afb_req_value(request, "args");
	json_object *result, *object = api && verb && args ? json_tokener_parse(args) : NULL;

	if (object == NULL)
		afb_req_fail(request, "failed", "bad arguments");
	else {
		rc = afb_req_subcall_sync_legacy(request, api, verb, object, &result);
		if (rc >= 0)
			afb_req_success(request, result, NULL);
		else {
			afb_req_fail(request, "failed", json_object_to_json_string(result));
			json_object_put(result);
		}
	}
}

static void eventadd (afb_req_t request)
{
	const char *tag = afb_req_value(request, "tag");
	const char *name = afb_req_value(request, "name");

	pthread_mutex_lock(&mutex);
	if (tag == NULL || name == NULL)
		afb_req_fail(request, "failed", "bad arguments");
	else if (0 != event_add(tag, name))
		afb_req_fail(request, "failed", "creation error");
	else
		afb_req_success(request, NULL, NULL);
	pthread_mutex_unlock(&mutex);
}

static void eventdel (afb_req_t request)
{
	const char *tag = afb_req_value(request, "tag");

	pthread_mutex_lock(&mutex);
	if (tag == NULL)
		afb_req_fail(request, "failed", "bad arguments");
	else if (0 != event_del(tag))
		afb_req_fail(request, "failed", "deletion error");
	else
		afb_req_success(request, NULL, NULL);
	pthread_mutex_unlock(&mutex);
}

static void eventsub (afb_req_t request)
{
	const char *tag = afb_req_value(request, "tag");

	pthread_mutex_lock(&mutex);
	if (tag == NULL)
		afb_req_fail(request, "failed", "bad arguments");
	else if (0 != event_subscribe(request, tag))
		afb_req_fail(request, "failed", "subscription error");
	else
		afb_req_success(request, NULL, NULL);
	pthread_mutex_unlock(&mutex);
}

static void eventunsub (afb_req_t request)
{
	const char *tag = afb_req_value(request, "tag");

	pthread_mutex_lock(&mutex);
	if (tag == NULL)
		afb_req_fail(request, "failed", "bad arguments");
	else if (0 != event_unsubscribe(request, tag))
		afb_req_fail(request, "failed", "unsubscription error");
	else
		afb_req_success(request, NULL, NULL);
	pthread_mutex_unlock(&mutex);
}

static void eventpush (afb_req_t request)
{
	const char *tag = afb_req_value(request, "tag");
	const char *data = afb_req_value(request, "data");
	json_object *object = data ? json_tokener_parse(data) : NULL;

	pthread_mutex_lock(&mutex);
	if (tag == NULL)
		afb_req_fail(request, "failed", "bad arguments");
	else if (0 > event_push(object, tag))
		afb_req_fail(request, "failed", "push error");
	else
		afb_req_success(request, NULL, NULL);
	pthread_mutex_unlock(&mutex);
	json_object_put(object);
}

static void callcb (void *prequest, json_object *object, const char *error, const char *info, afb_api_t api)
{
	afb_req_t request = prequest;
	afb_req_reply(request, json_object_get(object), error, info);
	afb_req_unref(request);
}

static void call (afb_req_t request)
{
	const char *api = afb_req_value(request, "api");
	const char *verb = afb_req_value(request, "verb");
	const char *args = afb_req_value(request, "args");
	json_object *object = api && verb && args ? json_tokener_parse(args) : NULL;

	afb_service_call(api, verb, object, callcb, afb_req_addref(request));
}

static void callsync (afb_req_t request)
{
	const char *api = afb_req_value(request, "api");
	const char *verb = afb_req_value(request, "verb");
	const char *args = afb_req_value(request, "args");
	json_object *object = api && verb && args ? json_tokener_parse(args) : NULL;
	json_object *result;
	char *error, *info;

	afb_service_call_sync(api, verb, object, &result, &error, &info);
	afb_req_reply(request, result, error, info);
	free(error);
	free(info);
}

static void verbose (afb_req_t request)
{
	int level = 5;
	json_object *query = afb_req_json(request), *l;

	if (json_object_is_type(query,json_type_int))
		level = json_object_get_int(query);
	else if (json_object_object_get_ex(query, "level", &l) && json_object_is_type(l, json_type_int))
		level = json_object_get_int(l);

	if (!json_object_object_get_ex(query,"message",&l))
		l = query;

	AFB_REQ_VERBOSE(request, level, "verbose called for %s", json_object_get_string(l));
	afb_req_success(request, NULL, NULL);
}

static void exitnow (afb_req_t request)
{
	int code = 0;
	json_object *query = afb_req_json(request), *l;

	if (json_object_is_type(query,json_type_int))
		code = json_object_get_int(query);
	else if (json_object_object_get_ex(query, "code", &l) && json_object_is_type(l, json_type_int))
		code = json_object_get_int(l);

	if (!json_object_object_get_ex(query,"reason",&l))
		l = NULL;

	AFB_REQ_NOTICE(request, "in phase of exiting with code %d, reason: %s", code, l ? json_object_get_string(l) : "unknown");
	afb_req_success(request, NULL, NULL);
	exit(code);
}

static void broadcast(afb_req_t request)
{
	const char *tag = afb_req_value(request, "tag");
	const char *name = afb_req_value(request, "name");
	const char *data = afb_req_value(request, "data");
	json_object *object = data ? json_tokener_parse(data) : NULL;

	if (tag != NULL) {
		pthread_mutex_lock(&mutex);
		if (0 > event_broadcast(object, tag))
			afb_req_fail(request, "failed", "broadcast error");
		else
			afb_req_success(request, NULL, NULL);
		pthread_mutex_unlock(&mutex);
	} else if (name != NULL) {
		if (0 > afb_daemon_broadcast_event(name, json_object_get(object)))
			afb_req_fail(request, "failed", "broadcast error");
		else
			afb_req_success(request, NULL, NULL);
	} else {
		afb_req_fail(request, "failed", "bad arguments");
	}
	json_object_put(object);
}

static void hasperm (afb_req_t request)
{
	const char *perm = afb_req_value(request, "perm");
	if (afb_req_has_permission(request, perm))
		afb_req_success_f(request, NULL, "permission %s granted", perm?:"(null)");
	else
		afb_req_fail_f(request, "not-granted", "permission %s NOT granted", perm?:"(null)");
}

static void appid (afb_req_t request)
{
	char *aid = afb_req_get_application_id(request);
	afb_req_success_f(request, aid ? json_object_new_string(aid) : NULL, "application is %s", aid?:"?");
	free(aid);
}

static void uid (afb_req_t request)
{
	int uid = afb_req_get_uid(request);
	afb_req_success_f(request, json_object_new_int(uid), "uid is %d", uid);
}

static void closess (afb_req_t request)
{
	afb_req_session_close(request);
	afb_req_reply(request, NULL, NULL, "session closed");
}

static void setloa (afb_req_t request)
{
	int loa = json_object_get_int(afb_req_json(request));
	afb_req_session_set_LOA(request, loa);
	afb_req_reply_f(request, NULL, NULL, "LOA set to %d", loa);
}

static void ok (afb_req_t request)
{
	afb_req_reply_f(request, NULL, NULL, NULL);
}

static void setctx (afb_req_t request)
{
	struct json_object *x = afb_req_json(request);
	afb_req_context(request, (int)(intptr_t)afb_req_get_vcbdata(request), (void*)json_object_get, (void*)json_object_put, x);
	afb_req_reply(request, json_object_get(x), NULL, "context set");
}

static void getctx (afb_req_t request)
{
	struct json_object *x = afb_req_context(request, 0, 0, 0, 0);
	afb_req_reply(request, json_object_get(x), NULL, "returning the context");
}

static void info (afb_req_t request)
{
	afb_req_reply(request, afb_req_get_client_info(request), NULL, NULL);
}

static void eventloop (afb_req_t request)
{
	afb_api_t api = afb_req_get_api(request);
	struct sd_event *ev = afb_api_get_event_loop(api);
	afb_req_reply(request, NULL, ev ? NULL : "no-event-loop", NULL);
}

static void dbus (afb_req_t request)
{
	afb_api_t api = afb_req_get_api(request);
	json_object *json = afb_req_json(request);
	struct sd_bus *bus = (json_object_get_boolean(json) ? afb_api_get_system_bus : afb_api_get_user_bus)(api);
	afb_req_reply(request, NULL, bus ? NULL : "no-bus", NULL);
}

static void replycount (afb_req_t request)
{
	json_object *json = afb_req_json(request);
	int count = json_object_get_int(json);
	while (count-- > 0)
		afb_req_reply(request, NULL, NULL, NULL);
}

static void get(afb_req_t request)
{
	struct afb_arg arg = afb_req_get(request, "name");
	const char *name, *value, *path;

	if (!arg.name || !arg.value)
		afb_req_reply(request, NULL, "invalid", "the parameter 'name' is missing");
	else {
		name = arg.name;
		value = afb_req_value(request, name);
		path = afb_req_path(request, name);
		afb_req_reply_f(request, NULL, NULL, "found for '%s': %s", name, value ?: path ?: "NULL");
	}
}

static void ref(afb_req_t request)
{
	afb_req_addref(request);
	afb_req_reply(request, NULL, NULL, NULL);
	afb_req_unref(request);
}

static void mute(afb_req_t request)
{
}

static void mutebug(afb_req_t request)
{
	afb_req_addref(request);
}

void queue_cb(int signum, void *arg)
{
	afb_req_t request = arg;
	afb_req_reply(request, NULL, NULL, NULL);
	afb_req_unref(request);
}

static void queue(afb_req_t request)
{
	afb_req_addref(request);
	afb_api_queue_job(afb_req_get_api(request), queue_cb, request, NULL, 0);
}

static void settings(afb_req_t request)
{
	afb_api_t api = afb_req_get_api(request);
	struct json_object *object = afb_api_settings(api);
	afb_req_reply(request, json_object_get(object), NULL, NULL);
}

static void rootdir (afb_req_t request)
{
	ssize_t s;
	afb_api_t api = afb_req_get_api(request);
	int fd = afb_api_rootdir_get_fd(api);
	char buffer[150], root[1025];
	sprintf(buffer, "/proc/self/fd/%d", fd);
	s = readlink(buffer, root, sizeof root - 1);
	if (s < 0)
		afb_req_reply_f(request, NULL, "error", "can't readlink %s: %m", buffer);
	else {
		root[s] = 0;
		afb_req_reply(request, json_object_new_string(root), NULL, NULL);
	}
}

static void locale (afb_req_t request)
{
	char buffer[150], root[1025];
	const char *lang, *file;
	ssize_t s;
	json_object *json = afb_req_json(request), *x;
	afb_api_t api = afb_req_get_api(request);
	int fd;

	lang = NULL;
	if (json_object_is_type(json, json_type_string))
		file = json_object_get_string(json);
	else {
		if (!json_object_object_get_ex(json, "file", &x)) {
			afb_req_reply(request, NULL, "invalid", "no file");
			return;
		}
		file = json_object_get_string(x);
		if (json_object_object_get_ex(json, "lang", &x))
			lang = json_object_get_string(x);
	}

	fd = afb_api_rootdir_open_locale(api, file, O_RDONLY, lang);
	if (fd < 0)
		afb_req_reply_f(request, NULL, "error", "can't open %s [%s]: %m", file?:"NULL", lang?:"NULL");
	else {
		sprintf(buffer, "/proc/self/fd/%d", fd);
		s = readlink(buffer, root, sizeof root - 1);
		if (s < 0)
			afb_req_reply_f(request, NULL, "error", "can't readlink %s: %m", buffer);
		else {
			root[s] = 0;
			afb_req_reply(request, json_object_new_string(root), NULL, NULL);
		}
		close(fd);
	}
}

static void in_after (afb_req_t request)
{
	int rc;
	const char *ts, *ty;
	char *te;
	double td;
	struct timespec t;

	/* get the type */
	ty = afb_req_value(request, "type") ?: "call";
	if (strcmp(ty, "call") && strcmp(ty, "callsync")
	 && strcmp(ty, "subcall") && strcmp(ty, "subcallsync"))
		return afb_req_reply(request, NULL, "invalid", "bad type");

	/* get the delay */
	ts = afb_req_value(request, "delay");
	if (!ts)
		return afb_req_reply(request, NULL, "invalid", "no delay");
	td = strtod(ts, &te);
	if (*te || td < 0 || td > 3e6) /* a month is the biggest accepted */
		return afb_req_reply(request, NULL, "invalid", "bad delay");

	/* wait for that time */
	if (td > 0) {
		t.tv_nsec = (long)(1e6 * modf(td, &td));
		t.tv_sec = (time_t)td;
		do {
			rc = nanosleep(&t, &t);
		} while (rc != 0 && errno == EINTR);

		if (rc)
			return afb_req_reply(request, NULL, "error", "sleep failed");
	}

	/* do the call */
	if (!strcmp(ty, "subcallsync"))
		subcall(request);
	else if (!strcmp(ty, "subcall"))
		subcallsync(request);
	else if (!strcmp(ty, "callsync"))
		callsync(request);
	else
		call(request);
}

static void *thread_after (void *closure)
{
	afb_req_t request = closure;
	in_after (request);
	afb_req_unref(request);
	return NULL;
}

static void after (afb_req_t request)
{
	int rc;
	pthread_t tid;
	pthread_attr_t attr;

	afb_req_addref(request);

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	rc =pthread_create(&tid, &attr, thread_after, request);
	pthread_attr_destroy(&attr);

	if (rc != 0) {
		afb_req_unref(request);
		afb_req_reply(request, NULL, "cant-start", NULL);
	}
}

static void api (afb_req_t request);

/**
 * Definition of an authorization entry
 */
static struct afb_auth auths[] = {
	{	/* 0 */
		.type = afb_auth_Or,
		.first = &auths[1],
		.next = &auths[9],
	},
	{	/* 1 */
		.type = afb_auth_And,
		.first = &auths[2],
		.next = &auths[3],
	},
	{	/* 2 */
		.type = afb_auth_Yes
	},
	{	/* 3 */
		.type = afb_auth_And,
		.first = &auths[4],
		.next = &auths[5],
	},
	{	/* 4 */
		.type = afb_auth_LOA,
		.loa = 0
	},
	{	/* 5 */
		.type = afb_auth_Or,
		.first = &auths[6],
		.next = &auths[7],
	},
	{	/* 6 */
		.type = afb_auth_No
	},
	{	/* 7 */
		.type = afb_auth_Not,
		.first = &auths[8]
	},
	{	/* 8 */
		.type = afb_auth_Yes
	},
	{	/* 9 */
		.type = afb_auth_And,
		.first = &auths[10],
		.next = &auths[13],
	},
	{	/* 10 */
		.type = afb_auth_Or,
		.first = &auths[12],
		.next = &auths[11],
	},
	{	/* 11 */
		.type = afb_auth_Not,
		.first = &auths[13]
	},
	{	/* 12 */
		.type = afb_auth_Token
	},
	{	/* 13 */
		.type = afb_auth_And,
		.first = &auths[14],
		.next = &auths[17],
	},
	{	/* 14 */
		.type = afb_auth_Or,
		.first = &auths[16],
		.next = &auths[15],
	},
	{	/* 15 */
		.type = afb_auth_Not,
		.first = &auths[16]
	},
	{	/* 16 */
		.type = afb_auth_Permission,
		.text = "permission"
	},
	{	/* 17 */
		.type = afb_auth_Yes
	}
};


// NOTE: this sample does not use session to keep test a basic as possible
//       in real application most APIs should be protected with AFB_SESSION_CHECK
static const struct afb_verb_v3 verbs[]= {
  { .verb="ping",        .callback=pingSample },
  { .verb="pingfail",    .callback=pingFail },
  { .verb="pingnull",    .callback=pingNull },
  { .verb="pingbug",     .callback=pingBug },
  { .verb="pingJson",    .callback=pingJson },
  { .verb="pingevent",   .callback=pingEvent },
  { .verb="subcall",     .callback=subcall },
  { .verb="subcallreq",  .callback=subcallreq },
  { .verb="subcallsync", .callback=subcallsync },
  { .verb="eventadd",    .callback=eventadd },
  { .verb="eventdel",    .callback=eventdel },
  { .verb="eventsub",    .callback=eventsub },
  { .verb="eventunsub",  .callback=eventunsub },
  { .verb="eventpush",   .callback=eventpush },
  { .verb="call",        .callback=call },
  { .verb="callsync",    .callback=callsync },
  { .verb="verbose",     .callback=verbose },
  { .verb="broadcast",   .callback=broadcast },
  { .verb="hasperm",     .callback=hasperm },
  { .verb="appid",       .callback=appid },
  { .verb="uid",         .callback=uid },
  { .verb="exit",        .callback=exitnow },
  { .verb="close",       .callback=closess, .session=AFB_SESSION_CLOSE },
  { .verb="set-loa",     .callback=setloa, .auth = &auths[0] },
  { .verb="has-loa-1",   .callback=ok, .session=AFB_SESSION_LOA_1 },
  { .verb="has-loa-2",   .callback=ok, .session=AFB_SESSION_LOA_2 },
  { .verb="has-loa-3",   .callback=ok, .session=AFB_SESSION_LOA_3 },
  { .verb="setctx",      .callback=setctx, .vcbdata = (void*)(intptr_t)1 },
  { .verb="setctxif",    .callback=setctx, .vcbdata = (void*)(intptr_t)0 },
  { .verb="getctx",      .callback=getctx },
  { .verb="checktok",    .callback=ok, .session=AFB_SESSION_CHECK },
  { .verb="reftok",      .callback=ok, .session=AFB_SESSION_CHECK | AFB_SESSION_REFRESH },
  { .verb="info",        .callback=info },
  { .verb="eventloop",   .callback=eventloop },
  { .verb="dbus",        .callback=dbus },
  { .verb="reply-count", .callback=replycount },
  { .verb="get",         .callback=get},
  { .verb="ref",         .callback=ref},
  { .verb="rootdir",     .callback=rootdir},
  { .verb="locale",      .callback=locale},
  { .verb="api",         .callback=api},
  { .verb="mute",        .callback=mute},
  { .verb="mutebug",     .callback=mutebug},
  { .verb="queue",       .callback=queue},
  { .verb="settings",    .callback=settings},
  { .verb="after",       .callback=after},
  { .verb=NULL}
};

static void pingSample2 (struct afb_req_x1 req)
{
	pingSample(req.closure);
}

static const struct afb_verb_v2 apiverbs2[]= {
  { .verb="ping",        .callback=pingSample2 },
  { .verb="ping2",        .callback=pingSample2 },
  { .verb=NULL }
};

static int apipreinit(void *closure, afb_api_t api)
{
	afb_api_set_verbs_v2(api, apiverbs2);
	afb_api_set_verbs_v3(api, verbs);
	return 0;
}

static void apiverb (afb_req_t request)
{
	afb_req_reply_f(request, json_object_get(afb_req_json(request)), NULL, "api: %s, verb: %s",
		afb_req_get_called_api(request), afb_req_get_called_verb(request));
}

static void apievhndl(void *closure, const char *event, struct json_object *args, afb_api_t api)
{
	struct json_object *obj = closure;
	afb_api_verbose(api, 0, NULL, 0, NULL, "the handler of closure(%s) received the event %s(%s)",
		json_object_get_string(obj), event, json_object_get_string(args));
}

static void api (afb_req_t request)
{
	struct api *sapi, **psapi;
	const char *action, *apiname, *verbname, *pattern;
	json_object *json = afb_req_json(request), *x, *closure;
	afb_api_t api = afb_req_get_api(request), oapi;

	/* get the action */
	if (!json_object_object_get_ex(json, "action", &x)) {
		afb_req_reply(request, NULL, "invalid", "no action");
		goto end;
	}
	action = json_object_get_string(x);

	/* get the verb */
	verbname = json_object_object_get_ex(json, "verb", &x) ?
		json_object_get_string(x) : NULL;

	/* get the pattern */
	pattern = json_object_object_get_ex(json, "pattern", &x) ?
		json_object_get_string(x) : NULL;

	/* get the closure */
	closure = NULL;
	json_object_object_get_ex(json, "closure", &closure);

	/* get the api */
	if (json_object_object_get_ex(json, "api", &x)) {
		apiname = json_object_get_string(x);
		sapi = searchapi(apiname, &psapi);
		oapi = sapi ? sapi->api : NULL;
	} else {
		oapi = api;
		apiname = afb_api_name(api);
		sapi = searchapi(apiname, &psapi);
	}

	/* search the sapi */
	if (!strcasecmp(action, "create")) {
		if (!apiname) {
			afb_req_reply(request, NULL, "invalid", "no api");
			goto end;
		}
		if (sapi) {
			afb_req_reply(request, NULL, "already-exist", NULL);
			goto end;
		}
		sapi = malloc (sizeof * sapi + strlen(apiname));
		if (!sapi) {
			afb_req_reply(request, NULL, "out-of-memory", NULL);
			goto end;
		}
		sapi->api = afb_api_new_api(api, apiname, NULL, 1, apipreinit, NULL);
		if (!sapi->api) {
			free(sapi);
			afb_req_reply_f(request, NULL, "cant-create", "%m");
			goto end;
		}
		strcpy(sapi->name, apiname);
		sapi->next = NULL;
		*psapi = sapi;
	} else {
		if (!oapi) {
			afb_req_reply(request, NULL, "cant-find-api", NULL);
			goto end;
		}
		if (!strcasecmp(action, "destroy")) {
			if (!sapi) {
				afb_req_reply(request, NULL, "cant-destroy", NULL);
				goto end;
			}
			afb_api_delete_api(oapi);
			*psapi = sapi->next;
			free(sapi);
		} else if (!strcasecmp(action, "addverb")) {
			if (!verbname){
				afb_req_reply(request, NULL, "invalid", "no verb");
				goto end;
			}
			afb_api_add_verb(oapi, verbname, NULL, apiverb, NULL, NULL, 0, !!strchr(verbname, '*'));
		} else if (!strcasecmp(action, "delverb")) {
			if (!verbname){
				afb_req_reply(request, NULL, "invalid", "no verb");
				goto end;
			}
			afb_api_del_verb(oapi, verbname, NULL);
		} else if (!strcasecmp(action, "addhandler")) {
			if (!pattern){
				afb_req_reply(request, NULL, "invalid", "no pattern");
				goto end;
			}
			afb_api_event_handler_add(oapi, pattern, apievhndl, json_object_get(closure));
		} else if (!strcasecmp(action, "delhandler")) {
			if (!pattern){
				afb_req_reply(request, NULL, "invalid", "no pattern");
				goto end;
			}
			closure = NULL;
			afb_api_event_handler_del(oapi, pattern, (void**)&closure);
			json_object_put(closure);
		} else if (!strcasecmp(action, "seal")) {
			afb_api_seal(oapi);
		} else {
			afb_req_reply_f(request, NULL, "invalid", "unknown action %s", action ?: "NULL");
			goto end;
		}
	}
	afb_req_reply(request, NULL, NULL, NULL);
end:	return;
}

/*************************************************************/

static int preinit(afb_api_t api)
{
	AFB_NOTICE("hello binding comes to live");
#if defined(PREINIT_PROVIDE_CLASS)
	afb_api_provide_class(api, PREINIT_PROVIDE_CLASS);
#endif
#if defined(PREINIT_REQUIRE_CLASS)
	afb_api_require_class(api, PREINIT_REQUIRE_CLASS);
#endif
	return 0;
}

static int init(afb_api_t api)
{
	AFB_NOTICE("hello binding starting");
#if defined(INIT_REQUIRE_API)
	afb_api_require_api(api, INIT_REQUIRE_API, 1);
#endif
	afb_api_add_alias(api, api->apiname, "fakename");
	return 0;
}

static void onevent(afb_api_t api, const char *event, struct json_object *object)
{
	AFB_NOTICE("received event %s(%s)", event, json_object_to_json_string(object));
}

const struct afb_binding_v3 afbBindingV3 = {
	.api = APINAME,
	.specification = NULL,
	.verbs = verbs,
	.preinit = preinit,
	.init = init,
	.onevent = onevent
};

