/*
 * Copyright (C) 2016-2019 "IoT.bzh"
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

#if WITH_AFB_HOOK && WITH_AFB_TRACE

#define _GNU_SOURCE

#include <assert.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#include <pthread.h>

#include <json-c/json.h>
#if !defined(JSON_C_TO_STRING_NOSLASHESCAPE)
#define JSON_C_TO_STRING_NOSLASHESCAPE 0
#endif

#define AFB_BINDING_VERSION 3
#include <afb/afb-binding.h>

#include "afb-hook.h"
#include "afb-hook-flags.h"
#include "afb-cred.h"
#include "afb-session.h"
#include "afb-xreq.h"
#include "afb-export.h"
#include "afb-evt.h"
#include "afb-session.h"
#include "afb-trace.h"

#include "wrap-json.h"
#include "verbose.h"

/*******************************************************************************/
/*****  default names                                                      *****/
/*******************************************************************************/

#if !defined(DEFAULT_EVENT_NAME)
#  define DEFAULT_EVENT_NAME "trace"
#endif
#if !defined(DEFAULT_TAG_NAME)
#  define DEFAULT_TAG_NAME "trace"
#endif

/*******************************************************************************/
/*****  types                                                              *****/
/*******************************************************************************/

/* struct for tags */
struct tag {
	struct tag *next;	/* link to the next */
	char tag[];		/* name of the tag */
};

/* struct for events */
struct event {
	struct event *next;		/* link to the next event */
	struct afb_evtid *evtid;	/* the event */
};

/* struct for sessions */
struct cookie {
	struct afb_session *session;    /* the session */
	struct afb_trace *trace;        /* the tracer */
};

/* struct for recording hooks */
struct hook {
	struct hook *next;		/* link to next hook */
	void *handler;			/* the handler of the hook */
	struct event *event;		/* the associated event */
	struct tag *tag;		/* the associated tag */
	struct afb_session *session;	/* the associated session */
};

/* types of hooks */
enum trace_type
{
	Trace_Type_Xreq,		/* xreq hooks */
	Trace_Type_Api,			/* api hooks */
	Trace_Type_Evt,			/* evt hooks */
	Trace_Type_Session,		/* session hooks */
	Trace_Type_Global,		/* global hooks */
#if !defined(REMOVE_LEGACY_TRACE)
	Trace_Legacy_Type_Ditf,		/* export hooks */
	Trace_Legacy_Type_Svc,		/* export hooks */
#endif
	Trace_Type_Count,		/* count of types of hooks */
};

/* client data */
struct afb_trace
{
	int refcount;				/* reference count */
	pthread_mutex_t mutex;			/* concurrency management */
	const char *apiname;			/* api name for events */
	struct afb_session *bound;		/* bound to session */
	struct event *events;			/* list of events */
	struct tag *tags;			/* list of tags */
	struct hook *hooks[Trace_Type_Count];	/* hooks */
};

/*******************************************************************************/
/*****  utility functions                                                  *****/
/*******************************************************************************/

static void ctxt_error(char **errors, const char *format, ...)
{
	int len;
	char *errs;
	size_t sz;
	char buffer[1024];
	va_list ap;

	va_start(ap, format);
	len = vsnprintf(buffer, sizeof buffer, format, ap);
	va_end(ap);
	if (len > (int)(sizeof buffer - 2))
		len = (int)(sizeof buffer - 2);
	buffer[len++] = '\n';
	buffer[len++] = 0;

	errs = *errors;
	sz = errs ? strlen(errs) : 0;
	errs = realloc(errs, sz + (size_t)len);
	if (errs) {
		memcpy(errs + sz, buffer, len);
		*errors = errs;
	}
}

/* timestamp */
static struct json_object *timestamp(const struct afb_hookid *hookid)
{
	return json_object_new_double((double)hookid->time.tv_sec +
			(double)hookid->time.tv_nsec * .000000001);
}

/* verbosity level name or NULL */
static const char *verbosity_level_name(int level)
{
	static const char *names[] = {
		"error",
		"warning",
		"notice",
		"info",
		"debug"
	};

	return level >= Log_Level_Error && level <= Log_Level_Debug ? names[level - Log_Level_Error] : NULL;
}

/* generic hook */
static void emit(void *closure, const struct afb_hookid *hookid, const char *type, const char *fmt1, const char *fmt2, va_list ap2, ...)
{
	struct hook *hook = closure;
	struct json_object *data, *data1, *data2;
	va_list ap1;

	data1 = data2 = data = NULL;
	va_start(ap1, ap2);
	wrap_json_vpack(&data1, fmt1, ap1);
	va_end(ap1);
	if (fmt2)
		wrap_json_vpack(&data2, fmt2, ap2);

	wrap_json_pack(&data, "{so ss ss si so so*}",
					"time", timestamp(hookid),
					"tag", hook->tag->tag,
					"type", type,
					"id", (int)(hookid->id & INT_MAX),
					type, data1,
					"data", data2);

	afb_evt_evtid_push(hook->event->evtid, data);
}

/*******************************************************************************/
/*****  trace the requests                                                 *****/
/*******************************************************************************/

static void hook_xreq(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, const char *action, const char *format, ...)
{
	struct json_object *cred = NULL;
	const char *session = NULL;
	va_list ap;

	if (xreq->context.session)
		session = afb_session_uuid(xreq->context.session);

	if (xreq->cred)
		wrap_json_pack(&cred, "{si ss si si ss* ss*}",
						"uid", (int)xreq->cred->uid,
						"user", xreq->cred->user,
						"gid", (int)xreq->cred->gid,
						"pid", (int)xreq->cred->pid,
						"label", xreq->cred->label,
						"id", xreq->cred->id
					);
	va_start(ap, format);
	emit(closure, hookid, "request", "{si ss ss ss so* ss*}", format, ap,
					"index", xreq->hookindex,
					"api", xreq->request.called_api,
					"verb", xreq->request.called_verb,
					"action", action,
					"credentials", cred,
					"session", session);
	va_end(ap);
}

static void hook_xreq_begin(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq)
{
	hook_xreq(closure, hookid, xreq, "begin", "{sO?}",
						"json", afb_xreq_unhooked_json((struct afb_xreq*)xreq));
}

static void hook_xreq_end(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq)
{
	hook_xreq(closure, hookid, xreq, "end", NULL);
}

static void hook_xreq_json(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, struct json_object *obj)
{
	hook_xreq(closure, hookid, xreq, "json", "{sO?}",
						"result", obj);
}

static void hook_xreq_get(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, const char *name, struct afb_arg arg)
{
	hook_xreq(closure, hookid, xreq, "get", "{ss? ss? ss? ss?}",
						"query", name,
						"name", arg.name,
						"value", arg.value,
						"path", arg.path);
}

static void hook_xreq_reply(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, struct json_object *obj, const char *error, const char *info)
{
	hook_xreq(closure, hookid, xreq, "reply", "{sO? ss? ss?}",
						"result", obj,
						"error", error,
						"info", info);
}

static void hook_xreq_context_get(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, void *value)
{
	hook_xreq(closure, hookid, xreq, "context_get", NULL);
}

static void hook_xreq_context_set(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, void *value, void (*free_value)(void*))
{
	hook_xreq(closure, hookid, xreq, "context_set", NULL);
}

static void hook_xreq_addref(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq)
{
	hook_xreq(closure, hookid, xreq, "addref", NULL);
}

static void hook_xreq_unref(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq)
{
	hook_xreq(closure, hookid, xreq, "unref", NULL);
}

static void hook_xreq_session_close(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq)
{
	hook_xreq(closure, hookid, xreq, "session_close", NULL);
}

static void hook_xreq_session_set_LOA(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, unsigned level, int result)
{
	hook_xreq(closure, hookid, xreq, "session_set_LOA", "{si si}",
					"level", level,
					"result", result);
}

static void hook_xreq_subscribe(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, struct afb_event_x2 *event, int result)
{
	hook_xreq(closure, hookid, xreq, "subscribe", "{s{ss si} si}",
					"event",
						"name", afb_evt_event_x2_fullname(event),
						"id", afb_evt_event_x2_id(event),
					"result", result);
}

static void hook_xreq_unsubscribe(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, struct afb_event_x2 *event, int result)
{
	hook_xreq(closure, hookid, xreq, "unsubscribe", "{s{ss? si} si}",
					"event",
						"name", afb_evt_event_x2_fullname(event),
						"id", afb_evt_event_x2_id(event),
					"result", result);
}

static void hook_xreq_subcall(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, const char *api, const char *verb, struct json_object *args)
{
	hook_xreq(closure, hookid, xreq, "subcall", "{ss? ss? sO?}",
					"api", api,
					"verb", verb,
					"args", args);
}

static void hook_xreq_subcall_result(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, struct json_object *object, const char *error, const char *info)
{
	hook_xreq(closure, hookid, xreq, "subcall_result", "{sO? ss? ss?}",
					"object", object,
					"error", error,
					"info", info);
}

static void hook_xreq_subcallsync(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, const char *api, const char *verb, struct json_object *args)
{
	hook_xreq(closure, hookid, xreq, "subcallsync", "{ss? ss? sO?}",
					"api", api,
					"verb", verb,
					"args", args);
}

static void hook_xreq_subcallsync_result(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, int status, struct json_object *object, const char *error, const char *info)
{
	hook_xreq(closure, hookid, xreq, "subcallsync_result",  "{si sO? ss? ss?}",
					"status", status,
					"object", object,
					"error", error,
					"info", info);
}

static void hook_xreq_vverbose(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, int level, const char *file, int line, const char *func, const char *fmt, va_list args)
{
	struct json_object *pos;
	int len;
	char *msg;
	va_list ap;

	pos = NULL;
	msg = NULL;

	va_copy(ap, args);
	len = vasprintf(&msg, fmt, ap);
	va_end(ap);

	if (file)
		wrap_json_pack(&pos, "{ss si ss*}", "file", file, "line", line, "function", func);

	hook_xreq(closure, hookid, xreq, "vverbose", "{si ss* ss? so*}",
					"level", level,
 					"type", verbosity_level_name(level),
					len < 0 ? "format" : "message", len < 0 ? fmt : msg,
					"position", pos);

	free(msg);
}

static void hook_xreq_store(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, struct afb_stored_req *sreq)
{
	hook_xreq(closure, hookid, xreq, "store", NULL);
}

static void hook_xreq_unstore(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq)
{
	hook_xreq(closure, hookid, xreq, "unstore", NULL);
}

static void hook_xreq_has_permission(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, const char *permission, int result)
{
	hook_xreq(closure, hookid, xreq, "has_permission", "{ss sb}",
					"permission", permission,
					"result", result);
}

static void hook_xreq_get_application_id(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, char *result)
{
	hook_xreq(closure, hookid, xreq, "get_application_id", "{ss?}",
					"result", result);
}

static void hook_xreq_context_make(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, int replace, void *(*create_value)(void*), void (*free_value)(void*), void *create_closure, void *result)
{
	char pc[50], pf[50], pv[50], pr[50];
	snprintf(pc, sizeof pc, "%p", create_value);
	snprintf(pf, sizeof pf, "%p", free_value);
	snprintf(pv, sizeof pv, "%p", create_closure);
	snprintf(pr, sizeof pr, "%p", result);
	hook_xreq(closure, hookid, xreq, "context_make", "{sb ss ss ss ss}",
					"replace", replace,
					"create", pc,
					"free", pf,
					"closure", pv,
					"result", pr);
}

static void hook_xreq_get_uid(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, int result)
{
	hook_xreq(closure, hookid, xreq, "get_uid", "{si}",
					"result", result);
}

static void hook_xreq_get_client_info(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, struct json_object *result)
{
	hook_xreq(closure, hookid, xreq, "get_client_info", "{sO}",
					"result", result);
}

static struct afb_hook_xreq_itf hook_xreq_itf = {
	.hook_xreq_begin = hook_xreq_begin,
	.hook_xreq_end = hook_xreq_end,
	.hook_xreq_json = hook_xreq_json,
	.hook_xreq_get = hook_xreq_get,
	.hook_xreq_reply = hook_xreq_reply,
	.hook_xreq_legacy_context_get = hook_xreq_context_get,
	.hook_xreq_legacy_context_set = hook_xreq_context_set,
	.hook_xreq_addref = hook_xreq_addref,
	.hook_xreq_unref = hook_xreq_unref,
	.hook_xreq_session_close = hook_xreq_session_close,
	.hook_xreq_session_set_LOA = hook_xreq_session_set_LOA,
	.hook_xreq_subscribe = hook_xreq_subscribe,
	.hook_xreq_unsubscribe = hook_xreq_unsubscribe,
	.hook_xreq_subcall = hook_xreq_subcall,
	.hook_xreq_subcall_result = hook_xreq_subcall_result,
	.hook_xreq_subcallsync = hook_xreq_subcallsync,
	.hook_xreq_subcallsync_result = hook_xreq_subcallsync_result,
	.hook_xreq_vverbose = hook_xreq_vverbose,
	.hook_xreq_legacy_store = hook_xreq_store,
	.hook_xreq_legacy_unstore = hook_xreq_unstore,
	.hook_xreq_has_permission = hook_xreq_has_permission,
	.hook_xreq_get_application_id = hook_xreq_get_application_id,
	.hook_xreq_context_make = hook_xreq_context_make,
	.hook_xreq_get_uid = hook_xreq_get_uid,
	.hook_xreq_get_client_info = hook_xreq_get_client_info,
};

/*******************************************************************************/
/*****  trace the api interface                                            *****/
/*******************************************************************************/

static void hook_api(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, const char *action, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	emit(closure, hookid, "api", "{ss ss}", format, ap,
					"api", afb_export_apiname(export),
					"action", action);
	va_end(ap);
}

static void hook_api_event_broadcast_before(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, const char *name, struct json_object *object)
{
	hook_api(closure, hookid, export, "event_broadcast_before", "{ss sO?}",
			"name", name, "data", object);
}

static void hook_api_event_broadcast_after(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, const char *name, struct json_object *object, int result)
{
	hook_api(closure, hookid, export, "event_broadcast_after", "{ss sO? si}",
			"name", name, "data", object, "result", result);
}

static void hook_api_get_event_loop(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, struct sd_event *result)
{
	hook_api(closure, hookid, export, "get_event_loop", NULL);
}

static void hook_api_get_user_bus(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, struct sd_bus *result)
{
	hook_api(closure, hookid, export, "get_user_bus", NULL);
}

static void hook_api_get_system_bus(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, struct sd_bus *result)
{
	hook_api(closure, hookid, export, "get_system_bus", NULL);
}

static void hook_api_vverbose(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, int level, const char *file, int line, const char *function, const char *fmt, va_list args)
{
	struct json_object *pos;
	int len;
	char *msg;
	va_list ap;

	pos = NULL;
	msg = NULL;

	va_copy(ap, args);
	len = vasprintf(&msg, fmt, ap);
	va_end(ap);

	if (file)
		wrap_json_pack(&pos, "{ss si ss*}", "file", file, "line", line, "function", function);

	hook_api(closure, hookid, export, "vverbose", "{si ss* ss? so*}",
					"level", level,
 					"type", verbosity_level_name(level),
					len < 0 ? "format" : "message", len < 0 ? fmt : msg,
					"position", pos);

	free(msg);
}

static void hook_api_event_make(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, const char *name, struct afb_event_x2 *result)
{
	hook_api(closure, hookid, export, "event_make", "{ss ss si}",
			"name", name, "event", afb_evt_event_x2_fullname(result), "id", afb_evt_event_x2_id(result));
}

static void hook_api_rootdir_get_fd(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, int result)
{
	char path[PATH_MAX], proc[100];
	const char *key, *val;
	ssize_t s;

	if (result >= 0) {
		snprintf(proc, sizeof proc, "/proc/self/fd/%d", result);
		s = readlink(proc, path, sizeof path);
		path[s < 0 ? 0 : s >= sizeof path ? sizeof path - 1 : s] = 0;
		key = "path";
		val = path;
	} else {
		key = "error";
		val = strerror(errno);
	}

	hook_api(closure, hookid, export, "rootdir_get_fd", "{ss}", key, val);
}

static void hook_api_rootdir_open_locale(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, const char *filename, int flags, const char *locale, int result)
{
	char path[PATH_MAX], proc[100];
	const char *key, *val;
	ssize_t s;

	if (result >= 0) {
		snprintf(proc, sizeof proc, "/proc/self/fd/%d", result);
		s = readlink(proc, path, sizeof path);
		path[s < 0 ? 0 : s >= sizeof path ? sizeof path - 1 : s] = 0;
		key = "path";
		val = path;
	} else {
		key = "error";
		val = strerror(errno);
	}

	hook_api(closure, hookid, export, "rootdir_open_locale", "{ss si ss* ss}",
			"file", filename,
			"flags", flags,
			"locale", locale,
			key, val);
}

static void hook_api_queue_job(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, void (*callback)(int signum, void *arg), void *argument, void *group, int timeout, int result)
{
	hook_api(closure, hookid, export, "queue_job", "{ss}", "result", result);
}

static void hook_api_unstore_req(void * closure, const struct afb_hookid *hookid, const struct afb_export *export, struct afb_stored_req *sreq)
{
	hook_api(closure, hookid, export, "unstore_req", NULL);
}

static void hook_api_require_api(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, const char *name, int initialized)
{
	hook_api(closure, hookid, export, "require_api", "{ss sb}", "name", name, "initialized", initialized);
}

static void hook_api_require_api_result(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, const char *name, int initialized, int result)
{
	hook_api(closure, hookid, export, "require_api_result", "{ss sb si}", "name", name, "initialized", initialized, "result", result);
}

static void hook_api_add_alias_cb(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, const char *api, const char *alias, int result)
{
	hook_api(closure, hookid, export, "add_alias", "{si ss? ss}", "status", result, "api", api, "alias", alias);
}

static void hook_api_start_before(void *closure, const struct afb_hookid *hookid, const struct afb_export *export)
{
	hook_api(closure, hookid, export, "start_before", NULL);
}

static void hook_api_start_after(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, int status)
{
	hook_api(closure, hookid, export, "start_after", "{si}", "result", status);
}

static void hook_api_on_event_before(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, const char *event, int evtid, struct json_object *object)
{
	hook_api(closure, hookid, export, "on_event_before", "{ss si sO*}",
			"event", event, "id", evtid, "data", object);
}

static void hook_api_on_event_after(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, const char *event, int evtid, struct json_object *object)
{
	hook_api(closure, hookid, export, "on_event_after", "{ss si sO?}",
			"event", event, "id", evtid, "data", object);
}

static void hook_api_call(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, const char *api, const char *verb, struct json_object *args)
{
	hook_api(closure, hookid, export, "call", "{ss ss sO?}",
			"api", api, "verb", verb, "args", args);
}

static void hook_api_call_result(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, struct json_object *object, const char *error, const char *info)
{
	hook_api(closure, hookid, export, "call_result", "{sO? ss? ss?}",
			"object", object, "error", error, "info", info);
}

static void hook_api_callsync(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, const char *api, const char *verb, struct json_object *args)
{
	hook_api(closure, hookid, export, "callsync", "{ss ss sO?}",
			"api", api, "verb", verb, "args", args);
}

static void hook_api_callsync_result(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, int status, struct json_object *object, const char *error, const char *info)
{
	hook_api(closure, hookid, export, "callsync_result", "{si sO? ss? ss?}",
			"status", status, "object", object, "error", error, "info", info);
}

static void hook_api_new_api_before(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, const char *api, const char *info, int noconcurrency)
{
	hook_api(closure, hookid, export, "new_api.before", "{ss ss? sb}",
			"api", api, "info", info, "noconcurrency", noconcurrency);
}

static void hook_api_new_api_after(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, int result, const char *api)
{
	hook_api(closure, hookid, export, "new_api.after", "{si ss}",
						"status", result, "api", api);
}

static void hook_api_api_set_verbs_v2(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, int result, const struct afb_verb_v2 *verbs)
{
	hook_api(closure, hookid, export, "set_verbs_v2", "{si}",  "status", result);
}

static void hook_api_api_set_verbs_v3(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, int result, const struct afb_verb_v3 *verbs)
{
	hook_api(closure, hookid, export, "set_verbs_v3", "{si}",  "status", result);
}


static void hook_api_api_add_verb(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, int result, const char *verb, const char *info, int glob)
{
	hook_api(closure, hookid, export, "add_verb", "{si ss ss? sb}", "status", result, "verb", verb, "info", info, "glob", glob);
}

static void hook_api_api_del_verb(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, int result, const char *verb)
{
	hook_api(closure, hookid, export, "del_verb", "{si ss}", "status", result, "verb", verb);
}

static void hook_api_api_set_on_event(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, int result)
{
	hook_api(closure, hookid, export, "set_on_event", "{si}",  "status", result);
}

static void hook_api_api_set_on_init(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, int result)
{
	hook_api(closure, hookid, export, "set_on_init", "{si}",  "status", result);
}

static void hook_api_api_seal(void *closure, const struct afb_hookid *hookid, const struct afb_export *export)
{
	hook_api(closure, hookid, export, "seal", NULL);
}

static void hook_api_event_handler_add(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, int result, const char *pattern)
{
	hook_api(closure, hookid, export, "event_handler_add", "{si ss?}",  "status", result, "pattern", pattern);
}

static void hook_api_event_handler_del(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, int result, const char *pattern)
{
	hook_api(closure, hookid, export, "event_handler_del", "{si ss?}",  "status", result, "pattern", pattern);
}

static void hook_api_class_provide(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, int result, const char *name)
{
	hook_api(closure, hookid, export, "class_provide", "{si ss?}",  "status", result, "name", name);
}

static void hook_api_class_require(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, int result, const char *name)
{
	hook_api(closure, hookid, export, "class_require", "{si ss?}",  "status", result, "name", name);
}

static void hook_api_delete_api(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, int result)
{
	hook_api(closure, hookid, export, "delete_api", "{si}",  "status", result);
}

static void hook_api_on_event_handler_before(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, const char *event, int event_x2, struct json_object *object, const char *pattern)
{
	hook_api(closure, hookid, export, "on_event_handler.before",
		"{ss ss sO?}", "pattern", pattern, "event", event, "data", object);
}

static void hook_api_on_event_handler_after(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, const char *event, int event_x2, struct json_object *object, const char *pattern)
{
	hook_api(closure, hookid, export, "on_event_handler.after",
		"{ss ss sO?}", "pattern", pattern, "event", event, "data", object);
}

static void hook_api_settings(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, struct json_object *object)
{
	hook_api(closure, hookid, export, "settings", "{sO}", "settings", object);
}

static struct afb_hook_api_itf hook_api_itf = {
	.hook_api_event_broadcast_before = hook_api_event_broadcast_before,
	.hook_api_event_broadcast_after = hook_api_event_broadcast_after,
	.hook_api_get_event_loop = hook_api_get_event_loop,
	.hook_api_get_user_bus = hook_api_get_user_bus,
	.hook_api_get_system_bus = hook_api_get_system_bus,
	.hook_api_vverbose = hook_api_vverbose,
	.hook_api_event_make = hook_api_event_make,
	.hook_api_rootdir_get_fd = hook_api_rootdir_get_fd,
	.hook_api_rootdir_open_locale = hook_api_rootdir_open_locale,
	.hook_api_queue_job = hook_api_queue_job,
	.hook_api_legacy_unstore_req = hook_api_unstore_req,
	.hook_api_require_api = hook_api_require_api,
	.hook_api_require_api_result = hook_api_require_api_result,
	.hook_api_add_alias = hook_api_add_alias_cb,
	.hook_api_start_before = hook_api_start_before,
	.hook_api_start_after = hook_api_start_after,
	.hook_api_on_event_before = hook_api_on_event_before,
	.hook_api_on_event_after = hook_api_on_event_after,
	.hook_api_call = hook_api_call,
	.hook_api_call_result = hook_api_call_result,
	.hook_api_callsync = hook_api_callsync,
	.hook_api_callsync_result = hook_api_callsync_result,
	.hook_api_new_api_before = hook_api_new_api_before,
	.hook_api_new_api_after = hook_api_new_api_after,
	.hook_api_api_set_verbs_v2 = hook_api_api_set_verbs_v2,
	.hook_api_api_set_verbs_v3 = hook_api_api_set_verbs_v3,
	.hook_api_api_add_verb = hook_api_api_add_verb,
	.hook_api_api_del_verb = hook_api_api_del_verb,
	.hook_api_api_set_on_event = hook_api_api_set_on_event,
	.hook_api_api_set_on_init = hook_api_api_set_on_init,
	.hook_api_api_seal = hook_api_api_seal,
	.hook_api_event_handler_add = hook_api_event_handler_add,
	.hook_api_event_handler_del = hook_api_event_handler_del,
	.hook_api_class_provide = hook_api_class_provide,
	.hook_api_class_require = hook_api_class_require,
	.hook_api_delete_api = hook_api_delete_api,
	.hook_api_on_event_handler_before = hook_api_on_event_handler_before,
	.hook_api_on_event_handler_after = hook_api_on_event_handler_after,
	.hook_api_settings = hook_api_settings,
};

/*******************************************************************************/
/*****  trace the events                                                   *****/
/*******************************************************************************/

static void hook_evt(void *closure, const struct afb_hookid *hookid, const char *evt, int id, const char *action, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	emit(closure, hookid, "event", "{si ss ss}", format, ap,
					"id", id,
					"name", evt,
					"action", action);
	va_end(ap);
}

static void hook_evt_create(void *closure, const struct afb_hookid *hookid, const char *evt, int id)
{
	hook_evt(closure, hookid, evt, id, "create", NULL);
}

static void hook_evt_push_before(void *closure, const struct afb_hookid *hookid, const char *evt, int id, struct json_object *obj)
{
	hook_evt(closure, hookid, evt, id, "push_before", "{sO*}", "data", obj);
}


static void hook_evt_push_after(void *closure, const struct afb_hookid *hookid, const char *evt, int id, struct json_object *obj, int result)
{
	hook_evt(closure, hookid, evt, id, "push_after", "{sO* si}", "data", obj, "result", result);
}

static void hook_evt_broadcast_before(void *closure, const struct afb_hookid *hookid, const char *evt, int id, struct json_object *obj)
{
	hook_evt(closure, hookid, evt, id, "broadcast_before", "{sO*}", "data", obj);
}

static void hook_evt_broadcast_after(void *closure, const struct afb_hookid *hookid, const char *evt, int id, struct json_object *obj, int result)
{
	hook_evt(closure, hookid, evt, id, "broadcast_after", "{sO* si}", "data", obj, "result", result);
}

static void hook_evt_name(void *closure, const struct afb_hookid *hookid, const char *evt, int id, const char *result)
{
	hook_evt(closure, hookid, evt, id, "name", "{ss}", "result", result);
}

static void hook_evt_addref(void *closure, const struct afb_hookid *hookid, const char *evt, int id)
{
	hook_evt(closure, hookid, evt, id, "addref", NULL);
}

static void hook_evt_unref(void *closure, const struct afb_hookid *hookid, const char *evt, int id)
{
	hook_evt(closure, hookid, evt, id, "unref", NULL);
}

static struct afb_hook_evt_itf hook_evt_itf = {
	.hook_evt_create = hook_evt_create,
	.hook_evt_push_before = hook_evt_push_before,
	.hook_evt_push_after = hook_evt_push_after,
	.hook_evt_broadcast_before = hook_evt_broadcast_before,
	.hook_evt_broadcast_after = hook_evt_broadcast_after,
	.hook_evt_name = hook_evt_name,
	.hook_evt_addref = hook_evt_addref,
	.hook_evt_unref = hook_evt_unref
};

/*******************************************************************************/
/*****  trace the sessions                                                 *****/
/*******************************************************************************/

static void hook_session(void *closure, const struct afb_hookid *hookid, struct afb_session *session, const char *action, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	emit(closure, hookid, "session", "{ss ss}", format, ap,
					"uuid", afb_session_uuid(session),
					"action", action);
	va_end(ap);
}

static void hook_session_create(void *closure, const struct afb_hookid *hookid, struct afb_session *session)
{
	hook_session(closure, hookid, session, "create", "{ss}", "token", afb_session_token(session));
}

static void hook_session_close(void *closure, const struct afb_hookid *hookid, struct afb_session *session)
{
	hook_session(closure, hookid, session, "close", NULL);
}

static void hook_session_destroy(void *closure, const struct afb_hookid *hookid, struct afb_session *session)
{
	hook_session(closure, hookid, session, "destroy", NULL);
}

static void hook_session_renew(void *closure, const struct afb_hookid *hookid, struct afb_session *session)
{
	hook_session(closure, hookid, session, "renew", "{ss}", "token", afb_session_token(session));
}

static void hook_session_addref(void *closure, const struct afb_hookid *hookid, struct afb_session *session)
{
	hook_session(closure, hookid, session, "addref", NULL);
}

static void hook_session_unref(void *closure, const struct afb_hookid *hookid, struct afb_session *session)
{
	hook_session(closure, hookid, session, "unref", NULL);
}

static struct afb_hook_session_itf hook_session_itf = {
	.hook_session_create = hook_session_create,
	.hook_session_close = hook_session_close,
	.hook_session_destroy = hook_session_destroy,
	.hook_session_renew = hook_session_renew,
	.hook_session_addref = hook_session_addref,
	.hook_session_unref = hook_session_unref
};

/*******************************************************************************/
/*****  trace the globals                                                  *****/
/*******************************************************************************/

static void hook_global(void *closure, const struct afb_hookid *hookid, const char *action, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	emit(closure, hookid, "global", "{ss}", format, ap, "action", action);
	va_end(ap);
}

static void hook_global_vverbose(void *closure, const struct afb_hookid *hookid, int level, const char *file, int line, const char *function, const char *fmt, va_list args)
{
	struct json_object *pos;
	int len;
	char *msg;
	va_list ap;

	pos = NULL;
	msg = NULL;

	va_copy(ap, args);
	len = vasprintf(&msg, fmt, ap);
	va_end(ap);

	if (file)
		wrap_json_pack(&pos, "{ss si ss*}", "file", file, "line", line, "function", function);

	hook_global(closure, hookid, "vverbose", "{si ss* ss? so*}",
					"level", level,
 					"type", verbosity_level_name(level),
					len < 0 ? "format" : "message", len < 0 ? fmt : msg,
					"position", pos);

	free(msg);
}

static struct afb_hook_global_itf hook_global_itf = {
	.hook_global_vverbose = hook_global_vverbose,
};

/*******************************************************************************/
/*****  abstract types                                                     *****/
/*******************************************************************************/

static
struct
{
	const char *name;
	void (*unref)(void*);
	int (*get_flag)(const char*);
}
abstracting[Trace_Type_Count] =
{
	[Trace_Type_Xreq] =
	{
		.name = "request",
		.unref =  (void(*)(void*))afb_hook_unref_xreq,
		.get_flag = afb_hook_flags_xreq_from_text
	},
	[Trace_Type_Api] =
	{
		.name = "api",
		.unref =  (void(*)(void*))afb_hook_unref_api,
		.get_flag = afb_hook_flags_api_from_text
	},
	[Trace_Type_Evt] =
	{
		.name = "event",
		.unref =  (void(*)(void*))afb_hook_unref_evt,
		.get_flag = afb_hook_flags_evt_from_text
	},
	[Trace_Type_Session] =
	{
		.name = "session",
		.unref =  (void(*)(void*))afb_hook_unref_session,
		.get_flag = afb_hook_flags_session_from_text
	},
	[Trace_Type_Global] =
	{
		.name = "global",
		.unref =  (void(*)(void*))afb_hook_unref_global,
		.get_flag = afb_hook_flags_global_from_text
	},
#if !defined(REMOVE_LEGACY_TRACE)
	[Trace_Legacy_Type_Ditf] =
	{
		.name = "daemon",
		.unref =  (void(*)(void*))afb_hook_unref_api,
		.get_flag = afb_hook_flags_legacy_ditf_from_text
	},
	[Trace_Legacy_Type_Svc] =
	{
		.name = "service",
		.unref =  (void(*)(void*))afb_hook_unref_api,
		.get_flag = afb_hook_flags_legacy_svc_from_text
	},
#endif
};

/*******************************************************************************/
/*****  handle trace data                                                  *****/
/*******************************************************************************/

/* drop hooks of 'trace' matching 'tag' and 'event' and 'session' */
static void trace_unhook(struct afb_trace *trace, struct tag *tag, struct event *event, struct afb_session *session)
{
	int i;
	struct hook *hook, **prev;

	/* remove any event */
	for (i = 0 ; i < Trace_Type_Count ; i++) {
		prev = &trace->hooks[i];
		while ((hook = *prev)) {
			if ((tag && tag != hook->tag)
			 || (event && event != hook->event)
			 || (session && session != hook->session))
				prev = &hook->next;
			else {
				*prev = hook->next;
				abstracting[i].unref(hook->handler);
				free(hook);
			}
		}
	}
}

/* cleanup: removes unused tags, events and sessions of the 'trace' */
static void trace_cleanup(struct afb_trace *trace)
{
	int i;
	struct hook *hook;
	struct tag *tag, **ptag;
	struct event *event, **pevent;

	/* clean tags */
	ptag = &trace->tags;
	while ((tag = *ptag)) {
		/* search for tag */
		for (hook = NULL, i = 0 ; !hook && i < Trace_Type_Count ; i++)
			for (hook = trace->hooks[i] ; hook && hook->tag != tag ; hook = hook->next);
		/* keep or free whether used or not */
		if (hook)
			ptag = &tag->next;
		else {
			*ptag = tag->next;
			free(tag);
		}
	}
	/* clean events */
	pevent = &trace->events;
	while ((event = *pevent)) {
		/* search for event */
		for (hook = NULL, i = 0 ; !hook && i < Trace_Type_Count ; i++)
			for (hook = trace->hooks[i] ; hook && hook->event != event ; hook = hook->next);
		/* keep or free whether used or not */
		if (hook)
			pevent = &event->next;
		else {
			*pevent = event->next;
			afb_evt_evtid_unref(event->evtid);
			free(event);
		}
	}
}

/*
 * Get the tag of 'name' within 'trace'.
 * If 'alloc' isn't zero, create the tag and add it.
 */
static struct tag *trace_get_tag(struct afb_trace *trace, const char *name, int alloc)
{
	struct tag *tag;

	/* search the tag of 'name' */
	tag = trace->tags;
	while (tag && strcmp(name, tag->tag))
		tag = tag->next;

	if (!tag && alloc) {
		/* creation if needed */
		tag = malloc(sizeof * tag + 1 + strlen(name));
		if (tag) {
			strcpy(tag->tag, name);
			tag->next = trace->tags;
			trace->tags = tag;
		}
	}
	return tag;
}

/*
 * Get the event of 'name' within 'trace'.
 * If 'alloc' isn't zero, create the event and add it.
 */
static struct event *trace_get_event(struct afb_trace *trace, const char *name, int alloc)
{
	struct event *event;

	/* search the event */
	event = trace->events;
	while (event && strcmp(afb_evt_evtid_name(event->evtid), name))
		event = event->next;

	if (!event && alloc) {
		event = malloc(sizeof * event);
		if (event) {
			event->evtid = afb_evt_evtid_create2(trace->apiname, name);
			if (event->evtid) {
				event->next = trace->events;
				trace->events = event;
			} else {
				free(event);
				event = NULL;
			}
		}
	}
	return event;
}

/*
 * called on session closing
 */
static void session_closed(void *item)
{
	struct cookie *cookie = item;

	pthread_mutex_lock(&cookie->trace->mutex);
	trace_unhook(cookie->trace, NULL, NULL, cookie->session);
	pthread_mutex_unlock(&cookie->trace->mutex);
	free(cookie);
}

/*
 * records the cookie of session for tracking close
 */
static void *session_open(void *closure)
{
	struct cookie *param = closure, *cookie;
	cookie = malloc(sizeof *cookie);
	if (cookie)
		*cookie = *param;
	return cookie;
}

/*
 * Get the session of 'uuid' within 'trace'.
 * If 'alloc' isn't zero, create the session and add it.
 */
static struct afb_session *trace_get_session_by_uuid(struct afb_trace *trace, const char *uuid, int alloc)
{
	struct cookie cookie;

	if (!alloc)
		cookie.session = afb_session_search(uuid);
	else {
		cookie.session = afb_session_get(uuid, AFB_SESSION_TIMEOUT_DEFAULT, NULL);
		if (cookie.session) {
			cookie.trace = trace;
			afb_session_cookie(cookie.session, cookie.trace, session_open, session_closed, &cookie, 0);
		}
	}
	return cookie.session;
}

static struct hook *trace_make_detached_hook(struct afb_trace *trace, const char *event, const char *tag)
{
	struct hook *hook;

	tag = tag ?: DEFAULT_TAG_NAME;
	event = event ?: DEFAULT_EVENT_NAME;
	hook = malloc(sizeof *hook);
	if (hook) {
		hook->tag = trace_get_tag(trace, tag, 1);
		hook->event = trace_get_event(trace, event, 1);
		hook->session = NULL;
		hook->handler = NULL;
	}
	return hook;
}

static void trace_attach_hook(struct afb_trace *trace, struct hook *hook, enum trace_type type)
{
	hook->next = trace->hooks[type];
	trace->hooks[type] = hook;
}

/*******************************************************************************/
/*****  handle client requests                                             *****/
/*******************************************************************************/

struct context
{
	struct afb_trace *trace;
	afb_req_t req;
	char *errors;
};

struct desc
{
	struct context *context;
	const char *name;
	const char *tag;
	const char *uuid;
	const char *apiname;
	const char *verbname;
	const char *pattern;
	int flags[Trace_Type_Count];
};

static void addhook(struct desc *desc, enum trace_type type)
{
	struct hook *hook;
	struct afb_session *session;
	struct afb_session *bind;
	struct afb_trace *trace = desc->context->trace;

	/* check permission for bound traces */
	bind = trace->bound;
	if (bind != NULL) {
		if (type != Trace_Type_Xreq) {
			ctxt_error(&desc->context->errors, "tracing %s is forbidden", abstracting[type].name);
			return;
		}
		if (desc->uuid) {
			ctxt_error(&desc->context->errors, "setting session is forbidden");
			return;
		}
	}

	/* allocate the hook */
	hook = trace_make_detached_hook(trace, desc->name, desc->tag);
	if (!hook) {
		ctxt_error(&desc->context->errors, "allocation of hook failed");
		return;
	}

	/* create the hook handler */
	switch (type) {
	case Trace_Type_Xreq:
		if (!desc->uuid)
			session = afb_session_addref(bind);
		else {
			session = trace_get_session_by_uuid(trace, desc->uuid, 1);
			if (!session) {
				ctxt_error(&desc->context->errors, "allocation of session failed");
				free(hook);
				return;
			}
		}
		hook->handler = afb_hook_create_xreq(desc->apiname, desc->verbname, session,
				desc->flags[type], &hook_xreq_itf, hook);
		afb_session_unref(session);
		break;
	case Trace_Type_Api:
		hook->handler = afb_hook_create_api(desc->apiname, desc->flags[type], &hook_api_itf, hook);
		break;
	case Trace_Type_Evt:
		hook->handler = afb_hook_create_evt(desc->pattern, desc->flags[type], &hook_evt_itf, hook);
		break;
	case Trace_Type_Session:
		hook->handler = afb_hook_create_session(desc->uuid, desc->flags[type], &hook_session_itf, hook);
		break;
	case Trace_Type_Global:
		hook->handler = afb_hook_create_global(desc->flags[type], &hook_global_itf, hook);
		break;
	default:
		break;
	}
	if (!hook->handler) {
		ctxt_error(&desc->context->errors, "creation of hook failed");
		free(hook);
		return;
	}

	/* attach and activate the hook */
	afb_req_subscribe(desc->context->req, afb_evt_event_x2_from_evtid(hook->event->evtid));
	trace_attach_hook(trace, hook, type);
}

static void addhooks(struct desc *desc)
{
	int i;

#if !defined(REMOVE_LEGACY_TRACE)
	desc->flags[Trace_Type_Api] |= desc->flags[Trace_Legacy_Type_Ditf] | desc->flags[Trace_Legacy_Type_Svc];
	desc->flags[Trace_Legacy_Type_Ditf] = desc->flags[Trace_Legacy_Type_Svc] = 0;
#endif

	for (i = 0 ; i < Trace_Type_Count ; i++) {
		if (desc->flags[i])
			addhook(desc, i);
	}
}

static void add_flags(void *closure, struct json_object *object, enum trace_type type)
{
	int value;
	const char *name, *queried;
	struct desc *desc = closure;

	if (wrap_json_unpack(object, "s", &name))
		ctxt_error(&desc->context->errors, "unexpected %s value %s",
					abstracting[type].name,
					json_object_to_json_string_ext(object, JSON_C_TO_STRING_NOSLASHESCAPE));
	else {
		queried = (name[0] == '*' && !name[1]) ? "all" : name;
		value = abstracting[type].get_flag(queried);
		if (value)
			desc->flags[type] |= value;
		else
			ctxt_error(&desc->context->errors, "unknown %s name %s",
					abstracting[type].name, name);
	}
}

static void add_xreq_flags(void *closure, struct json_object *object)
{
	add_flags(closure, object, Trace_Type_Xreq);
}

#if !defined(REMOVE_LEGACY_TRACE)
static void legacy_add_ditf_flags(void *closure, struct json_object *object)
{
	add_flags(closure, object, Trace_Legacy_Type_Ditf);
}

static void legacy_add_svc_flags(void *closure, struct json_object *object)
{
	add_flags(closure, object, Trace_Legacy_Type_Svc);
}
#endif

static void add_api_flags(void *closure, struct json_object *object)
{
	add_flags(closure, object, Trace_Type_Api);
}

static void add_evt_flags(void *closure, struct json_object *object)
{
	add_flags(closure, object, Trace_Type_Evt);
}

static void add_session_flags(void *closure, struct json_object *object)
{
	add_flags(closure, object, Trace_Type_Session);
}

static void add_global_flags(void *closure, struct json_object *object)
{
	add_flags(closure, object, Trace_Type_Global);
}

/* add hooks */
static void add(void *closure, struct json_object *object)
{
	int rc;
	struct desc desc;
	struct json_object *request, *event, *sub, *global, *session, *api;
#if !defined(REMOVE_LEGACY_TRACE)
	struct json_object *daemon, *service;
#endif

	memcpy (&desc, closure, sizeof desc);
	request = event = sub = global = session = api = NULL;
#if !defined(REMOVE_LEGACY_TRACE)
	daemon = service = NULL;
#endif

	rc = wrap_json_unpack(object, "{s?s s?s s?s s?s s?s s?s s?o s?o s?o s?o s?o s?o s?o}",
			"name", &desc.name,
			"tag", &desc.tag,
			"apiname", &desc.apiname,
			"verbname", &desc.verbname,
			"uuid", &desc.uuid,
			"pattern", &desc.pattern,
			"api", &api,
			"request", &request,
#if !defined(REMOVE_LEGACY_TRACE)
			"daemon", &daemon,
			"service", &service,
#endif
			"event", &event,
			"session", &session,
			"global", &global,
			"for", &sub);

	if (!rc) {
		/* replace stars */
		if (desc.apiname && desc.apiname[0] == '*' && !desc.apiname[1])
			desc.apiname = NULL;

		if (desc.verbname && desc.verbname[0] == '*' && !desc.verbname[1])
			desc.verbname = NULL;

		if (desc.uuid && desc.uuid[0] == '*' && !desc.uuid[1])
			desc.uuid = NULL;

		/* get what is expected */
		if (request)
			wrap_json_optarray_for_all(request, add_xreq_flags, &desc);

		if (api)
			wrap_json_optarray_for_all(api, add_api_flags, &desc);

#if !defined(REMOVE_LEGACY_TRACE)
		if (daemon)
			wrap_json_optarray_for_all(daemon, legacy_add_ditf_flags, &desc);

		if (service)
			wrap_json_optarray_for_all(service, legacy_add_svc_flags, &desc);
#endif

		if (event)
			wrap_json_optarray_for_all(event, add_evt_flags, &desc);

		if (session)
			wrap_json_optarray_for_all(session, add_session_flags, &desc);

		if (global)
			wrap_json_optarray_for_all(global, add_global_flags, &desc);

		/* apply */
		if (sub)
			wrap_json_optarray_for_all(sub, add, &desc);
		else
			addhooks(&desc);
	}
	else {
		wrap_json_optarray_for_all(object, add_xreq_flags, &desc);
		addhooks(&desc);
	}
}

/* drop hooks of given tag */
static void drop_tag(void *closure, struct json_object *object)
{
	int rc;
	struct context *context = closure;
	struct tag *tag;
	const char *name;

	rc = wrap_json_unpack(object, "s", &name);
	if (rc)
		ctxt_error(&context->errors, "unexpected tag value %s", json_object_to_json_string_ext(object, JSON_C_TO_STRING_NOSLASHESCAPE));
	else {
		tag = trace_get_tag(context->trace, name, 0);
		if (!tag)
			ctxt_error(&context->errors, "tag %s not found", name);
		else
			trace_unhook(context->trace, tag, NULL, NULL);
	}
}

/* drop hooks of given event */
static void drop_event(void *closure, struct json_object *object)
{
	int rc;
	struct context *context = closure;
	struct event *event;
	const char *name;

	rc = wrap_json_unpack(object, "s", &name);
	if (rc)
		ctxt_error(&context->errors, "unexpected event value %s", json_object_to_json_string_ext(object, JSON_C_TO_STRING_NOSLASHESCAPE));
	else {
		event = trace_get_event(context->trace, name, 0);
		if (!event)
			ctxt_error(&context->errors, "event %s not found", name);
		else
			trace_unhook(context->trace, NULL, event, NULL);
	}
}

/* drop hooks of given session */
static void drop_session(void *closure, struct json_object *object)
{
	int rc;
	struct context *context = closure;
	struct afb_session *session;
	const char *uuid;

	rc = wrap_json_unpack(object, "s", &uuid);
	if (rc)
		ctxt_error(&context->errors, "unexpected session value %s", json_object_to_json_string_ext(object, JSON_C_TO_STRING_NOSLASHESCAPE));
	else {
		session = trace_get_session_by_uuid(context->trace, uuid, 0);
		if (!session)
			ctxt_error(&context->errors, "session %s not found", uuid);
		else {
			trace_unhook(context->trace, NULL, NULL, session);
			afb_session_unref(session);
		}
	}
}

/*******************************************************************************/
/*****  public interface                                                   *****/
/*******************************************************************************/

/* allocates an afb_trace instance */
struct afb_trace *afb_trace_create(const char *apiname, struct afb_session *bound)
{
	struct afb_trace *trace;

	assert(apiname);

	trace = calloc(1, sizeof *trace);
	if (trace) {
		trace->refcount = 1;
		trace->bound = bound;
		trace->apiname = apiname;
		pthread_mutex_init(&trace->mutex, NULL);
	}
	return trace;
}

/* add a reference to the trace */
void afb_trace_addref(struct afb_trace *trace)
{
	__atomic_add_fetch(&trace->refcount, 1, __ATOMIC_RELAXED);
}

/* drop one reference to the trace */
void afb_trace_unref(struct afb_trace *trace)
{
	if (trace && !__atomic_sub_fetch(&trace->refcount, 1, __ATOMIC_RELAXED)) {
		/* clean hooks */
		trace_unhook(trace, NULL, NULL, NULL);
		trace_cleanup(trace);
		pthread_mutex_destroy(&trace->mutex);
		free(trace);
	}
}

/* add traces */
int afb_trace_add(afb_req_t req, struct json_object *args, struct afb_trace *trace)
{
	struct context context;
	struct desc desc;

	memset(&context, 0, sizeof context);
	context.trace = trace;
	context.req = req;

	memset(&desc, 0, sizeof desc);
	desc.context = &context;

	pthread_mutex_lock(&trace->mutex);
	wrap_json_optarray_for_all(args, add, &desc);
	pthread_mutex_unlock(&trace->mutex);

	if (!context.errors)
		return 0;

	afb_req_fail(req, "error-detected", context.errors);
	free(context.errors);
	return -1;
}

/* drop traces */
int afb_trace_drop(afb_req_t req, struct json_object *args, struct afb_trace *trace)
{
	int rc;
	struct context context;
	struct json_object *tags, *events, *uuids;

	memset(&context, 0, sizeof context);
	context.trace = trace;
	context.req = req;

	/* special: boolean value */
	if (!wrap_json_unpack(args, "b", &rc)) {
		if (rc) {
			pthread_mutex_lock(&trace->mutex);
			trace_unhook(trace, NULL, NULL, NULL);
			trace_cleanup(trace);
			pthread_mutex_unlock(&trace->mutex);
		}
		return 0;
	}

	tags = events = uuids = NULL;
	rc = wrap_json_unpack(args, "{s?o s?o s?o}",
			"event", &events,
			"tag", &tags,
			"uuid", &uuids);

	if (rc < 0 || !(events || tags || uuids)) {
		afb_req_fail(req, "error-detected", "bad drop arguments");
		return -1;
	}

	pthread_mutex_lock(&trace->mutex);

	if (tags)
		wrap_json_optarray_for_all(tags, drop_tag, &context);

	if (events)
		wrap_json_optarray_for_all(events, drop_event, &context);

	if (uuids)
		wrap_json_optarray_for_all(uuids, drop_session, &context);

	trace_cleanup(trace);

	pthread_mutex_unlock(&trace->mutex);

	if (!context.errors)
		return 0;

	afb_req_fail(req, "error-detected", context.errors);
	free(context.errors);
	return -1;
}

#endif
