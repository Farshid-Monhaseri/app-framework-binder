/*
 * Copyright (C) 2016, 2017, 2018 "IoT.bzh"
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

#include <limits.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/uio.h>

#include <json-c/json.h>
#if !defined(JSON_C_TO_STRING_NOSLASHESCAPE)
#define JSON_C_TO_STRING_NOSLASHESCAPE 0
#endif

#include <afb/afb-req-x1.h>
#include <afb/afb-event-x2.h>

#include "afb-context.h"
#include "afb-hook.h"
#include "afb-session.h"
#include "afb-cred.h"
#include "afb-xreq.h"
#include "afb-export.h"
#include "afb-evt.h"
#include "afb-api.h"
#include "afb-msg-json.h"
#include "verbose.h"

#include <fnmatch.h>
#define MATCH(pattern,string)   (\
		pattern \
			? !fnmatch((pattern),(string),FNM_CASEFOLD|FNM_EXTMATCH|FNM_PERIOD) \
			: afb_api_is_public(string))

#define MATCH_API(pattern,string)	MATCH(pattern,string)
#define MATCH_VERB(pattern,string)	MATCH(pattern,string)
#define MATCH_EVENT(pattern,string)	MATCH(pattern,string)
#define MATCH_SESSION(pattern,string)	MATCH(pattern,string)

/**
 * Definition of a hook for xreq
 */
struct afb_hook_xreq {
	struct afb_hook_xreq *next; /**< next hook */
	unsigned refcount; /**< reference count */
	unsigned flags; /**< hook flags */
	char *api; /**< api hooked or NULL for any */
	char *verb; /**< verb hooked or NULL for any */
	struct afb_session *session; /**< session hooked or NULL if any */
	struct afb_hook_xreq_itf *itf; /**< interface of hook */
	void *closure; /**< closure for callbacks */
};

/**
 * Definition of a hook for export
 */
struct afb_hook_api {
	struct afb_hook_api *next; /**< next hook */
	unsigned refcount; /**< reference count */
	unsigned flags; /**< hook flags */
	char *api; /**< api hooked or NULL for any */
	struct afb_hook_api_itf *itf; /**< interface of hook */
	void *closure; /**< closure for callbacks */
};

/**
 * Definition of a hook for evt
 */
struct afb_hook_evt {
	struct afb_hook_evt *next; /**< next hook */
	unsigned refcount; /**< reference count */
	unsigned flags; /**< hook flags */
	char *pattern; /**< event pattern name hooked or NULL for any */
	struct afb_hook_evt_itf *itf; /**< interface of hook */
	void *closure; /**< closure for callbacks */
};

/**
 * Definition of a hook for session
 */
struct afb_hook_session {
	struct afb_hook_session *next; /**< next hook */
	unsigned refcount; /**< reference count */
	unsigned flags; /**< hook flags */
	char *pattern; /**< event pattern name hooked or NULL for any */
	struct afb_hook_session_itf *itf; /**< interface of hook */
	void *closure; /**< closure for callbacks */
};

/**
 * Definition of a hook for global
 */
struct afb_hook_global {
	struct afb_hook_global *next; /**< next hook */
	unsigned refcount; /**< reference count */
	unsigned flags; /**< hook flags */
	struct afb_hook_global_itf *itf; /**< interface of hook */
	void *closure; /**< closure for callbacks */
};

/* synchronization across threads */
static pthread_rwlock_t rwlock = PTHREAD_RWLOCK_INITIALIZER;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

/* list of hooks for xreq */
static struct afb_hook_xreq *list_of_xreq_hooks = NULL;

/* list of hooks for export */
static struct afb_hook_api *list_of_api_hooks = NULL;

/* list of hooks for evt */
static struct afb_hook_evt *list_of_evt_hooks = NULL;

/* list of hooks for session */
static struct afb_hook_session *list_of_session_hooks = NULL;

/* list of hooks for global */
static struct afb_hook_global *list_of_global_hooks = NULL;

/* hook id */
static unsigned next_hookid = 0;

/******************************************************************************
 * section: hook id
 *****************************************************************************/
static void init_hookid(struct afb_hookid *hookid)
{
	hookid->id = __atomic_add_fetch(&next_hookid, 1, __ATOMIC_RELAXED);
	clock_gettime(CLOCK_REALTIME, &hookid->time);
}

/******************************************************************************
 * section: default callbacks for tracing requests
 *****************************************************************************/

static char *_pbuf_(const char *fmt, va_list args, char **palloc, char *sbuf, size_t szsbuf, size_t *outlen)
{
	int rc;
	va_list cp;

	*palloc = NULL;
	va_copy(cp, args);
	rc = vsnprintf(sbuf, szsbuf, fmt, args);
	if ((size_t)rc >= szsbuf) {
		sbuf[szsbuf-1] = 0;
		sbuf[szsbuf-2] = sbuf[szsbuf-3] = sbuf[szsbuf-4] = '.';
		rc = vasprintf(palloc, fmt, cp);
		if (rc >= 0)
			sbuf = *palloc;
	}
	va_end(cp);
	if (rc >= 0 && outlen)
		*outlen = (size_t)rc;
	return sbuf;
}

static void _hook_(const char *fmt1, const char *fmt2, va_list arg2, ...)
{
	static const char chars[] = "HOOK: [] \n";
	char *mem1, *mem2, buf1[256], buf2[2000];
	struct iovec iov[5];
	va_list arg1;

	/* "HOOK: [" */
	iov[0].iov_base = (void*)&chars[0];
	iov[0].iov_len = 7;

	/* fmt1 ... */
	va_start(arg1, arg2);
	iov[1].iov_base = _pbuf_(fmt1, arg1, &mem1, buf1, sizeof buf1, &iov[1].iov_len);
	va_end(arg1);

	/* "] " */
	iov[2].iov_base = (void*)&chars[7];
	iov[2].iov_len = 2;

	/* fmt2 arg2 */
	iov[3].iov_base = _pbuf_(fmt2, arg2, &mem2, buf2, sizeof buf2, &iov[3].iov_len);

	/* "\n" */
	iov[4].iov_base = (void*)&chars[9];
	iov[4].iov_len = 1;

	(void)writev(2, iov, 5);

	free(mem1);
	free(mem2);
}

static void _hook_xreq_(const struct afb_xreq *xreq, const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	_hook_("xreq-%06d:%s/%s", format, ap, xreq->hookindex, xreq->request.called_api, xreq->request.called_verb);
	va_end(ap);
}

static void hook_xreq_begin_cb(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq)
{
	if (!xreq->cred)
		_hook_xreq_(xreq, "BEGIN");
	else
		_hook_xreq_(xreq, "BEGIN uid=%d=%s gid=%d pid=%d label=%s id=%s",
			(int)xreq->cred->uid,
			xreq->cred->user,
			(int)xreq->cred->gid,
			(int)xreq->cred->pid,
			xreq->cred->label?:"(null)",
			xreq->cred->id?:"(null)"
		);
}

static void hook_xreq_end_cb(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq)
{
	_hook_xreq_(xreq, "END");
}

static void hook_xreq_json_cb(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, struct json_object *obj)
{
	_hook_xreq_(xreq, "json() -> %s", json_object_to_json_string_ext(obj, JSON_C_TO_STRING_NOSLASHESCAPE));
}

static void hook_xreq_get_cb(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, const char *name, struct afb_arg arg)
{
	_hook_xreq_(xreq, "get(%s) -> { name: %s, value: %s, path: %s }", name, arg.name, arg.value, arg.path);
}

static void hook_xreq_reply_cb(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, struct json_object *obj, const char *error, const char *info)
{
	_hook_xreq_(xreq, "reply[%s](%s, %s)", error?:"success", json_object_to_json_string_ext(obj, JSON_C_TO_STRING_NOSLASHESCAPE), info);
}

static void hook_xreq_legacy_context_get_cb(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, void *value)
{
	_hook_xreq_(xreq, "context_get() -> %p", value);
}

static void hook_xreq_legacy_context_set_cb(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, void *value, void (*free_value)(void*))
{
	_hook_xreq_(xreq, "context_set(%p, %p)", value, free_value);
}

static void hook_xreq_addref_cb(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq)
{
	_hook_xreq_(xreq, "addref()");
}

static void hook_xreq_unref_cb(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq)
{
	_hook_xreq_(xreq, "unref()");
}

static void hook_xreq_session_close_cb(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq)
{
	_hook_xreq_(xreq, "session_close()");
}

static void hook_xreq_session_set_LOA_cb(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, unsigned level, int result)
{
	_hook_xreq_(xreq, "session_set_LOA(%u) -> %d", level, result);
}

static void hook_xreq_subscribe_cb(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, struct afb_event_x2 *event_x2, int result)
{
	_hook_xreq_(xreq, "subscribe(%s:%d) -> %d", afb_evt_event_x2_fullname(event_x2), afb_evt_event_x2_id(event_x2), result);
}

static void hook_xreq_unsubscribe_cb(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, struct afb_event_x2 *event_x2, int result)
{
	_hook_xreq_(xreq, "unsubscribe(%s:%d) -> %d", afb_evt_event_x2_fullname(event_x2), afb_evt_event_x2_id(event_x2), result);
}

static void hook_xreq_subcall_cb(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, const char *api, const char *verb, struct json_object *args)
{
	_hook_xreq_(xreq, "subcall(%s/%s, %s) ...", api, verb, json_object_to_json_string_ext(args, JSON_C_TO_STRING_NOSLASHESCAPE));
}

static void hook_xreq_subcall_result_cb(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, struct json_object *object, const char *error, const char *info)
{
	_hook_xreq_(xreq, "    ...subcall... [%s] -> %s (%s)", error?:"success", json_object_to_json_string_ext(object, JSON_C_TO_STRING_NOSLASHESCAPE), info?:"");
}

static void hook_xreq_subcallsync_cb(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, const char *api, const char *verb, struct json_object *args)
{
	_hook_xreq_(xreq, "subcallsync(%s/%s, %s) ...", api, verb, json_object_to_json_string_ext(args, JSON_C_TO_STRING_NOSLASHESCAPE));
}

static void hook_xreq_subcallsync_result_cb(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, int status, struct json_object *object, const char *error, const char *info)
{
	_hook_xreq_(xreq, "    ...subcallsync... %d [%s] -> %s (%s)", status, error?:"success", json_object_to_json_string_ext(object, JSON_C_TO_STRING_NOSLASHESCAPE), info?:"");
}

static void hook_xreq_vverbose_cb(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, int level, const char *file, int line, const char *func, const char *fmt, va_list args)
{
	int len;
	char *msg;
	va_list ap;

	va_copy(ap, args);
	len = vasprintf(&msg, fmt, ap);
	va_end(ap);

	if (len < 0)
		_hook_xreq_(xreq, "vverbose(%d:%s, %s, %d, %s) -> %s ? ? ?", level, verbose_name_of_level(level), file, line, func, fmt);
	else {
		_hook_xreq_(xreq, "vverbose(%d:%s, %s, %d, %s) -> %s", level, verbose_name_of_level(level), file, line, func, msg);
		free(msg);
	}
}

static void hook_xreq_legacy_store_cb(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, struct afb_stored_req *sreq)
{
	_hook_xreq_(xreq, "store() -> %p", sreq);
}

static void hook_xreq_legacy_unstore_cb(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq)
{
	_hook_xreq_(xreq, "unstore()");
}

static void hook_xreq_has_permission_cb(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, const char *permission, int result)
{
	_hook_xreq_(xreq, "has_permission(%s) -> %d", permission, result);
}

static void hook_xreq_get_application_id_cb(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, char *result)
{
	_hook_xreq_(xreq, "get_application_id() -> %s", result);
}

static void hook_xreq_context_make_cb(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, int replace, void *(*create_value)(void*), void (*free_value)(void*), void *create_closure, void *result)
{
	_hook_xreq_(xreq, "context_make(replace=%s, %p, %p, %p) -> %p", replace?"yes":"no", create_value, free_value, create_closure, result);
}

static void hook_xreq_get_uid_cb(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, int result)
{
	_hook_xreq_(xreq, "get_uid() -> %d", result);
}

static void hook_xreq_get_client_info_cb(void *closure, const struct afb_hookid *hookid, const struct afb_xreq *xreq, struct json_object *result)
{
	_hook_xreq_(xreq, "get_client_info() -> %s", json_object_to_json_string_ext(result, JSON_C_TO_STRING_NOSLASHESCAPE));
}

static struct afb_hook_xreq_itf hook_xreq_default_itf = {
	.hook_xreq_begin = hook_xreq_begin_cb,
	.hook_xreq_end = hook_xreq_end_cb,
	.hook_xreq_json = hook_xreq_json_cb,
	.hook_xreq_get = hook_xreq_get_cb,
	.hook_xreq_reply = hook_xreq_reply_cb,
	.hook_xreq_legacy_context_get = hook_xreq_legacy_context_get_cb,
	.hook_xreq_legacy_context_set = hook_xreq_legacy_context_set_cb,
	.hook_xreq_addref = hook_xreq_addref_cb,
	.hook_xreq_unref = hook_xreq_unref_cb,
	.hook_xreq_session_close = hook_xreq_session_close_cb,
	.hook_xreq_session_set_LOA = hook_xreq_session_set_LOA_cb,
	.hook_xreq_subscribe = hook_xreq_subscribe_cb,
	.hook_xreq_unsubscribe = hook_xreq_unsubscribe_cb,
	.hook_xreq_subcall = hook_xreq_subcall_cb,
	.hook_xreq_subcall_result = hook_xreq_subcall_result_cb,
	.hook_xreq_subcallsync = hook_xreq_subcallsync_cb,
	.hook_xreq_subcallsync_result = hook_xreq_subcallsync_result_cb,
	.hook_xreq_vverbose = hook_xreq_vverbose_cb,
	.hook_xreq_legacy_store = hook_xreq_legacy_store_cb,
	.hook_xreq_legacy_unstore = hook_xreq_legacy_unstore_cb,
	.hook_xreq_has_permission = hook_xreq_has_permission_cb,
	.hook_xreq_get_application_id = hook_xreq_get_application_id_cb,
	.hook_xreq_context_make = hook_xreq_context_make_cb,
	.hook_xreq_get_uid = hook_xreq_get_uid_cb,
	.hook_xreq_get_client_info = hook_xreq_get_client_info_cb,
};

/******************************************************************************
 * section: hooks for tracing requests
 *****************************************************************************/

#define _HOOK_XREQ_2_(flag,func,...)   \
	struct afb_hook_xreq *hook; \
	struct afb_hookid hookid; \
	pthread_rwlock_rdlock(&rwlock); \
	init_hookid(&hookid); \
	hook = list_of_xreq_hooks; \
	while (hook) { \
		if (hook->refcount \
		 && hook->itf->hook_xreq_##func \
		 && (hook->flags & afb_hook_flag_req_##flag) != 0 \
		 && (!hook->session || hook->session == xreq->context.session) \
		 && MATCH_API(hook->api, xreq->request.called_api) \
		 && MATCH_VERB(hook->verb, xreq->request.called_verb)) { \
			hook->itf->hook_xreq_##func(hook->closure, &hookid, __VA_ARGS__); \
		} \
		hook = hook->next; \
	} \
	pthread_rwlock_unlock(&rwlock);

#define _HOOK_XREQ_(what,...)   _HOOK_XREQ_2_(what,what,__VA_ARGS__)

void afb_hook_xreq_begin(const struct afb_xreq *xreq)
{
	_HOOK_XREQ_(begin, xreq);
}

void afb_hook_xreq_end(const struct afb_xreq *xreq)
{
	_HOOK_XREQ_(end, xreq);
}

struct json_object *afb_hook_xreq_json(const struct afb_xreq *xreq, struct json_object *obj)
{
	_HOOK_XREQ_(json, xreq, obj);
	return obj;
}

struct afb_arg afb_hook_xreq_get(const struct afb_xreq *xreq, const char *name, struct afb_arg arg)
{
	_HOOK_XREQ_(get, xreq, name, arg);
	return arg;
}

void afb_hook_xreq_reply(const struct afb_xreq *xreq, struct json_object *obj, const char *error, const char *info)
{
	_HOOK_XREQ_(reply, xreq, obj, error, info);
}

void *afb_hook_xreq_legacy_context_get(const struct afb_xreq *xreq, void *value)
{
	_HOOK_XREQ_(legacy_context_get, xreq, value);
	return value;
}

void afb_hook_xreq_legacy_context_set(const struct afb_xreq *xreq, void *value, void (*free_value)(void*))
{
	_HOOK_XREQ_(legacy_context_set, xreq, value, free_value);
}

void afb_hook_xreq_addref(const struct afb_xreq *xreq)
{
	_HOOK_XREQ_(addref, xreq);
}

void afb_hook_xreq_unref(const struct afb_xreq *xreq)
{
	_HOOK_XREQ_(unref, xreq);
}

void afb_hook_xreq_session_close(const struct afb_xreq *xreq)
{
	_HOOK_XREQ_(session_close, xreq);
}

int afb_hook_xreq_session_set_LOA(const struct afb_xreq *xreq, unsigned level, int result)
{
	_HOOK_XREQ_(session_set_LOA, xreq, level, result);
	return result;
}

int afb_hook_xreq_subscribe(const struct afb_xreq *xreq, struct afb_event_x2 *event_x2, int result)
{
	_HOOK_XREQ_(subscribe, xreq, event_x2, result);
	return result;
}

int afb_hook_xreq_unsubscribe(const struct afb_xreq *xreq, struct afb_event_x2 *event_x2, int result)
{
	_HOOK_XREQ_(unsubscribe, xreq, event_x2, result);
	return result;
}

void afb_hook_xreq_subcall(const struct afb_xreq *xreq, const char *api, const char *verb, struct json_object *args, int flags)
{
	_HOOK_XREQ_(subcall, xreq, api, verb, args);
}

void afb_hook_xreq_subcall_result(const struct afb_xreq *xreq, struct json_object *object, const char *error, const char *info)
{
	_HOOK_XREQ_(subcall_result, xreq, object, error, info);
}

void afb_hook_xreq_subcallsync(const struct afb_xreq *xreq, const char *api, const char *verb, struct json_object *args, int flags)
{
	_HOOK_XREQ_(subcallsync, xreq, api, verb, args);
}

int  afb_hook_xreq_subcallsync_result(const struct afb_xreq *xreq, int status, struct json_object *object, const char *error, const char *info)
{
	_HOOK_XREQ_(subcallsync_result, xreq, status, object, error, info);
	return status;
}

void afb_hook_xreq_vverbose(const struct afb_xreq *xreq, int level, const char *file, int line, const char *func, const char *fmt, va_list args)
{
	_HOOK_XREQ_(vverbose, xreq, level, file ?: "?", line, func ?: "?", fmt, args);
}

void afb_hook_xreq_legacy_store(const struct afb_xreq *xreq, struct afb_stored_req *sreq)
{
	_HOOK_XREQ_(legacy_store, xreq, sreq);
}

void afb_hook_xreq_legacy_unstore(const struct afb_xreq *xreq)
{
	_HOOK_XREQ_(legacy_unstore, xreq);
}

int afb_hook_xreq_has_permission(const struct afb_xreq *xreq, const char *permission, int result)
{
	_HOOK_XREQ_(has_permission, xreq, permission, result);
	return result;
}

char *afb_hook_xreq_get_application_id(const struct afb_xreq *xreq, char *result)
{
	_HOOK_XREQ_(get_application_id, xreq, result);
	return result;
}

void *afb_hook_xreq_context_make(const struct afb_xreq *xreq, int replace, void *(*create_value)(void*), void (*free_value)(void*), void *create_closure, void *result)
{
	_HOOK_XREQ_(context_make, xreq, replace, create_value, free_value, create_closure, result);
	return result;
}

int afb_hook_xreq_get_uid(const struct afb_xreq *xreq, int result)
{
	_HOOK_XREQ_(get_uid, xreq, result);
	return result;
}

struct json_object *afb_hook_xreq_get_client_info(const struct afb_xreq *xreq, struct json_object *result)
{
	_HOOK_XREQ_(get_client_info, xreq, result);
	return result;
}

/******************************************************************************
 * section: hooking xreqs
 *****************************************************************************/

void afb_hook_init_xreq(struct afb_xreq *xreq)
{
	static int reqindex = 0;

	int f, flags;
	int add, x;
	struct afb_hook_xreq *hook;

	/* scan hook list to get the expected flags */
	flags = 0;
	pthread_rwlock_rdlock(&rwlock);
	hook = list_of_xreq_hooks;
	while (hook) {
		f = hook->flags & afb_hook_flags_req_all;
		add = f != 0
		   && (!hook->session || hook->session == xreq->context.session)
		   && MATCH_API(hook->api, xreq->request.called_api)
		   && MATCH_VERB(hook->verb, xreq->request.called_verb);
		if (add)
			flags |= f;
		hook = hook->next;
	}
	pthread_rwlock_unlock(&rwlock);

	/* store the hooking data */
	xreq->hookflags = flags;
	if (flags) {
		do {
			x = __atomic_load_n(&reqindex, __ATOMIC_RELAXED);
			xreq->hookindex = (x + 1) % 1000000 ?: 1;
		} while (x != __atomic_exchange_n(&reqindex, xreq->hookindex, __ATOMIC_RELAXED));
	}
}

struct afb_hook_xreq *afb_hook_create_xreq(const char *api, const char *verb, struct afb_session *session, int flags, struct afb_hook_xreq_itf *itf, void *closure)
{
	struct afb_hook_xreq *hook;

	/* alloc the result */
	hook = calloc(1, sizeof *hook);
	if (hook == NULL)
		return NULL;

	/* get a copy of the names */
	hook->api = api ? strdup(api) : NULL;
	hook->verb = verb ? strdup(verb) : NULL;
	if ((api && !hook->api) || (verb && !hook->verb)) {
		free(hook->api);
		free(hook->verb);
		free(hook);
		return NULL;
	}

	/* initialise the rest */
	hook->session = session;
	if (session)
		afb_session_addref(session);
	hook->refcount = 1;
	hook->flags = flags;
	hook->itf = itf ? itf : &hook_xreq_default_itf;
	hook->closure = closure;

	/* record the hook */
	pthread_mutex_lock(&mutex);
	hook->next = list_of_xreq_hooks;
	list_of_xreq_hooks = hook;
	pthread_mutex_unlock(&mutex);

	/* returns it */
	return hook;
}

struct afb_hook_xreq *afb_hook_addref_xreq(struct afb_hook_xreq *hook)
{
	__atomic_add_fetch(&hook->refcount, 1, __ATOMIC_RELAXED);
	return hook;
}

static void hook_clean_xreq()
{
	struct afb_hook_xreq **prv, *hook, *head;

	if (pthread_rwlock_trywrlock(&rwlock) == 0) {
		/* unlink under mutex */
		head = NULL;
		pthread_mutex_lock(&mutex);
		prv = &list_of_xreq_hooks;
		while ((hook = *prv)) {
			if (hook->refcount)
				prv = &(*prv)->next;
			else {
				*prv = hook->next;
				hook->next = head;
				head = hook;
			}
		}
		pthread_mutex_unlock(&mutex);
		pthread_rwlock_unlock(&rwlock);

		/* free found hooks */
		while((hook = head)) {
			head = hook->next;
			free(hook->api);
			free(hook->verb);
			if (hook->session)
				afb_session_unref(hook->session);
			free(hook);
		}
	}
}

void afb_hook_unref_xreq(struct afb_hook_xreq *hook)
{
	if (hook && !__atomic_sub_fetch(&hook->refcount, 1, __ATOMIC_RELAXED))
		hook_clean_xreq();
}

/******************************************************************************
 * section: default callbacks for tracing daemon interface
 *****************************************************************************/

static void _hook_api_(const struct afb_export *export, const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	_hook_("api-%s", format, ap, afb_export_apiname(export));
	va_end(ap);
}

static void hook_api_event_broadcast_before_cb(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, const char *name, struct json_object *object)
{
	_hook_api_(export, "event_broadcast.before(%s, %s)....", name, json_object_to_json_string_ext(object, JSON_C_TO_STRING_NOSLASHESCAPE));
}

static void hook_api_event_broadcast_after_cb(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, const char *name, struct json_object *object, int result)
{
	_hook_api_(export, "event_broadcast.after(%s, %s) -> %d", name, json_object_to_json_string_ext(object, JSON_C_TO_STRING_NOSLASHESCAPE), result);
}

static void hook_api_get_event_loop_cb(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, struct sd_event *result)
{
	_hook_api_(export, "get_event_loop() -> %p", result);
}

static void hook_api_get_user_bus_cb(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, struct sd_bus *result)
{
	_hook_api_(export, "get_user_bus() -> %p", result);
}

static void hook_api_get_system_bus_cb(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, struct sd_bus *result)
{
	_hook_api_(export, "get_system_bus() -> %p", result);
}

static void hook_api_vverbose_cb(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, int level, const char *file, int line, const char *function, const char *fmt, va_list args)
{
	int len;
	char *msg;
	va_list ap;

	va_copy(ap, args);
	len = vasprintf(&msg, fmt, ap);
	va_end(ap);

	if (len < 0)
		_hook_api_(export, "vverbose(%d:%s, %s, %d, %s) -> %s ? ? ?", level, verbose_name_of_level(level), file, line, function, fmt);
	else {
		_hook_api_(export, "vverbose(%d:%s, %s, %d, %s) -> %s", level, verbose_name_of_level(level), file, line, function, msg);
		free(msg);
	}
}

static void hook_api_event_make_cb(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, const char *name, struct afb_event_x2 *result)
{
	_hook_api_(export, "event_make(%s) -> %s:%d", name, afb_evt_event_x2_fullname(result), afb_evt_event_x2_id(result));
}

static void hook_api_rootdir_get_fd_cb(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, int result)
{
	char path[PATH_MAX], proc[100];
	ssize_t s;

	if (result < 0)
		_hook_api_(export, "rootdir_get_fd() -> %d, %m", result);
	else {
		snprintf(proc, sizeof proc, "/proc/self/fd/%d", result);
		s = readlink(proc, path, sizeof path);
		path[s < 0 ? 0 : s >= sizeof path ? sizeof path - 1 : s] = 0;
		_hook_api_(export, "rootdir_get_fd() -> %d = %s", result, path);
	}
}

static void hook_api_rootdir_open_locale_cb(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, const char *filename, int flags, const char *locale, int result)
{
	char path[PATH_MAX], proc[100];
	ssize_t s;

	if (!locale)
		locale = "(null)";
	if (result < 0)
		_hook_api_(export, "rootdir_open_locale(%s, %d, %s) -> %d, %m", filename, flags, locale, result);
	else {
		snprintf(proc, sizeof proc, "/proc/self/fd/%d", result);
		s = readlink(proc, path, sizeof path);
		path[s < 0 ? 0 : s >= sizeof path ? sizeof path - 1 : s] = 0;
		_hook_api_(export, "rootdir_open_locale(%s, %d, %s) -> %d = %s", filename, flags, locale, result, path);
	}
}

static void hook_api_queue_job_cb(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, void (*callback)(int signum, void *arg), void *argument, void *group, int timeout, int result)
{
	_hook_api_(export, "queue_job(%p, %p, %p, %d) -> %d", callback, argument, group, timeout, result);
}

static void hook_api_unstore_req_cb(void *closure, const struct afb_hookid *hookid,  const struct afb_export *export, struct afb_stored_req *sreq)
{
	_hook_api_(export, "unstore_req(%p)", sreq);
}

static void hook_api_require_api_cb(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, const char *name, int initialized)
{
	_hook_api_(export, "require_api(%s, %d)...", name, initialized);
}

static void hook_api_require_api_result_cb(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, const char *name, int initialized, int result)
{
	_hook_api_(export, "...require_api(%s, %d) -> %d", name, initialized, result);
}

static void hook_api_add_alias_cb(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, const char *api, const char *alias, int result)
{
	_hook_api_(export, "add_alias(%s -> %s) -> %d", api, alias?:"<null>", result);
}

static void hook_api_start_before_cb(void *closure, const struct afb_hookid *hookid, const struct afb_export *export)
{
	_hook_api_(export, "start.before");
}

static void hook_api_start_after_cb(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, int status)
{
	_hook_api_(export, "start.after -> %d", status);
}

static void hook_api_on_event_before_cb(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, const char *event, int event_x2, struct json_object *object)
{
	_hook_api_(export, "on_event.before(%s, %d, %s)", event, event_x2, json_object_to_json_string_ext(object, JSON_C_TO_STRING_NOSLASHESCAPE));
}

static void hook_api_on_event_after_cb(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, const char *event, int event_x2, struct json_object *object)
{
	_hook_api_(export, "on_event.after(%s, %d, %s)", event, event_x2, json_object_to_json_string_ext(object, JSON_C_TO_STRING_NOSLASHESCAPE));
}

static void hook_api_call_cb(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, const char *api, const char *verb, struct json_object *args)
{
	_hook_api_(export, "call(%s/%s, %s) ...", api, verb, json_object_to_json_string_ext(args, JSON_C_TO_STRING_NOSLASHESCAPE));
}

static void hook_api_call_result_cb(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, struct json_object *object, const char *error, const char *info)
{
	_hook_api_(export, "    ...call... [%s] -> %s (%s)", error?:"success", json_object_to_json_string_ext(object, JSON_C_TO_STRING_NOSLASHESCAPE), info?:"");
}

static void hook_api_callsync_cb(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, const char *api, const char *verb, struct json_object *args)
{
	_hook_api_(export, "callsync(%s/%s, %s) ...", api, verb, json_object_to_json_string_ext(args, JSON_C_TO_STRING_NOSLASHESCAPE));
}

static void hook_api_callsync_result_cb(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, int status, struct json_object *object, const char *error, const char *info)
{
	_hook_api_(export, "    ...callsync... %d [%s] -> %s (%s)", status, error?:"success", json_object_to_json_string_ext(object, JSON_C_TO_STRING_NOSLASHESCAPE), info?:"");
}

static void hook_api_new_api_before_cb(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, const char *api, const char *info, int noconcurrency)
{
	_hook_api_(export, "new_api.before %s (%s)%s ...", api, info?:"", noconcurrency?" no-concurrency" : "");
}

static void hook_api_new_api_after_cb(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, int result, const char *api)
{
	_hook_api_(export, "... new_api.after %s -> %s (%d)", api, result >= 0 ? "OK" : "ERROR", result);
}

static void hook_api_api_set_verbs_v2_cb(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, int result, const struct afb_verb_v2 *verbs)
{
	_hook_api_(export, "set_verbs_v2 -> %s (%d)", result >= 0 ? "OK" : "ERROR", result);
}

static void hook_api_api_set_verbs_v3_cb(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, int result, const struct afb_verb_v3 *verbs)
{
	_hook_api_(export, "set_verbs_v3 -> %s (%d)", result >= 0 ? "OK" : "ERROR", result);
}

static void hook_api_api_add_verb_cb(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, int result, const char *verb, const char *info, int glob)
{
	_hook_api_(export, "add_verb(%s%s [%s]) -> %s (%d)", verb, glob?" (GLOB)":"", info?:"", result >= 0 ? "OK" : "ERROR", result);
}

static void hook_api_api_del_verb_cb(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, int result, const char *verb)
{
	_hook_api_(export, "del_verb(%s) -> %s (%d)", verb, result >= 0 ? "OK" : "ERROR", result);
}

static void hook_api_api_set_on_event_cb(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, int result)
{
	_hook_api_(export, "set_on_event -> %s (%d)", result >= 0 ? "OK" : "ERROR", result);
}

static void hook_api_api_set_on_init_cb(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, int result)
{
	_hook_api_(export, "set_on_init -> %s (%d)", result >= 0 ? "OK" : "ERROR", result);
}

static void hook_api_api_seal_cb(void *closure, const struct afb_hookid *hookid, const struct afb_export *export)
{
	_hook_api_(export, "seal");
}

static void hook_api_event_handler_add_cb(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, int result, const char *pattern)
{
	_hook_api_(export, "event_handler_add(%s) -> %s (%d)", pattern, result >= 0 ? "OK" : "ERROR", result);
}

static void hook_api_event_handler_del_cb(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, int result, const char *pattern)
{
	_hook_api_(export, "event_handler_del(%s) -> %s (%d)", pattern, result >= 0 ? "OK" : "ERROR", result);
}

static void hook_api_class_provide_cb(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, int result, const char *name)
{
	_hook_api_(export, "class_provide(%s) -> %s (%d)", name, result >= 0 ? "OK" : "ERROR", result);
}

static void hook_api_class_require_cb(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, int result, const char *name)
{
	_hook_api_(export, "class_require(%s) -> %s (%d)", name, result >= 0 ? "OK" : "ERROR", result);
}

static void hook_api_delete_api_cb(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, int result)
{
	_hook_api_(export, "delete_api -> %s (%d)", result >= 0 ? "OK" : "ERROR", result);
}

static void hook_api_on_event_handler_before_cb(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, const char *event, int event_x2, struct json_object *object, const char *pattern)
{
	_hook_api_(export, "on_event_handler[%s].before(%s, %d, %s)", pattern, event, event_x2, json_object_to_json_string_ext(object, JSON_C_TO_STRING_NOSLASHESCAPE));
}

static void hook_api_on_event_handler_after_cb(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, const char *event, int event_x2, struct json_object *object, const char *pattern)
{
	_hook_api_(export, "on_event_handler[%s].after(%s, %d, %s)", pattern, event, event_x2, json_object_to_json_string_ext(object, JSON_C_TO_STRING_NOSLASHESCAPE));
}

static void hook_api_settings_cb(void *closure, const struct afb_hookid *hookid, const struct afb_export *export, struct json_object *object)
{
	_hook_api_(export, "settings -> %s", json_object_to_json_string_ext(object, JSON_C_TO_STRING_NOSLASHESCAPE));
}

static struct afb_hook_api_itf hook_api_default_itf = {
	.hook_api_event_broadcast_before = hook_api_event_broadcast_before_cb,
	.hook_api_event_broadcast_after = hook_api_event_broadcast_after_cb,
	.hook_api_get_event_loop = hook_api_get_event_loop_cb,
	.hook_api_get_user_bus = hook_api_get_user_bus_cb,
	.hook_api_get_system_bus = hook_api_get_system_bus_cb,
	.hook_api_vverbose = hook_api_vverbose_cb,
	.hook_api_event_make = hook_api_event_make_cb,
	.hook_api_rootdir_get_fd = hook_api_rootdir_get_fd_cb,
	.hook_api_rootdir_open_locale = hook_api_rootdir_open_locale_cb,
	.hook_api_queue_job = hook_api_queue_job_cb,
	.hook_api_legacy_unstore_req = hook_api_unstore_req_cb,
	.hook_api_require_api = hook_api_require_api_cb,
	.hook_api_require_api_result = hook_api_require_api_result_cb,
	.hook_api_add_alias = hook_api_add_alias_cb,
	.hook_api_start_before = hook_api_start_before_cb,
	.hook_api_start_after = hook_api_start_after_cb,
	.hook_api_on_event_before = hook_api_on_event_before_cb,
	.hook_api_on_event_after = hook_api_on_event_after_cb,
	.hook_api_call = hook_api_call_cb,
	.hook_api_call_result = hook_api_call_result_cb,
	.hook_api_callsync = hook_api_callsync_cb,
	.hook_api_callsync_result = hook_api_callsync_result_cb,
	.hook_api_new_api_before = hook_api_new_api_before_cb,
	.hook_api_new_api_after = hook_api_new_api_after_cb,
	.hook_api_api_set_verbs_v2 = hook_api_api_set_verbs_v2_cb,
	.hook_api_api_set_verbs_v3 = hook_api_api_set_verbs_v3_cb,
	.hook_api_api_add_verb = hook_api_api_add_verb_cb,
	.hook_api_api_del_verb = hook_api_api_del_verb_cb,
	.hook_api_api_set_on_event = hook_api_api_set_on_event_cb,
	.hook_api_api_set_on_init = hook_api_api_set_on_init_cb,
	.hook_api_api_seal = hook_api_api_seal_cb,
	.hook_api_event_handler_add = hook_api_event_handler_add_cb,
	.hook_api_event_handler_del = hook_api_event_handler_del_cb,
	.hook_api_class_provide = hook_api_class_provide_cb,
	.hook_api_class_require = hook_api_class_require_cb,
	.hook_api_delete_api = hook_api_delete_api_cb,
	.hook_api_on_event_handler_before = hook_api_on_event_handler_before_cb,
	.hook_api_on_event_handler_after = hook_api_on_event_handler_after_cb,
	.hook_api_settings = hook_api_settings_cb,
};

/******************************************************************************
 * section: hooks for tracing daemon interface (export)
 *****************************************************************************/

#define _HOOK_API_2_(flag,func,...)   \
	struct afb_hook_api *hook; \
	struct afb_hookid hookid; \
	const char *apiname = afb_export_apiname(export); \
	pthread_rwlock_rdlock(&rwlock); \
	init_hookid(&hookid); \
	hook = list_of_api_hooks; \
	while (hook) { \
		if (hook->refcount \
		 && hook->itf->hook_api_##func \
		 && (hook->flags & afb_hook_flag_api_##flag) != 0 \
		 && MATCH_API(hook->api, apiname)) { \
			hook->itf->hook_api_##func(hook->closure, &hookid, __VA_ARGS__); \
		} \
		hook = hook->next; \
	} \
	pthread_rwlock_unlock(&rwlock);

#define _HOOK_API_(what,...)   _HOOK_API_2_(what,what,__VA_ARGS__)

void afb_hook_api_event_broadcast_before(const struct afb_export *export, const char *name, struct json_object *object)
{
	_HOOK_API_2_(event_broadcast, event_broadcast_before, export, name, object);
}

int afb_hook_api_event_broadcast_after(const struct afb_export *export, const char *name, struct json_object *object, int result)
{
	_HOOK_API_2_(event_broadcast, event_broadcast_after, export, name, object, result);
	return result;
}

struct sd_event *afb_hook_api_get_event_loop(const struct afb_export *export, struct sd_event *result)
{
	_HOOK_API_(get_event_loop, export, result);
	return result;
}

struct sd_bus *afb_hook_api_get_user_bus(const struct afb_export *export, struct sd_bus *result)
{
	_HOOK_API_(get_user_bus, export, result);
	return result;
}

struct sd_bus *afb_hook_api_get_system_bus(const struct afb_export *export, struct sd_bus *result)
{
	_HOOK_API_(get_system_bus, export, result);
	return result;
}

void afb_hook_api_vverbose(const struct afb_export *export, int level, const char *file, int line, const char *function, const char *fmt, va_list args)
{
	_HOOK_API_(vverbose, export, level, file, line, function, fmt, args);
}

struct afb_event_x2 *afb_hook_api_event_make(const struct afb_export *export, const char *name, struct afb_event_x2 *result)
{
	_HOOK_API_(event_make, export, name, result);
	return result;
}

int afb_hook_api_rootdir_get_fd(const struct afb_export *export, int result)
{
	_HOOK_API_(rootdir_get_fd, export, result);
	return result;
}

int afb_hook_api_rootdir_open_locale(const struct afb_export *export, const char *filename, int flags, const char *locale, int result)
{
	_HOOK_API_(rootdir_open_locale, export, filename, flags, locale, result);
	return result;
}

int afb_hook_api_queue_job(const struct afb_export *export, void (*callback)(int signum, void *arg), void *argument, void *group, int timeout, int result)
{
	_HOOK_API_(queue_job, export, callback, argument, group, timeout, result);
	return result;
}

void afb_hook_api_legacy_unstore_req(const struct afb_export *export, struct afb_stored_req *sreq)
{
	_HOOK_API_(legacy_unstore_req, export, sreq);
}

void afb_hook_api_require_api(const struct afb_export *export, const char *name, int initialized)
{
	_HOOK_API_(require_api, export, name, initialized);
}

int afb_hook_api_require_api_result(const struct afb_export *export, const char *name, int initialized, int result)
{
	_HOOK_API_2_(require_api, require_api_result, export, name, initialized, result);
	return result;
}

int afb_hook_api_add_alias(const struct afb_export *export, const char *api, const char *alias, int result)
{
	_HOOK_API_(add_alias, export, api, alias, result);
	return result;
}

void afb_hook_api_start_before(const struct afb_export *export)
{
	_HOOK_API_2_(start, start_before, export);
}

int afb_hook_api_start_after(const struct afb_export *export, int status)
{
	_HOOK_API_2_(start, start_after, export, status);
	return status;
}

void afb_hook_api_on_event_before(const struct afb_export *export, const char *event, int event_x2, struct json_object *object)
{
	_HOOK_API_2_(on_event, on_event_before, export, event, event_x2, object);
}

void afb_hook_api_on_event_after(const struct afb_export *export, const char *event, int event_x2, struct json_object *object)
{
	_HOOK_API_2_(on_event, on_event_after, export, event, event_x2, object);
}

void afb_hook_api_call(const struct afb_export *export, const char *api, const char *verb, struct json_object *args)
{
	_HOOK_API_(call, export, api, verb, args);
}

void afb_hook_api_call_result(const struct afb_export *export, struct json_object *object, const char*error, const char *info)
{
	_HOOK_API_2_(call, call_result, export, object, error, info);

}

void afb_hook_api_callsync(const struct afb_export *export, const char *api, const char *verb, struct json_object *args)
{
	_HOOK_API_(callsync, export, api, verb, args);
}

int afb_hook_api_callsync_result(const struct afb_export *export, int status, struct json_object *object, const char *error, const char *info)
{
	_HOOK_API_2_(callsync, callsync_result, export, status, object, error, info);
	return status;
}

void afb_hook_api_new_api_before(const struct afb_export *export, const char *api, const char *info, int noconcurrency)
{
	_HOOK_API_2_(new_api, new_api_before, export, api, info, noconcurrency);
}

int afb_hook_api_new_api_after(const struct afb_export *export, int result, const char *api)
{
	_HOOK_API_2_(new_api, new_api_after, export, result, api);
	return result;
}

int afb_hook_api_api_set_verbs_v2(const struct afb_export *export, int result, const struct afb_verb_v2 *verbs)
{
	_HOOK_API_2_(api_set_verbs, api_set_verbs_v2, export, result, verbs);
	return result;
}

int afb_hook_api_api_set_verbs_v3(const struct afb_export *export, int result, const struct afb_verb_v3 *verbs)
{
	_HOOK_API_2_(api_set_verbs, api_set_verbs_v3, export, result, verbs);
	return result;
}

int afb_hook_api_api_add_verb(const struct afb_export *export, int result, const char *verb, const char *info, int glob)
{
	_HOOK_API_(api_add_verb, export, result, verb, info, glob);
	return result;
}

int afb_hook_api_api_del_verb(const struct afb_export *export, int result, const char *verb)
{
	_HOOK_API_(api_del_verb, export, result, verb);
	return result;
}

int afb_hook_api_api_set_on_event(const struct afb_export *export, int result)
{
	_HOOK_API_(api_set_on_event, export, result);
	return result;
}

int afb_hook_api_api_set_on_init(const struct afb_export *export, int result)
{
	_HOOK_API_(api_set_on_init, export, result);
	return result;
}

void afb_hook_api_api_seal(const struct afb_export *export)
{
	_HOOK_API_(api_seal, export);
}

int afb_hook_api_event_handler_add(const struct afb_export *export, int result, const char *pattern)
{
	_HOOK_API_(event_handler_add, export, result, pattern);
	return result;
}
int afb_hook_api_event_handler_del(const struct afb_export *export, int result, const char *pattern)
{
	_HOOK_API_(event_handler_del, export, result, pattern);
	return result;
}
int afb_hook_api_class_provide(const struct afb_export *export, int result, const char *name)
{
	_HOOK_API_(class_provide, export, result, name);
	return result;
}
int afb_hook_api_class_require(const struct afb_export *export, int result, const char *name)
{
	_HOOK_API_(class_require, export, result, name);
	return result;
}

int afb_hook_api_delete_api(const struct afb_export *export, int result)
{
	_HOOK_API_(delete_api, export, result);
	return result;
}

void afb_hook_api_on_event_handler_before(const struct afb_export *export, const char *event, int event_x2, struct json_object *object, const char *pattern)
{
	_HOOK_API_2_(on_event_handler, on_event_handler_before, export, event, event_x2, object, pattern);
}

void afb_hook_api_on_event_handler_after(const struct afb_export *export, const char *event, int event_x2, struct json_object *object, const char *pattern)
{
	_HOOK_API_2_(on_event_handler, on_event_handler_after, export, event, event_x2, object, pattern);
}

struct json_object *afb_hook_api_settings(const struct afb_export *export, struct json_object *object)
{
	_HOOK_API_(settings, export, object);
	return object;
}

/******************************************************************************
 * section: hooking export
 *****************************************************************************/

int afb_hook_flags_api(const char *api)
{
	int flags;
	struct afb_hook_api *hook;

	flags = 0;
	pthread_rwlock_rdlock(&rwlock);
	hook = list_of_api_hooks;
	while (hook) {
		if (!api || MATCH_API(hook->api, api))
			flags |= hook->flags;
		hook = hook->next;
	}
	pthread_rwlock_unlock(&rwlock);
	return flags;
}

struct afb_hook_api *afb_hook_create_api(const char *api, int flags, struct afb_hook_api_itf *itf, void *closure)
{
	struct afb_hook_api *hook;

	/* alloc the result */
	hook = calloc(1, sizeof *hook);
	if (hook == NULL)
		return NULL;

	/* get a copy of the names */
	hook->api = api ? strdup(api) : NULL;
	if (api && !hook->api) {
		free(hook);
		return NULL;
	}

	/* initialise the rest */
	hook->refcount = 1;
	hook->flags = flags;
	hook->itf = itf ? itf : &hook_api_default_itf;
	hook->closure = closure;

	/* record the hook */
	pthread_mutex_lock(&mutex);
	hook->next = list_of_api_hooks;
	list_of_api_hooks = hook;
	pthread_mutex_unlock(&mutex);

	/* returns it */
	return hook;
}

struct afb_hook_api *afb_hook_addref_api(struct afb_hook_api *hook)
{
	__atomic_add_fetch(&hook->refcount, 1, __ATOMIC_RELAXED);
	return hook;
}

static void hook_clean_api()
{
	struct afb_hook_api **prv, *hook, *head;

	if (pthread_rwlock_trywrlock(&rwlock) == 0) {
		/* unlink under mutex */
		head = NULL;
		pthread_mutex_lock(&mutex);
		prv = &list_of_api_hooks;
		while ((hook = *prv)) {
			if (hook->refcount)
				prv = &(*prv)->next;
			else {
				*prv = hook->next;
				hook->next = head;
				head = hook;
			}
		}
		pthread_mutex_unlock(&mutex);
		pthread_rwlock_unlock(&rwlock);

		/* free found hooks */
		while((hook = head)) {
			head = hook->next;
			free(hook->api);
			free(hook);
		}
	}
}

void afb_hook_unref_api(struct afb_hook_api *hook)
{
	if (hook && !__atomic_sub_fetch(&hook->refcount, 1, __ATOMIC_RELAXED))
		hook_clean_api();
}

/******************************************************************************
 * section: default callbacks for tracing service interface (evt)
 *****************************************************************************/

static void _hook_evt_(const char *evt, int id, const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	_hook_("evt-%s:%d", format, ap, evt, id);
	va_end(ap);
}

static void hook_evt_create_cb(void *closure, const struct afb_hookid *hookid, const char *evt, int id)
{
	_hook_evt_(evt, id, "create");
}

static void hook_evt_push_before_cb(void *closure, const struct afb_hookid *hookid, const char *evt, int id, struct json_object *obj)
{
	_hook_evt_(evt, id, "push.before(%s)", json_object_to_json_string_ext(obj, JSON_C_TO_STRING_NOSLASHESCAPE));
}


static void hook_evt_push_after_cb(void *closure, const struct afb_hookid *hookid, const char *evt, int id, struct json_object *obj, int result)
{
	_hook_evt_(evt, id, "push.after(%s) -> %d", json_object_to_json_string_ext(obj, JSON_C_TO_STRING_NOSLASHESCAPE), result);
}

static void hook_evt_broadcast_before_cb(void *closure, const struct afb_hookid *hookid, const char *evt, int id, struct json_object *obj)
{
	_hook_evt_(evt, id, "broadcast.before(%s)", json_object_to_json_string_ext(obj, JSON_C_TO_STRING_NOSLASHESCAPE));
}

static void hook_evt_broadcast_after_cb(void *closure, const struct afb_hookid *hookid, const char *evt, int id, struct json_object *obj, int result)
{
	_hook_evt_(evt, id, "broadcast.after(%s) -> %d", json_object_to_json_string_ext(obj, JSON_C_TO_STRING_NOSLASHESCAPE), result);
}

static void hook_evt_name_cb(void *closure, const struct afb_hookid *hookid, const char *evt, int id, const char *result)
{
	_hook_evt_(evt, id, "name -> %s", result);
}

static void hook_evt_addref_cb(void *closure, const struct afb_hookid *hookid, const char *evt, int id)
{
	_hook_evt_(evt, id, "addref");
}

static void hook_evt_unref_cb(void *closure, const struct afb_hookid *hookid, const char *evt, int id)
{
	_hook_evt_(evt, id, "unref");
}

static struct afb_hook_evt_itf hook_evt_default_itf = {
	.hook_evt_create = hook_evt_create_cb,
	.hook_evt_push_before = hook_evt_push_before_cb,
	.hook_evt_push_after = hook_evt_push_after_cb,
	.hook_evt_broadcast_before = hook_evt_broadcast_before_cb,
	.hook_evt_broadcast_after = hook_evt_broadcast_after_cb,
	.hook_evt_name = hook_evt_name_cb,
	.hook_evt_addref = hook_evt_addref_cb,
	.hook_evt_unref = hook_evt_unref_cb
};

/******************************************************************************
 * section: hooks for tracing events interface (evt)
 *****************************************************************************/

#define _HOOK_EVT_(what,...)   \
	struct afb_hook_evt *hook; \
	struct afb_hookid hookid; \
	pthread_rwlock_rdlock(&rwlock); \
	init_hookid(&hookid); \
	hook = list_of_evt_hooks; \
	while (hook) { \
		if (hook->refcount \
		 && hook->itf->hook_evt_##what \
		 && (hook->flags & afb_hook_flag_evt_##what) != 0 \
		 && MATCH_EVENT(hook->pattern, evt)) { \
			hook->itf->hook_evt_##what(hook->closure, &hookid, __VA_ARGS__); \
		} \
		hook = hook->next; \
	} \
	pthread_rwlock_unlock(&rwlock);

void afb_hook_evt_create(const char *evt, int id)
{
	_HOOK_EVT_(create, evt, id);
}

void afb_hook_evt_push_before(const char *evt, int id, struct json_object *obj)
{
	_HOOK_EVT_(push_before, evt, id, obj);
}

int afb_hook_evt_push_after(const char *evt, int id, struct json_object *obj, int result)
{
	_HOOK_EVT_(push_after, evt, id, obj, result);
	return result;
}

void afb_hook_evt_broadcast_before(const char *evt, int id, struct json_object *obj)
{
	_HOOK_EVT_(broadcast_before, evt, id, obj);
}

int afb_hook_evt_broadcast_after(const char *evt, int id, struct json_object *obj, int result)
{
	_HOOK_EVT_(broadcast_after, evt, id, obj, result);
	return result;
}

void afb_hook_evt_name(const char *evt, int id, const char *result)
{
	_HOOK_EVT_(name, evt, id, result);
}

void afb_hook_evt_addref(const char *evt, int id)
{
	_HOOK_EVT_(addref, evt, id);
}

void afb_hook_evt_unref(const char *evt, int id)
{
	_HOOK_EVT_(unref, evt, id);
}

/******************************************************************************
 * section: hooking services (evt)
 *****************************************************************************/

int afb_hook_flags_evt(const char *name)
{
	int flags;
	struct afb_hook_evt *hook;

	flags = 0;
	pthread_rwlock_rdlock(&rwlock);
	hook = list_of_evt_hooks;
	while (hook) {
		if (!name || MATCH_EVENT(hook->pattern, name))
			flags |= hook->flags;
		hook = hook->next;
	}
	pthread_rwlock_unlock(&rwlock);
	return flags;
}

struct afb_hook_evt *afb_hook_create_evt(const char *pattern, int flags, struct afb_hook_evt_itf *itf, void *closure)
{
	struct afb_hook_evt *hook;

	/* alloc the result */
	hook = calloc(1, sizeof *hook);
	if (hook == NULL)
		return NULL;

	/* get a copy of the names */
	hook->pattern = pattern ? strdup(pattern) : NULL;
	if (pattern && !hook->pattern) {
		free(hook);
		return NULL;
	}

	/* initialise the rest */
	hook->refcount = 1;
	hook->flags = flags;
	hook->itf = itf ? itf : &hook_evt_default_itf;
	hook->closure = closure;

	/* record the hook */
	pthread_mutex_lock(&mutex);
	hook->next = list_of_evt_hooks;
	list_of_evt_hooks = hook;
	pthread_mutex_unlock(&mutex);

	/* returns it */
	return hook;
}

struct afb_hook_evt *afb_hook_addref_evt(struct afb_hook_evt *hook)
{
	__atomic_add_fetch(&hook->refcount, 1, __ATOMIC_RELAXED);
	return hook;
}

static void hook_clean_evt()
{
	struct afb_hook_evt **prv, *hook, *head;

	if (pthread_rwlock_trywrlock(&rwlock) == 0) {
		/* unlink under mutex */
		head = NULL;
		pthread_mutex_lock(&mutex);
		prv = &list_of_evt_hooks;
		while ((hook = *prv)) {
			if (hook->refcount)
				prv = &(*prv)->next;
			else {
				*prv = hook->next;
				hook->next = head;
				head = hook;
			}
		}
		pthread_mutex_unlock(&mutex);
		pthread_rwlock_unlock(&rwlock);

		/* free found hooks */
		while((hook = head)) {
			head = hook->next;
			free(hook->pattern);
			free(hook);
		}
	}
}

void afb_hook_unref_evt(struct afb_hook_evt *hook)
{
	if (hook && !__atomic_sub_fetch(&hook->refcount, 1, __ATOMIC_RELAXED))
		hook_clean_evt();
}

/******************************************************************************
 * section: default callbacks for sessions (session)
 *****************************************************************************/

static void _hook_session_(struct afb_session *session, const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	_hook_("session-%s", format, ap, afb_session_uuid(session));
	va_end(ap);
}

static void hook_session_create_cb(void *closure, const struct afb_hookid *hookid, struct afb_session *session)
{
	_hook_session_(session, "create -> token=%s", afb_session_token(session));
}

static void hook_session_close_cb(void *closure, const struct afb_hookid *hookid, struct afb_session *session)
{
	_hook_session_(session, "close");
}

static void hook_session_destroy_cb(void *closure, const struct afb_hookid *hookid, struct afb_session *session)
{
	_hook_session_(session, "destroy");
}

static void hook_session_renew_cb(void *closure, const struct afb_hookid *hookid, struct afb_session *session)
{
	_hook_session_(session, "renew -> token=%s", afb_session_token(session));
}

static void hook_session_addref_cb(void *closure, const struct afb_hookid *hookid, struct afb_session *session)
{
	_hook_session_(session, "addref");
}

static void hook_session_unref_cb(void *closure, const struct afb_hookid *hookid, struct afb_session *session)
{
	_hook_session_(session, "unref");
}

static struct afb_hook_session_itf hook_session_default_itf = {
	.hook_session_create = hook_session_create_cb,
	.hook_session_close = hook_session_close_cb,
	.hook_session_destroy = hook_session_destroy_cb,
	.hook_session_renew = hook_session_renew_cb,
	.hook_session_addref = hook_session_addref_cb,
	.hook_session_unref = hook_session_unref_cb
};

/******************************************************************************
 * section: hooks for tracing sessions (session)
 *****************************************************************************/

#define _HOOK_SESSION_(what,...)   \
	struct afb_hook_session *hook; \
	struct afb_hookid hookid; \
	const char *sessid = 0; \
	pthread_rwlock_rdlock(&rwlock); \
	init_hookid(&hookid); \
	hook = list_of_session_hooks; \
	while (hook) { \
		if (hook->refcount \
		 && hook->itf->hook_session_##what \
		 && (hook->flags & afb_hook_flag_session_##what) != 0 \
		 && MATCH_SESSION(hook->pattern, (sessid?:(sessid=afb_session_uuid(session))))) { \
			hook->itf->hook_session_##what(hook->closure, &hookid, __VA_ARGS__); \
		} \
		hook = hook->next; \
	} \
	pthread_rwlock_unlock(&rwlock);

void afb_hook_session_create(struct afb_session *session)
{
	_HOOK_SESSION_(create, session);
}

void afb_hook_session_close(struct afb_session *session)
{
	_HOOK_SESSION_(close, session);
}

void afb_hook_session_destroy(struct afb_session *session)
{
	_HOOK_SESSION_(destroy, session);
}

void afb_hook_session_renew(struct afb_session *session)
{
	_HOOK_SESSION_(renew, session);
}

void afb_hook_session_addref(struct afb_session *session)
{
	_HOOK_SESSION_(addref, session);
}

void afb_hook_session_unref(struct afb_session *session)
{
	_HOOK_SESSION_(unref, session);
}


/******************************************************************************
 * section: hooking sessions (session)
 *****************************************************************************/

struct afb_hook_session *afb_hook_create_session(const char *pattern, int flags, struct afb_hook_session_itf *itf, void *closure)
{
	struct afb_hook_session *hook;

	/* alloc the result */
	hook = calloc(1, sizeof *hook);
	if (hook == NULL)
		return NULL;

	/* get a copy of the names */
	hook->pattern = pattern ? strdup(pattern) : NULL;
	if (pattern && !hook->pattern) {
		free(hook);
		return NULL;
	}

	/* initialise the rest */
	hook->refcount = 1;
	hook->flags = flags;
	hook->itf = itf ? itf : &hook_session_default_itf;
	hook->closure = closure;

	/* record the hook */
	pthread_mutex_lock(&mutex);
	hook->next = list_of_session_hooks;
	list_of_session_hooks = hook;
	pthread_mutex_unlock(&mutex);

	/* returns it */
	return hook;
}

struct afb_hook_session *afb_hook_addref_session(struct afb_hook_session *hook)
{
	__atomic_add_fetch(&hook->refcount, 1, __ATOMIC_RELAXED);
	return hook;
}

static void hook_clean_session()
{
	struct afb_hook_session **prv, *hook, *head;

	if (pthread_rwlock_trywrlock(&rwlock) == 0) {
		/* unlink under mutex */
		head = NULL;
		pthread_mutex_lock(&mutex);
		prv = &list_of_session_hooks;
		while ((hook = *prv)) {
			if (hook->refcount)
				prv = &(*prv)->next;
			else {
				*prv = hook->next;
				hook->next = head;
				head = hook;
			}
		}
		pthread_mutex_unlock(&mutex);
		pthread_rwlock_unlock(&rwlock);

		/* free found hooks */
		while((hook = head)) {
			head = hook->next;
			free(hook->pattern);
			free(hook);
		}
	}
}

void afb_hook_unref_session(struct afb_hook_session *hook)
{
	if (hook && !__atomic_sub_fetch(&hook->refcount, 1, __ATOMIC_RELAXED))
		hook_clean_session();
}

/******************************************************************************
 * section: default callbacks for globals (global)
 *****************************************************************************/

static void _hook_global_(const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	_hook_("global", format, ap);
	va_end(ap);
}

static void hook_global_vverbose_cb(void *closure, const struct afb_hookid *hookid, int level, const char *file, int line, const char *func, const char *fmt, va_list args)
{
	int len;
	char *msg;
	va_list ap;

	va_copy(ap, args);
	len = vasprintf(&msg, fmt, ap);
	va_end(ap);

	if (len < 0)
		_hook_global_("vverbose(%d:%s, %s, %d, %s) -> %s ? ? ?", level, verbose_name_of_level(level), file, line, func, fmt);
	else {
		_hook_global_("vverbose(%d:%s, %s, %d, %s) -> %s", level, verbose_name_of_level(level), file, line, func, msg);
		free(msg);
	}
}

static struct afb_hook_global_itf hook_global_default_itf = {
	.hook_global_vverbose = hook_global_vverbose_cb
};

/******************************************************************************
 * section: hooks for tracing globals (global)
 *****************************************************************************/

#define _HOOK_GLOBAL_(what,...)   \
	struct afb_hook_global *hook; \
	struct afb_hookid hookid; \
	pthread_rwlock_rdlock(&rwlock); \
	init_hookid(&hookid); \
	hook = list_of_global_hooks; \
	while (hook) { \
		if (hook->refcount \
		 && hook->itf->hook_global_##what \
		 && (hook->flags & afb_hook_flag_global_##what) != 0) { \
			hook->itf->hook_global_##what(hook->closure, &hookid, __VA_ARGS__); \
		} \
		hook = hook->next; \
	} \
	pthread_rwlock_unlock(&rwlock);

static void afb_hook_global_vverbose(int level, const char *file, int line, const char *func, const char *fmt, va_list args)
{
	_HOOK_GLOBAL_(vverbose, level, file ?: "?", line, func ?: "?", fmt ?: "", args);
}

/******************************************************************************
 * section: hooking globals (global)
 *****************************************************************************/

static void update_global()
{
	struct afb_hook_global *hook;
	int flags = 0;

	pthread_rwlock_rdlock(&rwlock);
	hook = list_of_global_hooks;
	while (hook) {
		if (hook->refcount)
			flags = hook->flags;
		hook = hook->next;
	}
	verbose_observer = (flags & afb_hook_flag_global_vverbose) ? afb_hook_global_vverbose : NULL;
	pthread_rwlock_unlock(&rwlock);
}

struct afb_hook_global *afb_hook_create_global(int flags, struct afb_hook_global_itf *itf, void *closure)
{
	struct afb_hook_global *hook;

	/* alloc the result */
	hook = calloc(1, sizeof *hook);
	if (hook == NULL)
		return NULL;

	/* initialise the rest */
	hook->refcount = 1;
	hook->flags = flags;
	hook->itf = itf ? itf : &hook_global_default_itf;
	hook->closure = closure;

	/* record the hook */
	pthread_mutex_lock(&mutex);
	hook->next = list_of_global_hooks;
	list_of_global_hooks = hook;
	pthread_mutex_unlock(&mutex);

	/* update hooking */
	update_global();

	/* returns it */
	return hook;
}

struct afb_hook_global *afb_hook_addref_global(struct afb_hook_global *hook)
{
	__atomic_add_fetch(&hook->refcount, 1, __ATOMIC_RELAXED);
	return hook;
}

static void hook_clean_global()
{
	struct afb_hook_global **prv, *hook, *head;

	if (pthread_rwlock_trywrlock(&rwlock) == 0) {
		/* unlink under mutex */
		head = NULL;
		pthread_mutex_lock(&mutex);
		prv = &list_of_global_hooks;
		while ((hook = *prv)) {
			if (hook->refcount)
				prv = &(*prv)->next;
			else {
				*prv = hook->next;
				hook->next = head;
				head = hook;
			}
		}
		pthread_mutex_unlock(&mutex);
		pthread_rwlock_unlock(&rwlock);

		/* free found hooks */
		while((hook = head)) {
			head = hook->next;
			free(hook);
		}
	}
}

void afb_hook_unref_global(struct afb_hook_global *hook)
{
	if (hook && !__atomic_sub_fetch(&hook->refcount, 1, __ATOMIC_RELAXED)) {
		/* update hooking */
		update_global();
		hook_clean_global();
	}
}

