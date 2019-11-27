/*
 * Copyright (C) 2016-2019 "IoT.bzh"
 * Author: José Bollo <jose.bollo@iot.bzh>
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
#include <errno.h>

#include <json-c/json.h>

#define AFB_BINDING_VERSION 0
#include <afb/afb-binding.h>

#include "afb-calls.h"
#include "afb-cred.h"
#include "afb-evt.h"
#include "afb-export.h"
#include "afb-hook.h"
#include "afb-msg-json.h"
#include "afb-session.h"
#include "afb-xreq.h"
#include "afb-error-text.h"

#include "jobs.h"
#include "verbose.h"

#define CALLFLAGS            (afb_req_x2_subcall_api_session|afb_req_x2_subcall_catch_events)
#define LEGACY_SUBCALLFLAGS  (afb_req_x2_subcall_pass_events|afb_req_x2_subcall_on_behalf)


/************************************************************************/

struct modes
{
	unsigned hooked: 1;
	unsigned sync: 1;
	unsigned legacy: 1;
};

#define mode_sync  ((struct modes){ .hooked=0, .sync=1, .legacy=0 })
#define mode_async  ((struct modes){ .hooked=0, .sync=0, .legacy=0 })
#define mode_legacy_sync  ((struct modes){ .hooked=0, .sync=1, .legacy=1 })
#define mode_legacy_async  ((struct modes){ .hooked=0, .sync=0, .legacy=1 })

#if WITH_AFB_HOOK
#define mode_hooked_sync  ((struct modes){ .hooked=1, .sync=1, .legacy=0 })
#define mode_hooked_async  ((struct modes){ .hooked=1, .sync=0, .legacy=0 })
#define mode_hooked_legacy_sync  ((struct modes){ .hooked=1, .sync=1, .legacy=1 })
#define mode_hooked_legacy_async  ((struct modes){ .hooked=1, .sync=0, .legacy=1 })
#endif

union callback {
	void *any;
	union {
		void (*legacy_v1)(void*, int, struct json_object*);
		void (*legacy_v2)(void*, int, struct json_object*, struct afb_req_x1);
		void (*legacy_v3)(void*, int, struct json_object*, struct afb_req_x2*);
		void (*x3)(void*, struct json_object*, const char*, const char *, struct afb_req_x2*);
	} subcall;
	union {
		void (*legacy_v12)(void*, int, struct json_object*);
		void (*legacy_v3)(void*, int, struct json_object*, struct afb_api_x3*);
		void (*x3)(void*, struct json_object*, const char*, const char*, struct afb_api_x3*);
	} call;
};

struct callreq
{
	struct afb_xreq xreq;

	struct afb_export *export;

	struct modes mode;

	int flags;

	union {
		struct {
			struct jobloop *jobloop;
			int returned;
			int status;
			struct json_object **object;
			char **error;
			char **info;
		};
		struct {
			union callback callback;
			void *closure;
			union {
				void (*final)(void*, struct json_object*, const char*, const char*, union callback, struct afb_export*,struct afb_xreq*);
				void (*legacy_final)(void*, int, struct json_object*, union callback, struct afb_export*,struct afb_xreq*);
			};
		};
	};
};

/******************************************************************************/

static int store_reply(
		struct json_object *iobject, const char *ierror, const char *iinfo,
		struct json_object **sobject, char **serror, char **sinfo)
{
	if (serror) {
		if (!ierror)
			*serror = NULL;
		else if (!(*serror = strdup(ierror))) {
			ERROR("can't report error %s", ierror);
			json_object_put(iobject);
			iobject = NULL;
			iinfo = NULL;
		}
	}

	if (sobject)
		*sobject = iobject;
	else
		json_object_put(iobject);

	if (sinfo) {
		if (!iinfo)
			*sinfo = NULL;
		else if (!(*sinfo = strdup(iinfo)))
			ERROR("can't report info %s", iinfo);
	}

	return -!!ierror;
}

/******************************************************************************/

static void sync_leave(struct callreq *callreq)
{
	struct jobloop *jobloop = __atomic_exchange_n(&callreq->jobloop, NULL, __ATOMIC_RELAXED);
	if (jobloop)
		jobs_leave(jobloop);
}

static void sync_enter(int signum, void *closure, struct jobloop *jobloop)
{
	struct callreq *callreq = closure;
	if (!signum) {
		callreq->jobloop = jobloop;
		afb_export_process_xreq(callreq->export, &callreq->xreq);
	} else {
		afb_xreq_reply(&callreq->xreq, NULL, afb_error_text_internal_error, NULL);
	}
}

/******************************************************************************/

static void callreq_destroy_cb(struct afb_xreq *xreq)
{
	struct callreq *callreq = CONTAINER_OF_XREQ(struct callreq, xreq);

	afb_context_disconnect(&callreq->xreq.context);
	json_object_put(callreq->xreq.json);
	afb_cred_unref(callreq->xreq.cred);
	free(callreq);
}

static void callreq_reply_cb(struct afb_xreq *xreq, struct json_object *object, const char *error, const char *info)
{
	struct callreq *callreq = CONTAINER_OF_XREQ(struct callreq, xreq);

#if WITH_AFB_HOOK
	/* centralized hooking */
	if (callreq->mode.hooked) {
		if (callreq->mode.sync) {
			if (callreq->xreq.caller)
				afb_hook_xreq_subcallsync_result(callreq->xreq.caller, -!!error, object, error, info);
			else
				afb_hook_api_callsync_result(callreq->export, -!!error, object, error, info);
		} else {
			if (callreq->xreq.caller)
				afb_hook_xreq_subcall_result(callreq->xreq.caller, object, error, info);
			else
				afb_hook_api_call_result(callreq->export, object, error, info);
		}
	}
#endif

	/* true report of the result */
	if (callreq->mode.sync) {
		callreq->returned = 1;
		if (callreq->mode.legacy) {
			callreq->status = -!!error;
			if (callreq->object)
				*callreq->object = afb_msg_json_reply(object, error, info, NULL);
			else
				json_object_put(object);
		} else {
			callreq->status = store_reply(object, error, info,
					callreq->object, callreq->error, callreq->info);
		}
		sync_leave(callreq);
	} else {
		if (callreq->mode.legacy) {
			object = afb_msg_json_reply(object, error, info, NULL);
			callreq->legacy_final(callreq->closure, -!!error, object, callreq->callback, callreq->export, callreq->xreq.caller);
		} else {
			callreq->final(callreq->closure, object, error, info, callreq->callback, callreq->export, callreq->xreq.caller);
		}
		json_object_put(object);
	}
}

static int callreq_subscribe_cb(struct afb_xreq *xreq, struct afb_event_x2 *event)
{
	int rc = 0, rc2;
	struct callreq *callreq = CONTAINER_OF_XREQ(struct callreq, xreq);

	if (callreq->flags & afb_req_x2_subcall_pass_events)
		rc = afb_xreq_subscribe(callreq->xreq.caller, event);
	if (callreq->flags & afb_req_x2_subcall_catch_events) {
		rc2 = afb_export_subscribe(callreq->export, event);
		if (rc2 < 0)
			rc = rc2;
	}
	return rc;
}

static int callreq_unsubscribe_cb(struct afb_xreq *xreq, struct afb_event_x2 *event)
{
	int rc = 0, rc2;
	struct callreq *callreq = CONTAINER_OF_XREQ(struct callreq, xreq);

	if (callreq->flags & afb_req_x2_subcall_pass_events)
		rc = afb_xreq_unsubscribe(callreq->xreq.caller, event);
	if (callreq->flags & afb_req_x2_subcall_catch_events) {
		rc2 = afb_export_unsubscribe(callreq->export, event);
		if (rc2 < 0)
			rc = rc2;
	}
	return rc;
}

/******************************************************************************/

const struct afb_xreq_query_itf afb_calls_xreq_itf = {
	.unref = callreq_destroy_cb,
	.reply = callreq_reply_cb,
	.subscribe = callreq_subscribe_cb,
	.unsubscribe = callreq_unsubscribe_cb
};

/******************************************************************************/

static struct callreq *callreq_create(
		struct afb_export *export,
		struct afb_xreq *caller,
		const char *api,
		const char *verb,
		struct json_object *args,
		int flags,
		struct modes mode)
{
	struct callreq *callreq;
	size_t lenapi, lenverb;
	char *api2, *verb2;

	lenapi = 1 + strlen(api);
	lenverb = 1 + strlen(verb);
	callreq = malloc(lenapi + lenverb + sizeof *callreq);
	if (!callreq) {
		ERROR("out of memory");
		json_object_put(args);
		errno = ENOMEM;
	} else {
		afb_xreq_init(&callreq->xreq, &afb_calls_xreq_itf);
		callreq->xreq.context.validated = 1;
		api2 = (char*)&callreq[1];
		callreq->xreq.request.called_api = memcpy(api2, api, lenapi);;
		verb2 = &api2[lenapi];
		callreq->xreq.request.called_verb = memcpy(verb2, verb, lenverb);
		callreq->xreq.json = args;
		callreq->mode = mode;
		if (caller) {
			export = afb_export_from_api_x3(caller->request.api);
			if (flags & afb_req_x2_subcall_on_behalf)
				callreq->xreq.cred = afb_cred_addref(caller->cred);
			callreq->xreq.caller = caller;
			afb_xreq_unhooked_addref(caller);
		}
		if (caller && (flags & afb_req_x2_subcall_api_session))
			afb_context_subinit(&callreq->xreq.context, &caller->context);
		else
			afb_export_context_init(export, &callreq->xreq.context);
		callreq->export = export;
		callreq->flags = flags;
	}
	return callreq;
}

/******************************************************************************/

static int do_sync(
		struct afb_export *export,
		struct afb_xreq *caller,
		const char *api,
		const char *verb,
		struct json_object *args,
		int flags,
		struct json_object **object,
		char **error,
		char **info,
		struct modes mode)
{
	struct callreq *callreq;
	int rc;

	/* allocates the request */
	callreq = callreq_create(export, caller, api, verb, args, flags, mode);
	if (!callreq)
		goto interr;

	/* initializes the request */
	callreq->jobloop = NULL;
	callreq->returned = 0;
	callreq->status = 0;
	callreq->object = object;
	callreq->error = error;
	callreq->info = info;

	afb_xreq_unhooked_addref(&callreq->xreq); /* avoid early callreq destruction */

	rc = jobs_enter(NULL, 0, sync_enter, callreq);
	if (rc >= 0 && callreq->returned) {
		rc = callreq->status;
		afb_xreq_unhooked_unref(&callreq->xreq);
		return rc;
	}

	afb_xreq_unhooked_unref(&callreq->xreq);
interr:
	return store_reply(NULL, afb_error_text_internal_error, NULL, object, error, info);
}

/******************************************************************************/

static void do_async(
		struct afb_export *export,
		struct afb_xreq *caller,
		const char *api,
		const char *verb,
		struct json_object *args,
		int flags,
		void *callback,
		void *closure,
		void (*final)(void*, struct json_object*, const char*, const char*, union callback, struct afb_export*,struct afb_xreq*),
		struct modes mode)
{
	struct callreq *callreq;

	callreq = callreq_create(export, caller, api, verb, args, flags, mode);

	if (!callreq)
		final(closure, NULL, afb_error_text_internal_error, NULL, (union callback){ .any = callback }, export, caller);
	else {
		callreq->callback.any = callback;
		callreq->closure = closure;
		callreq->final = final;

		afb_export_process_xreq(callreq->export, &callreq->xreq);
	}
}

/******************************************************************************/

static void final_call(
	void *closure,
	struct json_object *object,
	const char *error,
	const char *info,
	union callback callback,
	struct afb_export *export,
	struct afb_xreq *caller)
{
	if (callback.call.x3)
		callback.call.x3(closure, object, error, info, afb_export_to_api_x3(export));
}

static void final_subcall(
	void *closure,
	struct json_object *object,
	const char *error,
	const char *info,
	union callback callback,
	struct afb_export *export,
	struct afb_xreq *caller)
{
	if (callback.subcall.x3)
		callback.subcall.x3(closure, object, error, info, xreq_to_req_x2(caller));
}

/******************************************************************************/

void afb_calls_call(
		struct afb_export *export,
		const char *api,
		const char *verb,
		struct json_object *args,
		void (*callback)(void*, struct json_object*, const char *error, const char *info, struct afb_api_x3*),
		void *closure)
{
	do_async(export, NULL, api, verb, args, CALLFLAGS, callback, closure, final_call, mode_async);
}

int afb_calls_call_sync(
		struct afb_export *export,
		const char *api,
		const char *verb,
		struct json_object *args,
		struct json_object **object,
		char **error,
		char **info)
{
	return do_sync(export, NULL, api, verb, args, CALLFLAGS, object, error, info, mode_sync);
}

void afb_calls_subcall(
			struct afb_xreq *xreq,
			const char *api,
			const char *verb,
			struct json_object *args,
			int flags,
			void (*callback)(void *closure, struct json_object *object, const char *error, const char * info, struct afb_req_x2 *req),
			void *closure)
{
	do_async(NULL, xreq, api, verb, args, flags, callback, closure, final_subcall, mode_async);
}

int afb_calls_subcall_sync(
			struct afb_xreq *xreq,
			const char *api,
			const char *verb,
			struct json_object *args,
			int flags,
			struct json_object **object,
			char **error,
			char **info)
{
	return do_sync(NULL, xreq, api, verb, args, flags, object, error, info, mode_sync);
}

#if WITH_AFB_HOOK
void afb_calls_hooked_call(
		struct afb_export *export,
		const char *api,
		const char *verb,
		struct json_object *args,
		void (*callback)(void*, struct json_object*, const char *error, const char *info, struct afb_api_x3*),
		void *closure)
{
	afb_hook_api_call(export, api, verb, args);
	do_async(export, NULL, api, verb, args, CALLFLAGS, callback, closure, final_call, mode_hooked_async);
}

int afb_calls_hooked_call_sync(
		struct afb_export *export,
		const char *api,
		const char *verb,
		struct json_object *args,
		struct json_object **object,
		char **error,
		char **info)
{
	afb_hook_api_callsync(export, api, verb, args);
	return do_sync(export, NULL, api, verb, args, CALLFLAGS, object, error, info, mode_hooked_sync);
}

void afb_calls_hooked_subcall(
			struct afb_xreq *xreq,
			const char *api,
			const char *verb,
			struct json_object *args,
			int flags,
			void (*callback)(void *closure, struct json_object *object, const char *error, const char * info, struct afb_req_x2 *req),
			void *closure)
{
	afb_hook_xreq_subcall(xreq, api, verb, args, flags);
	do_async(NULL, xreq, api, verb, args, flags, callback, closure, final_subcall, mode_hooked_async);
}

int afb_calls_hooked_subcall_sync(
			struct afb_xreq *xreq,
			const char *api,
			const char *verb,
			struct json_object *args,
			int flags,
			struct json_object **object,
			char **error,
			char **info)
{
	afb_hook_xreq_subcallsync(xreq, api, verb, args, flags);
	return do_sync(NULL, xreq, api, verb, args, flags, object, error, info, mode_hooked_sync);
}
#endif

/******************************************************************************/
/******************************************************************************/
/******************************************************************************/
/******************************************************************************/
/******************************************************************************/
/******************************************************************************/
/******************************************************************************/
/******************************************************************************/

static int do_legacy_sync(
		struct afb_export *export,
		struct afb_xreq *caller,
		const char *api,
		const char *verb,
		struct json_object *args,
		int flags,
		struct json_object **object,
		struct modes mode)
{
	struct callreq *callreq;
	int rc;

	/* allocates the request */
	callreq = callreq_create(export, caller, api, verb, args, flags, mode);
	if (!callreq)
		goto interr;

	/* initializes the request */
	callreq->jobloop = NULL;
	callreq->returned = 0;
	callreq->status = 0;
	callreq->object = object;

	afb_xreq_unhooked_addref(&callreq->xreq); /* avoid early callreq destruction */

	rc = jobs_enter(NULL, 0, sync_enter, callreq);
	if (rc >= 0 && callreq->returned) {
		rc = callreq->status;
		afb_xreq_unhooked_unref(&callreq->xreq);
		return rc;
	}

	afb_xreq_unhooked_unref(&callreq->xreq);
interr:
	if (object)
		*object = afb_msg_json_reply(NULL, afb_error_text_internal_error, NULL, NULL);
	return -1;
}

/******************************************************************************/

static void do_legacy_async(
		struct afb_export *export,
		struct afb_xreq *caller,
		const char *api,
		const char *verb,
		struct json_object *args,
		int flags,
		void *callback,
		void *closure,
		void (*final)(void*, int, struct json_object*, union callback, struct afb_export*,struct afb_xreq*),
		struct modes mode)
{
	struct callreq *callreq;
	struct json_object *ie;

	callreq = callreq_create(export, caller, api, verb, args, flags, mode);

	if (!callreq) {
		ie = afb_msg_json_reply(NULL, afb_error_text_internal_error, NULL, NULL);
		final(closure, -1, ie, (union callback){ .any = callback }, export, caller);
		json_object_put(ie);
	} else {
		callreq->callback.any = callback;
		callreq->closure = closure;
		callreq->legacy_final = final;

		afb_export_process_xreq(callreq->export, &callreq->xreq);
	}
}

/******************************************************************************/

static void final_legacy_call_v12(
	void *closure,
	int status,
	struct json_object *object,
	union callback callback,
	struct afb_export *export,
	struct afb_xreq *caller)
{
	if (callback.call.legacy_v12)
		callback.call.legacy_v12(closure, status, object);
}

static void final_legacy_call_v3(
	void *closure,
	int status,
	struct json_object *object,
	union callback callback,
	struct afb_export *export,
	struct afb_xreq *caller)
{
	if (callback.call.legacy_v3)
		callback.call.legacy_v3(closure, status, object, afb_export_to_api_x3(export));
}

/******************************************************************************/

void afb_calls_legacy_call_v12(
		struct afb_export *export,
		const char *api,
		const char *verb,
		struct json_object *args,
		void (*callback)(void*, int, struct json_object*),
		void *closure)
{
	do_legacy_async(export, NULL, api, verb, args, CALLFLAGS, callback, closure, final_legacy_call_v12, mode_legacy_async);
}

void afb_calls_legacy_call_v3(
		struct afb_export *export,
		const char *api,
		const char *verb,
		struct json_object *args,
		void (*callback)(void*, int, struct json_object*, struct afb_api_x3 *),
		void *closure)
{
	do_legacy_async(export, NULL, api, verb, args, CALLFLAGS, callback, closure, final_legacy_call_v3, mode_legacy_async);
}

int afb_calls_legacy_call_sync(
		struct afb_export *export,
		const char *api,
		const char *verb,
		struct json_object *args,
		struct json_object **result)
{
	return do_legacy_sync(export, NULL, api, verb, args, CALLFLAGS, result, mode_legacy_sync);
}

#if WITH_AFB_HOOK
void afb_calls_legacy_hooked_call_v12(
		struct afb_export *export,
		const char *api,
		const char *verb,
		struct json_object *args,
		void (*callback)(void*, int, struct json_object*),
		void *closure)
{
	afb_hook_api_call(export, api, verb, args);
	do_legacy_async(export, NULL, api, verb, args, CALLFLAGS, callback, closure, final_legacy_call_v12, mode_hooked_legacy_async);
}

void afb_calls_legacy_hooked_call_v3(
		struct afb_export *export,
		const char *api,
		const char *verb,
		struct json_object *args,
		void (*callback)(void*, int, struct json_object*, struct afb_api_x3 *),
		void *closure)
{
	afb_hook_api_call(export, api, verb, args);
	do_legacy_async(export, NULL, api, verb, args, CALLFLAGS, callback, closure, final_legacy_call_v3, mode_hooked_legacy_async);
}

int afb_calls_legacy_hooked_call_sync(
		struct afb_export *export,
		const char *api,
		const char *verb,
		struct json_object *args,
		struct json_object **result)
{
	int rc;
	struct json_object *object;

	afb_hook_api_callsync(export, api, verb, args);
	rc = do_legacy_sync(export, NULL, api, verb, args, CALLFLAGS, &object, mode_hooked_legacy_sync);
	if (result)
		*result = object;
	else
		json_object_put(object);
	return rc;
}
#endif

/******************************************************************************/

static void final_legacy_subcall_v1(
	void *closure,
	int status,
	struct json_object *object,
	union callback callback,
	struct afb_export *export,
	struct afb_xreq *caller)
{
	if (callback.subcall.legacy_v1)
		callback.subcall.legacy_v1(closure, status, object);
}

static void final_legacy_subcall_v2(
	void *closure,
	int status,
	struct json_object *object,
	union callback callback,
	struct afb_export *export,
	struct afb_xreq *caller)
{
	if (callback.subcall.legacy_v2)
		callback.subcall.legacy_v2(closure, status, object, xreq_to_req_x1(caller));
}

static void final_legacy_subcall_v3(
	void *closure,
	int status,
	struct json_object *object,
	union callback callback,
	struct afb_export *export,
	struct afb_xreq *caller)
{
	if (callback.subcall.legacy_v3)
		callback.subcall.legacy_v3(closure, status, object, xreq_to_req_x2(caller));
}

/******************************************************************************/

void afb_calls_legacy_subcall_v1(
		struct afb_xreq *caller,
		const char *api,
		const char *verb,
		struct json_object *args,
		void (*callback)(void*, int, struct json_object*),
		void *closure)
{
	do_legacy_async(NULL, caller, api, verb, args, LEGACY_SUBCALLFLAGS, callback, closure, final_legacy_subcall_v1, mode_legacy_async);
}

void afb_calls_legacy_subcall_v2(
		struct afb_xreq *caller,
		const char *api,
		const char *verb,
		struct json_object *args,
		void (*callback)(void*, int, struct json_object*, struct afb_req_x1),
		void *closure)
{
	do_legacy_async(NULL, caller, api, verb, args, LEGACY_SUBCALLFLAGS, callback, closure, final_legacy_subcall_v2, mode_legacy_async);
}

void afb_calls_legacy_subcall_v3(
		struct afb_xreq *caller,
		const char *api,
		const char *verb,
		struct json_object *args,
		void (*callback)(void*, int, struct json_object*, struct afb_req_x2 *),
		void *closure)
{
	do_legacy_async(NULL, caller, api, verb, args, LEGACY_SUBCALLFLAGS, callback, closure, final_legacy_subcall_v3, mode_legacy_async);
}

int afb_calls_legacy_subcall_sync(
		struct afb_xreq *caller,
		const char *api,
		const char *verb,
		struct json_object *args,
		struct json_object **result)
{
	return do_legacy_sync(NULL, caller, api, verb, args, LEGACY_SUBCALLFLAGS, result, mode_legacy_sync);
}

#if WITH_AFB_HOOK
void afb_calls_legacy_hooked_subcall_v1(
		struct afb_xreq *caller,
		const char *api,
		const char *verb,
		struct json_object *args,
		void (*callback)(void*, int, struct json_object*),
		void *closure)
{
	afb_hook_xreq_subcall(caller, api, verb, args, LEGACY_SUBCALLFLAGS);
	do_legacy_async(NULL, caller, api, verb, args, LEGACY_SUBCALLFLAGS, callback, closure, final_legacy_subcall_v1, mode_hooked_legacy_async);
}

void afb_calls_legacy_hooked_subcall_v2(
		struct afb_xreq *caller,
		const char *api,
		const char *verb,
		struct json_object *args,
		void (*callback)(void*, int, struct json_object*, struct afb_req_x1),
		void *closure)
{
	afb_hook_xreq_subcall(caller, api, verb, args, LEGACY_SUBCALLFLAGS);
	do_legacy_async(NULL, caller, api, verb, args, LEGACY_SUBCALLFLAGS, callback, closure, final_legacy_subcall_v2, mode_hooked_legacy_async);
}

void afb_calls_legacy_hooked_subcall_v3(
		struct afb_xreq *caller,
		const char *api,
		const char *verb,
		struct json_object *args,
		void (*callback)(void*, int, struct json_object*, struct afb_req_x2 *),
		void *closure)
{
	afb_hook_xreq_subcall(caller, api, verb, args, LEGACY_SUBCALLFLAGS);
	do_legacy_async(NULL, caller, api, verb, args, LEGACY_SUBCALLFLAGS, callback, closure, final_legacy_subcall_v3, mode_hooked_legacy_async);
}

int afb_calls_legacy_hooked_subcall_sync(
		struct afb_xreq *caller,
		const char *api,
		const char *verb,
		struct json_object *args,
		struct json_object **result)
{
	afb_hook_xreq_subcallsync(caller, api, verb, args, LEGACY_SUBCALLFLAGS);
	return do_legacy_sync(NULL, caller, api, verb, args, LEGACY_SUBCALLFLAGS, result, mode_hooked_legacy_sync);
}
#endif

