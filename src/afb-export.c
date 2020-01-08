/*
 * Copyright (C) 2015-2020 "IoT.bzh"
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

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fnmatch.h>
#include <ctype.h>

#include <json-c/json.h>
#if !defined(JSON_C_TO_STRING_NOSLASHESCAPE)
#define JSON_C_TO_STRING_NOSLASHESCAPE 0
#endif

#define AFB_BINDING_VERSION 0
#include <afb/afb-binding.h>

#include "afb-api.h"
#include "afb-apiset.h"
#if WITH_LEGACY_BINDING_V1
#include "afb-api-so-v1.h"
#endif
#if WITH_LEGACY_BINDING_V2
#include "afb-api-so-v2.h"
#endif
#include "afb-api-v3.h"
#include "afb-common.h"
#include "afb-evt.h"
#include "afb-export.h"
#include "afb-hook.h"
#include "afb-msg-json.h"
#include "afb-session.h"
#include "afb-xreq.h"
#include "afb-calls.h"
#include "afb-error-text.h"

#include "systemd.h"
#include "jobs.h"
#include "verbose.h"
#include "globset.h"
#include "sig-monitor.h"
#include "wrap-json.h"

/*************************************************************************
 * internal types
 ************************************************************************/

/*
 * Actually supported versions
 */
enum afb_api_version
{
	Api_Version_None = 0,
#if WITH_LEGACY_BINDING_V1
	Api_Version_1 = 1,
#endif
#if WITH_LEGACY_BINDING_V2
	Api_Version_2 = 2,
#endif
	Api_Version_3 = 3
};

/*
 * The states of exported APIs
 */
enum afb_api_state
{
	Api_State_Pre_Init,
	Api_State_Init,
	Api_State_Run
};

/*
 * structure of the exported API
 */
struct afb_export
{
	/* keep it first */
	struct afb_api_x3 api;

	/* reference count */
	int refcount;

	/* version of the api */
	unsigned version: 4;

	/* current state */
	unsigned state: 4;

	/* declared */
	unsigned declared: 1;

	/* unsealed */
	unsigned unsealed: 1;

#if WITH_AFB_HOOK
	/* hooking flags */
	int hookditf;
	int hooksvc;
#endif

	/* session for service */
	struct afb_session *session;

	/* apiset the API is declared in */
	struct afb_apiset *declare_set;

	/* apiset for calls */
	struct afb_apiset *call_set;

	/* event listener for service or NULL */
	struct afb_evt_listener *listener;

	/* event handler list */
	struct globset *event_handlers;

	/* creator if any */
	struct afb_export *creator;

	/* path indication if any */
	const char *path;

	/* settings */
	struct json_object *settings;

	/* internal descriptors */
	union {
#if WITH_LEGACY_BINDING_V1
		struct afb_binding_v1 *v1;
#endif
		const struct afb_binding_v2 *v2;
		struct afb_api_v3 *v3;
	} desc;

	/* start function */
	union {
#if WITH_LEGACY_BINDING_V1
		int (*v1)(struct afb_service_x1);
#endif
		int (*v2)();
		int (*v3)(struct afb_api_x3 *api);
	} init;

	/* event handling */
	void (*on_any_event_v12)(const char *event, struct json_object *object);
	void (*on_any_event_v3)(struct afb_api_x3 *api, const char *event, struct json_object *object);

	/* exported data */
	union {
#if WITH_LEGACY_BINDING_V1
		struct afb_binding_interface_v1 v1;
#endif
		struct afb_binding_data_v2 *v2;
	} export;

	/* initial name */
	char name[];
};

/*****************************************************************************/

static inline struct afb_api_x3 *to_api_x3(struct afb_export *export)
{
	return (struct afb_api_x3*)export;
}

static inline struct afb_export *from_api_x3(struct afb_api_x3 *api)
{
	return (struct afb_export*)api;
}

struct afb_export *afb_export_from_api_x3(struct afb_api_x3 *api)
{
	return from_api_x3(api);
}

struct afb_api_x3 *afb_export_to_api_x3(struct afb_export *export)
{
	return to_api_x3(export);
}

/******************************************************************************
 ******************************************************************************
 ******************************************************************************
 ******************************************************************************
	SETTINGS
 ******************************************************************************
 ******************************************************************************
 ******************************************************************************
 ******************************************************************************/

static struct json_object *configuration;

void afb_export_set_config(struct json_object *config)
{
	struct json_object *save = configuration;
	configuration = json_object_get(config);
	json_object_put(save);
}

static struct json_object *make_settings(struct afb_export *export)
{
	struct json_object *result;
	struct json_object *obj;
	struct afb_export *iter;
	char *path;

	/* clone the globals */
	if (json_object_object_get_ex(configuration, "*", &obj))
		result = wrap_json_clone(obj);
	else
		result = json_object_new_object();

	/* add locals */
	if (json_object_object_get_ex(configuration, export->name, &obj))
		wrap_json_object_add(result, obj);

	/* add library path */
	for (iter = export ; iter && !iter->path ; iter = iter->creator);
	if (iter) {
		path = realpath(iter->path, NULL);
		json_object_object_add(result, "binding-path", json_object_new_string(path));
		free(path);
	}

	export->settings = result;
	return result;
}

/******************************************************************************
 ******************************************************************************
 ******************************************************************************
 ******************************************************************************
                                           F R O M     D I T F
 ******************************************************************************
 ******************************************************************************
 ******************************************************************************
 ******************************************************************************/

/**********************************************
* normal flow
**********************************************/
static void vverbose_cb(struct afb_api_x3 *closure, int level, const char *file, int line, const char *function, const char *fmt, va_list args)
{
	char *p;
	struct afb_export *export = from_api_x3(closure);

	if (!fmt || vasprintf(&p, fmt, args) < 0)
		vverbose(level, file, line, function, fmt, args);
	else {
		verbose(level, file, line, function, (verbose_is_colorized() == 0 ? "[API %s] %s" : COLOR_API "[API %s]" COLOR_DEFAULT " %s"), export->api.apiname, p);
		free(p);
	}
}

static struct afb_event_x2 *event_x2_make_cb(struct afb_api_x3 *closure, const char *name)
{
	struct afb_export *export = from_api_x3(closure);

	/* check daemon state */
	if (export->state == Api_State_Pre_Init) {
		ERROR("[API %s] Bad call to 'afb_daemon_event_make(%s)', must not be in PreInit", export->api.apiname, name);
		errno = EINVAL;
		return NULL;
	}

	/* create the event */
	return afb_evt_event_x2_create2(export->api.apiname, name);
}

static int event_broadcast_cb(struct afb_api_x3 *closure, const char *name, struct json_object *object)
{
	size_t plen, nlen;
	char *event;
	struct afb_export *export = from_api_x3(closure);

	/* check daemon state */
	if (export->state == Api_State_Pre_Init) {
		ERROR("[API %s] Bad call to 'afb_daemon_event_broadcast(%s, %s)', must not be in PreInit",
			export->api.apiname, name, json_object_to_json_string_ext(object, JSON_C_TO_STRING_NOSLASHESCAPE));
		errno = EINVAL;
		return 0;
	}

	/* makes the event name */
	plen = strlen(export->api.apiname);
	nlen = strlen(name);
	event = alloca(nlen + plen + 2);
	memcpy(event, export->api.apiname, plen);
	event[plen] = '/';
	memcpy(event + plen + 1, name, nlen + 1);

	/* broadcast the event */
	return afb_evt_broadcast(event, object);
}

static struct sd_event *get_event_loop(struct afb_api_x3 *closure)
{
	jobs_acquire_event_manager();
	return systemd_get_event_loop();
}

static struct sd_bus *get_user_bus(struct afb_api_x3 *closure)
{
	jobs_acquire_event_manager();
	return systemd_get_user_bus();
}

static struct sd_bus *get_system_bus(struct afb_api_x3 *closure)
{
	jobs_acquire_event_manager();
	return systemd_get_system_bus();
}

static int rootdir_open_locale_cb(struct afb_api_x3 *closure, const char *filename, int flags, const char *locale)
{
	return afb_common_rootdir_open_locale(filename, flags, locale);
}

static int queue_job_cb(struct afb_api_x3 *closure, void (*callback)(int signum, void *arg), void *argument, void *group, int timeout)
{
	return jobs_queue(group, timeout, callback, argument);
}

static int require_api_cb(struct afb_api_x3 *closure, const char *name, int initialized)
{
	struct afb_export *export = from_api_x3(closure);
	int rc, rc2;
	char *iter, *end, save;

	/* emit a warning about unexpected require in preinit */
	if (export->state == Api_State_Pre_Init && initialized) {
		ERROR("[API %s] requiring initialized apis in pre-init is forbiden", export->api.apiname);
		errno = EINVAL;
		return -1;
	}

	/* scan the names in a local copy */
	rc = 0;
	iter = strdupa(name);
	for(;;) {
		/* skip any space */
		save = *iter;
		while(isspace(save))
			save = *++iter;
		if (!save) /* at end? */
			return rc;

		/* search for the end */
		end = iter;
		while (save && !isspace(save))
			save = *++end;
		*end = 0;

		/* check the required api */
		if (export->state == Api_State_Pre_Init) {
			rc2 = afb_apiset_require(export->declare_set, export->api.apiname, iter);
			if (rc2 < 0) {
				if (rc == 0)
					WARNING("[API %s] requiring apis pre-init may lead to unexpected result", export->api.apiname);
				ERROR("[API %s] requiring api %s in pre-init failed", export->api.apiname, iter);
			}
		} else {
			rc2 = -!((initialized ? afb_apiset_lookup_started : afb_apiset_lookup)(export->call_set, iter, 1));
			if (rc2 < 0) {
				ERROR("[API %s] requiring api %s%s failed", export->api.apiname,
					 iter, initialized ? " initialized" : "");
			}
		}
		if (rc2 < 0)
			rc = rc2;

		*end = save;
		iter = end;
	}
}

static int add_alias_cb(struct afb_api_x3 *closure, const char *apiname, const char *aliasname)
{
	struct afb_export *export = from_api_x3(closure);
	if (!afb_api_is_valid_name(aliasname)) {
		ERROR("[API %s] Can't add alias to %s: bad API name", export->api.apiname, aliasname);
		errno = EINVAL;
		return -1;
	}
	NOTICE("[API %s] aliasing [API %s] to [API %s]", export->api.apiname, apiname?:"<null>", aliasname);
	afb_export_add_alias(export, apiname, aliasname);
	return 0;
}

static struct afb_api_x3 *api_new_api_cb(
		struct afb_api_x3 *closure,
		const char *api,
		const char *info,
		int noconcurrency,
		int (*preinit)(void*, struct afb_api_x3 *),
		void *preinit_closure)
{
	struct afb_export *export = from_api_x3(closure);
	struct afb_api_v3 *apiv3 = afb_api_v3_create(
					export->declare_set, export->call_set,
					api, info, noconcurrency,
					preinit, preinit_closure, 1,
					export, NULL);
	return apiv3 ? to_api_x3(afb_api_v3_export(apiv3)) : NULL;
}

#if WITH_LEGACY_BINDING_V1 || WITH_LEGACY_BINDING_V2

static void legacy_vverbose_v1_cb(struct afb_api_x3 *closure, int level, const char *file, int line, const char *fmt, va_list args)
{
	vverbose_cb(closure, level, file, line, NULL, fmt, args);
}

static struct afb_event_x1 legacy_event_x1_make_cb(struct afb_api_x3 *closure, const char *name)
{
	struct afb_event_x2 *event = event_x2_make_cb(closure, name);
	return afb_evt_event_from_evtid(afb_evt_event_x2_to_evtid(event));
}

static struct afb_req_x1 legacy_unstore_req_cb(struct afb_api_x3 *closure, struct afb_stored_req *sreq)
{
	return afb_xreq_unstore(sreq);
}

static const struct afb_daemon_itf_x1 daemon_itf = {
	.vverbose_v1 = legacy_vverbose_v1_cb,
	.vverbose_v2 = vverbose_cb,
	.event_make = legacy_event_x1_make_cb,
	.event_broadcast = event_broadcast_cb,
	.get_event_loop = get_event_loop,
	.get_user_bus = get_user_bus,
	.get_system_bus = get_system_bus,
	.rootdir_get_fd = afb_common_rootdir_get_fd,
	.rootdir_open_locale = rootdir_open_locale_cb,
	.queue_job = queue_job_cb,
	.unstore_req = legacy_unstore_req_cb,
	.require_api = require_api_cb,
	.add_alias = add_alias_cb,
	.new_api = api_new_api_cb,
};
#endif

#if WITH_AFB_HOOK
static void hooked_vverbose_cb(struct afb_api_x3 *closure, int level, const char *file, int line, const char *function, const char *fmt, va_list args)
{
	struct afb_export *export = from_api_x3(closure);
	va_list ap;
	va_copy(ap, args);
	vverbose_cb(closure, level, file, line, function, fmt, args);
	afb_hook_api_vverbose(export, level, file, line, function, fmt, ap);
	va_end(ap);
}

static struct afb_event_x2 *hooked_event_x2_make_cb(struct afb_api_x3 *closure, const char *name)
{
	struct afb_export *export = from_api_x3(closure);
	struct afb_event_x2 *r = event_x2_make_cb(closure, name);
	afb_hook_api_event_make(export, name, r);
	return r;
}

static int hooked_event_broadcast_cb(struct afb_api_x3 *closure, const char *name, struct json_object *object)
{
	int r;
	struct afb_export *export = from_api_x3(closure);
	json_object_get(object);
	afb_hook_api_event_broadcast_before(export, name, json_object_get(object));
	r = event_broadcast_cb(closure, name, object);
	afb_hook_api_event_broadcast_after(export, name, object, r);
	json_object_put(object);
	return r;
}

static struct sd_event *hooked_get_event_loop(struct afb_api_x3 *closure)
{
	struct afb_export *export = from_api_x3(closure);
	struct sd_event *r;

	jobs_acquire_event_manager();
	r = get_event_loop(closure);
	return afb_hook_api_get_event_loop(export, r);
}

static struct sd_bus *hooked_get_user_bus(struct afb_api_x3 *closure)
{
	struct afb_export *export = from_api_x3(closure);
	struct sd_bus *r;

	jobs_acquire_event_manager();
	r = get_user_bus(closure);
	return afb_hook_api_get_user_bus(export, r);
}

static struct sd_bus *hooked_get_system_bus(struct afb_api_x3 *closure)
{
	struct afb_export *export = from_api_x3(closure);
	struct sd_bus *r;

	jobs_acquire_event_manager();
	r = get_system_bus(closure);
	return afb_hook_api_get_system_bus(export, r);
}

static int hooked_rootdir_get_fd(struct afb_api_x3 *closure)
{
	struct afb_export *export = from_api_x3(closure);
	int r = afb_common_rootdir_get_fd();
	return afb_hook_api_rootdir_get_fd(export, r);
}

static int hooked_rootdir_open_locale_cb(struct afb_api_x3 *closure, const char *filename, int flags, const char *locale)
{
	struct afb_export *export = from_api_x3(closure);
	int r = rootdir_open_locale_cb(closure, filename, flags, locale);
	return afb_hook_api_rootdir_open_locale(export, filename, flags, locale, r);
}

static int hooked_queue_job_cb(struct afb_api_x3 *closure, void (*callback)(int signum, void *arg), void *argument, void *group, int timeout)
{
	struct afb_export *export = from_api_x3(closure);
	int r = queue_job_cb(closure, callback, argument, group, timeout);
	return afb_hook_api_queue_job(export, callback, argument, group, timeout, r);
}

static int hooked_require_api_cb(struct afb_api_x3 *closure, const char *name, int initialized)
{
	int result;
	struct afb_export *export = from_api_x3(closure);
	afb_hook_api_require_api(export, name, initialized);
	result = require_api_cb(closure, name, initialized);
	return afb_hook_api_require_api_result(export, name, initialized, result);
}

static int hooked_add_alias_cb(struct afb_api_x3 *closure, const char *apiname, const char *aliasname)
{
	struct afb_export *export = from_api_x3(closure);
	int result = add_alias_cb(closure, apiname, aliasname);
	return afb_hook_api_add_alias(export, apiname, aliasname, result);
}

static struct afb_api_x3 *hooked_api_new_api_cb(
		struct afb_api_x3 *closure,
		const char *api,
		const char *info,
		int noconcurrency,
		int (*preinit)(void*, struct afb_api_x3 *),
		void *preinit_closure)
{
	struct afb_api_x3 *result;
	struct afb_export *export = from_api_x3(closure);
	afb_hook_api_new_api_before(export, api, info, noconcurrency);
	result = api_new_api_cb(closure, api, info, noconcurrency, preinit, preinit_closure);
	afb_hook_api_new_api_after(export, -!result, api);
	return result;
}

#if WITH_LEGACY_BINDING_V1 || WITH_LEGACY_BINDING_V2

static void legacy_hooked_vverbose_v1_cb(struct afb_api_x3 *closure, int level, const char *file, int line, const char *fmt, va_list args)
{
	hooked_vverbose_cb(closure, level, file, line, NULL, fmt, args);
}

static struct afb_event_x1 legacy_hooked_event_x1_make_cb(struct afb_api_x3 *closure, const char *name)
{
	struct afb_event_x2 *event = hooked_event_x2_make_cb(closure, name);
	struct afb_event_x1 e;
	e.closure = event;
	e.itf = event ? event->itf : NULL;
	return e;
}

static struct afb_req_x1 legacy_hooked_unstore_req_cb(struct afb_api_x3 *closure, struct afb_stored_req *sreq)
{
	struct afb_export *export = from_api_x3(closure);
	afb_hook_api_legacy_unstore_req(export, sreq);
	return legacy_unstore_req_cb(closure, sreq);
}

static const struct afb_daemon_itf_x1 hooked_daemon_itf = {
	.vverbose_v1 = legacy_hooked_vverbose_v1_cb,
	.vverbose_v2 = hooked_vverbose_cb,
	.event_make = legacy_hooked_event_x1_make_cb,
	.event_broadcast = hooked_event_broadcast_cb,
	.get_event_loop = hooked_get_event_loop,
	.get_user_bus = hooked_get_user_bus,
	.get_system_bus = hooked_get_system_bus,
	.rootdir_get_fd = hooked_rootdir_get_fd,
	.rootdir_open_locale = hooked_rootdir_open_locale_cb,
	.queue_job = hooked_queue_job_cb,
	.unstore_req = legacy_hooked_unstore_req_cb,
	.require_api = hooked_require_api_cb,
	.add_alias = hooked_add_alias_cb,
	.new_api = hooked_api_new_api_cb,
};
#endif

#endif

/******************************************************************************
 ******************************************************************************
 ******************************************************************************
 ******************************************************************************
                                           F R O M     S V C
 ******************************************************************************
 ******************************************************************************
 ******************************************************************************
 ******************************************************************************/

/* the common session for services sharing their session */
static struct afb_session *common_session;

/******************************************************************************
 ******************************************************************************
 ******************************************************************************
 ******************************************************************************
                                           F R O M     S V C
 ******************************************************************************
 ******************************************************************************
 ******************************************************************************
 ******************************************************************************/

static void call_x3(
		struct afb_api_x3 *apix3,
		const char *api,
		const char *verb,
		struct json_object *args,
		void (*callback)(void*, struct json_object*, const char *error, const char *info, struct afb_api_x3*),
		void *closure)
{
	struct afb_export *export = from_api_x3(apix3);
	return afb_calls_call(export, api, verb, args, callback, closure);
}

static int call_sync_x3(
		struct afb_api_x3 *apix3,
		const char *api,
		const char *verb,
		struct json_object *args,
		struct json_object **object,
		char **error,
		char **info)
{
	struct afb_export *export = from_api_x3(apix3);
	return afb_calls_call_sync(export, api, verb, args, object, error, info);
}

static void legacy_call_x3(
		struct afb_api_x3 *apix3,
		const char *api,
		const char *verb,
		struct json_object *args,
		void (*callback)(void*, int, struct json_object*, struct afb_api_x3*),
		void *closure)
{
	struct afb_export *export = from_api_x3(apix3);
	afb_calls_legacy_call_v3(export, api, verb, args, callback, closure);
}

static int legacy_call_sync(
		struct afb_api_x3 *apix3,
		const char *api,
		const char *verb,
		struct json_object *args,
		struct json_object **result)
{
	struct afb_export *export = from_api_x3(apix3);
	return afb_calls_legacy_call_sync(export, api, verb, args, result);
}

#if WITH_LEGACY_BINDING_V1 || WITH_LEGACY_BINDING_V2

static void legacy_call_v12(
		struct afb_api_x3 *apix3,
		const char *api,
		const char *verb,
		struct json_object *args,
		void (*callback)(void*, int, struct json_object*),
		void *closure)
{
	struct afb_export *export = from_api_x3(apix3);
	afb_calls_legacy_call_v12(export, api, verb, args, callback, closure);
}

/* the interface for services */
static const struct afb_service_itf_x1 service_itf = {
	.call = legacy_call_v12,
	.call_sync = legacy_call_sync
};
#endif

#if WITH_AFB_HOOK
static void hooked_call_x3(
		struct afb_api_x3 *apix3,
		const char *api,
		const char *verb,
		struct json_object *args,
		void (*callback)(void*, struct json_object*, const char*, const char*, struct afb_api_x3*),
		void *closure)
{
	struct afb_export *export = from_api_x3(apix3);
	afb_calls_hooked_call(export, api, verb, args, callback, closure);
}

static int hooked_call_sync_x3(
		struct afb_api_x3 *apix3,
		const char *api,
		const char *verb,
		struct json_object *args,
		struct json_object **object,
		char **error,
		char **info)
{
	struct afb_export *export = from_api_x3(apix3);
	return afb_calls_hooked_call_sync(export, api, verb, args, object, error, info);
}

static void legacy_hooked_call_x3(
		struct afb_api_x3 *apix3,
		const char *api,
		const char *verb,
		struct json_object *args,
		void (*callback)(void*, int, struct json_object*, struct afb_api_x3*),
		void *closure)
{
	struct afb_export *export = from_api_x3(apix3);
	afb_calls_legacy_hooked_call_v3(export, api, verb, args, callback, closure);
}

static int legacy_hooked_call_sync(
		struct afb_api_x3 *apix3,
		const char *api,
		const char *verb,
		struct json_object *args,
		struct json_object **result)
{
	struct afb_export *export = from_api_x3(apix3);
	return afb_calls_legacy_hooked_call_sync(export, api, verb, args, result);
}

#if WITH_LEGACY_BINDING_V1 || WITH_LEGACY_BINDING_V2

static void legacy_hooked_call_v12(
		struct afb_api_x3 *apix3,
		const char *api,
		const char *verb,
		struct json_object *args,
		void (*callback)(void*, int, struct json_object*),
		void *closure)
{
	struct afb_export *export = from_api_x3(apix3);
	afb_calls_legacy_hooked_call_v12(export, api, verb, args, callback, closure);
}

/* the interface for services */
static const struct afb_service_itf_x1 hooked_service_itf = {
	.call = legacy_hooked_call_v12,
	.call_sync = legacy_hooked_call_sync
};
#endif

#endif

/******************************************************************************
 ******************************************************************************
 ******************************************************************************
 ******************************************************************************
                                           F R O M     D Y N A P I
 ******************************************************************************
 ******************************************************************************
 ******************************************************************************
 ******************************************************************************/

static int api_set_verbs_v2_cb(
		struct afb_api_x3 *api,
		const struct afb_verb_v2 *verbs)
{
#if WITH_LEGACY_BINDING_V2
	struct afb_export *export = from_api_x3(api);

	if (export->unsealed) {
		afb_api_v3_set_verbs_v2(export->desc.v3, verbs);
		return 0;
	}

	errno = EPERM;
#else
	errno = ECANCELED;
#endif
	return -1;
}

static int api_set_verbs_v3_cb(
		struct afb_api_x3 *api,
		const struct afb_verb_v3 *verbs)
{
	struct afb_export *export = from_api_x3(api);

	if (!export->unsealed) {
		errno = EPERM;
		return -1;
	}

	afb_api_v3_set_verbs_v3(export->desc.v3, verbs);
	return 0;
}

static int api_add_verb_cb(
		struct afb_api_x3 *api,
		const char *verb,
		const char *info,
		void (*callback)(struct afb_req_x2 *req),
		void *vcbdata,
		const struct afb_auth *auth,
		uint32_t session,
		int glob)
{
	struct afb_export *export = from_api_x3(api);

	if (!export->unsealed) {
		errno = EPERM;
		return -1;
	}

	return afb_api_v3_add_verb(export->desc.v3, verb, info, callback, vcbdata, auth, (uint16_t)session, glob);
}

static int api_del_verb_cb(
		struct afb_api_x3 *api,
		const char *verb,
		void **vcbdata)
{
	struct afb_export *export = from_api_x3(api);

	if (!export->unsealed) {
		errno = EPERM;
		return -1;
	}

	return afb_api_v3_del_verb(export->desc.v3, verb, vcbdata);
}

static int api_set_on_event_cb(
		struct afb_api_x3 *api,
		void (*onevent)(struct afb_api_x3 *api, const char *event, struct json_object *object))
{
	struct afb_export *export = from_api_x3(api);
	return afb_export_handle_events_v3(export, onevent);
}

static int api_set_on_init_cb(
		struct afb_api_x3 *api,
		int (*oninit)(struct afb_api_x3 *api))
{
	struct afb_export *export = from_api_x3(api);

	return afb_export_handle_init_v3(export, oninit);
}

static void api_seal_cb(
		struct afb_api_x3 *api)
{
	struct afb_export *export = from_api_x3(api);

	export->unsealed = 0;
}

static int event_handler_add_cb(
		struct afb_api_x3 *api,
		const char *pattern,
		void (*callback)(void *, const char*, struct json_object*, struct afb_api_x3*),
		void *closure)
{
	struct afb_export *export = from_api_x3(api);

	return afb_export_event_handler_add(export, pattern, callback, closure);
}

static int event_handler_del_cb(
		struct afb_api_x3 *api,
		const char *pattern,
		void **closure)
{
	struct afb_export *export = from_api_x3(api);

	return afb_export_event_handler_del(export, pattern, closure);
}

static int class_provide_cb(struct afb_api_x3 *api, const char *name)
{
	struct afb_export *export = from_api_x3(api);

	int rc = 0, rc2;
	char *iter, *end, save;

	iter = strdupa(name);
	for(;;) {
		/* skip any space */
		save = *iter;
		while(isspace(save))
			save = *++iter;
		if (!save) /* at end? */
			return rc;

		/* search for the end */
		end = iter;
		while (save && !isspace(save))
			save = *++end;
		*end = 0;

		rc2 = afb_apiset_provide_class(export->declare_set, api->apiname, iter);
		if (rc2 < 0)
			rc = rc2;

		*end = save;
		iter = end;
	}
}

static int class_require_cb(struct afb_api_x3 *api, const char *name)
{
	struct afb_export *export = from_api_x3(api);

	int rc = 0, rc2;
	char *iter, *end, save;

	iter = strdupa(name);
	for(;;) {
		/* skip any space */
		save = *iter;
		while(isspace(save))
			save = *++iter;
		if (!save) /* at end? */
			return rc;

		/* search for the end */
		end = iter;
		while (save && !isspace(save))
			save = *++end;
		*end = 0;

		rc2 = afb_apiset_require_class(export->declare_set, api->apiname, iter);
		if (rc2 < 0)
			rc = rc2;

		*end = save;
		iter = end;
	}
}

static int delete_api_cb(struct afb_api_x3 *api)
{
	struct afb_export *export = from_api_x3(api);

	if (!export->unsealed) {
		errno = EPERM;
		return -1;
	}

	afb_export_undeclare(export);
	afb_export_unref(export);
	return 0;
}

static struct json_object *settings_cb(struct afb_api_x3 *api)
{
	struct afb_export *export = from_api_x3(api);
	struct json_object *result = export->settings;
	if (!result)
		result = make_settings(export);
	return result;
}

static const struct afb_api_x3_itf api_x3_itf = {

	.vverbose = (void*)vverbose_cb,

	.get_event_loop = get_event_loop,
	.get_user_bus = get_user_bus,
	.get_system_bus = get_system_bus,
	.rootdir_get_fd = afb_common_rootdir_get_fd,
	.rootdir_open_locale = rootdir_open_locale_cb,
	.queue_job = queue_job_cb,

	.require_api = require_api_cb,
	.add_alias = add_alias_cb,

	.event_broadcast = event_broadcast_cb,
	.event_make = event_x2_make_cb,

	.legacy_call = legacy_call_x3,
	.legacy_call_sync = legacy_call_sync,

	.api_new_api = api_new_api_cb,
	.api_set_verbs_v2 = api_set_verbs_v2_cb,
	.api_add_verb = api_add_verb_cb,
	.api_del_verb = api_del_verb_cb,
	.api_set_on_event = api_set_on_event_cb,
	.api_set_on_init = api_set_on_init_cb,
	.api_seal = api_seal_cb,
	.api_set_verbs_v3 = api_set_verbs_v3_cb,
	.event_handler_add = event_handler_add_cb,
	.event_handler_del = event_handler_del_cb,

	.call = call_x3,
	.call_sync = call_sync_x3,

	.class_provide = class_provide_cb,
	.class_require = class_require_cb,

	.delete_api = delete_api_cb,
	.settings = settings_cb,
};

#if WITH_AFB_HOOK
static int hooked_api_set_verbs_v2_cb(
		struct afb_api_x3 *api,
		const struct afb_verb_v2 *verbs)
{
	struct afb_export *export = from_api_x3(api);
	int result = api_set_verbs_v2_cb(api, verbs);
	return afb_hook_api_api_set_verbs_v2(export, result, verbs);
}

static int hooked_api_set_verbs_v3_cb(
		struct afb_api_x3 *api,
		const struct afb_verb_v3 *verbs)
{
	struct afb_export *export = from_api_x3(api);
	int result = api_set_verbs_v3_cb(api, verbs);
	return afb_hook_api_api_set_verbs_v3(export, result, verbs);
}

static int hooked_api_add_verb_cb(
		struct afb_api_x3 *api,
		const char *verb,
		const char *info,
		void (*callback)(struct afb_req_x2 *req),
		void *vcbdata,
		const struct afb_auth *auth,
		uint32_t session,
		int glob)
{
	struct afb_export *export = from_api_x3(api);
	int result = api_add_verb_cb(api, verb, info, callback, vcbdata, auth, session, glob);
	return afb_hook_api_api_add_verb(export, result, verb, info, glob);
}

static int hooked_api_del_verb_cb(
		struct afb_api_x3 *api,
		const char *verb,
		void **vcbdata)
{
	struct afb_export *export = from_api_x3(api);
	int result = api_del_verb_cb(api, verb, vcbdata);
	return afb_hook_api_api_del_verb(export, result, verb);
}

static int hooked_api_set_on_event_cb(
		struct afb_api_x3 *api,
		void (*onevent)(struct afb_api_x3 *api, const char *event, struct json_object *object))
{
	struct afb_export *export = from_api_x3(api);
	int result = api_set_on_event_cb(api, onevent);
	return afb_hook_api_api_set_on_event(export, result);
}

static int hooked_api_set_on_init_cb(
		struct afb_api_x3 *api,
		int (*oninit)(struct afb_api_x3 *api))
{
	struct afb_export *export = from_api_x3(api);
	int result = api_set_on_init_cb(api, oninit);
	return afb_hook_api_api_set_on_init(export, result);
}

static void hooked_api_seal_cb(
		struct afb_api_x3 *api)
{
	struct afb_export *export = from_api_x3(api);
	afb_hook_api_api_seal(export);
	api_seal_cb(api);
}

static int hooked_event_handler_add_cb(
		struct afb_api_x3 *api,
		const char *pattern,
		void (*callback)(void *, const char*, struct json_object*, struct afb_api_x3*),
		void *closure)
{
	struct afb_export *export = from_api_x3(api);
	int result = event_handler_add_cb(api, pattern, callback, closure);
	return afb_hook_api_event_handler_add(export, result, pattern);
}

static int hooked_event_handler_del_cb(
		struct afb_api_x3 *api,
		const char *pattern,
		void **closure)
{
	struct afb_export *export = from_api_x3(api);
	int result = event_handler_del_cb(api, pattern, closure);
	return afb_hook_api_event_handler_del(export, result, pattern);
}

static int hooked_class_provide_cb(struct afb_api_x3 *api, const char *name)
{
	struct afb_export *export = from_api_x3(api);
	int result = class_provide_cb(api, name);
	return afb_hook_api_class_provide(export, result, name);
}

static int hooked_class_require_cb(struct afb_api_x3 *api, const char *name)
{
	struct afb_export *export = from_api_x3(api);
	int result = class_require_cb(api, name);
	return afb_hook_api_class_require(export, result, name);
}

static int hooked_delete_api_cb(struct afb_api_x3 *api)
{
	struct afb_export *export = afb_export_addref(from_api_x3(api));
	int result = delete_api_cb(api);
	result = afb_hook_api_delete_api(export, result);
	afb_export_unref(export);
	return result;
}

static struct json_object *hooked_settings_cb(struct afb_api_x3 *api)
{
	struct afb_export *export = from_api_x3(api);
	struct json_object *result = settings_cb(api);
	result = afb_hook_api_settings(export, result);
	return result;
}

static const struct afb_api_x3_itf hooked_api_x3_itf = {

	.vverbose = hooked_vverbose_cb,

	.get_event_loop = hooked_get_event_loop,
	.get_user_bus = hooked_get_user_bus,
	.get_system_bus = hooked_get_system_bus,
	.rootdir_get_fd = hooked_rootdir_get_fd,
	.rootdir_open_locale = hooked_rootdir_open_locale_cb,
	.queue_job = hooked_queue_job_cb,

	.require_api = hooked_require_api_cb,
	.add_alias = hooked_add_alias_cb,

	.event_broadcast = hooked_event_broadcast_cb,
	.event_make = hooked_event_x2_make_cb,

	.legacy_call = legacy_hooked_call_x3,
	.legacy_call_sync = legacy_hooked_call_sync,

	.api_new_api = hooked_api_new_api_cb,
	.api_set_verbs_v2 = hooked_api_set_verbs_v2_cb,
	.api_add_verb = hooked_api_add_verb_cb,
	.api_del_verb = hooked_api_del_verb_cb,
	.api_set_on_event = hooked_api_set_on_event_cb,
	.api_set_on_init = hooked_api_set_on_init_cb,
	.api_seal = hooked_api_seal_cb,
	.api_set_verbs_v3 = hooked_api_set_verbs_v3_cb,
	.event_handler_add = hooked_event_handler_add_cb,
	.event_handler_del = hooked_event_handler_del_cb,

	.call = hooked_call_x3,
	.call_sync = hooked_call_sync_x3,

	.class_provide = hooked_class_provide_cb,
	.class_require = hooked_class_require_cb,

	.delete_api = hooked_delete_api_cb,
	.settings = hooked_settings_cb,
};
#endif

/******************************************************************************
 ******************************************************************************
 ******************************************************************************
 ******************************************************************************
                      L I S T E N E R S
 ******************************************************************************
 ******************************************************************************
 ******************************************************************************
 ******************************************************************************/

/*
 * Propagates the event to the service
 */
static void listener_of_events(void *closure, const char *event, uint16_t eventid, struct json_object *object)
{
	const struct globset_handler *handler;
	void (*callback)(void *, const char*, struct json_object*, struct afb_api_x3*);
	struct afb_export *export = from_api_x3(closure);

#if WITH_AFB_HOOK
	/* hook the event before */
	if (export->hooksvc & afb_hook_flag_api_on_event)
		afb_hook_api_on_event_before(export, event, eventid, object);
#endif

	/* transmit to specific handlers */
	/* search the handler */
	handler = export->event_handlers ? globset_match(export->event_handlers, event) : NULL;
	if (handler) {
		callback = handler->callback;
#if WITH_AFB_HOOK
		if (!(export->hooksvc & afb_hook_flag_api_on_event_handler))
#endif
			callback(handler->closure, event, object, to_api_x3(export));
#if WITH_AFB_HOOK
		else {
			afb_hook_api_on_event_handler_before(export, event, eventid, object, handler->pattern);
			callback(handler->closure, event, object, to_api_x3(export));
			afb_hook_api_on_event_handler_after(export, event, eventid, object, handler->pattern);
		}
#endif
	} else {
		/* transmit to default handler */
		if (export->on_any_event_v3)
			export->on_any_event_v3(to_api_x3(export), event, object);
		else if (export->on_any_event_v12)
			export->on_any_event_v12(event, object);
	}

#if WITH_AFB_HOOK
	/* hook the event after */
	if (export->hooksvc & afb_hook_flag_api_on_event)
		afb_hook_api_on_event_after(export, event, eventid, object);
#endif
	json_object_put(object);
}

static void listener_of_pushed_events(void *closure, const char *event, uint16_t eventid, struct json_object *object)
{
	listener_of_events(closure, event, eventid, object);
}

static void listener_of_broadcasted_events(void *closure, const char *event, struct json_object *object, const uuid_binary_t uuid, uint8_t hop)
{
	listener_of_events(closure, event, 0, object);
}

/* the interface for events */
static const struct afb_evt_itf evt_itf = {
	.broadcast = listener_of_broadcasted_events,
	.push = listener_of_pushed_events
};

/* ensure an existing listener */
static int ensure_listener(struct afb_export *export)
{
	if (!export->listener) {
		export->listener = afb_evt_listener_create(&evt_itf, export);
		if (export->listener == NULL)
			return -1;
	}
	return 0;
}

int afb_export_event_handler_add(
			struct afb_export *export,
			const char *pattern,
			void (*callback)(void *, const char*, struct json_object*, struct afb_api_x3*),
			void *closure)
{
	int rc;

	/* ensure the listener */
	rc = ensure_listener(export);
	if (rc < 0)
		return rc;

	/* ensure the globset for event handling */
	if (!export->event_handlers) {
		export->event_handlers = globset_create();
		if (!export->event_handlers)
			goto oom_error;
	}

	/* add the handler */
	rc = globset_add(export->event_handlers, pattern, callback, closure);
	if (rc == 0)
		return 0;

	if (errno == EEXIST) {
		ERROR("[API %s] event handler %s already exists", export->api.apiname, pattern);
		return -1;
	}

oom_error:
	ERROR("[API %s] can't allocate event handler %s", export->api.apiname, pattern);
	return -1;
}

int afb_export_event_handler_del(
			struct afb_export *export,
			const char *pattern,
			void **closure)
{
	if (export->event_handlers
	&& !globset_del(export->event_handlers, pattern, closure))
		return 0;

	ERROR("[API %s] event handler %s not found", export->api.apiname, pattern);
	errno = ENOENT;
	return -1;
}

/******************************************************************************
 ******************************************************************************
 ******************************************************************************
 ******************************************************************************
                                           M E R G E D
 ******************************************************************************
 ******************************************************************************
 ******************************************************************************
 ******************************************************************************/

static void set_interfaces(struct afb_export *export)
{
#if WITH_AFB_HOOK
	export->hookditf = afb_hook_flags_api(export->api.apiname);
	export->hooksvc = afb_hook_flags_api(export->api.apiname);
	export->api.itf = export->hookditf|export->hooksvc ? &hooked_api_x3_itf : &api_x3_itf;

	switch (export->version) {
#if WITH_LEGACY_BINDING_V1
	case Api_Version_1:
		export->export.v1.daemon.itf = export->hookditf ? &hooked_daemon_itf : &daemon_itf;
		break;
#endif
#if WITH_LEGACY_BINDING_V2
	case Api_Version_2:
		export->export.v2->daemon.itf = export->hookditf ? &hooked_daemon_itf : &daemon_itf;
		export->export.v2->service.itf = export->hooksvc ? &hooked_service_itf : &service_itf;
		break;
#endif
	}
#else

	export->api.itf = &api_x3_itf;

	switch (export->version) {
#if WITH_LEGACY_BINDING_V1
	case Api_Version_1:
		export->export.v1.daemon.itf = &daemon_itf;
		break;
#endif
#if WITH_LEGACY_BINDING_V2
	case Api_Version_2:
		export->export.v2->daemon.itf = &daemon_itf;
		export->export.v2->service.itf = &service_itf;
		break;
#endif
	}

#endif
}

static struct afb_export *create(
				struct afb_apiset *declare_set,
				struct afb_apiset *call_set,
				const char *apiname,
				const char *path,
				enum afb_api_version version)
{
	struct afb_export *export;
	size_t lenapi;

	/* session shared with other exports */
	if (common_session == NULL) {
		common_session = afb_session_create (0);
		if (common_session == NULL)
			return NULL;
	}
	lenapi = strlen(apiname);
	export = calloc(1, sizeof *export + 1 + lenapi + (path == apiname || !path ? 0 : 1 + strlen(path)));
	if (!export)
		errno = ENOMEM;
	else {
		export->refcount = 1;
		strcpy(export->name, apiname);
		export->api.apiname = export->name;
		if (path == apiname)
			export->path = export->name;
		else if (path)
			export->path = strcpy(&export->name[lenapi + 1], path);
		export->version = version;
		export->state = Api_State_Pre_Init;
		export->session = afb_session_addref(common_session);
		export->declare_set = afb_apiset_addref(declare_set);
		export->call_set = afb_apiset_addref(call_set);
	}
	return export;
}

struct afb_export *afb_export_addref(struct afb_export *export)
{
	if (export)
		__atomic_add_fetch(&export->refcount, 1, __ATOMIC_RELAXED);
	return export;
}

void afb_export_unref(struct afb_export *export)
{
	if (export && !__atomic_sub_fetch(&export->refcount, 1, __ATOMIC_RELAXED))
		afb_export_destroy(export);
}

void afb_export_destroy(struct afb_export *export)
{
	if (export) {
		if (export->event_handlers)
			globset_destroy(export->event_handlers);
		if (export->listener != NULL)
			afb_evt_listener_unref(export->listener);
		afb_session_unref(export->session);
		afb_apiset_unref(export->declare_set);
		afb_apiset_unref(export->call_set);
		json_object_put(export->settings);
		afb_export_unref(export->creator);
		if (export->api.apiname != export->name)
			free((void*)export->api.apiname);
		free(export);
	}
}

struct afb_export *afb_export_create_none_for_path(
			struct afb_apiset *declare_set,
			struct afb_apiset *call_set,
			const char *path,
			int (*creator)(void*, struct afb_api_x3*),
			void *closure)
{
	struct afb_export *export = create(declare_set, call_set, path, path, Api_Version_None);
	if (export) {
		afb_export_logmask_set(export, logmask);
		set_interfaces(export);
		if (creator && creator(closure, to_api_x3(export)) < 0) {
			afb_export_unref(export);
			export = NULL;
		}
	}
	return export;
}

#if WITH_LEGACY_BINDING_V1
struct afb_export *afb_export_create_v1(struct afb_apiset *declare_set,
			struct afb_apiset *call_set,
			const char *apiname,
			int (*init)(struct afb_service_x1),
			void (*onevent)(const char*, struct json_object*),
			const char* path)
{
	struct afb_export *export = create(declare_set, call_set, apiname, path, Api_Version_1);
	if (export) {
		export->init.v1 = init;
		export->on_any_event_v12 = onevent;
		export->export.v1.mode = AFB_MODE_LOCAL;
		export->export.v1.daemon.closure = to_api_x3(export);
		afb_export_logmask_set(export, logmask);
		set_interfaces(export);
	}
	return export;
}
#endif

#if WITH_LEGACY_BINDING_V2
struct afb_export *afb_export_create_v2(struct afb_apiset *declare_set,
			struct afb_apiset *call_set,
			const char *apiname,
			const struct afb_binding_v2 *binding,
			struct afb_binding_data_v2 *data,
			int (*init)(),
			void (*onevent)(const char*, struct json_object*),
			const char* path)
{
	struct afb_export *export = create(declare_set, call_set, apiname, path, Api_Version_2);
	if (export) {
		export->init.v2 = init;
		export->on_any_event_v12 = onevent;
		export->desc.v2 = binding;
		export->export.v2 = data;
		data->daemon.closure = to_api_x3(export);
		data->service.closure = to_api_x3(export);
		afb_export_logmask_set(export, logmask);
		set_interfaces(export);
	}
	return export;
}
#endif

struct afb_export *afb_export_create_v3(struct afb_apiset *declare_set,
			struct afb_apiset *call_set,
			const char *apiname,
			struct afb_api_v3 *apiv3,
			struct afb_export* creator,
			const char* path)
{
	struct afb_export *export = create(declare_set, call_set, apiname, path, Api_Version_3);
	if (export) {
		export->unsealed = 1;
		export->desc.v3 = apiv3;
		export->creator = afb_export_addref(creator);
		afb_export_logmask_set(export, logmask);
		set_interfaces(export);
	}
	return export;
}

int afb_export_add_alias(struct afb_export *export, const char *apiname, const char *aliasname)
{
	return afb_apiset_add_alias(export->declare_set, apiname ?: export->api.apiname, aliasname);
}

int afb_export_rename(struct afb_export *export, const char *apiname)
{
	char *name;

	if (export->declared) {
		errno = EBUSY;
		return -1;
	}

	/* copy the name locally */
	name = strdup(apiname);
	if (!name) {
		errno = ENOMEM;
		return -1;
	}

	if (export->api.apiname != export->name)
		free((void*)export->api.apiname);
	export->api.apiname = name;

	set_interfaces(export);
	return 0;
}

const char *afb_export_apiname(const struct afb_export *export)
{
	return export->api.apiname;
}

int afb_export_unshare_session(struct afb_export *export)
{
	if (export->session == common_session) {
		export->session = afb_session_create (0);
		if (export->session)
			afb_session_unref(common_session);
		else {
			export->session = common_session;
			return -1;
		}
	}
	return 0;
}

#if WITH_LEGACY_BINDING_V1 || WITH_LEGACY_BINDING_V2
int afb_export_handle_events_v12(struct afb_export *export, void (*on_event)(const char *event, struct json_object *object))
{
	/* check version */
	switch (export->version) {
#if WITH_LEGACY_BINDING_V1
	case Api_Version_1:
#endif
#if WITH_LEGACY_BINDING_V2
	case Api_Version_2:
		break;
#endif
	default:
		ERROR("invalid version 12 for API %s", export->api.apiname);
		errno = EINVAL;
		return -1;
	}

	export->on_any_event_v12 = on_event;
	return ensure_listener(export);
}
#endif

int afb_export_handle_events_v3(struct afb_export *export, void (*on_event)(struct afb_api_x3 *api, const char *event, struct json_object *object))
{
	/* check version */
	switch (export->version) {
	case Api_Version_3: break;
	default:
		ERROR("invalid version Dyn for API %s", export->api.apiname);
		errno = EINVAL;
		return -1;
	}

	export->on_any_event_v3 = on_event;
	return ensure_listener(export);
}

int afb_export_handle_init_v3(struct afb_export *export, int (*oninit)(struct afb_api_x3 *api))
{
	if (export->state != Api_State_Pre_Init) {
		ERROR("[API %s] Bad call to 'afb_api_x3_on_init', must be in PreInit", export->api.apiname);
		errno = EINVAL;
		return -1;
	}

	export->init.v3  = oninit;
	return 0;
}

#if WITH_LEGACY_BINDING_V1
/*
 * Starts a new service (v1)
 */
struct afb_binding_v1 *afb_export_register_v1(struct afb_export *export, struct afb_binding_v1 *(*regfun)(const struct afb_binding_interface_v1*))
{
	return export->desc.v1 = regfun(&export->export.v1);
}
#endif

int afb_export_preinit_x3(
		struct afb_export *export,
		int (*preinit)(void*, struct afb_api_x3*),
		void *closure)
{
	return preinit(closure, to_api_x3(export));
}

int afb_export_logmask_get(const struct afb_export *export)
{
	return export->api.logmask;
}

void afb_export_logmask_set(struct afb_export *export, int mask)
{
	export->api.logmask = mask;
	switch (export->version) {
#if WITH_LEGACY_BINDING_V1
	case Api_Version_1: export->export.v1.verbosity = verbosity_from_mask(mask); break;
#endif
#if WITH_LEGACY_BINDING_V2
	case Api_Version_2: export->export.v2->verbosity = verbosity_from_mask(mask); break;
#endif
	}
}

void *afb_export_userdata_get(const struct afb_export *export)
{
	return export->api.userdata;
}

void afb_export_userdata_set(struct afb_export *export, void *data)
{
	export->api.userdata = data;
}

/******************************************************************************
 ******************************************************************************
 ******************************************************************************
 ******************************************************************************
                                           N E W
 ******************************************************************************
 ******************************************************************************
 ******************************************************************************
 ******************************************************************************/

struct init
{
	int return_code;
	struct afb_export *export;
};

static void do_init(int sig, void *closure)
{
	int rc = -1;
	struct init *init = closure;
	struct afb_export *export;

	if (sig)
		errno = EFAULT;
	else {
		export = init->export;
		switch (export->version) {
#if WITH_LEGACY_BINDING_V1
		case Api_Version_1:
			rc = export->init.v1 ? export->init.v1(
				(struct afb_service_x1){
#if WITH_AFB_HOOK
					.itf = &hooked_service_itf,
#else
					.itf = &service_itf,
#endif
					.closure = to_api_x3(export) }) : 0;
			break;
#endif
#if WITH_LEGACY_BINDING_V2
		case Api_Version_2:
			rc = export->init.v2 ? export->init.v2() : 0;
			break;
#endif
		case Api_Version_3:
			rc = export->init.v3 ? export->init.v3(to_api_x3(export)) : 0;
			break;
		default:
			errno = EINVAL;
			break;
		}
	}
	init->return_code = rc;
};


int afb_export_start(struct afb_export *export)
{
	struct init init;
	int rc;

	/* check state */
	switch (export->state) {
	case Api_State_Run:
		return 0;

	case Api_State_Init:
		/* starting in progress: it is an error */
		ERROR("Service of API %s required started while starting", export->api.apiname);
		return -1;

	default:
		break;
	}

	/* set event handling */
#if WITH_LEGACY_BINDING_V1 || WITH_LEGACY_BINDING_V2
	switch (export->version) {
#if WITH_LEGACY_BINDING_V1
	case Api_Version_1:
#endif
#if WITH_LEGACY_BINDING_V2
	case Api_Version_2:
#endif
		if (export->on_any_event_v12) {
			rc = afb_export_handle_events_v12(export, export->on_any_event_v12);
			break;
		}
		/*@fallthrough@*/
	default:
		rc = 0;
		break;
	}
	if (rc < 0) {
		ERROR("Can't set event handler for %s", export->api.apiname);
		return -1;
	}
#endif

#if WITH_AFB_HOOK
	/* Starts the service */
	if (export->hooksvc & afb_hook_flag_api_start)
		afb_hook_api_start_before(export);
#endif

	export->state = Api_State_Init;
	init.export = export;
	sig_monitor(0, do_init, &init);
	rc = init.return_code;
	export->state = Api_State_Run;

#if WITH_AFB_HOOK
	if (export->hooksvc & afb_hook_flag_api_start)
		afb_hook_api_start_after(export, rc);
#endif

	if (rc < 0) {
		/* initialisation error */
		ERROR("Initialisation of service API %s failed (%d): %m", export->api.apiname, rc);
		return rc;
	}

	return 0;
}

static void api_call_cb(void *closure, struct afb_xreq *xreq)
{
	struct afb_export *export = closure;

	xreq->request.api = to_api_x3(export);

	switch (export->version) {
#if WITH_LEGACY_BINDING_V1
	case Api_Version_1:
		afb_api_so_v1_process_call(export->desc.v1, xreq);
		break;
#endif
#if WITH_LEGACY_BINDING_V2
	case Api_Version_2:
		afb_api_so_v2_process_call(export->desc.v2, xreq);
		break;
#endif
	case Api_Version_3:
		afb_api_v3_process_call(export->desc.v3, xreq);
		break;
	default:
		afb_xreq_reply(xreq, NULL, afb_error_text_internal_error, NULL);
		break;
	}
}

static void api_describe_cb(void *closure, void (*describecb)(void *, struct json_object *), void *clocb)
{
	struct afb_export *export = closure;
	struct json_object *result;

	switch (export->version) {
#if WITH_LEGACY_BINDING_V1
	case Api_Version_1:
		result = afb_api_so_v1_make_description_openAPIv3(export->desc.v1, export->api.apiname);
		break;
#endif
#if WITH_LEGACY_BINDING_V2
	case Api_Version_2:
		result = afb_api_so_v2_make_description_openAPIv3(export->desc.v2, export->api.apiname);
		break;
#endif
	case Api_Version_3:
		result = afb_api_v3_make_description_openAPIv3(export->desc.v3, export->api.apiname);
		break;
	default:
		result = NULL;
		break;
	}
	describecb(clocb, result);
}

static int api_service_start_cb(void *closure)
{
	struct afb_export *export = closure;

	return afb_export_start(export);
}

#if WITH_AFB_HOOK
static void api_update_hooks_cb(void *closure)
	__attribute__((alias("set_interfaces")));

void afb_export_update_hooks(struct afb_export *export)
	__attribute__((alias("set_interfaces")));
#endif

static int api_get_logmask_cb(void *closure)
{
	struct afb_export *export = closure;

	return afb_export_logmask_get(export);
}

static void api_set_logmask_cb(void *closure, int level)
{
	struct afb_export *export = closure;

	afb_export_logmask_set(export, level);
}

static void api_unref_cb(void *closure)
{
	struct afb_export *export = closure;

	afb_export_unref(export);
}

static struct afb_api_itf export_api_itf =
{
	.call = api_call_cb,
	.service_start = api_service_start_cb,
#if WITH_AFB_HOOK
	.update_hooks = api_update_hooks_cb,
#endif
	.get_logmask = api_get_logmask_cb,
	.set_logmask = api_set_logmask_cb,
	.describe = api_describe_cb,
	.unref = api_unref_cb
};

int afb_export_declare(struct afb_export *export,
			int noconcurrency)
{
	int rc;
	struct afb_api_item afb_api;

	if (export->declared)
		rc = 0;
	else {
		/* init the record structure */
		afb_api.closure = afb_export_addref(export);
		afb_api.itf = &export_api_itf;
		afb_api.group = noconcurrency ? export : NULL;

		/* records the binding */
		rc = afb_apiset_add(export->declare_set, export->api.apiname, afb_api);
		if (rc >= 0)
			export->declared = 1;
		else {
			ERROR("can't declare export %s to set %s, ABORTING it!",
				export->api.apiname,
				afb_apiset_name(export->declare_set));
			afb_export_unref(export);
		}
	}

	return rc;
}

void afb_export_undeclare(struct afb_export *export)
{
	if (export->declared) {
		export->declared = 0;
		afb_apiset_del(export->declare_set, export->api.apiname);
	}
}

int afb_export_subscribe(struct afb_export *export, struct afb_event_x2 *event)
{
	return afb_evt_listener_watch_x2(export->listener, event);
}

int afb_export_unsubscribe(struct afb_export *export, struct afb_event_x2 *event)
{
	return afb_evt_listener_unwatch_x2(export->listener, event);
}

void afb_export_process_xreq(struct afb_export *export, struct afb_xreq *xreq)
{
	afb_xreq_process(xreq, export->call_set);
}

void afb_export_context_init(struct afb_export *export, struct afb_context *context)
{
	afb_context_init_validated(context, export->session, NULL, NULL);
}

