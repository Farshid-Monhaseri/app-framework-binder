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

#pragma once

/* declared here */
struct afb_api_x3;
struct afb_api_x3_itf;

/* referenced here */
struct sd_event;
struct sd_bus;
struct afb_req_x2;
struct afb_event_x2;
struct afb_auth;
struct afb_verb_v2;
struct afb_verb_v3;

/** @addtogroup AFB_API
 *  @{ */

/**
 * Structure for the APIv3
 */
struct afb_api_x3
{
	/**
	 * Interface functions
	 *
	 * Don't use it directly, prefer helper functions.
	 */
	const struct afb_api_x3_itf *itf;

	/**
	 * The name of the api
	 *
	 * @see afb_api_x3_name
	 */
	const char *apiname;

	/**
	 * User defined data
	 *
	 * @see afb_api_x3_set_userdata
	 * @see afb_api_x3_get_userdata
	 */
	void *userdata;

	/**
	 * Current verbosity mask
	 *
	 * The bits tells what verbosity is required for the api.
	 * It is related to the syslog levels.
	 *
	 *      EMERGENCY         0        System is unusable
	 *      ALERT             1        Action must be taken immediately
	 *      CRITICAL          2        Critical conditions
	 *      ERROR             3        Error conditions
	 *      WARNING           4        Warning conditions
	 *      NOTICE            5        Normal but significant condition
	 *      INFO              6        Informational
	 *      DEBUG             7        Debug-level messages
	 */
	int logmask;
};

/**
 * Definition of the function's interface for the APIv3
 */
struct afb_api_x3_itf
{
	/* CAUTION: respect the order, add at the end */

	/** sending log messages */
	void (*vverbose)(
		struct afb_api_x3 *api,
		int level,
		const char *file,
		int line,
		const char * func,
		const char *fmt,
		va_list args);

	/** gets the common systemd's event loop */
	struct sd_event *(*get_event_loop)(
		struct afb_api_x3 *api);

	/** gets the common systemd's user d-bus */
	struct sd_bus *(*get_user_bus)(
		struct afb_api_x3 *api);

	/** gets the common systemd's system d-bus */
	struct sd_bus *(*get_system_bus)(
		struct afb_api_x3 *api);

	/** get the file descriptor for the root directory */
	int (*rootdir_get_fd)(
		struct afb_api_x3 *api);

	/** get a file using locale setting */
	int (*rootdir_open_locale)(
		struct afb_api_x3 *api,
		const char *filename,
		int flags,
		const char *locale);

	/** queue a job */
	int (*queue_job)(
		struct afb_api_x3 *api,
		void (*callback)(int signum, void *arg),
		void *argument,
		void *group,
		int timeout);

	/** requires an api initialized or not */
	int (*require_api)(
		struct afb_api_x3 *api,
		const char *name,
		int initialized);

	/** add an alias */
	int (*add_alias)(
		struct afb_api_x3 *api,
		const char *name,
		const char *as_name);

	/** broadcasts event 'name' with 'object' */
	int (*event_broadcast)(
		struct afb_api_x3 *api,
		const char *name,
		struct json_object *object);

	/** creates an event of 'name' */
	struct afb_event_x2 *(*event_make)(
		struct afb_api_x3 *api,
		const char *name);

	/** legacy asynchronous invocation */
	void (*legacy_call)(
		struct afb_api_x3 *api,
		const char *apiname,
		const char *verb,
		struct json_object *args,
		void (*callback)(void*, int, struct json_object*, struct afb_api_x3 *),
		void *closure);

	/** legacy synchronous invocation */
	int (*legacy_call_sync)(
		struct afb_api_x3 *api,
		const char *apiname,
		const char *verb,
		struct json_object *args,
		struct json_object **result);

	/** creation of a new api*/
	struct afb_api_x3 *(*api_new_api)(
		struct afb_api_x3 *api,
		const char *apiname,
		const char *info,
		int noconcurrency,
		int (*preinit)(void*, struct afb_api_x3 *),
		void *closure);

	/** set verbs of the api using v2 description */
	int (*api_set_verbs_v2)(
		struct afb_api_x3 *api,
		const struct afb_verb_v2 *verbs);

	/** add one verb to the api */
	int (*api_add_verb)(
		struct afb_api_x3 *api,
		const char *verb,
		const char *info,
		void (*callback)(struct afb_req_x2 *req),
		void *vcbdata,
		const struct afb_auth *auth,
		uint32_t session,
		int glob);

	/** delete one verb of the api */
	int (*api_del_verb)(
		struct afb_api_x3 *api,
		const char *verb,
		void **vcbdata);

	/** set the api's callback for processing events */
	int (*api_set_on_event)(
		struct afb_api_x3 *api,
		void (*onevent)(struct afb_api_x3 *api, const char *event, struct json_object *object));

	/** set the api's callback for initialisation */
	int (*api_set_on_init)(
		struct afb_api_x3 *api,
		int (*oninit)(struct afb_api_x3 *api));

	/** seal the api */
	void (*api_seal)(
		struct afb_api_x3 *api);

	/** set verbs of the api using v3 description */
	int (*api_set_verbs_v3)(
		struct afb_api_x3 *api,
		const struct afb_verb_v3 *verbs);

	/** add an event handler for the api */
	int (*event_handler_add)(
		struct afb_api_x3 *api,
		const char *pattern,
		void (*callback)(void *, const char*, struct json_object*, struct afb_api_x3*),
		void *closure);

	/** delete an event handler of the api */
	int (*event_handler_del)(
		struct afb_api_x3 *api,
		const char *pattern,
		void **closure);

	/** asynchronous call for the api */
	void (*call)(
		struct afb_api_x3 *api,
		const char *apiname,
		const char *verb,
		struct json_object *args,
		void (*callback)(void*, struct json_object*, const char*, const char*, struct afb_api_x3 *),
		void *closure);

	/** synchronous call for the api */
	int (*call_sync)(
		struct afb_api_x3 *api,
		const char *apiname,
		const char *verb,
		struct json_object *args,
		struct json_object **result,
		char **error,
		char **info);

	/** indicate provided classes of the api */
	int (*class_provide)(
		struct afb_api_x3 *api,
		const char *name);

	/** indicate required classes of the api */
	int (*class_require)(
		struct afb_api_x3 *api,
		const char *name);

	/** delete the api */
	int (*delete_api)(
		struct afb_api_x3 *api);

	/** settings of the api */
	struct json_object *(*settings)(
		struct afb_api_x3 *api);
};

/** @} */
