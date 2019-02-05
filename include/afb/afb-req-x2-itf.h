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

/* defined here */
struct afb_req_x2;
struct afb_req_x2_itf;

/* referenced here */
#include "afb-arg.h"
struct afb_req_x1;
struct afb_event_x1;
struct afb_event_x2;
struct afb_api_x3;
struct afb_stored_req;

/** @addtogroup AFB_REQ
 *  @{ */

/**
 * structure for the request
 */
struct afb_req_x2
{
	/**
	 * interface for the request
	 */
	const struct afb_req_x2_itf *itf;

	/**
	 * current api (if any)
	 */
	struct afb_api_x3 *api;

	/**
	 * closure associated with the callback processing the verb of the request
	 * as given at its declaration
	 */
	void *vcbdata;

	/**
	 * the name of the called api
	 */
	const char *called_api;

	/**
	 * the name of the called verb
	 */
	const char *called_verb;
};

/**
 * subcall flags
 *
 * When making subcalls, it is now possible to explicitely set the subcall
 * mode to a combination of the following flags using binary OR.
 *
 * In particular, the following combination of flags are to be known:
 *
 *  - for **subcall** having a similar behaviour to the subcalls of bindings
 *    version 1 and 2: afb_req_x2_subcall_pass_events|afb_req_x2_subcall_on_behalf
 * 
 *  - for **subcall** having the behaviour of the **call**:
 *    afb_req_x2_subcall_catch_events|afb_req_x2_subcall_api_session
 *
 * Be aware that if none of mode  afb_req_x2_subcall_catch_events or
 * afb_req_x2_subcall_pass_events is set, subscrption to events will be ignored.
 */
enum afb_req_x2_subcall_flags
{
	/**
	 * the calling API wants to receive the events from subscription
	 */
	afb_req_x2_subcall_catch_events = 1,

	/**
	 * the original request will receive the events from subscription
	 */
	afb_req_x2_subcall_pass_events = 2,

	/**
	 * the calling API wants to use the credentials of the original request
	 */
	afb_req_x2_subcall_on_behalf = 4,

	/**
	 * the calling API wants to use its session instead of the one of the
	 * original request
	 */
	afb_req_x2_subcall_api_session = 8,
};

/**
 * Interface for handling requests.
 *
 * It records the functions to be called for the request.
 * Don't use this structure directly, Use the helper functions instead.
 */
struct afb_req_x2_itf
{
	/* CAUTION: respect the order, add at the end */

	/** get the json */
	struct json_object *(*json)(
			struct afb_req_x2 *req);

	/** get an argument */
	struct afb_arg (*get)(
			struct afb_req_x2 *req,
			const char *name);

	/** reply a success @deprecated use @ref reply */
	void (*legacy_success)(
			struct afb_req_x2 *req,
			struct json_object *obj,
			const char *info);

	/** reply a failure @deprecated use @ref reply */
	void (*legacy_fail)(
			struct afb_req_x2 *req,
			const char *status,
			const char *info);

	/** reply a success @deprecated use @ref vreply */
	void (*legacy_vsuccess)(
			struct afb_req_x2 *req,
			struct json_object *obj,
			const char *fmt,
			va_list args);

	/** reply a failure @deprecated use @ref vreply */
	void (*legacy_vfail)(
			struct afb_req_x2 *req,
			const char *status,
			const char *fmt,
			va_list args);

	/** get a client context @deprecated use @ref context_make */
	void *(*legacy_context_get)(
			struct afb_req_x2 *req);

	/** set a client context @deprecated use @ref context_make */
	void (*legacy_context_set)(
			struct afb_req_x2 *req,
			void *value,
			void (*free_value)(void*));

	/** increase reference count of the request */
	struct afb_req_x2 *(*addref)(
			struct afb_req_x2 *req);

	/** decrease reference count of the request */
	void (*unref)(
			struct afb_req_x2 *req);

	/** close the client session related to the api of the request */
	void (*session_close)(
			struct afb_req_x2 *req);

	/** set the levele of assurancy related to the api of the request */
	int (*session_set_LOA)(
			struct afb_req_x2 *req,
			unsigned level);

	/** make subscription of the client of the request to the event @deprecated use @ref subscribe_event_x2 */
	int (*legacy_subscribe_event_x1)(
			struct afb_req_x2 *req,
			struct afb_event_x1 event);

	/** remove subscription of the client of the request to the event @deprecated use @ref unsubscribe_event_x2 */
	int (*legacy_unsubscribe_event_x1)(
			struct afb_req_x2 *req,
			struct afb_event_x1 event);

	/** asynchronous subcall @deprecated use @ref subcall */
	void (*legacy_subcall)(
			struct afb_req_x2 *req,
			const char *api,
			const char *verb,
			struct json_object *args,
			void (*callback)(void*, int, struct json_object*),
			void *cb_closure);

	/** synchronous subcall @deprecated use @ref subcallsync */
	int (*legacy_subcallsync)(
			struct afb_req_x2 *req,
			const char *api,
			const char *verb,
			struct json_object *args,
			struct json_object **result);

	/** log a message for the request */
	void (*vverbose)(
			struct afb_req_x2 *req,
			int level,
			const char *file,
			int line,
			const char * func,
			const char *fmt,
			va_list args);

	/** store the request @deprecated no more needed */
	struct afb_stored_req *(*legacy_store_req)(
			struct afb_req_x2 *req);

	/** asynchronous subcall with request @deprecated use @ref subcall */
	void (*legacy_subcall_req)(
			struct afb_req_x2 *req,
			const char *api,
			const char *verb,
			struct json_object *args,
			void (*callback)(void*, int, struct json_object*, struct afb_req_x1),
			void *cb_closure);

	/** store the request @deprecated no more needed */
	int (*has_permission)(
			struct afb_req_x2 *req,
			const char *permission);

	/** get the application id of the client of the request */
	char *(*get_application_id)(
			struct afb_req_x2 *req);

	/** handle client context of the api getting the request */
	void *(*context_make)(
			struct afb_req_x2 *req,
			int replace,
			void *(*create_value)(void *creation_closure),
			void (*free_value)(void*),
			void *creation_closure);

	/** make subscription of the client of the request to the event */
	int (*subscribe_event_x2)(
			struct afb_req_x2 *req,
			struct afb_event_x2 *event);

	/** remove subscription of the client of the request to the event */
	int (*unsubscribe_event_x2)(
			struct afb_req_x2 *req,
			struct afb_event_x2 *event);

	/** asynchronous subcall with request @deprecated use @ref subcall */
	void (*legacy_subcall_request)(
			struct afb_req_x2 *req,
			const char *api,
			const char *verb,
			struct json_object *args,
			void (*callback)(void*, int, struct json_object*, struct afb_req_x2 *req),
			void *cb_closure);

	/** get the user id  (unix) of the client of the request */
	int (*get_uid)(
			struct afb_req_x2 *req);

	/** reply to the request */
	void (*reply)(
			struct afb_req_x2 *req,
			struct json_object *obj,
			const char *error,
			const char *info);

	/** reply to the request with formating of info */
	void (*vreply)(
			struct afb_req_x2 *req,
			struct json_object *obj,
			const char *error,
			const char *fmt,
			va_list args);

	/** get description of the client of the request */
	struct json_object *(*get_client_info)(
			struct afb_req_x2 *req);

	/** asynchronous subcall */
	void (*subcall)(
			struct afb_req_x2 *req,
			const char *apiname,
			const char *verb,
			struct json_object *args,
			int flags,
			void (*callback)(void *closure, struct json_object *object, const char *error, const char * info, struct afb_req_x2 *req),
			void *closure);

	/** synchronous subcall */
	int (*subcallsync)(
			struct afb_req_x2 *req,
			const char *api,
			const char *verb,
			struct json_object *args,
			int flags,
			struct json_object **object,
			char **error,
			char **info);
};


/** @} */
