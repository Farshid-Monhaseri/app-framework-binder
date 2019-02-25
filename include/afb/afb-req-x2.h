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

#include "afb-req-x2-itf.h"
#include "afb-api-x3.h"

/** @defgroup AFB_REQ
 *  @{ */

/**
 * Checks whether the request 'req' is valid or not.
 *
 * @param req the request to check
 *
 * @return 0 if not valid or 1 if valid.
 */
static inline
int afb_req_x2_is_valid(
			struct afb_req_x2 *req)
{
	return !!req;
}

/**
 * Retrieves the api that serves the request
 *
 * @param req the request whose serving api is queried
 *
 * @return the api serving the request
 */
static inline
struct afb_api_x3 *afb_req_x2_get_api(
			struct afb_req_x2 *req)
{
	return req->api;
}

/**
 * Retrieves the callback data of the verb. This callback data is set
 * when the verb is created.
 *
 * @param req whose verb vcbdata is queried
 *
 * @return the callback data attached to the verb description
 */
static inline
void *afb_req_x2_get_vcbdata(
			struct afb_req_x2 *req)
{
	return req->vcbdata;
}

/**
 * Retrieve the name of the called api.
 *
 * @param req the request
 *
 * @return the name of the called api
 *
 * @see afb_api_x3_add_alias
 */
static inline
const char *afb_req_x2_get_called_api(
			struct afb_req_x2 *req)
{
	return req->called_api;
}

/**
 * Retrieve the name of the called verb
 *
 * @param req the request
 *
 * @return the name of the called verb
 */
static inline
const char *afb_req_x2_get_called_verb(
			struct afb_req_x2 *req)
{
	return req->called_verb;
}

/**
 * Is the log message of 'level (as defined for syslog) required for the
 * request 'req'?
 *
 * @param req the request
 * @param level the level to check as defined for syslog:
 *
 *      EMERGENCY         0        System is unusable
 *      ALERT             1        Action must be taken immediately
 *      CRITICAL          2        Critical conditions
 *      ERROR             3        Error conditions
 *      WARNING           4        Warning conditions
 *      NOTICE            5        Normal but significant condition
 *      INFO              6        Informational
 *      DEBUG             7        Debug-level messages
 *
 * @return 0 if not required or a value not null if required
 *
 * @see syslog
 */
static inline
int afb_req_x2_wants_log_level(
			struct afb_req_x2 *req,
			int level)
{
	return afb_api_x3_wants_log_level(afb_req_x2_get_api(req), level);
}

/**
 * Gets from the request 'req' the argument of 'name'.
 *
 * Returns a PLAIN structure of type 'struct afb_arg'.
 *
 * When the argument of 'name' is not found, all fields of result are set to NULL.
 *
 * When the argument of 'name' is found, the fields are filled,
 * in particular, the field 'result.name' is set to 'name'.
 *
 * There is a special name value: the empty string.
 * The argument of name "" is defined only if the request was made using
 * an HTTP POST of Content-Type "application/json". In that case, the
 * argument of name "" receives the value of the body of the HTTP request.
 *
 * @param req the request
 * @param name the name of the argument to get
 *
 * @return a structure describing the retrieved argument for the request
 *
 * @see afb_req_x2_value
 * @see afb_req_x2_path
 */
static inline
struct afb_arg afb_req_x2_get(
			struct afb_req_x2 *req,
			const char *name)
{
	return req->itf->get(req, name);
}

/**
 * Gets from the request 'req' the string value of the argument of 'name'.
 * Returns NULL if when there is no argument of 'name'.
 * Returns the value of the argument of 'name' otherwise.
 *
 * Shortcut for: afb_req_x2_get(req, name).value
 *
 * @param req the request
 * @param name the name of the argument's value to get
 *
 * @return the value as a string or NULL
 *
 * @see afb_req_x2_get
 * @see afb_req_x2_path
 */
static inline
const char *afb_req_x2_value(
			struct afb_req_x2 *req,
			const char *name)
{
	return afb_req_x2_get(req, name).value;
}

/**
 * Gets from the request 'req' the path for file attached to the argument of 'name'.
 * Returns NULL if when there is no argument of 'name' or when there is no file.
 * Returns the path of the argument of 'name' otherwise.
 *
 * Shortcut for: afb_req_x2_get(req, name).path
 *
 * @param req the request
 * @param name the name of the argument's path to get
 *
 * @return the path if any or NULL
 *
 * @see afb_req_x2_get
 * @see afb_req_x2_value
 */
static inline
const char *afb_req_x2_path(
			struct afb_req_x2 *req,
			const char *name)
{
	return afb_req_x2_get(req, name).path;
}

/**
 * Gets from the request 'req' the json object hashing the arguments.
 *
 * The returned object must not be released using 'json_object_put'.
 *
 * @param req the request
 *
 * @return the JSON object of the query
 *
 * @see afb_req_x2_get
 * @see afb_req_x2_value
 * @see afb_req_x2_path
 */
static inline
struct json_object *afb_req_x2_json(
			struct afb_req_x2 *req)
{
	return req->itf->json(req);
}

/**
 * Sends a reply to the request 'req'.
 *
 * The status of the reply is set to 'error' (that must be NULL on success).
 * Its send the object 'obj' (can be NULL) with an
 * informational comment 'info (can also be NULL).
 *
 * For convenience, the function calls 'json_object_put' for 'obj'.
 * Thus, in the case where 'obj' should remain available after
 * the function returns, the function 'json_object_get' shall be used.
 *
 * @param req the request
 * @param obj the replied object or NULL
 * @param error the error message if it is a reply error or NULL
 * @param info an informative text or NULL
 *
 * @see afb_req_x2_reply_v
 * @see afb_req_x2_reply_f
 */
static inline
void afb_req_x2_reply(
			struct afb_req_x2 *req,
			struct json_object *obj,
			const char *error,
			const char *info)
{
	req->itf->reply(req, obj, error, info);
}

/**
 * Same as 'afb_req_x2_reply_f' but the arguments to the format 'info'
 * are given as a variable argument list instance.
 *
 * For convenience, the function calls 'json_object_put' for 'obj'.
 * Thus, in the case where 'obj' should remain available after
 * the function returns, the function 'json_object_get' shall be used.
 *
 * @param req the request
 * @param obj the replied object or NULL
 * @param error the error message if it is a reply error or NULL
 * @param info an informative text containing a format as for vprintf
 * @param args the va_list of arguments to the format as for vprintf
 *
 * @see afb_req_x2_reply
 * @see afb_req_x2_reply_f
 * @see vprintf
 */
static inline
void afb_req_x2_reply_v(
			struct afb_req_x2 *req,
			struct json_object *obj,
			const char *error,
			const char *info,
			va_list args)
{
	req->itf->vreply(req, obj, error, info, args);
}

/**
 * Same as 'afb_req_x2_reply' but the 'info' is a formatting
 * string followed by arguments.
 *
 * For convenience, the function calls 'json_object_put' for 'obj'.
 * Thus, in the case where 'obj' should remain available after
 * the function returns, the function 'json_object_get' shall be used.
 *
 * @param req the request
 * @param obj the replied object or NULL
 * @param error the error message if it is a reply error or NULL
 * @param info an informative text containing a format as for printf
 * @param ... the arguments to the format as for printf
 *
 * @see afb_req_x2_reply
 * @see afb_req_x2_reply_v
 * @see printf
 */
__attribute__((format(printf, 4, 5)))
static inline
void afb_req_x2_reply_f(
			struct afb_req_x2 *req,
			struct json_object *obj,
			const char *error,
			const char *info,
			...)
{
	va_list args;
	va_start(args, info);
	afb_req_x2_reply_v(req, obj, error, info, args);
	va_end(args);
}

/**
 * Manage the pointer stored by the binding for the client session of 'req'.
 *
 * If no previous pointer is stored or if 'replace' is not zero, a new value
 * is generated using the function 'create_context' called with the 'closure'.
 * If 'create_context' is NULL the generated value is 'closure'.
 *
 * When a value is created, the function 'free_context' is recorded and will
 * be called (with the created value as argument) to free the created value when
 * it is not more used.
 *
 * This function is atomic: it ensures that 2 threads will not race together.
 *
 * @param req the request
 * @param replace if not zero an existing value is replaced
 * @param create_context the creation function or NULL
 * @param free_context the destroying function or NULL
 * @param closure the closure to the creation function
 *
 * @return the stored value
 */
static inline
void *afb_req_x2_context(
			struct afb_req_x2 *req,
			int replace,
			void *(*create_context)(void *closure),
			void (*free_context)(void*),
			void *closure)
{
	return req->itf->context_make(req, replace, create_context, free_context, closure);
}

/**
 * Gets the pointer stored by the binding for the session of 'req'.
 * When the binding has not yet recorded a pointer, NULL is returned.
 *
 * Shortcut for: afb_req_x2_context(req, 0, NULL, NULL, NULL)
 *
 * @param req the request
 *
 * @return the previously stored value
 */
static inline
void *afb_req_x2_context_get(
			struct afb_req_x2 *req)
{
	return afb_req_x2_context(req, 0, 0, 0, 0);
}

/**
 * Stores for the binding the pointer 'context' to the session of 'req'.
 * The function 'free_context' will be called when the session is closed
 * or if binding stores an other pointer.
 *
 * Shortcut for: afb_req_x2_context(req, 1, NULL, free_context, context)
 *
 *
 * @param req the request
 * @param context the context value to store
 * @param free_context the cleaning function for the stored context (can be NULL)
 */
static inline
void afb_req_x2_context_set(
			struct afb_req_x2 *req,
			void *context,
			void (*free_context)(void*))
{
	afb_req_x2_context(req, 1, 0, free_context, context);
}

/**
 * Frees the pointer stored by the binding for the session of 'req'
 * and sets it to NULL.
 *
 * Shortcut for: afb_req_x2_context_set(req, NULL, NULL)
 *
 * @param req the request
 */
static inline
void afb_req_x2_context_clear(
			struct afb_req_x2 *req)
{
	afb_req_x2_context(req, 1, 0, 0, 0);
}

/**
 * Increments the count of references of 'req'.
 *
 * @param req the request
 *
 * @return returns the request req
 */
static inline
struct afb_req_x2 *afb_req_x2_addref(
			struct afb_req_x2 *req)
{
	return req->itf->addref(req);
}

/**
 * Decrement the count of references of 'req'.
 *
 * @param req the request
 */
static inline
void afb_req_x2_unref(
			struct afb_req_x2 *req)
{
	req->itf->unref(req);
}

/**
 * Closes the session associated with 'req'
 * and delete all associated contexts.
 *
 * @param req the request
 */
static inline
void afb_req_x2_session_close(
			struct afb_req_x2 *req)
{
	req->itf->session_close(req);
}

/**
 * Sets the level of assurance of the session of 'req'
 * to 'level'. The effect of this function is subject of
 * security policies.
 *
 * @param req the request
 * @param level of assurance from 0 to 7
 *
 * @return 0 on success or -1 if failed.
 */
static inline
int afb_req_x2_session_set_LOA(
			struct afb_req_x2 *req,
			unsigned level)
{
	return req->itf->session_set_LOA(req, level);
}

/**
 * Establishes for the client link identified by 'req' a subscription
 * to the 'event'.
 *
 * @param req the request
 * @param event the event to subscribe
 *
 * @return 0 in case of successful subscription or -1 in case of error.
 */
static inline
int afb_req_x2_subscribe(
			struct afb_req_x2 *req,
			struct afb_event_x2 *event)
{
	return req->itf->subscribe_event_x2(req, event);
}

/**
 * Revokes the subscription established to the 'event' for the client
 * link identified by 'req'.
 * Returns 0 in case of successful subscription or -1 in case of error.
 *
 * @param req the request
 * @param event the event to revoke
 *
 * @return 0 in case of successful subscription or -1 in case of error.
 */
static inline
int afb_req_x2_unsubscribe(
			struct afb_req_x2 *req,
			struct afb_event_x2 *event)
{
	return req->itf->unsubscribe_event_x2(req, event);
}

/**
 * @deprecated use @ref afb_req_x2_subcall
 *
 * Makes a call to the method of name 'api' / 'verb' with the object 'args'.
 * This call is made in the context of the request 'req'.
 * On completion, the function 'callback' is invoked with the
 * 'closure' given at call and two other parameters: 'iserror' and 'result'.
 * 'status' is 0 on success or negative when on an error reply.
 * 'result' is the json object of the reply, you must not call json_object_put
 * on the result.
 *
 * For convenience, the function calls 'json_object_put' for 'args'.
 * Thus, in the case where 'args' should remain available after
 * the function returns, the function 'json_object_get' shall be used.
 *
 * @param req the request
 * @param api the name of the api to call
 * @param verb the name of the verb to call
 * @param args the arguments of the call as a JSON object
 * @param callback the call back that will receive the reply
 * @param closure the closure passed back to the callback
 *
 * @see afb_req_x2_subcall
 * @see afb_req_x2_subcall_sync
 */
static inline
void afb_req_x2_subcall_legacy(
			struct afb_req_x2 *req,
			const char *api,
			const char *verb,
			struct json_object *args,
			void (*callback)(void *closure, int iserror, struct json_object *result, struct afb_req_x2 *req),
			void *closure)
{
	req->itf->legacy_subcall_request(req, api, verb, args, callback, closure);
}

/**
 * @deprecated use @ref afb_req_x2_subcall_sync
 *
 * Makes a call to the method of name 'api' / 'verb' with the object 'args'.
 * This call is made in the context of the request 'req'.
 * This call is synchronous, it waits untill completion of the request.
 * It returns 0 on success or a negative value on error answer.
 * The object pointed by 'result' is filled and must be released by the caller
 * after its use by calling 'json_object_put'.
 *
 * For convenience, the function calls 'json_object_put' for 'args'.
 * Thus, in the case where 'args' should remain available after
 * the function returns, the function 'json_object_get' shall be used.
 *
 * @param req the request
 * @param api the name of the api to call
 * @param verb the name of the verb to call
 * @param args the arguments of the call as a JSON object
 * @param result the pointer to the JSON object pointer that will receive the result
 *
 * @return 0 on success or a negative value on error answer.
 *
 * @see afb_req_x2_subcall
 * @see afb_req_x2_subcall_sync
 */
static inline
int afb_req_x2_subcall_sync_legacy(
			struct afb_req_x2 *req,
			const char *api,
			const char *verb,
			struct json_object *args,
			struct json_object **result)
{
	return req->itf->legacy_subcallsync(req, api, verb, args, result);
}

/**
 * Send associated to 'req' a message described by 'fmt' and its 'args'
 * to the journal for the verbosity 'level'.
 *
 * 'file', 'line' and 'func' are indicators of position of the code in source files
 * (see macros __FILE__, __LINE__ and __func__).
 *
 * 'level' is defined by syslog standard:
 *      EMERGENCY         0        System is unusable
 *      ALERT             1        Action must be taken immediately
 *      CRITICAL          2        Critical conditions
 *      ERROR             3        Error conditions
 *      WARNING           4        Warning conditions
 *      NOTICE            5        Normal but significant condition
 *      INFO              6        Informational
 *      DEBUG             7        Debug-level messages
 *
 * @param req the request
 * @param level the level of the message
 * @param file the source filename that emits the message or NULL
 * @param line the line number in the source filename that emits the message
 * @param func the name of the function that emits the message or NULL
 * @param fmt the message format as for printf
 * @param args the arguments to the format 'fmt'
 *
 * @see printf
 * @see afb_req_x2_verbose
 */
static inline
void afb_req_x2_vverbose(
			struct afb_req_x2 *req,
			int level, const char *file,
			int line,
			const char * func,
			const char *fmt,
			va_list args)
{
	req->itf->vverbose(req, level, file, line, func, fmt, args);
}

/**
 * Send associated to 'req' a message described by 'fmt' and following parameters
 * to the journal for the verbosity 'level'.
 *
 * 'file', 'line' and 'func' are indicators of position of the code in source files
 * (see macros __FILE__, __LINE__ and __func__).
 *
 * 'level' is defined by syslog standard:
 *      EMERGENCY         0        System is unusable
 *      ALERT             1        Action must be taken immediately
 *      CRITICAL          2        Critical conditions
 *      ERROR             3        Error conditions
 *      WARNING           4        Warning conditions
 *      NOTICE            5        Normal but significant condition
 *      INFO              6        Informational
 *      DEBUG             7        Debug-level messages
 *
 * @param req the request
 * @param level the level of the message
 * @param file the source filename that emits the message or NULL
 * @param line the line number in the source filename that emits the message
 * @param func the name of the function that emits the message or NULL
 * @param fmt the message format as for printf
 * @param ... the arguments of the format 'fmt'
 *
 * @see printf
 * @see afb_req_x2_vverbose
 */
__attribute__((format(printf, 6, 7)))
static inline
void afb_req_x2_verbose(
			struct afb_req_x2 *req,
			int level, const char *file,
			int line,
			const char * func,
			const char *fmt,
			...)
{
	va_list args;
	va_start(args, fmt);
	afb_req_x2_vverbose(req, level, file, line, func, fmt, args);
	va_end(args);
}

/**
 * Check whether the 'permission' is granted or not to the client
 * identified by 'req'.
 *
 * @param req the request
 * @param permission string to check
 *
 * @return 1 if the permission is granted or 0 otherwise.
 */
static inline
int afb_req_x2_has_permission(
			struct afb_req_x2 *req,
			const char *permission)
{
	return req->itf->has_permission(req, permission);
}

/**
 * Get the application identifier of the client application for the
 * request 'req'.
 *
 * Returns the application identifier or NULL when the application
 * can not be identified.
 *
 * The returned value if not NULL must be freed by the caller
 *
 * @param req the request
 *
 * @return the string for the application id of the client MUST BE FREED
 */
static inline
char *afb_req_x2_get_application_id(
			struct afb_req_x2 *req)
{
	return req->itf->get_application_id(req);
}

/**
 * Get the user identifier (UID) of the client for the
 * request 'req'.
 *
 * @param req the request
 *
 * @return -1 when the application can not be identified or the unix uid.
 *
 */
static inline
int afb_req_x2_get_uid(
			struct afb_req_x2 *req)
{
	return req->itf->get_uid(req);
}

/**
 * Get informations about the client of the
 * request 'req'.
 *
 * Returns an object with client informations:
 *  {
 *    "pid": int, "uid": int, "gid": int,
 *    "label": string, "id": string, "user": string,
 *    "uuid": string, "LOA": int
 *  }
 *
 * If some of this information can't be computed, the field of the return
 * object will not be set at all.
 *
 * @param req the request
 *
 * @return a JSON object that must be freed using @ref json_object_put
 */
static inline
struct json_object *afb_req_x2_get_client_info(
			struct afb_req_x2 *req)
{
	return req->itf->get_client_info(req);
}

/**
 * Calls the 'verb' of the 'api' with the arguments 'args' and 'verb' in the name of the binding.
 * The result of the call is delivered to the 'callback' function with the 'callback_closure'.
 *
 * For convenience, the function calls 'json_object_put' for 'args'.
 * Thus, in the case where 'args' should remain available after
 * the function returns, the function 'json_object_get' shall be used.
 *
 * The 'callback' receives 5 arguments:
 *  1. 'closure' the user defined closure pointer 'closure',
 *  2. 'object'  a JSON object returned (can be NULL)
 *  3. 'error'   a string not NULL in case of error
 *  4. 'info'    a string handling some info (can be NULL)
 *  5. 'req'     the req
 *
 * NOTE: For convenience, *json_object_put* is called on 'object' after the
 * callback returns. So, it is wrong to call *json_object_put* in the callback.
 *
 * @param req      The request
 * @param api      The api name of the method to call
 * @param verb     The verb name of the method to call
 * @param args     The arguments to pass to the method
 * @param flags    The bit field of flags for the subcall as defined by @ref afb_req_x2_subcall_flags
 * @param callback The to call on completion
 * @param closure  The closure to pass to the callback
 *
 * @see also 'afb_req_subcall_sync'
 */
static inline
void afb_req_x2_subcall(
			struct afb_req_x2 *req,
			const char *api,
			const char *verb,
			struct json_object *args,
			int flags,
			void (*callback)(void *closure, struct json_object *object, const char *error, const char * info, struct afb_req_x2 *req),
			void *closure)
{
	req->itf->subcall(req, api, verb, args, flags, callback, closure);
}

/**
 * Makes a call to the method of name 'api' / 'verb' with the object 'args'.
 * This call is made in the context of the request 'req'.
 * This call is synchronous, it waits untill completion of the request.
 * It returns 0 on success or a negative value on error answer.
 *
 * For convenience, the function calls 'json_object_put' for 'args'.
 * Thus, in the case where 'args' should remain available after
 * the function returns, the function 'json_object_get' shall be used.
 *
 * See also:
 *  - 'afb_req_x2_subcall_req' that is convenient to keep request alive automatically.
 *  - 'afb_req_x2_subcall' that doesn't keep request alive automatically.
 *
 * @param req      The request
 * @param api      The api name of the method to call
 * @param verb     The verb name of the method to call
 * @param args     The arguments to pass to the method
 * @param flags    The bit field of flags for the subcall as defined by @ref afb_req_x2_subcall_flags
 * @param object   a pointer where the replied JSON object is stored must be freed using @ref json_object_put (can be NULL)
 * @param error    a pointer where a copy of the replied error is stored must be freed using @ref free (can be NULL)
 * @param info     a pointer where a copy of the replied info is stored must be freed using @ref free (can be NULL)
 *
 * @return 0 in case of success or -1 in case of error
 */
static inline
int afb_req_x2_subcall_sync(
			struct afb_req_x2 *req,
			const char *api,
			const char *verb,
			struct json_object *args,
			int flags,
			struct json_object **object,
			char **error,
			char **info)
{
	return req->itf->subcallsync(req, api, verb, args, flags, object, error, info);
}


/** @} */
