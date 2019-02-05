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

#include "afb-req-x1-itf.h"
#include "afb-event-x1.h"

/** @addtogroup AFB_REQ
 *  @{ */

/**
 * @deprecated use bindings version 3
 *
 * Converts the 'req' to an afb_request.
 */
static inline struct afb_req_x2 *afb_req_x1_to_req_x2(struct afb_req_x1 req)
{
	return req.closure;
}

/**
 * @deprecated use bindings version 3
 *
 * Checks whether the request 'req' is valid or not.
 *
 * Returns 0 if not valid or 1 if valid.
 */
static inline int afb_req_x1_is_valid(struct afb_req_x1 req)
{
	return !!req.itf;
}

/**
 * @deprecated use bindings version 3
 *
 * Gets from the request 'req' the argument of 'name'.
 * Returns a PLAIN structure of type 'struct afb_arg'.
 * When the argument of 'name' is not found, all fields of result are set to NULL.
 * When the argument of 'name' is found, the fields are filled,
 * in particular, the field 'result.name' is set to 'name'.
 *
 * There is a special name value: the empty string.
 * The argument of name "" is defined only if the request was made using
 * an HTTP POST of Content-Type "application/json". In that case, the
 * argument of name "" receives the value of the body of the HTTP request.
 */
static inline struct afb_arg afb_req_x1_get(struct afb_req_x1 req, const char *name)
{
	return req.itf->get(req.closure, name);
}

/**
 * @deprecated use bindings version 3
 *
 * Gets from the request 'req' the string value of the argument of 'name'.
 * Returns NULL if when there is no argument of 'name'.
 * Returns the value of the argument of 'name' otherwise.
 *
 * Shortcut for: afb_req_get(req, name).value
 */
static inline const char *afb_req_x1_value(struct afb_req_x1 req, const char *name)
{
	return afb_req_x1_get(req, name).value;
}

/**
 * @deprecated use bindings version 3
 *
 * Gets from the request 'req' the path for file attached to the argument of 'name'.
 * Returns NULL if when there is no argument of 'name' or when there is no file.
 * Returns the path of the argument of 'name' otherwise.
 *
 * Shortcut for: afb_req_get(req, name).path
 */
static inline const char *afb_req_x1_path(struct afb_req_x1 req, const char *name)
{
	return afb_req_x1_get(req, name).path;
}

/**
 * @deprecated use bindings version 3
 *
 * Gets from the request 'req' the json object hashing the arguments.
 * The returned object must not be released using 'json_object_put'.
 */
static inline struct json_object *afb_req_x1_json(struct afb_req_x1 req)
{
	return req.itf->json(req.closure);
}

/**
 * @deprecated use bindings version 3
 *
 * Sends a reply to the request 'req'.
 * The status of the reply is set to 'error' (that must be NULL on success).
 * Its send the object 'obj' (can be NULL) with an
 * informational comment 'info (can also be NULL).
 *
 * For convenience, the function calls 'json_object_put' for 'obj'.
 * Thus, in the case where 'obj' should remain available after
 * the function returns, the function 'json_object_get' shall be used.
 */
static inline void afb_req_x1_reply(struct afb_req_x1 req, struct json_object *obj, const char *error, const char *info)
{
	req.itf->reply(req.closure, obj, error, info);
}

/**
 * @deprecated use bindings version 3
 *
 * Same as 'afb_req_x1_reply' but the 'info' is a formatting
 * string followed by arguments.
 *
 * For convenience, the function calls 'json_object_put' for 'obj'.
 * Thus, in the case where 'obj' should remain available after
 * the function returns, the function 'json_object_get' shall be used.
 */
static inline void afb_req_x1_reply_f(struct afb_req_x1 req, struct json_object *obj, const char *error, const char *info, ...) __attribute__((format(printf, 4, 5)));
static inline void afb_req_x1_reply_f(struct afb_req_x1 req, struct json_object *obj, const char *error, const char *info, ...)
{
	va_list args;
	va_start(args, info);
	req.itf->vreply(req.closure, obj, error, info, args);
	va_end(args);
}

/**
 * @deprecated use bindings version 3
 *
 * Same as 'afb_req_x1_reply_f' but the arguments to the format 'info'
 * are given as a variable argument list instance.
 *
 * For convenience, the function calls 'json_object_put' for 'obj'.
 * Thus, in the case where 'obj' should remain available after
 * the function returns, the function 'json_object_get' shall be used.
 */
static inline void afb_req_x1_reply_v(struct afb_req_x1 req, struct json_object *obj, const char *error, const char *info, va_list args)
{
	req.itf->vreply(req.closure, obj, error, info, args);
}

/**
 * @deprecated use bindings version 3
 *
 * Gets the pointer stored by the binding for the session of 'req'.
 * When the binding has not yet recorded a pointer, NULL is returned.
 */
static inline void *afb_req_x1_context_get(struct afb_req_x1 req)
{
	return req.itf->context_make(req.closure, 0, 0, 0, 0);
}

/**
 * @deprecated use bindings version 3
 *
 * Stores for the binding the pointer 'context' to the session of 'req'.
 * The function 'free_context' will be called when the session is closed
 * or if binding stores an other pointer.
 */
static inline void afb_req_x1_context_set(struct afb_req_x1 req, void *context, void (*free_context)(void*))
{
	req.itf->context_make(req.closure, 1, 0, free_context, context);
}

/**
 * @deprecated use bindings version 3
 *
 * Gets the pointer stored by the binding for the session of 'req'.
 * If the stored pointer is NULL, indicating that no pointer was
 * already stored, afb_req_context creates a new context by calling
 * the function 'create_context' and stores it with the freeing function
 * 'free_context'.
 */
static inline void *afb_req_x1_context(struct afb_req_x1 req, void *(*create_context)(), void (*free_context)(void*))
{
	return req.itf->context_make(req.closure, 0, (void *(*)(void*))(void*)create_context, free_context, 0);
}

/**
 * @deprecated use bindings version 3
 *
 * Gets the pointer stored by the binding for the session of 'request'.
 * If no previous pointer is stored or if 'replace' is not zero, a new value
 * is generated using the function 'create_context' called with the 'closure'.
 * If 'create_context' is NULL the generated value is 'closure'.
 * When a value is created, the function 'free_context' is recorded and will
 * be called (with the created value as argument) to free the created value when
 * it is not more used.
 * This function is atomic: it ensures that 2 threads will not race together.
 */
static inline void *afb_req_x1_context_make(struct afb_req_x1 req, int replace, void *(*create_context)(void *closure), void (*free_context)(void*), void *closure)
{
	return req.itf->context_make(req.closure, replace, create_context, free_context, closure);
}

/**
 * @deprecated use bindings version 3
 *
 * Frees the pointer stored by the binding for the session of 'req'
 * and sets it to NULL.
 *
 * Shortcut for: afb_req_context_set(req, NULL, NULL)
 */
static inline void afb_req_x1_context_clear(struct afb_req_x1 req)
{
	req.itf->context_make(req.closure, 1, 0, 0, 0);
}

/**
 * @deprecated use bindings version 3
 *
 * Adds one to the count of references of 'req'.
 * This function MUST be called by asynchronous implementations
 * of verbs if no reply was sent before returning.
 */
static inline void afb_req_x1_addref(struct afb_req_x1 req)
{
	req.itf->addref(req.closure);
}

/**
 * @deprecated use bindings version 3
 *
 * Substracts one to the count of references of 'req'.
 * This function MUST be called by asynchronous implementations
 * of verbs after sending the asynchronous reply.
 */
static inline void afb_req_x1_unref(struct afb_req_x1 req)
{
	req.itf->unref(req.closure);
}

/**
 * @deprecated use bindings version 3
 *
 * Closes the session associated with 'req'
 * and delete all associated contexts.
 */
static inline void afb_req_x1_session_close(struct afb_req_x1 req)
{
	req.itf->session_close(req.closure);
}

/**
 * @deprecated use bindings version 3
 *
 * Sets the level of assurance of the session of 'req'
 * to 'level'. The effect of this function is subject of
 * security policies.
 * Returns 1 on success or 0 if failed.
 */
static inline int afb_req_x1_session_set_LOA(struct afb_req_x1 req, unsigned level)
{
	return 1 + req.itf->session_set_LOA(req.closure, level);
}

/**
 * @deprecated use bindings version 3
 *
 * Establishes for the client link identified by 'req' a subscription
 * to the 'event'.
 * Returns 0 in case of successful subscription or -1 in case of error.
 */
static inline int afb_req_x1_subscribe(struct afb_req_x1 req, struct afb_event_x1 event)
{
	return req.itf->legacy_subscribe_event_x1(req.closure, event);
}

/**
 * @deprecated use bindings version 3
 *
 * Revokes the subscription established to the 'event' for the client
 * link identified by 'req'.
 * Returns 0 in case of successful subscription or -1 in case of error.
 */
static inline int afb_req_x1_unsubscribe(struct afb_req_x1 req, struct afb_event_x1 event)
{
	return req.itf->legacy_unsubscribe_event_x1(req.closure, event);
}

/**
 * @deprecated use bindings version 3
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
 * See also:
 *  - 'afb_req_subcall_req' that is convenient to keep request alive automatically.
 *  - 'afb_req_subcall_sync' the synchronous version
 */
static inline void afb_req_x1_subcall(struct afb_req_x1 req, const char *api, const char *verb, struct json_object *args, void (*callback)(void *closure, int iserror, struct json_object *result), void *closure)
{
	req.itf->legacy_subcall(req.closure, api, verb, args, callback, closure);
}

/**
 * @deprecated use bindings version 3
 *
 * Makes a call to the method of name 'api' / 'verb' with the object 'args'.
 * This call is made in the context of the request 'req'.
 * On completion, the function 'callback' is invoked with the
 * original request 'req', the 'closure' given at call and two
 * other parameters: 'iserror' and 'result'.
 * 'status' is 0 on success or negative when on an error reply.
 * 'result' is the json object of the reply, you must not call json_object_put
 * on the result.
 *
 * For convenience, the function calls 'json_object_put' for 'args'.
 * Thus, in the case where 'args' should remain available after
 * the function returns, the function 'json_object_get' shall be used.
 *
 * See also:
 *  - 'afb_req_subcall' that doesn't keep request alive automatically.
 *  - 'afb_req_subcall_sync' the synchronous version
 */
static inline void afb_req_x1_subcall_req(struct afb_req_x1 req, const char *api, const char *verb, struct json_object *args, void (*callback)(void *closure, int iserror, struct json_object *result, struct afb_req_x1 req), void *closure)
{
	req.itf->legacy_subcall_req(req.closure, api, verb, args, callback, closure);
}

/**
 * @deprecated use bindings version 3
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
 * See also:
 *  - 'afb_req_subcall_req' that is convenient to keep request alive automatically.
 *  - 'afb_req_subcall' that doesn't keep request alive automatically.
 */
static inline int afb_req_x1_subcall_sync(struct afb_req_x1 req, const char *api, const char *verb, struct json_object *args, struct json_object **result)
{
	return req.itf->legacy_subcallsync(req.closure, api, verb, args, result);
}

/**
 * @deprecated use bindings version 3
 *
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
 */
static inline void afb_req_x1_verbose(struct afb_req_x1 req, int level, const char *file, int line, const char * func, const char *fmt, ...) __attribute__((format(printf, 6, 7)));
static inline void afb_req_x1_verbose(struct afb_req_x1 req, int level, const char *file, int line, const char * func, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	req.itf->vverbose(req.closure, level, file, line, func, fmt, args);
	va_end(args);
}

/**
 * @deprecated use bindings version 3
 *
 * Check whether the 'permission' is granted or not to the client
 * identified by 'req'.
 *
 * Returns 1 if the permission is granted or 0 otherwise.
 */
static inline int afb_req_x1_has_permission(struct afb_req_x1 req, const char *permission)
{
	return req.itf->has_permission(req.closure, permission);
}

/**
 * @deprecated use bindings version 3
 *
 * Get the application identifier of the client application for the
 * request 'req'.
 *
 * Returns the application identifier or NULL when the application
 * can not be identified.
 *
 * The returned value if not NULL must be freed by the caller
 */
static inline char *afb_req_x1_get_application_id(struct afb_req_x1 req)
{
	return req.itf->get_application_id(req.closure);
}

/**
 * @deprecated use bindings version 3
 *
 * Get the user identifier (UID) of the client application for the
 * request 'req'.
 *
 * Returns -1 when the application can not be identified.
 */
static inline int afb_req_x1_get_uid(struct afb_req_x1 req)
{
	return req.itf->get_uid(req.closure);
}

/**
 * @deprecated use bindings version 3
 *
 * Get informations about the client of the
 * request 'req'.
 *
 * Returns an object with client informations:
 *  {
 *    "pid": int, "uid": int, "gid": int,
 *    "smack": string, "appid": string,
 *    "uuid": string, "LOA": int
 *  }
 */
static inline struct json_object *afb_req_x1_get_client_info(struct afb_req_x1 req)
{
	return req.itf->get_client_info(req.closure);
}



/** @} */
