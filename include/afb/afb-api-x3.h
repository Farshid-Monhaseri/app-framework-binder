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

#pragma once

#include "afb-verbosity.h"
#include "afb-api-x3-itf.h"

/** @defgroup AFB_API
 *  @{ */

/**
 * Get the name of the 'api'.
 *
 * @param api the api whose name is to be returned
 *
 * @return the name of the api.
 *
 * The returned value must not be changed nor freed.
 */
static inline
const char *afb_api_x3_name(
			struct afb_api_x3 *api)
{
	return api->apiname;
}

/**
 * Get the "userdata" pointer of the 'api'
 *
 * @param api the api whose user's data is to be returned
 *
 * @return the user's data  pointer of the api.
 *
 * @see afb_api_x3_set_userdata
 */
static inline
void *afb_api_x3_get_userdata(
			struct afb_api_x3 *api)
{
	return api->userdata;
}

/**
 * Set the "userdata" pointer of the 'api' to 'value'
 *
 * @param api   the api whose user's data is to be set
 * @param value the data to set
 *
 * @see afb_api_x3_get_userdata
 */
static inline
void afb_api_x3_set_userdata(
			struct afb_api_x3 *api,
			void *value)
{
	api->userdata = value;
}

/**
 * Is the log message of 'level (as defined for syslog) required for the api?
 *
 * @param api   the api to check
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
int afb_api_x3_wants_log_level(
			struct afb_api_x3 *api,
			int level)
{
	return AFB_SYSLOG_MASK_WANT(api->logmask, level);
}

/**
 * Send to the journal with the logging 'level' a message described
 * by 'fmt' applied to the va-list 'args'.
 *
 * 'file', 'line' and 'func' are indicators of code position in source files
 * (see macros __FILE__, __LINE__ and __func__).
 *
 * 'level' is defined by syslog standard:
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
 * @param api the api that collects the logging message
 * @param level the level of the message
 * @param file the source file that logs the messages or NULL
 * @param line the line in the source file that logs the message
 * @param func the name of the function in the source file that logs (or NULL)
 * @param fmt the format of the message as in printf
 * @param args the arguments to the format string of the message as a va_list
 *
 * @see syslog
 * @see printf
 */
static inline
void afb_api_x3_vverbose(
			struct afb_api_x3 *api,
			int level,
			const char *file,
			int line,
			const char *func,
			const char *fmt,
			va_list args)
{
	api->itf->vverbose(api, level, file, line, func, fmt, args);
}

/**
 * Send to the journal with the log 'level' a message described
 * by 'fmt' and following parameters.
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
 * @param api the api that collects the logging message
 * @param level the level of the message
 * @param file the source file that logs the messages or NULL
 * @param line the line in the source file that logs the message
 * @param func the name of the function in the source file that logs (or NULL)
 * @param fmt the format of the message as in printf
 * @param ... the arguments to the format string of the message
 *
 * @see syslog
 * @see printf
 */
__attribute__((format(printf, 6, 7)))
static inline
void afb_api_x3_verbose(
		struct afb_api_x3 *api,
		int level,
		const char *file,
		int line,
		const char *func,
		const char *fmt,
		...)
{
	va_list args;
	va_start(args, fmt);
	api->itf->vverbose(api, level, file, line, func, fmt, args);
	va_end(args);
}

/**
 * Retrieves the common systemd's event loop of AFB
 *
 * @param api the api that uses the event loop
 *
 * @return the systemd event loop if active, NULL otherwise
 *
 * @see afb_api_x3_get_user_bus
 * @see afb_api_x3_get_system_bus
 */
static inline
struct sd_event *afb_api_x3_get_event_loop(
			struct afb_api_x3 *api)
{
	return api->itf->get_event_loop(api);
}

/**
 * Retrieves the common systemd's user/session d-bus of AFB
 *
 * @param api the api that uses the user dbus
 *
 * @return the systemd user connection to dbus if active, NULL otherwise
 *
 * @see afb_api_x3_get_event_loop
 * @see afb_api_x3_get_system_bus
 */
static inline
struct sd_bus *afb_api_x3_get_user_bus(
			struct afb_api_x3 *api)
{
	return api->itf->get_user_bus(api);
}

/**
 * Retrieves the common systemd's system d-bus of AFB
 *
 * @param api the api that uses the system dbus
 *
 * @return the systemd system connection to dbus if active, NULL otherwise
 *
 * @see afb_api_x3_get_event_loop
 * @see afb_api_x3_get_user_bus
 */

static inline
struct sd_bus *afb_api_x3_get_system_bus(
			struct afb_api_x3 *api)
{
	return api->itf->get_system_bus(api);
}

/**
 * Get the root directory file descriptor. This file descriptor can
 * be used with functions 'openat', 'fstatat', ...
 *
 * CAUTION, manipulate this this descriptor with care, in particular, don't close
 * it.
 *
 * This can be used to get the path of the root directory using:
 *
 * ```C
 * char buffer[MAX_PATH], proc[100];
 * int dirfd = afb_api_rootdir_get_fd(api);
 * snprintf(proc, sizeof proc, "/proc/self/fd/%d", dirfd);
 * readlink(proc, buffer, sizeof buffer);
 * ```
 *
 * But note that within AGL this is the value given by the environment variable
 * AFM_APP_INSTALL_DIR.
 *
 * @param api the api that uses the directory file descriptor
 *
 * @return the file descriptor of the root directory.
 *
 * @see afb_api_x3_rootdir_open_locale
 */
static inline
int afb_api_x3_rootdir_get_fd(
			struct afb_api_x3 *api)
{
	return api->itf->rootdir_get_fd(api);
}

/**
 * Opens 'filename' within the root directory with 'flags' (see function openat)
 * using the 'locale' definition (example: "jp,en-US") that can be NULL.
 *
 * The filename must be relative to the root of the bindings.
 *
 * The opening mode must be for read or write but not for O_CREAT.
 *
 * The definition of locales and of how files are searched can be checked
 * here: https://www.w3.org/TR/widgets/#folder-based-localization
 * and https://tools.ietf.org/html/rfc7231#section-5.3.5
 *
 * @param api the api that queries the file
 * @param filename the relative path to the file to open
 * @param flags the flags for opening as for C function 'open'
 * @param locale string indicating how to search content, can be NULL
 *
 * @return the file descriptor or -1 in case of error and errno is set with the
 * error indication.
 *
 * @see open
 * @see afb_api_x3_rootdir_get_fd
 */
static inline
int afb_api_x3_rootdir_open_locale(
			struct afb_api_x3 *api,
			const char *filename,
			int flags,
			const char *locale)
{
	return api->itf->rootdir_open_locale(api, filename, flags, locale);
}

/**
 * Queue the job defined by 'callback' and 'argument' for being executed asynchronously
 * in this thread (later) or in an other thread.
 *
 * If 'group' is not NULL, the jobs queued with a same value (as the pointer value 'group')
 * are executed in sequence in the order of there submission.
 *
 * If 'timeout' is not 0, it represent the maximum execution time for the job in seconds.
 * At first, the job is called with 0 as signum and the given argument.
 *
 * The job is executed with the monitoring of its time and some signals like SIGSEGV and
 * SIGFPE. When a such signal is catched, the job is terminated and reexecuted but with
 * signum being the signal number (SIGALRM when timeout expired).
 *
 * When executed, the callback function receives 2 arguments:
 *
 *  - int signum: the signal catched if any or zero at the beginning
 *  - void *arg: the parameter 'argument'
 *
 * A typical implementation of the job callback is:
 *
 * ```C
 * void my_job_cb(int signum, void *arg)
 * {
 *	struct myarg_t *myarg = arg;
 *	if (signum)
 *		AFB_API_ERROR(myarg->api, "job interrupted with signal %s", strsignal(signum));
 *	else
 *		really_do_my_job(myarg);
 * }
 * ```
 *
 * @param api the api that queue the job
 * @param callback the job as a callback function
 * @param argument the argument to pass to the queued job
 * @param group the group of the job, NULL if no group
 * @param timeout the timeout of execution of the job
 *
 * @return 0 in case of success or -1 in case of error with errno set appropriately.
 */
static inline
int afb_api_x3_queue_job(
			struct afb_api_x3 *api,
			void (*callback)(int signum, void *arg),
			void *argument,
			void *group,
			int timeout)
{
	return api->itf->queue_job(api, callback, argument, group, timeout);
}

/**
 * Check that it requires the API of 'name'.
 * If 'initialized' is not zero it request the API to be
 * initialized, implying its initialization if needed.
 *
 * Calling this function is only allowed within init.
 *
 * A single request allows to require multiple apis.
 *
 * @param api the api that requires the other api by its name
 * @param name a space separated list of required api names
 * @param initialized if zero, the api is just required to exist. If not zero,
 * the api is required to exist and to be initialized at return of the call
 * (initializing it if needed and possible as a side effect of the call).
 *
 * @return 0 in case of success or -1 in case of error with errno set appropriately.
 */
static inline
int afb_api_x3_require_api(
			struct afb_api_x3 *api,
			const char *name,
			int initialized)
{
	return api->itf->require_api(api, name, initialized);
}

/**
 * Create an aliased name 'as_name' for the api 'name'.
 * Calling this function is only allowed within preinit.
 *
 * @param api the api that requires the aliasing
 * @param name the api to alias
 * @param as_name the aliased name of the aliased api
 *
 * @return 0 in case of success or -1 in case of error with errno set appropriately.
 */
static inline
int afb_api_x3_add_alias(
			struct afb_api_x3 *api,
			const char *name,
			const char *as_name)
{
	return api->itf->add_alias(api, name, as_name);
}

/**
 * Broadcasts widely the event of 'name' with the data 'object'.
 * 'object' can be NULL.
 *
 * For convenience, the function calls 'json_object_put' for 'object'.
 * Thus, in the case where 'object' should remain available after
 * the function returns, the function 'json_object_get' shall be used.
 *
 * Calling this function is only forbidden during preinit.
 *
 * The event sent as the name API/name where API is the name of the
 * api.
 *
 * @param api the api that broadcast the event
 * @param name the event name suffix
 * @param object the object that comes with the event
 *
 * @return the count of clients that received the event.
 */
static inline
int afb_api_x3_broadcast_event(
			struct afb_api_x3 *api,
			const char *name,
			struct json_object *object)
{
	return api->itf->event_broadcast(api, name, object);
}

/**
 * Creates an event of 'name' and returns it.
 *
 * Calling this function is only forbidden during preinit.
 *
 * See afb_event_is_valid to check if there is an error.
 *
 * The event created as the name API/name where API is the name of the
 * api.
 *
 * @param api the api that creates the event
 * @param name the event name suffix
 *
 * @return the created event. Use the function afb_event_is_valid to check
 * whether the event is valid (created) or not (error as reported by errno).
 *
 * @see afb_event_is_valid
 */
static inline
struct afb_event_x2 *afb_api_x3_make_event_x2(
			struct afb_api_x3 *api,
			const char *name)
{
	return api->itf->event_make(api, name);
}

/**
 * @deprecated try to use @ref afb_api_x3_call instead
 *
 *  * Calls the 'verb' of the 'api' with the arguments 'args' and 'verb' in the name of the binding.
 * The result of the call is delivered to the 'callback' function with the 'callback_closure'.
 *
 * For convenience, the function calls 'json_object_put' for 'args'.
 * Thus, in the case where 'args' should remain available after
 * the function returns, the function 'json_object_get' shall be used.
 *
 * The 'callback' receives 3 arguments:
 *  1. 'closure' the user defined closure pointer 'closure',
 *  2. 'status' a status being 0 on success or negative when an error occurred,
 *  2. 'result' the resulting data as a JSON object.
 *
 * @param api      The api
 * @param apiname  The api name of the method to call
 * @param verb     The verb name of the method to call
 * @param args     The arguments to pass to the method
 * @param callback The to call on completion
 * @param closure  The closure to pass to the callback
 *
 * @see also 'afb_api_call'
 * @see also 'afb_api_call_sync'
 * @see also 'afb_api_call_sync_legacy'
 * @see also 'afb_req_subcall'
 * @see also 'afb_req_subcall_sync'
 */
static inline
void afb_api_x3_call_legacy(
			struct afb_api_x3 *api,
			const char *apiname,
			const char *verb,
			struct json_object *args,
			void (*callback)(void *closure,
					int status,
					struct json_object *result,
					struct afb_api_x3 *api),
			void *closure)
{
	api->itf->legacy_call(api, apiname, verb, args, callback, closure);
}

/**
 * @deprecated try to use @ref afb_api_x3_call_sync instead
 *
 * Calls the 'verb' of the 'api' with the arguments 'args' and 'verb' in the name of the binding.
 * 'result' will receive the response.
 *
 * For convenience, the function calls 'json_object_put' for 'args'.
 * Thus, in the case where 'args' should remain available after
 * the function returns, the function 'json_object_get' shall be used.
 *
 * @param api      The api
 * @param apiname  The api name of the method to call
 * @param verb     The verb name of the method to call
 * @param args     The arguments to pass to the method
 * @param result   Where to store the result - should call json_object_put on it -
 *
 * @returns 0 in case of success or a negative value in case of error.
 *
 * @see also 'afb_api_call'
 * @see also 'afb_api_call_sync'
 * @see also 'afb_api_call_legacy'
 * @see also 'afb_req_subcall'
 * @see also 'afb_req_subcall_sync'
 */
static inline
int afb_api_x3_call_sync_legacy(
			struct afb_api_x3 *api,
			const char *apiname,
			const char *verb,
			struct json_object *args,
			struct json_object **result)
{
	return api->itf->legacy_call_sync(api, apiname, verb, args, result);
}

/**
 * Creates a new api of name 'apiname' briefly described by 'info' (that can
 * be NULL).
 *
 * When the pre-initialization function is given, it is a function that
 * receives 2 parameters:
 *
 *  - the closure as given in the call
 *  - the created api that can be initialised
 *
 * This pre-initialization function must return a negative value to abort
 * the creation of the api. Otherwise, it returns a non-negative value to
 * continue.
 *
 * @param api the api that creates the other one
 * @param apiname the name of the new api
 * @param info the brief description of the new api (can be NULL)
 * @param noconcurrency zero or not zero whether the new api is reentrant or not
 * @param preinit the pre-initialization function if any (can be NULL)
 * @param closure the closure for the pre-initialization preinit
 *
 * @return the created api in case of success or NULL on error
 *
 * @see afb_api_x3_delete_api
 */
static inline
struct afb_api_x3 *afb_api_x3_new_api(
			struct afb_api_x3 *api,
			const char *apiname,
			const char *info,
			int noconcurrency,
			int (*preinit)(void*, struct afb_api_x3 *),
			void *closure)
{
	return api->itf->api_new_api(api, apiname, info, noconcurrency, preinit, closure);
}

/**
 * @deprecated use @ref afb_api_x3_set_verbs_v3 instead
 *
 * Set the verbs of the 'api' using description of verbs of the api v2
 *
 * @param api the api that will get the verbs
 * @param verbs the array of verbs to add terminated with an item with name=NULL
 *
 * @return 0 in case of success or -1 on failure with errno set
 *
 * @see afb_verb_v2
 * @see afb_api_x3_add_verb
 * @see afb_api_x3_set_verbs_v3
 */
static inline
int afb_api_x3_set_verbs_v2(
			struct afb_api_x3 *api,
			const struct afb_verb_v2 *verbs)
{
	return api->itf->api_set_verbs_v2(api, verbs);
}

/**
 * Add one verb to the dynamic set of the api
 *
 * @param api the api to change
 * @param verb name of the verb
 * @param info brief description of the verb, can be NULL
 * @param callback callback function implementing the verb
 * @param vcbdata data for the verb callback, available through req
 * @param auth required authorization, can be NULL
 * @param session authorization and session requirements of the verb
 * @param glob is the verb glob name
 *
 * @return 0 in case of success or -1 on failure with errno set
 *
 * @see afb_verb_v3
 * @see afb_api_x3_del_verb
 * @see afb_api_x3_set_verbs_v3
 * @see fnmatch for matching names using glob
 */
static inline
int afb_api_x3_add_verb(
			struct afb_api_x3 *api,
			const char *verb,
			const char *info,
			void (*callback)(struct afb_req_x2 *req),
			void *vcbdata,
			const struct afb_auth *auth,
			uint32_t session,
			int glob)
{
	return api->itf->api_add_verb(api, verb, info, callback, vcbdata, auth, session, glob);
}

/**
 * Delete one verb from the dynamic set of the api
 *
 * @param api the api to change
 * @param verb name of the verb to delete
 * @param vcbdata if not NULL will receive the vcbdata of the deleted verb
 *
 * @return 0 in case of success or -1 on failure with errno set
 *
 * @see afb_api_x3_add_verb
 */
static inline
int afb_api_x3_del_verb(
			struct afb_api_x3 *api,
			const char *verb,
			void **vcbdata)
{
	return api->itf->api_del_verb(api, verb, vcbdata);
}

/**
 * Set the callback 'onevent' to process events in the name of the 'api'.
 *
 * This setting can be done statically using the global variable
 * @ref afbBindingV3.
 *
 * This function replace any previously global event callback set.
 *
 * When an event is received, the callback 'onevent' is called with 3 parameters
 *
 *  - the api that recorded the event handler
 *  - the full name of the event
 *  - the companion JSON object of the event
 *
 * @param api the api that wants to process events
 * @param onevent the callback function that will process events (can be NULL
 *        to remove event callback)
 *
 * @return 0 in case of success or -1 on failure with errno set
 *
 * @see afbBindingV3
 * @see afb_binding_v3
 * @see afb_api_x3_event_handler_add
 * @see afb_api_x3_event_handler_del
 */
static inline
int afb_api_x3_on_event(
			struct afb_api_x3 *api,
			void (*onevent)(
				struct afb_api_x3 *api,
				const char *event,
				struct json_object *object))
{
	return api->itf->api_set_on_event(api, onevent);
}

/**
 * Set the callback 'oninit' to process initialization of the 'api'.
 *
 * This setting can be done statically using the global variable
 * @ref afbBindingV3
 *
 * This function replace any previously initialization callback set.
 *
 * This function is only valid during the pre-initialization stage.
 *
 * The callback initialization function will receive one argument: the api
 * to initialize.
 *
 * @param api the api that wants to process events
 * @param oninit the callback function that initialize the api
 *
 * @return 0 in case of success or -1 on failure with errno set
 *
 * @see afbBindingV3
 * @see afb_binding_v3
 */
static inline
int afb_api_x3_on_init(
			struct afb_api_x3 *api,
			int (*oninit)(struct afb_api_x3 *api))
{
	return api->itf->api_set_on_init(api, oninit);
}

/**
 * Seal the api. After a call to this function the api can not be modified
 * anymore.
 *
 * @param api the api to be sealed
 */
static inline
void afb_api_x3_seal(
			struct afb_api_x3 *api)
{
	api->itf->api_seal(api);
}

/**
 * Set the verbs of the 'api' using description of verbs of the api v2
 *
 * @param api the api that will get the verbs
 * @param verbs the array of verbs to add terminated with an item with name=NULL
 *
 * @return 0 in case of success or -1 on failure with errno set
 *
 * @see afb_verb_v3
 * @see afb_api_x3_add_verb
 * @see afb_api_x3_del_verb
 */
static inline
int afb_api_x3_set_verbs_v3(
			struct afb_api_x3 *api,
			const struct afb_verb_v3 *verbs)
{
	return api->itf->api_set_verbs_v3(api, verbs);
}

/**
 * Add a specific event handler for the api
 *
 * The handler callback is called when an event matching the given pattern
 * is received (it is received if broadcasted or after subscription through
 * a call or a subcall).
 *
 * The handler callback receive 4 arguments:
 *
 *  - the closure given here
 *  - the event full name
 *  - the companion JSON object of the event
 *  - the api that subscribed the event
 *
 * @param api the api that creates the handler
 * @param pattern the global pattern of the event to handle
 * @param callback the handler callback function
 * @param closure the closure of the handler
 *
 * @return 0 in case of success or -1 on failure with errno set
 *
 * @see afb_api_x3_on_event
 * @see afb_api_x3_event_handler_del
 */
static inline
int afb_api_x3_event_handler_add(
			struct afb_api_x3 *api,
			const char *pattern,
			void (*callback)(
				void *,
				const char*,
				struct json_object*,
				struct afb_api_x3*),
			void *closure)
{
	return api->itf->event_handler_add(api, pattern, callback, closure);
}

/**
 * Delete a specific event handler for the api
 *
 * @param api the api that the handler belongs to
 * @param pattern the global pattern of the handler to remove
 * @param closure if not NULL it will receive the closure set to the handler
 *
 * @return 0 in case of success or -1 on failure with errno set
 *
 * @see afb_api_x3_on_event
 * @see afb_api_x3_event_handler_add
 */
static inline
int afb_api_x3_event_handler_del(
			struct afb_api_x3 *api,
			const char *pattern,
			void **closure)
{
	return api->itf->event_handler_del(api, pattern, closure);
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
 *  3. 'error'   a string not NULL in case of error but NULL on success
 *  4. 'info'    a string handling some info (can be NULL)
 *  5. 'api'     the api
 *
 * NOTE: For convenience, *json_object_put* is called on 'object' after the
 * callback returns. So, it is wrong to call *json_object_put* in the callback.
 *
 * @param api      The api that makes the call
 * @param apiname  The api name of the method to call
 * @param verb     The verb name of the method to call
 * @param args     The arguments to pass to the method
 * @param callback The to call on completion
 * @param closure  The closure to pass to the callback
 *
 * @see afb_req_subcall
 * @see afb_req_subcall_sync
 * @see afb_api_x3_call_sync
 */
static inline
void afb_api_x3_call(
			struct afb_api_x3 *api,
			const char *apiname,
			const char *verb,
			struct json_object *args,
			void (*callback)(
				void *closure,
				struct json_object *object,
				const char *error,
				const char * info,
				struct afb_api_x3 *api),
			void *closure)
{
	api->itf->call(api, apiname, verb, args, callback, closure);
}

/**
 * Calls the 'verb' of the 'api' with the arguments 'args' and 'verb' in the name of the binding.
 * 'result' will receive the response.
 *
 * For convenience, the function calls 'json_object_put' for 'args'.
 * Thus, in the case where 'args' should remain available after
 * the function returns, the function 'json_object_get' shall be used.
 *
 * @param api      The api that makes the call
 * @param apiname  The api name of the method to call
 * @param verb     The verb name of the method to call
 * @param args     The arguments to pass to the method
 * @param object   Where to store the returned object - should call json_object_put on it - can be NULL
 * @param error    Where to store the copied returned error - should call free on it - can be NULL
 * @param info     Where to store the copied returned info - should call free on it - can be NULL
 *
 * @returns 0 in case of success or a negative value in case of error.
 *
 * @see afb_req_subcall
 * @see afb_req_subcall_sync
 * @see afb_api_x3_call
 */
static inline
int afb_api_x3_call_sync(
			struct afb_api_x3 *api,
			const char *apiname,
			const char *verb,
			struct json_object *args,
			struct json_object **object,
			char **error,
			char **info)
{
	return api->itf->call_sync(api, apiname, verb, args, object, error, info);
}

/**
 * Tells that the api provides a class of features. Classes are intended to
 * allow ordering of initializations: apis that provides a given class are
 * initialized before apis requiring it.
 *
 * This function is only valid during the pre-initialization stage.
 *
 * @param api  the api that provides the classes
 * @param name a space separated list of the names of the provided classes
 *
 * @returns 0 in case of success or a negative value in case of error.
 *
 * @see afb_api_x3_require_class
 */
static inline
int afb_api_x3_provide_class(
			struct afb_api_x3 *api,
			const char *name)
{
	return api->itf->class_provide(api, name);
}

/**
 * Tells that the api requires a set of class features. Classes are intended to
 * allow ordering of initializations: apis that provides a given class are
 * initialized before apis requiring it.
 *
 * This function is only valid during the pre-initialization stage.
 *
 * @param api  the api that requires the classes
 * @param name a space separated list of the names of the required classes
 *
 * @returns 0 in case of success or a negative value in case of error.
 *
 * @see afb_api_x3_provide_class
 */
static inline
int afb_api_x3_require_class(
			struct afb_api_x3 *api,
			const char *name)
{
	return api->itf->class_require(api, name);
}

/**
 * Delete the given api.
 *
 * It is of the responsibility of the caller to don't used the deleted api
 * anymore after this function returned.
 *
 * @param api the api to delete
 *
 * @returns 0 in case of success or a negative value in case of error.
 *
 * @see afb_api_x3_new_api
 */
static inline
int afb_api_x3_delete_api(
			struct afb_api_x3 *api)
{
	return api->itf->delete_api(api);
}

/**
 * Settings of the api.
 *
 * Get the settings of the API. The settings are recorded
 * as a JSON object. The returned object should not be modified.
 * It MUST NOT be released using json_object_put.
 *
 * @param api the api whose settings are required
 *
 * @returns The setting object.
 */
static inline
struct json_object *afb_api_x3_settings(
			struct afb_api_x3 *api)
{
	return api->itf->settings(api);
}

/** @} */
