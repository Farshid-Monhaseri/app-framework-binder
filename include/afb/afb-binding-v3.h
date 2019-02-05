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

/**< @file afb/afb-binding-v3.h */

#pragma once

/******************************************************************************/

#include "afb-auth.h"
#include "afb-event-x2.h"
#include "afb-req-x2.h"
#include "afb-session-x2.h"
#include "afb-api-x3.h"

/******************************************************************************/

/**
 * @page validity-v3 Validity of a binding v3
 *
 * A binding V3 MUST have at least two exported symbols of name:
 *
 *   - @ref afbBindingV3root
 *   - @ref afbBindingV3  and/or  @ref afbBindingV3entry
 *
 * @ref afbBindingV3root is automatically created when **AFB_BINDING_VERSION == 3**
 * without programmer action, as a hidden variable linked as *weak*.
 *
 * The symbols @ref afbBindingV3  and  **afbBindingV3entry** are under control
 * of the programmer.
 *
 * The symbol @ref afbBindingV3 if defined is used, as in binding v2, to describe
 * an API that will be declared during pre-initialization of bindings.
 *
 * The symbol @ref afbBindingV3entry if defined will be called during
 * pre-initialization.
 *
 * If @ref afbBindingV3entry and @ref afbBindingV3 are both defined, it is an
 * error to fill the field @ref preinit of @ref afbBindingV3.
 *
 * @see afb_binding_v3
 * @see afbBindingV3root
 * @see afbBindingV3entry
 * @see afbBindingV3
 */

/**
 * Description of one verb as provided for binding API version 3
 */
struct afb_verb_v3
{
	/** name of the verb, NULL only at end of the array */
	const char *verb;

	/** callback function implementing the verb */
	void (*callback)(struct afb_req_x2 *req);

	/** required authorization, can be NULL */
	const struct afb_auth *auth;

	/** some info about the verb, can be NULL */
	const char *info;

	/**< data for the verb callback */
	void *vcbdata;

	/** authorization and session requirements of the verb */
	uint16_t session;

	/** is the verb glob name */
	uint16_t glob: 1;
};

/**
 * Description of the bindings of type version 3
 */
struct afb_binding_v3
{
	/** api name for the binding, can't be NULL */
	const char *api;

	/** textual specification of the binding, can be NULL */
	const char *specification;

	/** some info about the api, can be NULL */
	const char *info;

	/** array of descriptions of verbs terminated by a NULL name, can be NULL */
	const struct afb_verb_v3 *verbs;

	/** callback at load of the binding */
	int (*preinit)(struct afb_api_x3 *api);

	/** callback for starting the service */
	int (*init)(struct afb_api_x3 *api);

	/** callback for handling events */
	void (*onevent)(struct afb_api_x3 *api, const char *event, struct json_object *object);

	/** userdata for afb_api_x3 */
	void *userdata;

	/** space separated list of provided class(es) */
	const char *provide_class;

	/** space separated list of required class(es) */
	const char *require_class;

	/** space separated list of required API(es) */
	const char *require_api;

	/** avoids concurrent requests to verbs */
	unsigned noconcurrency: 1;
};

/**
 * Default root binding's api that can be used when no explicit context is
 * available.
 *
 * When @ref afbBindingV3 is defined, this variable records the corresponding
 * api handler. Otherwise, it points to an fake handles that allows logging
 * and api creation.
 *
 * @see afbBindingV3entry
 * @see afbBindingV3
 * @see @ref validity-v3
 */
#if AFB_BINDING_VERSION != 3
extern
#endif
struct afb_api_x3 *afbBindingV3root __attribute__((weak));

/**
 * Pre-initialization function.
 *
 * If this function is defined and exported in the produced binding
 * (shared object), it will be called during pre-initialization with the
 * rootapi defined by \ref afbBindingV3root
 *
 * @param rootapi the root api (equals to afbBindingV3root)
 *
 * @return the function must return a negative integer on error to abort the
 * initialization of the binding. Any positive or zero returned value is a
 * interpreted as a success.

 * @see afbBindingV3root
 * @see afbBindingV3
 * @see @ref validity-v3
 */
extern int afbBindingV3entry(struct afb_api_x3 *rootapi);

/**
 * Static definition of the root api of the binding.
 *
 * This symbol if defined describes the API of the binding.
 *
 * If it is not defined then the function @ref afbBindingV3entry must be defined
 *
 * @see afbBindingV3root
 * @see afbBindingV3entry
 * @see @ref validity-v3
 */
extern const struct afb_binding_v3 afbBindingV3;

#include "afb-auth.h"
#include "afb-session-x2.h"
#include "afb-verbosity.h"

#include "afb-event-x2.h"
#include "afb-req-x2.h"
#include "afb-api-x3.h"

/*
 * Macros for logging messages
 */

#if defined(AFB_BINDING_PRAGMA_NO_VERBOSE_DATA)

# define AFB_API_VERBOSE_V3(api,level,...) \
		do { if(level <= AFB_VERBOSITY_LEVEL_ERROR) \
			afb_api_x3_verbose(api,level,__FILE__,__LINE__,NULL,__VA_ARGS__); \
		else afb_api_x3_verbose(api,level,__FILE__,__LINE__,NULL); } while(0)

# define AFB_REQ_VERBOSE_V3(req,level,...) \
		do { if(level <= AFB_VERBOSITY_LEVEL_ERROR) \
			afb_req_x2_verbose(req,level,__FILE__,__LINE__,NULL,__VA_ARGS__); \
		else afb_req_x2_verbose(req,level,__FILE__,__LINE__,NULL); } while(0)

#elif defined(AFB_BINDING_PRAGMA_NO_VERBOSE_DETAILS)

# define AFB_API_VERBOSE_V3(api,level,...) \
	afb_api_x3_verbose(api,level,NULL,0,NULL,__VA_ARGS__)

# define AFB_REQ_VERBOSE_V3(req,level,...) \
	afb_req_x2_verbose(req,level,NULL,0,NULL,__VA_ARGS__)

#else

# define AFB_API_VERBOSE_V3(api,level,...) \
	afb_api_x3_verbose(api,level,__FILE__,__LINE__,__func__,__VA_ARGS__)

# define AFB_REQ_VERBOSE_V3(req,level,...) \
	afb_req_x2_verbose(req,level,__FILE__,__LINE__,__func__,__VA_ARGS__)

#endif

#define _AFB_API_LOGGING_V3_(api,llevel,...) \
        do{ if(afb_api_wants_log_level((api),(llevel))) AFB_API_VERBOSE_V3((api),(llevel),__VA_ARGS__); }while(0)
#define _AFB_REQ_LOGGING_V3_(req,llevel,...) \
        do{ if(afb_req_wants_log_level((req),(llevel))) AFB_REQ_VERBOSE_V3((req),(llevel),__VA_ARGS__); }while(0)

#define AFB_API_ERROR_V3(api,...)		_AFB_API_LOGGING_V3_(api,AFB_SYSLOG_LEVEL_ERROR,__VA_ARGS__)
#define AFB_API_WARNING_V3(api,...)		_AFB_API_LOGGING_V3_(api,AFB_SYSLOG_LEVEL_WARNING,__VA_ARGS__)
#define AFB_API_NOTICE_V3(api,...)		_AFB_API_LOGGING_V3_(api,AFB_SYSLOG_LEVEL_NOTICE,__VA_ARGS__)
#define AFB_API_INFO_V3(api,...)		_AFB_API_LOGGING_V3_(api,AFB_SYSLOG_LEVEL_INFO,__VA_ARGS__)
#define AFB_API_DEBUG_V3(api,...)		_AFB_API_LOGGING_V3_(api,AFB_SYSLOG_LEVEL_DEBUG,__VA_ARGS__)

#define AFB_REQ_ERROR_V3(req,...)		_AFB_REQ_LOGGING_V3_(req,AFB_SYSLOG_LEVEL_ERROR,__VA_ARGS__)
#define AFB_REQ_WARNING_V3(req,...)		_AFB_REQ_LOGGING_V3_(req,AFB_SYSLOG_LEVEL_WARNING,__VA_ARGS__)
#define AFB_REQ_NOTICE_V3(req,...)		_AFB_REQ_LOGGING_V3_(req,AFB_SYSLOG_LEVEL_NOTICE,__VA_ARGS__)
#define AFB_REQ_INFO_V3(req,...)		_AFB_REQ_LOGGING_V3_(req,AFB_SYSLOG_LEVEL_INFO,__VA_ARGS__)
#define AFB_REQ_DEBUG_V3(req,...)		_AFB_REQ_LOGGING_V3_(req,AFB_SYSLOG_LEVEL_DEBUG,__VA_ARGS__)

#define AFB_ERROR_V3(...)			AFB_API_ERROR_V3(afbBindingV3root,__VA_ARGS__)
#define AFB_WARNING_V3(...)			AFB_API_WARNING_V3(afbBindingV3root,__VA_ARGS__)
#define AFB_NOTICE_V3(...)			AFB_API_NOTICE_V3(afbBindingV3root,__VA_ARGS__)
#define AFB_INFO_V3(...)			AFB_API_INFO_V3(afbBindingV3root,__VA_ARGS__)
#define AFB_DEBUG_V3(...)			AFB_API_DEBUG_V3(afbBindingV3root,__VA_ARGS__)

#define afb_get_root_api_v3()			(afbBindingV3root)
#define afb_get_logmask_v3()			(afbBindingV3root->logmask)
#define afb_get_verbosity_v3()			AFB_SYSLOG_LEVEL_TO_VERBOSITY(_afb_verbomask_to_upper_level_(afbBindingV3root->logmask))

#define afb_daemon_get_event_loop_v3()		afb_api_get_event_loop(afbBindingV3root)
#define afb_daemon_get_user_bus_v3()		afb_api_get_user_bus(afbBindingV3root)
#define afb_daemon_get_system_bus_v3()		afb_api_get_system_bus(afbBindingV3root)
#define afb_daemon_broadcast_event_v3(...)	afb_api_broadcast_event(afbBindingV3root,__VA_ARGS__)
#define afb_daemon_make_event_v3(...)		afb_api_make_event(afbBindingV3root,__VA_ARGS__)
#define afb_daemon_verbose_v3(...)		afb_api_verbose(afbBindingV3root,__VA_ARGS__)
#define afb_daemon_rootdir_get_fd_v3()		afb_api_rootdir_get_fd(afbBindingV3root)
#define afb_daemon_rootdir_open_locale_v3(...)	afb_api_rootdir_open_locale(afbBindingV3root,__VA_ARGS__)
#define afb_daemon_queue_job_v3(...)		afb_api_queue_job(afbBindingV3root,__VA_ARGS__)
#define afb_daemon_require_api_v3(...)		afb_api_require_api(afbBindingV3root,__VA_ARGS__)
#define afb_daemon_add_alias_v3(...)		afb_api_add_alias(afbBindingV3root,__VA_ARGS__)

#define afb_service_call_v3(...)		afb_api_call(afbBindingV3root,__VA_ARGS__)
#define afb_service_call_sync_v3(...)		afb_api_call_sync(afbBindingV3root,__VA_ARGS__)
#define afb_service_call_legacy_v3(...)		afb_api_call_legacy(afbBindingV3root,__VA_ARGS__)
#define afb_service_call_sync_legacy_v3(...)	afb_api_call_sync_legacy(afbBindingV3root,__VA_ARGS__)

