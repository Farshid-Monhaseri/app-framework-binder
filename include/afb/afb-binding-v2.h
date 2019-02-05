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

/******************************************************************************/

#include "afb-verbosity.h"
#include "afb-auth.h"
#include "afb-event-x1.h"
#include "afb-req-x1.h"
#include "afb-service-itf-x1.h"
#include "afb-daemon-itf-x1.h"

#include "afb-req-v2.h"
#include "afb-session-x2.h"

/******************************************************************************/

/**
 * @deprecated use bindings version 3
 *
 * Description of one verb as provided for binding API version 2
 */
struct afb_verb_v2
{
        const char *verb;                       /**< name of the verb, NULL only at end of the array */
        void (*callback)(struct afb_req_x1 req);/**< callback function implementing the verb */
        const struct afb_auth *auth;		/**< required authorisation, can be NULL */
        const char *info;			/**< some info about the verb, can be NULL */
        uint32_t session;                       /**< authorisation and session requirements of the verb */
};

/**
 * @deprecated use bindings version 3
 *
 * Description of the bindings of type version 2
 */
struct afb_binding_v2
{
        const char *api;			/**< api name for the binding */
        const char *specification;		/**< textual specification of the binding, can be NULL */
        const char *info;			/**< some info about the api, can be NULL */
        const struct afb_verb_v2 *verbs;	/**< array of descriptions of verbs terminated by a NULL name */
        int (*preinit)();                       /**< callback at load of the binding */
        int (*init)();                          /**< callback for starting the service */
        void (*onevent)(const char *event, struct json_object *object); /**< callback for handling events */
        unsigned noconcurrency: 1;		/**< avoids concurrent requests to verbs */
};

/**
 * @deprecated use bindings version 3
 *
 * structure for the global data of the binding
 */
struct afb_binding_data_v2
{
        int verbosity;			/**< level of verbosity */
        struct afb_daemon_x1 daemon;	/**< access to daemon APIs */
        struct afb_service_x1 service;	/**< access to service APIs */
};

/**
 * @page validity-v2 Validity of a binding v2
 *
 * A binding V2 MUST have two exported symbols of name:
 *
 *            -  @ref afbBindingV2
 *            -  @ref afbBindingV2data
 */

/**
 * @deprecated use bindings version 3
 *
 * The global mandatory description of the binding
 */
#if !defined(AFB_BINDING_MAIN_NAME_V2)
extern const struct afb_binding_v2 afbBindingV2;
#endif

/**
 * @deprecated use bindings version 3
 *
 * The global auto declared internal data of the binding
 */
#if AFB_BINDING_VERSION != 2
extern
#endif
struct afb_binding_data_v2 afbBindingV2data  __attribute__ ((weak));

#define afb_get_verbosity_v2()	(afbBindingV2data.verbosity)
#define afb_get_daemon_v2()	(afbBindingV2data.daemon)
#define afb_get_service_v2()	(afbBindingV2data.service)

/******************************************************************************/
/*
 * Macros for logging messages
 */
#if defined(AFB_BINDING_PRAGMA_NO_VERBOSE_DATA)

#define AFB_VERBOSE_V2(level,...) \
		do { if(level <= AFB_VERBOSITY_LEVEL_ERROR) \
			afb_daemon_verbose_v2(level,__FILE__,__LINE__,NULL,__VA_ARGS__); \
		else afb_daemon_verbose_v2(level,__FILE__,__LINE__,NULL); } while(0)

#define AFB_REQ_VERBOSE_V2(req,level,...) \
		do { if(level <= AFB_VERBOSITY_LEVEL_ERROR) \
			afb_req_x1_verbose(req,level,__FILE__,__LINE__,NULL,__VA_ARGS__); \
		else afb_req_x1_verbose(req,level,__FILE__,__LINE__,NULL); } while(0)

#elif defined(AFB_BINDING_PRAGMA_NO_VERBOSE_DETAILS)

#define AFB_VERBOSE_V2(level,...) \
		afb_daemon_verbose_v2(level,NULL,0,NULL,__VA_ARGS__)

#define AFB_REQ_VERBOSE_V2(req,level,...) \
		afb_req_x1_verbose(req,level,NULL,0,NULL,__VA_ARGS__)

#else

#define AFB_VERBOSE_V2(level,...) \
		afb_daemon_verbose_v2(level,__FILE__,__LINE__,__func__,__VA_ARGS__)

#define AFB_REQ_VERBOSE_V2(req,level,...) \
		afb_req_x1_verbose(req,level,__FILE__,__LINE__,__func__,__VA_ARGS__)

#endif

#define _AFB_LOGGING_V2_(vlevel,llevel,...) \
        do{ if(afb_get_verbosity_v2()>=vlevel) AFB_VERBOSE_V2(llevel,__VA_ARGS__); } while(0)
#define _AFB_REQ_LOGGING_V2_(vlevel,llevel,req,...) \
        do{ if(afb_get_verbosity_v2()>=vlevel) AFB_REQ_VERBOSE_V2(req,llevel,__VA_ARGS__); } while(0)

#define AFB_ERROR_V2(...)       _AFB_LOGGING_V2_(AFB_VERBOSITY_LEVEL_ERROR,AFB_SYSLOG_LEVEL_ERROR,__VA_ARGS__)
#define AFB_WARNING_V2(...)     _AFB_LOGGING_V2_(AFB_VERBOSITY_LEVEL_WARNING,AFB_SYSLOG_LEVEL_WARNING,__VA_ARGS__)
#define AFB_NOTICE_V2(...)      _AFB_LOGGING_V2_(AFB_VERBOSITY_LEVEL_NOTICE,AFB_SYSLOG_LEVEL_NOTICE,__VA_ARGS__)
#define AFB_INFO_V2(...)        _AFB_LOGGING_V2_(AFB_VERBOSITY_LEVEL_INFO,AFB_SYSLOG_LEVEL_INFO,__VA_ARGS__)
#define AFB_DEBUG_V2(...)       _AFB_LOGGING_V2_(AFB_VERBOSITY_LEVEL_DEBUG,AFB_SYSLOG_LEVEL_DEBUG,__VA_ARGS__)
#define AFB_REQ_ERROR_V2(...)   _AFB_REQ_LOGGING_V2_(AFB_VERBOSITY_LEVEL_ERROR,AFB_SYSLOG_LEVEL_ERROR,__VA_ARGS__)
#define AFB_REQ_WARNING_V2(...) _AFB_REQ_LOGGING_V2_(AFB_VERBOSITY_LEVEL_WARNING,AFB_SYSLOG_LEVEL_WARNING,__VA_ARGS__)
#define AFB_REQ_NOTICE_V2(...)  _AFB_REQ_LOGGING_V2_(AFB_VERBOSITY_LEVEL_NOTICE,AFB_SYSLOG_LEVEL_NOTICE,__VA_ARGS__)
#define AFB_REQ_INFO_V2(...)    _AFB_REQ_LOGGING_V2_(AFB_VERBOSITY_LEVEL_INFO,AFB_SYSLOG_LEVEL_INFO,__VA_ARGS__)
#define AFB_REQ_DEBUG_V2(...)   _AFB_REQ_LOGGING_V2_(AFB_VERBOSITY_LEVEL_DEBUG,AFB_SYSLOG_LEVEL_DEBUG,__VA_ARGS__)

/******************************************************************************/

#if 0 && AFB_BINDING_VERSION >= 2

# define afb_verbose_error()	(afb_get_verbosity() >= AFB_VERBOSITY_LEVEL_ERROR)
# define afb_verbose_warning()	(afb_get_verbosity() >= AFB_VERBOSITY_LEVEL_WARNING)
# define afb_verbose_notice()	(afb_get_verbosity() >= AFB_VERBOSITY_LEVEL_NOTICE)
# define afb_verbose_info()	(afb_get_verbosity() >= AFB_VERBOSITY_LEVEL_INFO)
# define afb_verbose_debug()	(afb_get_verbosity() >= AFB_VERBOSITY_LEVEL_DEBUG)

#endif

#include "afb-daemon-v2.h"
#include "afb-service-v2.h"

