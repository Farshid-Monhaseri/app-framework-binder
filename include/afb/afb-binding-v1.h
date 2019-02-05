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
#include "afb-req-x1.h"
#include "afb-event-x1.h"
#include "afb-service-itf-x1.h"
#include "afb-daemon-itf-x1.h"

#include "afb-req-v1.h"
#include "afb-session-x1.h"
#include "afb-service-v1.h"
#include "afb-daemon-v1.h"

struct afb_binding_v1;
struct afb_binding_interface_v1;

/******************************************************************************/

/**
 * @deprecated use bindings version 3
 *
 * Function for registering the binding
 *
 * A binding V1 MUST have an exported function of name
 *
 *              afbBindingV1Register
 *
 * This function is called during loading of the binding. It
 * receives an 'interface' that should be recorded for later access to
 * functions provided by the framework.
 *
 * This function MUST return the address of a structure that describes
 * the binding and its implemented verbs.
 *
 * In case of initialisation error, NULL must be returned.
 *
 * Be aware that the given 'interface' is not fully functionnal
 * because no provision is given to the name and description
 * of the binding. Check the function 'afbBindingV1ServiceInit'
 * defined in the file <afb/afb-service-v1.h> because when
 * the function 'afbBindingV1ServiceInit' is called, the 'interface'
 * is fully functionnal.
 */
extern const struct afb_binding_v1 *afbBindingV1Register (const struct afb_binding_interface_v1 *interface);

/**
 * @deprecated use bindings version 3
 *
 * When a binding have an exported implementation of the
 * function 'afbBindingV1ServiceInit', defined below,
 * the framework calls it for initialising the service after
 * registration of all bindings.
 *
 * The object 'service' should be recorded. It has functions that
 * allows the binding to call features with its own personality.
 *
 * The function should return 0 in case of success or, else, should return
 * a negative value.
 */
extern int afbBindingV1ServiceInit(struct afb_service_x1 service);

/**
 * @deprecated use bindings version 3
 *
 * When a binding have an implementation of the function 'afbBindingV1ServiceEvent',
 * defined below, the framework calls that function for any broadcasted event or for
 * events that the service subscribed to in its name.
 *
 * It receive the 'event' name and its related data in 'object' (be aware that 'object'
 * might be NULL).
 */
extern void afbBindingV1ServiceEvent(const char *event, struct json_object *object);


/**
 * @deprecated use bindings version 3
 *
 * Description of one verb of the API provided by the binding
 * This enumeration is valid for bindings of type version 1
 */
struct afb_verb_desc_v1
{
       const char *name;                       /**< name of the verb */
       enum afb_session_flags_x1 session;      /**< authorisation and session requirements of the verb */
       void (*callback)(struct afb_req_x1 req);/**< callback function implementing the verb */
       const char *info;                       /**< textual description of the verb */
};

/**
 * @deprecated use bindings version 3
 *
 * Description of the bindings of type version 1
 */
struct afb_binding_desc_v1
{
       const char *info;                       /**< textual information about the binding */
       const char *prefix;                     /**< required prefix name for the binding */
       const struct afb_verb_desc_v1 *verbs;   /**< array of descriptions of verbs terminated by a NULL name */
};

/**
 * @deprecated use bindings version 3
 *
 * Definition of the type+versions of the binding version 1.
 * The definition uses hashes.
 */
enum  afb_binding_type_v1
{
       AFB_BINDING_VERSION_1 = 123456789
};

/**
 * @deprecated use bindings version 3
 *
 * Description of a binding version 1
 */
struct afb_binding_v1
{
       enum afb_binding_type_v1 type; /**< type of the binding */
       union {
               struct afb_binding_desc_v1 v1;   /**< description of the binding of type 1 */
       };
};

/**
 * @deprecated use bindings version 3
 *
 * config mode for bindings version 1
 */
enum afb_mode_v1
{
        AFB_MODE_LOCAL = 0,     /**< run locally */
        AFB_MODE_REMOTE,        /**< run remotely */
        AFB_MODE_GLOBAL         /**< run either remotely or locally (DONT USE! reserved for future) */
};

/**
 * @deprecated use bindings version 3
 *
 * Interface between the daemon and the binding version 1.
 */
struct afb_binding_interface_v1
{
        struct afb_daemon_x1 daemon;    /**< access to the daemon facilies */
        int verbosity;                  /**< level of verbosity */
        enum afb_mode_v1 mode;          /**< run mode (local or remote) */
};

/******************************************************************************/
/*
 * Macros for logging messages
 */
#if defined(AFB_BINDING_PRAGMA_NO_VERBOSE_DATA)

# define AFB_VERBOSE_V1(itf,level,...) \
		do { if(level <= AFB_VERBOSITY_LEVEL_ERROR) \
			afb_daemon_verbose2_v1(itf->daemon,level,__FILE__,__LINE__,NULL,__VA_ARGS__); \
		else afb_daemon_verbose2_v1(itf->daemon,level,__FILE__,__LINE__,NULL); } while(0)

# define AFB_REQ_VERBOSE_V1(req,level,...) \
		do { if(level <= AFB_VERBOSITY_LEVEL_ERROR) \
			afb_req_x1_verbose(req,level,__FILE__,__LINE__,NULL,__VA_ARGS__); \
		else afb_req_x1_verbose(req,level,__FILE__,__LINE__,NULL); } while(0)

#elif defined(AFB_BINDING_PRAGMA_NO_VERBOSE_DETAILS)

# define AFB_VERBOSE_V1(itf,level,...) \
                afb_daemon_verbose2_v1(itf->daemon,level,NULL,0,NULL,__VA_ARGS__)

# define AFB_REQ_VERBOSE_V1(req,level,...) \
                afb_req_x1_verbose(req,level,NULL,0,NULL,__VA_ARGS__)

#else

# define AFB_VERBOSE_V1(itf,level,...) \
                afb_daemon_verbose2_v1(itf->daemon,level,__FILE__,__LINE__,__func__,__VA_ARGS__)

# define AFB_REQ_VERBOSE_V1(req,level,...) \
                afb_req_x1_verbose(req,level,__FILE__,__LINE__,__func__,__VA_ARGS__)

#endif

#define _AFB_LOGGING_V1_(itf,vlevel,llevel,...) \
        do{ if(itf->verbosity>=vlevel) AFB_VERBOSE_V1(itf,llevel,__VA_ARGS__); }while(0)
#define _AFB_REQ_LOGGING_V1_(itf,vlevel,llevel,req,...) \
        do{ if(itf->verbosity>=vlevel) AFB_REQ_VERBOSE_V1(itf,llevel,__VA_ARGS__); }while(0)

# define AFB_ERROR_V1(itf,...)       _AFB_LOGGING_V1_(itf,AFB_VERBOSITY_LEVEL_ERROR,AFB_SYSLOG_LEVEL_ERROR,__VA_ARGS__)
# define AFB_WARNING_V1(itf,...)     _AFB_LOGGING_V1_(itf,AFB_VERBOSITY_LEVEL_WARNING,AFB_SYSLOG_LEVEL_WARNING,__VA_ARGS__)
# define AFB_NOTICE_V1(itf,...)      _AFB_LOGGING_V1_(itf,AFB_VERBOSITY_LEVEL_NOTICE,AFB_SYSLOG_LEVEL_NOTICE,__VA_ARGS__)
# define AFB_INFO_V1(itf,...)        _AFB_LOGGING_V1_(itf,AFB_VERBOSITY_LEVEL_INFO,AFB_SYSLOG_LEVEL_INFO,__VA_ARGS__)
# define AFB_DEBUG_V1(itf,...)       _AFB_LOGGING_V1_(itf,AFB_VERBOSITY_LEVEL_DEBUG,AFB_SYSLOG_LEVEL_DEBUG,__VA_ARGS__)

# define AFB_REQ_ERROR_V1(itf,...)   _AFB_REQ_LOGGING_V1_(itf,AFB_VERBOSITY_LEVEL_ERROR,AFB_SYSLOG_LEVEL_ERROR,__VA_ARGS__)
# define AFB_REQ_WARNING_V1(itf,...) _AFB_REQ_LOGGING_V1_(itf,AFB_VERBOSITY_LEVEL_WARNING,AFB_SYSLOG_LEVEL_WARNING,__VA_ARGS__)
# define AFB_REQ_NOTICE_V1(itf,...)  _AFB_REQ_LOGGING_V1_(itf,AFB_VERBOSITY_LEVEL_NOTICE,AFB_SYSLOG_LEVEL_NOTICE,__VA_ARGS__)
# define AFB_REQ_INFO_V1(itf,...)    _AFB_REQ_LOGGING_V1_(itf,AFB_VERBOSITY_LEVEL_INFO,AFB_SYSLOG_LEVEL_INFO,__VA_ARGS__)
# define AFB_REQ_DEBUG_V1(itf,...)   _AFB_REQ_LOGGING_V1_(itf,AFB_VERBOSITY_LEVEL_DEBUG,AFB_SYSLOG_LEVEL_DEBUG,__VA_ARGS__)

/******************************************************************************/

#if  AFB_BINDING_VERSION == 1 && defined(AFB_BINDING_PRAGMA_KEEP_VERBOSE_UNPREFIX)
# define ERROR			AFB_ERROR
# define WARNING		AFB_WARNING
# define NOTICE			AFB_NOTICE
# define INFO			AFB_INFO
# define DEBUG			AFB_DEBUG

# define REQ_ERROR		AFB_REQ_ERROR
# define REQ_WARNING		AFB_REQ_WARNING
# define REQ_NOTICE		AFB_REQ_NOTICE
# define REQ_INFO		AFB_REQ_INFO
# define REQ_DEBUG		AFB_REQ_DEBUG
#endif

