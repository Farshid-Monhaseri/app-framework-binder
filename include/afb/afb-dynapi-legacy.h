
/*
 * Copyright (C) 2018, 2019 "IoT.bzh"
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

/***************************************************************************************************/

#define afb_dynapi			afb_api_x3
#define afb_dynapi_itf			afb_api_x3_itf

#define afb_request			afb_req_x2
#define afb_request_get_dynapi		afb_req_x2_get_api
#define afb_request_get_vcbdata		afb_req_x2_get_vcbdata
#define afb_request_get_api		afb_req_x2_get_called_api
#define afb_request_get_verb		afb_req_x2_get_called_verb
#define afb_request_wants_log_level	afb_req_x2_wants_log_level

#define afb_request_get			afb_req_x2_get
#define afb_request_value		afb_req_x2_value
#define afb_request_path		afb_req_x2_path
#define afb_request_json		afb_req_x2_json
#define afb_request_reply		afb_req_x2_reply
#define afb_request_reply_f		afb_req_x2_reply_f
#define afb_request_reply_v		afb_req_x2_reply_v
#define afb_request_success(r,o,i)	afb_req_x2_reply(r,o,0,i)
#define afb_request_success_f(r,o,...)	afb_req_x2_reply_f(r,o,0,__VA_ARGS__)
#define afb_request_success_v(r,o,f,v)	afb_req_x2_reply_v(r,o,0,f,v)
#define afb_request_fail(r,e,i)		afb_req_x2_reply(r,0,e,i)
#define afb_request_fail_f(r,e,f,...)	afb_req_x2_reply_f(r,0,e,f,__VA_ARGS__)
#define afb_request_fail_v(r,e,f,v)	afb_req_x2_reply_v(r,0,e,f,v)
#define afb_request_context_get		afb_req_x2_context_get
#define afb_request_context_set		afb_req_x2_context_set
#define afb_request_context		afb_req_x2_context
#define afb_request_context_clear	afb_req_x2_context_clear
#define afb_request_addref		afb_req_x2_addref
#define afb_request_unref		afb_req_x2_unref
#define afb_request_session_close	afb_req_x2_session_close
#define afb_request_session_set_LOA	afb_req_x2_session_set_LOA
#define afb_request_subscribe		afb_req_x2_subscribe
#define afb_request_unsubscribe		afb_req_x2_unsubscribe
#define afb_request_subcall		afb_req_x2_subcall_legacy
#define afb_request_subcall_sync	afb_req_x2_subcall_sync_legacy
#define afb_request_verbose		afb_req_x2_verbose
#define afb_request_has_permission	afb_req_x2_has_permission
#define afb_request_get_application_id	afb_req_x2_get_application_id
#define afb_request_get_uid		afb_req_x2_get_uid
#define afb_request_get_client_info	afb_req_x2_get_client_info

#define afb_dynapi_name		 	afb_api_x3_name
#define afb_dynapi_get_userdata	 	afb_api_x3_get_userdata
#define afb_dynapi_set_userdata	 	afb_api_x3_set_userdata
#define afb_dynapi_wants_log_level	afb_api_x3_wants_log_level

#define afb_dynapi_verbose	 	afb_api_x3_verbose
#define afb_dynapi_vverbose	 	afb_api_x3_vverbose
#define afb_dynapi_get_event_loop	afb_api_x3_get_event_loop
#define afb_dynapi_get_user_bus		afb_api_x3_get_user_bus
#define afb_dynapi_get_system_bus	afb_api_x3_get_system_bus
#define afb_dynapi_rootdir_get_fd	afb_api_x3_rootdir_get_fd
#define afb_dynapi_rootdir_open_locale	afb_api_x3_rootdir_open_locale
#define afb_dynapi_queue_job		afb_api_x3_queue_job
#define afb_dynapi_require_api		afb_api_x3_require_api
#define afb_dynapi_rename_api		afb_api_x3_add_alias
#define afb_dynapi_broadcast_event	afb_api_x3_broadcast_event
#define afb_dynapi_make_eventid		afb_api_x3_make_event_x2
#define afb_dynapi_call			afb_api_x3_call_legacy
#define afb_dynapi_call_sync		afb_api_x3_call_sync_legacy
#define afb_dynapi_new_api(...)		(-!afb_api_x3_new_api(__VA_ARGS__))
#define afb_dynapi_set_verbs_v2		afb_api_x3_set_verbs_v2
#define afb_dynapi_add_verb(a,b,c,d,e,f,g)	afb_api_x3_add_verb(a,b,c,d,e,f,g,0)
#define afb_dynapi_sub_verb(a,b)	afb_api_x3_del_verb(a,b,NULL)
#define afb_dynapi_on_event		afb_api_x3_on_event
#define afb_dynapi_on_init		afb_api_x3_on_init
#define afb_dynapi_seal			afb_api_x3_seal

#define afb_eventid_broadcast		afb_event_x2_broadcast
#define afb_eventid_push		afb_event_x2_push
#define afb_eventid_name		afb_event_x2_name
#define afb_eventid_unref		afb_event_x2_unref
#define afb_eventid_addref		afb_event_x2_addref

#define afb_eventid			afb_event_x2
#define afb_eventid_is_valid		afb_event_x2_is_valid
#define afb_eventid_broadcast		afb_event_x2_broadcast
#define afb_eventid_push		afb_event_x2_push
#define afb_eventid_drop		afb_event_x2_unref
#define afb_eventid_name		afb_event_x2_name
#define afb_eventid_unref		afb_event_x2_unref
#define afb_eventid_addref		afb_event_x2_addref

/*
 * The function afbBindingVdyn if exported allows to create
 * pure dynamic bindings. When the binding is loaded, it receives
 * a virtual dynapi that can be used to create apis. The
 * given API can not be used except for creating dynamic apis.
 */
extern int afbBindingVdyn(struct afb_dynapi *dynapi);

/*
 * Macros for logging messages
 */
/* macro for setting file, line and function automatically */
# if !defined(AFB_BINDING_PRAGMA_NO_VERBOSE_DETAILS)
#define AFB_REQUEST_VERBOSE(req,level,...) afb_req_x2_verbose(req,level,__FILE__,__LINE__,__func__,__VA_ARGS__)
#else
#define AFB_REQUEST_VERBOSE(req,level,...) afb_req_x2_verbose(req,level,NULL,0,NULL,__VA_ARGS__)
#endif

#if defined(AFB_BINDING_PRAGMA_NO_VERBOSE_DATA)

# define _AFB_DYNAPI_LOGGING_(llevel,dynapi,...) \
	do{ \
		if(_AFB_SYSLOG_MASK_WANT_(dynapi->logmask,llevel)) {\
			if (llevel <= AFB_VERBOSITY_LEVEL_ERROR) \
				afb_dynapi_verbose(dynapi,llevel,__FILE__,__LINE__,__func__,__VA_ARGS__); \
			else \
				afb_dynapi_verbose(dynapi,llevel,__FILE__,__LINE__,NULL,NULL); \
		} \
	}while(0)
# define _AFB_REQUEST_LOGGING_(llevel,request,...) \
	do{ \
		if(request->_AFB_SYSLOG_MASK_WANT_(dynapi->logmask,llevel)) \
			afb_request_verbose(request,llevel,__FILE__,__LINE__,NULL,NULL); \
	}while(0)

#elif defined(AFB_BINDING_PRAGMA_NO_VERBOSE_DETAILS)

# define _AFB_DYNAPI_LOGGING_(llevel,dynapi,...) \
	do{ \
		if(_AFB_SYSLOG_MASK_WANT_(dynapi->logmask,llevel)) \
			afb_dynapi_verbose(dynapi,llevel,NULL,0,NULL,__VA_ARGS__); \
	}while(0)
# define _AFB_REQUEST_LOGGING_(llevel,request,...) \
	do{ \
		if(request->_AFB_SYSLOG_MASK_WANT_(dynapi->logmask,llevel)) \
			afb_request_verbose(request,llevel,NULL,0,NULL,__VA_ARGS__); \
	}while(0)

#else

# define _AFB_DYNAPI_LOGGING_(llevel,dynapi,...) \
	do{ \
		if(AFB_SYSLOG_MASK_WANT(dynapi->logmask,llevel)) \
			afb_dynapi_verbose(dynapi,llevel,__FILE__,__LINE__,__func__,__VA_ARGS__); \
	}while(0)
# define _AFB_REQUEST_LOGGING_(llevel,request,...) \
	do{ \
		if(AFB_SYSLOG_MASK_WANT(request->api->logmask,llevel)) \
			afb_request_verbose(request,llevel,__FILE__,__LINE__,__func__,__VA_ARGS__); \
	}while(0)

#endif

#define AFB_DYNAPI_ERROR(...)     _AFB_DYNAPI_LOGGING_(AFB_SYSLOG_LEVEL_ERROR,__VA_ARGS__)
#define AFB_DYNAPI_WARNING(...)   _AFB_DYNAPI_LOGGING_(AFB_SYSLOG_LEVEL_WARNING,__VA_ARGS__)
#define AFB_DYNAPI_NOTICE(...)    _AFB_DYNAPI_LOGGING_(AFB_SYSLOG_LEVEL_NOTICE,__VA_ARGS__)
#define AFB_DYNAPI_INFO(...)      _AFB_DYNAPI_LOGGING_(AFB_SYSLOG_LEVEL_INFO,__VA_ARGS__)
#define AFB_DYNAPI_DEBUG(...)     _AFB_DYNAPI_LOGGING_(AFB_SYSLOG_LEVEL_DEBUG,__VA_ARGS__)
#define AFB_REQUEST_ERROR(...)    _AFB_REQUEST_LOGGING_(AFB_SYSLOG_LEVEL_ERROR,__VA_ARGS__)
#define AFB_REQUEST_WARNING(...)  _AFB_REQUEST_LOGGING_(AFB_SYSLOG_LEVEL_WARNING,__VA_ARGS__)
#define AFB_REQUEST_NOTICE(...)   _AFB_REQUEST_LOGGING_(AFB_SYSLOG_LEVEL_NOTICE,__VA_ARGS__)
#define AFB_REQUEST_INFO(...)     _AFB_REQUEST_LOGGING_(AFB_SYSLOG_LEVEL_INFO,__VA_ARGS__)
#define AFB_REQUEST_DEBUG(...)    _AFB_REQUEST_LOGGING_(AFB_SYSLOG_LEVEL_DEBUG,__VA_ARGS__)

typedef struct afb_eventid afb_eventid;
typedef struct afb_dynapi afb_dynapi;
typedef struct afb_request afb_request;

#define _AFB_SYSLOG_LEVEL_EMERGENCY_	AFB_SYSLOG_LEVEL_EMERGENCY
#define _AFB_SYSLOG_LEVEL_ALERT_	AFB_SYSLOG_LEVEL_ALERT
#define _AFB_SYSLOG_LEVEL_CRITICAL_	AFB_SYSLOG_LEVEL_CRITICAL
#define _AFB_SYSLOG_LEVEL_ERROR_	AFB_SYSLOG_LEVEL_ERROR
#define _AFB_SYSLOG_LEVEL_WARNING_	AFB_SYSLOG_LEVEL_WARNING
#define _AFB_SYSLOG_LEVEL_NOTICE_	AFB_SYSLOG_LEVEL_NOTICE
#define _AFB_SYSLOG_LEVEL_INFO_		AFB_SYSLOG_LEVEL_INFO
#define _AFB_SYSLOG_LEVEL_DEBUG_	AFB_SYSLOG_LEVEL_DEBUG
