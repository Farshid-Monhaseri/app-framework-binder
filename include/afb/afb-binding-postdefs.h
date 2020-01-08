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

typedef enum   afb_auth_type            afb_auth_type_t;
typedef struct afb_auth                 afb_auth_t;
typedef struct afb_arg                  afb_arg_t;

#if AFB_BINDING_VERSION == 1

typedef struct afb_verb_desc_v1         afb_verb_t;
typedef struct afb_binding_v1           afb_binding_t;
typedef struct afb_binding_interface_v1 afb_binding_interface_v1;

typedef struct afb_daemon_x1            afb_daemon_t;
typedef struct afb_service_x1           afb_service_t;

typedef struct afb_event_x1             afb_event_t;
typedef struct afb_req_x1               afb_req_t;

typedef struct afb_stored_req           afb_stored_req_t;

#ifndef __cplusplus
typedef struct afb_event_x1             afb_event;
typedef struct afb_req_x1               afb_req;
typedef struct afb_stored_req           afb_stored_req;
#endif

#endif

#if AFB_BINDING_VERSION == 2

typedef struct afb_verb_v2              afb_verb_t;
typedef struct afb_binding_v2           afb_binding_t;

typedef struct afb_daemon               afb_daemon_t;
typedef struct afb_event                afb_event_t;
typedef struct afb_req                  afb_req_t;
typedef struct afb_stored_req           afb_stored_req_t;
typedef struct afb_service              afb_service_t;

#define afbBindingExport		afbBindingV2

#ifndef __cplusplus
typedef struct afb_verb_v2              afb_verb_v2;
typedef struct afb_binding_v2           afb_binding_v2;
typedef struct afb_event_x1             afb_event;
typedef struct afb_req_x1               afb_req;
typedef struct afb_stored_req           afb_stored_req;
#endif

#endif

#if AFB_BINDING_VERSION == 3

typedef struct afb_verb_v3              afb_verb_t;
typedef struct afb_binding_v3           afb_binding_t;

typedef struct afb_event_x2            *afb_event_t;
typedef struct afb_req_x2              *afb_req_t;
typedef struct afb_api_x3              *afb_api_t;
typedef enum afb_req_subcall_flags	afb_req_subcall_flags_t;

#define afbBindingExport		afbBindingV3
#define afbBindingRoot			afbBindingV3root
#define afbBindingEntry			afbBindingV3entry

/* compatibility with previous versions */

typedef struct afb_api_x3              *afb_daemon_t;
typedef struct afb_api_x3              *afb_service_t;

#endif


#if defined(AFB_BINDING_WANT_DYNAPI)
typedef struct afb_dynapi              *afb_dynapi_t;
typedef struct afb_request             *afb_request_t;
typedef struct afb_eventid             *afb_eventid_t;
#endif