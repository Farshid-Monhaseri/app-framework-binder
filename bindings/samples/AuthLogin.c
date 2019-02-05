/*
 * Copyright (C) 2015-2019 "IoT.bzh"
 * Author "Fulup Ar Foll"
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

#define _GNU_SOURCE
#include <stdio.h>
#include <json-c/json.h>

#define AFB_BINDING_VERSION 3
#include <afb/afb-binding.h>

// Dummy sample of Client Application Context
typedef struct {
  int  something;
  void *whateveryouwant;
} MyClientApplicationHandle;


// This function is call when Client Session Context is removed
// Note: when freeCtxCB==NULL standard free/malloc is called
static void clientContextFree(void *context) {
    fprintf (stderr,"Plugin[token] Closing Session\n");
    free (context);
}

// Request Creation of new context if it does not exist
static void clientContextConnect (afb_req_t request)
{
    json_object *jresp;

    // add an application specific client context to session
    afb_req_context_set(request, malloc (sizeof (MyClientApplicationHandle)), clientContextFree);

    // do something intelligent to check if we should or not update level of assurance from 0(anonymous) to 1(logged)
    afb_req_session_set_LOA(request, 1);

    // Send response to UI
    jresp = json_object_new_object();
    json_object_object_add(jresp, "token", json_object_new_string ("A New Token and Session Context Was Created"));

    afb_req_success(request, jresp, NULL);

}

// Before entering here token will be check and renew
static void clientContextRefresh (afb_req_t request) {
    json_object *jresp;


    jresp = json_object_new_object();
    json_object_object_add(jresp, "token", json_object_new_string ("Token was refreshed"));

    afb_req_success(request, jresp, NULL);
}


// Session token will we verified before entering here
static void clientContextCheck (afb_req_t request) {

    json_object *jresp = json_object_new_object();
    json_object_object_add(jresp, "isvalid", json_object_new_boolean (1));

    afb_req_success(request, jresp, NULL);
}


// Close and Free context
static void clientContextLogout (afb_req_t request) {
    json_object *jresp;

    /* after this call token will be reset
     *  - no further access to API will be possible
     *  - every context from any used plugin will be freed
     */

    jresp = json_object_new_object();
    json_object_object_add(jresp, "info", json_object_new_string ("Token and all resources are released"));

    // WARNING: if you free context resource manually here do not forget to set *request.context=NULL;
    afb_req_success(request, jresp, NULL);

    afb_req_session_set_LOA(request, 0);
}
// Close and Free context
static void clientGetPing (afb_req_t request) {
    static int count=0;
    json_object *jresp;

    jresp = json_object_new_object();
    json_object_object_add(jresp, "count", json_object_new_int (count ++));

    afb_req_success(request, jresp, NULL);
}


static const struct afb_verb_v3 verbs[]= {
  {.verb="ping"    , .session=AFB_SESSION_NONE                     , .callback=clientGetPing       ,.info="Ping Rest Test Service"},
  {.verb="connect" , .session=AFB_SESSION_LOA_0 | AFB_SESSION_RENEW, .callback=clientContextConnect,.info="Connect/Login Client"},
  {.verb="refresh" , .session=AFB_SESSION_LOA_1 | AFB_SESSION_RENEW, .callback=clientContextRefresh,.info="Refresh Client Authentication Token"},
  {.verb="check"   , .session=AFB_SESSION_LOA_1                    , .callback=clientContextCheck  ,.info="Check Client Authentication Token"},
  {.verb="logout"  , .session=AFB_SESSION_LOA_1 | AFB_SESSION_CLOSE, .callback=clientContextLogout ,.info="Logout Client and Free resources"},
  {NULL}
};

const struct afb_binding_v3 afbBindingV3 =
{
    .api   = "auth",		/* the API name (or binding name or prefix) */
    .info  = "Application Framework Binder Authentication sample",	/* short description of of the binding */
    .verbs = verbs	/* the array describing the verbs of the API */
};
