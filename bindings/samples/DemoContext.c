/*
 * Copyright (C) 2015-2020 "IoT.bzh"
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

typedef struct {
  /*
   * client context is attached a session but private to a each plugin.
   * Context is passed to each API under request->context
   *
   * Note:
   *  -client context is free when a session is closed. Developer should not
   *   forget that even if context is private to each plugin, session is unique
   *   to a client. When session close, every plugin are notified to free there
   *   private context.
   *  -by default standard "free" function from libc is used to free context.
   *   Developer may define it own under plugin->freeCB. This call received
   *   FreeCtxCb(void *ClientCtx, void*PluginHandle, char*SessionUUID) if
   *   FreeCtxCb=(void*)-1 then context wont be free by session manager.
   *  -when an API use AFB_SESSION_RESET this close the session and each plugin
   *   will be notified to free ressources.
   */

  int  count;
  char *abcd;

} MyClientContextT;

// This function is call at session open time. Any client trying to
// call it with an already open session will be denied.
// Ex: http://localhost:1234/api/context/create?token=123456789
static void myCreate (afb_req_t request)
{
    MyClientContextT *ctx = malloc (sizeof (MyClientContextT));

    // store something in our plugin private client context
    ctx->count = 0;
    ctx->abcd  = "SomeThingUseful";

    afb_req_context_set(request, ctx, free);
    afb_req_success_f(request, NULL, "SUCCESS: create client context for plugin [%s]", ctx->abcd);
}

// This function can only be called with a valid token. Token should be renew before
// session timeout a standard renew api is avaliable at /api/token/renew this API
// can be called automatically with <token-renew> HTML5 widget.
// ex: http://localhost:1234/api/context/action?token=xxxxxx-xxxxxx-xxxxx-xxxxx-xxxxxx
static void myAction (afb_req_t request)
{
    MyClientContextT *ctx = (MyClientContextT*) afb_req_context_get(request);

    if (!ctx) {
	afb_req_fail(request, "invalid-state", "Can't perform action");
	return;
    }
    // store something in our plugin private client context
    ctx->count++;
    afb_req_success_f(request, NULL, "SUCCESS: plugin [%s] Check=[%d]\n", ctx->abcd, ctx->count);
}

// After execution of this function, client session will be close and if they
// created a context [request->context != NULL] every plugins will be notified
// that they should free context resources.
// ex: http://localhost:1234/api/context/close?token=xxxxxx-xxxxxx-xxxxx-xxxxx-xxxxxx
static void myClose (afb_req_t request)
{
    MyClientContextT *ctx = (MyClientContextT*) afb_req_context_get(request);

    if (!ctx) {
        afb_req_success(request, NULL, NULL);
	return;
    }
    // store something in our plugin private client context
    ctx->count++;
    afb_req_success_f(request, NULL, "SUCCESS: plugin [%s] Close=[%d]\n", ctx->abcd, ctx->count);
}

// Set the LOA
static void setLOA(afb_req_t request, unsigned loa)
{
    if (afb_req_session_set_LOA(request, loa) >= 0)
	afb_req_success_f(request, NULL, "loa set to %u", loa);
    else
	afb_req_fail_f(request, "failed", "can't set loa to %u", loa);
}

static void clientSetLOA(afb_req_t request)
{
    setLOA(request, (unsigned)(intptr_t)request->vcbdata);
}

static void clientCheckLOA(afb_req_t request)
{
    afb_req_success(request, NULL, "LOA checked and okay");
}

// NOTE: this sample does not use session to keep test a basic as possible
//       in real application most APIs should be protected with AFB_SESSION_CHECK
static const struct afb_verb_v3 verbs[]= {
  {.verb="create", .session=AFB_SESSION_NONE, .callback=myCreate  , .info="Create a new session"},
  {.verb="action", .session=AFB_SESSION_CHECK , .callback=myAction  , .info="Use Session Context"},
  {.verb="close" , .session=AFB_SESSION_CLOSE , .callback=myClose   , .info="Free Context"},
  {.verb="set_loa_0", .session=AFB_SESSION_RENEW, .callback=clientSetLOA       ,.vcbdata=(void*)(intptr_t)0 ,.info="Set level of assurance to 0"},
  {.verb="set_loa_1", .session=AFB_SESSION_RENEW, .callback=clientSetLOA       ,.vcbdata=(void*)(intptr_t)1 ,.info="Set level of assurance to 1"},
  {.verb="set_loa_2", .session=AFB_SESSION_RENEW, .callback=clientSetLOA       ,.vcbdata=(void*)(intptr_t)2 ,.info="Set level of assurance to 2"},
  {.verb="set_loa_3", .session=AFB_SESSION_RENEW, .callback=clientSetLOA       ,.vcbdata=(void*)(intptr_t)3 ,.info="Set level of assurance to 3"},
  {.verb="check_loa_ge_0", .session=AFB_SESSION_LOA_0, .callback=clientCheckLOA ,.vcbdata=(void*)(intptr_t)0 ,.info="Check whether level of assurance is greater or equal to 0"},
  {.verb="check_loa_ge_1", .session=AFB_SESSION_LOA_1, .callback=clientCheckLOA ,.vcbdata=(void*)(intptr_t)1 ,.info="Check whether level of assurance is greater or equal to 1"},
  {.verb="check_loa_ge_2", .session=AFB_SESSION_LOA_2, .callback=clientCheckLOA ,.vcbdata=(void*)(intptr_t)2 ,.info="Check whether level of assurance is greater or equal to 2"},
  {.verb="check_loa_ge_3", .session=AFB_SESSION_LOA_3, .callback=clientCheckLOA ,.vcbdata=(void*)(intptr_t)3 ,.info="Check whether level of assurance is greater or equal to 3"},
  {0, 0, 0, 0, 0, 0, 0}
};

const struct afb_binding_v3 afbBindingV3 =
{
    .api   = "context",		/* the API name (or binding name or prefix) */
    .info  = "Sample of Client Context Usage",	/* short description of of the binding */
    .verbs = verbs	/* the array describing the verbs of the API */
};
