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

#define _GNU_SOURCE

#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <string.h>

#include <json-c/json.h>

#include "afb-wsj1.h"
#include "afb-ws-json1.h"
#include "afb-msg-json.h"
#include "afb-session.h"
#include "afb-cred.h"
#include "afb-apiset.h"
#include "afb-xreq.h"
#include "afb-context.h"
#include "afb-evt.h"
#include "afb-token.h"

#include "systemd.h"
#include "verbose.h"
#include "fdev.h"

/* predeclaration of structures */
struct afb_ws_json1;
struct afb_wsreq;

/* predeclaration of websocket callbacks */
static void aws_on_hangup_cb(void *closure, struct afb_wsj1 *wsj1);
static void aws_on_call_cb(void *closure, const char *api, const char *verb, struct afb_wsj1_msg *msg);
static void aws_on_push_cb(void *closure, const char *event, int eventid, struct json_object *object);
static void aws_on_broadcast_cb(void *closure, const char *event, struct json_object *object, const uuid_binary_t uuid, uint8_t hop);

/* predeclaration of wsreq callbacks */
static void wsreq_destroy(struct afb_xreq *xreq);
static void wsreq_reply(struct afb_xreq *xreq, struct json_object *object, const char *error, const char *info);
static int wsreq_subscribe(struct afb_xreq *xreq, struct afb_event_x2 *event);
static int wsreq_unsubscribe(struct afb_xreq *xreq, struct afb_event_x2 *event);

/* declaration of websocket structure */
struct afb_ws_json1
{
	int refcount;
	void (*cleanup)(void*);
	void *cleanup_closure;
	struct afb_session *session;
	struct afb_token *token;
	struct afb_evt_listener *listener;
	struct afb_wsj1 *wsj1;
	struct afb_cred *cred;
	struct afb_apiset *apiset;
	int new_session;
};

/* declaration of wsreq structure */
struct afb_wsreq
{
	struct afb_xreq xreq;
	struct afb_ws_json1 *aws;
	struct afb_wsreq *next;
	struct afb_wsj1_msg *msgj1;
};

/* interface for afb_ws_json1 / afb_wsj1 */
static struct afb_wsj1_itf wsj1_itf = {
	.on_hangup = aws_on_hangup_cb,
	.on_call = aws_on_call_cb
};

/* interface for xreq */
const struct afb_xreq_query_itf afb_ws_json1_xreq_itf = {
	.reply = wsreq_reply,
	.subscribe = wsreq_subscribe,
	.unsubscribe = wsreq_unsubscribe,
	.unref = wsreq_destroy
};

/* the interface for events */
static const struct afb_evt_itf evt_itf = {
	.broadcast = aws_on_broadcast_cb,
	.push = aws_on_push_cb
};

/***************************************************************
****************************************************************
**
**  functions of afb_ws_json1 / afb_wsj1
**
****************************************************************
***************************************************************/

struct afb_ws_json1 *afb_ws_json1_create(struct fdev *fdev, struct afb_apiset *apiset, struct afb_context *context, void (*cleanup)(void*), void *cleanup_closure)
{
	struct afb_ws_json1 *result;

	assert(fdev);
	assert(context != NULL);

	result = malloc(sizeof * result);
	if (result == NULL)
		goto error;

	result->refcount = 1;
	result->cleanup = cleanup;
	result->cleanup_closure = cleanup_closure;
	result->session = afb_session_addref(context->session);
	result->token = afb_token_addref(context->token);
	result->new_session = context->created != 0;
	if (result->session == NULL)
		goto error2;

	result->wsj1 = afb_wsj1_create(fdev, &wsj1_itf, result);
	if (result->wsj1 == NULL)
		goto error3;

	result->listener = afb_evt_listener_create(&evt_itf, result);
	if (result->listener == NULL)
		goto error4;

	result->cred = afb_cred_create_for_socket(fdev_fd(fdev));
	result->apiset = afb_apiset_addref(apiset);
	return result;

error4:
	afb_wsj1_unref(result->wsj1);
error3:
	afb_session_unref(result->session);
	afb_token_unref(result->token);
error2:
	free(result);
error:
	fdev_unref(fdev);
	return NULL;
}

struct afb_ws_json1 *afb_ws_json1_addref(struct afb_ws_json1 *ws)
{
	__atomic_add_fetch(&ws->refcount, 1, __ATOMIC_RELAXED);
	return ws;
}

void afb_ws_json1_unref(struct afb_ws_json1 *ws)
{
	if (!__atomic_sub_fetch(&ws->refcount, 1, __ATOMIC_RELAXED)) {
		afb_evt_listener_unref(ws->listener);
		afb_wsj1_unref(ws->wsj1);
		if (ws->cleanup != NULL)
			ws->cleanup(ws->cleanup_closure);
		afb_token_unref(ws->token);
		afb_session_unref(ws->session);
		afb_cred_unref(ws->cred);
		afb_apiset_unref(ws->apiset);
		free(ws);
	}
}

static void aws_on_hangup_cb(void *closure, struct afb_wsj1 *wsj1)
{
	struct afb_ws_json1 *ws = closure;
	afb_ws_json1_unref(ws);
}

static void aws_on_call_cb(void *closure, const char *api, const char *verb, struct afb_wsj1_msg *msg)
{
	struct afb_ws_json1 *ws = closure;
	struct afb_wsreq *wsreq;

	DEBUG("received websocket request for %s/%s: %s", api, verb, afb_wsj1_msg_object_s(msg));

	/* allocate */
	wsreq = calloc(1, sizeof *wsreq);
	if (wsreq == NULL) {
		afb_wsj1_close(ws->wsj1, 1008, NULL);
		return;
	}

	/* init the context */
	afb_xreq_init(&wsreq->xreq, &afb_ws_json1_xreq_itf);
	afb_context_init(&wsreq->xreq.context, ws->session, afb_wsj1_msg_token(msg));
	if (!wsreq->xreq.context.invalidated)
		wsreq->xreq.context.validated = 1;
	if (ws->new_session != 0) {
		wsreq->xreq.context.created = 1;
		ws->new_session = 0;
	}

	/* fill and record the request */
	afb_wsj1_msg_addref(msg);
	wsreq->msgj1 = msg;
	wsreq->xreq.cred = afb_cred_addref(ws->cred);
	wsreq->xreq.request.called_api = api;
	wsreq->xreq.request.called_verb = verb;
	wsreq->xreq.json = afb_wsj1_msg_object_j(wsreq->msgj1);
	wsreq->aws = afb_ws_json1_addref(ws);

	/* emits the call */
	afb_xreq_process(&wsreq->xreq, ws->apiset);
}

static void aws_on_event(struct afb_ws_json1 *aws, const char *event, struct json_object *object)
{
	afb_wsj1_send_event_j(aws->wsj1, event, afb_msg_json_event(event, object));
}

static void aws_on_push_cb(void *closure, const char *event, int eventid, struct json_object *object)
{
	aws_on_event(closure, event, object);
}

static void aws_on_broadcast_cb(void *closure, const char *event, struct json_object *object, const uuid_binary_t uuid, uint8_t hop)
{
	aws_on_event(closure, event, afb_msg_json_event(event, object));
}

/***************************************************************
****************************************************************
**
**  functions of wsreq / afb_req
**
****************************************************************
***************************************************************/

static void wsreq_destroy(struct afb_xreq *xreq)
{
	struct afb_wsreq *wsreq = CONTAINER_OF_XREQ(struct afb_wsreq, xreq);

	afb_context_disconnect(&wsreq->xreq.context);
	afb_wsj1_msg_unref(wsreq->msgj1);
	afb_cred_unref(wsreq->xreq.cred);
	afb_ws_json1_unref(wsreq->aws);
	free(wsreq);
}

static void wsreq_reply(struct afb_xreq *xreq, struct json_object *object, const char *error, const char *info)
{
	struct afb_wsreq *wsreq = CONTAINER_OF_XREQ(struct afb_wsreq, xreq);
	int rc;
	struct json_object *reply;

	/* create the reply */
	reply = afb_msg_json_reply(object, error, info, &xreq->context);

	rc = (error ? afb_wsj1_reply_error_j : afb_wsj1_reply_ok_j)(
			wsreq->msgj1, reply, afb_context_sent_token(&wsreq->xreq.context));
	if (rc)
		ERROR("Can't send reply: %m");
}

static int wsreq_subscribe(struct afb_xreq *xreq, struct afb_event_x2 *event)
{
	struct afb_wsreq *wsreq = CONTAINER_OF_XREQ(struct afb_wsreq, xreq);

	return afb_evt_event_x2_add_watch(wsreq->aws->listener, event);
}

static int wsreq_unsubscribe(struct afb_xreq *xreq, struct afb_event_x2 *event)
{
	struct afb_wsreq *wsreq = CONTAINER_OF_XREQ(struct afb_wsreq, xreq);

	return afb_evt_event_x2_remove_watch(wsreq->aws->listener, event);
}

