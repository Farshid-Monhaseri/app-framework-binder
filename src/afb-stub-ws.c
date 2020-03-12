/*
 * Copyright (C) 2015-2020 "IoT.bzh"
 * Author José Bollo <jose.bollo@iot.bzh>
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
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <endian.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>

#include <json-c/json.h>

#include <afb/afb-event-x2.h>

#include "afb-session.h"
#include "afb-cred.h"
#include "afb-api.h"
#include "afb-apiset.h"
#include "afb-proto-ws.h"
#include "afb-stub-ws.h"
#include "afb-context.h"
#include "afb-evt.h"
#include "afb-xreq.h"
#include "afb-token.h"
#include "afb-error-text.h"
#include "verbose.h"
#include "fdev.h"
#include "jobs.h"
#include "u16id.h"

struct afb_stub_ws;

/**
 * structure for a ws request: requests on server side
 */
struct server_req {
	struct afb_xreq xreq;		/**< the xreq */
	struct afb_stub_ws *stubws;	/**< the client of the request */
	struct afb_proto_ws_call *call;	/**< the incoming call */
};

/**
 * structure for jobs of describing
 */
struct server_describe
{
	struct afb_stub_ws *stubws;
	struct afb_proto_ws_describe *describe;
};

/******************* stub description for client or servers ******************/

struct afb_stub_ws
{
	/* protocol */
	struct afb_proto_ws *proto;

	/* apiset */
	struct afb_apiset *apiset;

	/* on hangup callback */
	void (*on_hangup)(struct afb_stub_ws *);

	union {
		/* server side */
		struct {
			/* listener for events */
			struct afb_evt_listener *listener;

			/* sessions */
			struct server_session *sessions;

			/* credentials of the client */
			struct afb_cred *cred;

			/* event from server */
			struct u16id2bool *event_flags;

			/* transmitted sessions */
			struct u16id2ptr *session_proxies;

			/* transmitted tokens */
			struct u16id2ptr *token_proxies;
		};

		/* client side */
		struct {
			/* event from server */
			struct u16id2ptr *event_proxies;

			/* transmitted sessions */
			struct u16id2bool *session_flags;

			/* transmitted tokens */
			struct u16id2bool *token_flags;

			/* robustify */
			struct {
				struct fdev *(*reopen)(void*);
				void *closure;
				void (*release)(void*);
			} robust;
		};
	};

	/* count of references */
	unsigned refcount;

	/* type of the stub: 0=server, 1=client */
	uint8_t is_client;

	/* the api name */
	char apiname[];
};

static struct afb_proto_ws *afb_stub_ws_create_proto(struct afb_stub_ws *stubws, struct fdev *fdev, uint8_t server);

/******************* ws request part for server *****************/

/* decrement the reference count of the request and free/release it on falling to null */
static void server_req_destroy_cb(struct afb_xreq *xreq)
{
	struct server_req *wreq = CONTAINER_OF_XREQ(struct server_req, xreq);

	afb_context_disconnect(&wreq->xreq.context);
	json_object_put(wreq->xreq.json);
	afb_proto_ws_call_unref(wreq->call);
	afb_stub_ws_unref(wreq->stubws);
	free(wreq);
}

static void server_req_reply_cb(struct afb_xreq *xreq, struct json_object *obj, const char *error, const char *info)
{
	int rc;
	struct server_req *wreq = CONTAINER_OF_XREQ(struct server_req, xreq);

	rc = afb_proto_ws_call_reply(wreq->call, obj, error, info);
	if (rc < 0)
		ERROR("error while sending reply");
	json_object_put(obj);
}

static int server_req_subscribe_cb(struct afb_xreq *xreq, struct afb_event_x2 *event)
{
	int rc;
	struct server_req *wreq = CONTAINER_OF_XREQ(struct server_req, xreq);

	rc = afb_evt_listener_watch_x2(wreq->stubws->listener, event);
	if (rc >= 0)
		rc = afb_proto_ws_call_subscribe(wreq->call,  afb_evt_event_x2_id(event));
	if (rc < 0)
		ERROR("error while subscribing event");
	return rc;
}

static int server_req_unsubscribe_cb(struct afb_xreq *xreq, struct afb_event_x2 *event)
{
	int rc;
	struct server_req *wreq = CONTAINER_OF_XREQ(struct server_req, xreq);

	rc = afb_proto_ws_call_unsubscribe(wreq->call,  afb_evt_event_x2_id(event));
	if (rc < 0)
		ERROR("error while unsubscribing event");
	return rc;
}

static const struct afb_xreq_query_itf server_req_xreq_itf = {
	.reply = server_req_reply_cb,
	.unref = server_req_destroy_cb,
	.subscribe = server_req_subscribe_cb,
	.unsubscribe = server_req_unsubscribe_cb
};

/******************* client part **********************************/

static struct afb_proto_ws *client_get_proto(struct afb_stub_ws *stubws)
{
	struct fdev *fdev;
	struct afb_proto_ws *proto;

	proto = stubws->proto;
	if (proto == NULL && stubws->robust.reopen) {
		fdev = stubws->robust.reopen(stubws->robust.closure);
		if (fdev != NULL)
			proto = afb_stub_ws_create_proto(stubws, fdev, 1);
	}
	return proto;
}

static int client_make_ids(struct afb_stub_ws *stubws, struct afb_proto_ws *proto, struct afb_context *context, uint16_t *sessionid, uint16_t *tokenid)
{
	int rc, rc2;
	uint16_t sid, tid;

	rc = 0;

	/* get the session */
	if (!context->session)
		sid = 0;
	else {
		sid = afb_session_id(context->session);
		rc2 = u16id2bool_set(&stubws->session_flags, sid, 1);
		if (rc2 < 0)
			rc = rc2;
		else if (rc2 == 0)
			rc = afb_proto_ws_client_session_create(proto, sid, afb_session_uuid(context->session));
	}

	/* get the token */
	if (!context->token)
		tid = 0;
	else {
		tid = afb_token_id(context->token);
		rc2 = u16id2bool_set(&stubws->token_flags, tid, 1);
		if (rc2 < 0)
			rc = rc2;
		else if (rc2 == 0) {
			rc2 = afb_proto_ws_client_token_create(proto, tid, afb_token_string(context->token));
			if (rc2 < 0)
				rc = rc2;
		}
	}

	*sessionid = sid;
	*tokenid = tid;
	return rc;
}

/* on call, propagate it to the ws service */
static void client_api_call_cb(void * closure, struct afb_xreq *xreq)
{
	int rc;
	struct afb_stub_ws *stubws = closure;
	struct afb_proto_ws *proto;
	uint16_t sessionid;
	uint16_t tokenid;

	proto = client_get_proto(stubws);
	if (proto == NULL) {
		afb_xreq_reply(xreq, NULL, afb_error_text_disconnected, NULL);
		return;
	}

	rc = client_make_ids(stubws, proto, &xreq->context, &sessionid, &tokenid);
	if (rc >= 0) {
		afb_xreq_unhooked_addref(xreq);
		rc = afb_proto_ws_client_call(
				proto,
				xreq->request.called_verb,
				afb_xreq_json(xreq),
				sessionid,
				tokenid,
				xreq,
				xreq_on_behalf_cred_export(xreq));
	}
	if (rc < 0) {
		afb_xreq_reply(xreq, NULL, afb_error_text_internal_error, "can't send message");
		afb_xreq_unhooked_unref(xreq);
	}
}

/* get the description */
static void client_api_describe_cb(void * closure, void (*describecb)(void *, struct json_object *), void *clocb)
{
	struct afb_stub_ws *stubws = closure;
	struct afb_proto_ws *proto;

	proto = client_get_proto(stubws);
	if (proto)
		afb_proto_ws_client_describe(proto, describecb, clocb);
	else
		describecb(clocb, NULL);
}

/******************* server part: manage events **********************************/

static void server_event_add_cb(void *closure, const char *event, uint16_t eventid)
{
	int rc;
	struct afb_stub_ws *stubws = closure;

	if (stubws->proto != NULL) {
		rc = u16id2bool_set(&stubws->event_flags, eventid, 1);
		if (rc == 0) {
			rc = afb_proto_ws_server_event_create(stubws->proto, eventid, event);
			if (rc < 0)
				u16id2bool_set(&stubws->event_flags, eventid, 0);
		}
	}
}

static void server_event_remove_cb(void *closure, const char *event, uint16_t eventid)
{
	struct afb_stub_ws *stubws = closure;

	if (stubws->proto != NULL) {
		if (u16id2bool_set(&stubws->event_flags, eventid, 0))
			afb_proto_ws_server_event_remove(stubws->proto, eventid);
	}
}

static void server_event_push_cb(void *closure, const char *event, uint16_t eventid, struct json_object *object)
{
	struct afb_stub_ws *stubws = closure;

	if (stubws->proto != NULL && u16id2bool_get(stubws->event_flags, eventid))
		afb_proto_ws_server_event_push(stubws->proto, eventid, object);
	json_object_put(object);
}

static void server_event_broadcast_cb(void *closure, const char *event, struct json_object *object, const uuid_binary_t uuid, uint8_t hop)
{
	struct afb_stub_ws *stubws = closure;

	if (stubws->proto != NULL)
		afb_proto_ws_server_event_broadcast(stubws->proto, event, object, uuid, hop);
	json_object_put(object);
}

/*****************************************************/

static void client_on_reply_cb(void *closure, void *request, struct json_object *object, const char *error, const char *info)
{
	struct afb_xreq *xreq = request;

	afb_xreq_reply(xreq, object, error, info);
	afb_xreq_unhooked_unref(xreq);
}

static void client_on_event_create_cb(void *closure, uint16_t event_id, const char *event_name)
{
	struct afb_stub_ws *stubws = closure;
	struct afb_event_x2 *event;
	int rc;
	
	/* check conflicts */
	event = afb_evt_event_x2_create(event_name);
	if (event == NULL)
		ERROR("can't create event %s, out of memory", event_name);
	else {
		rc = u16id2ptr_add(&stubws->event_proxies, event_id, event);
		if (rc < 0) {
			ERROR("can't record event %s", event_name);
			afb_evt_event_x2_unref(event);
		}
	}
}

static void client_on_event_remove_cb(void *closure, uint16_t event_id)
{
	struct afb_stub_ws *stubws = closure;
	struct afb_event_x2 *event;
	int rc;

	rc = u16id2ptr_drop(&stubws->event_proxies, event_id, (void**)&event);
	if (rc == 0 && event)
		afb_evt_event_x2_unref(event);
}

static void client_on_event_subscribe_cb(void *closure, void *request, uint16_t event_id)
{
	struct afb_stub_ws *stubws = closure;
	struct afb_xreq *xreq = request;
	struct afb_event_x2 *event;
	int rc;

	rc = u16id2ptr_get(stubws->event_proxies, event_id, (void**)&event);
	if (rc < 0 || !event || afb_xreq_subscribe(xreq, event) < 0)
		ERROR("can't subscribe: %m");
}

static void client_on_event_unsubscribe_cb(void *closure, void *request, uint16_t event_id)
{
	struct afb_stub_ws *stubws = closure;
	struct afb_xreq *xreq = request;
	struct afb_event_x2 *event;
	int rc;

	rc = u16id2ptr_get(stubws->event_proxies, event_id, (void**)&event);
	if (rc < 0 || !event || afb_xreq_unsubscribe(xreq, event) < 0)
		ERROR("can't unsubscribe: %m");
}

static void client_on_event_push_cb(void *closure, uint16_t event_id, struct json_object *data)
{
	struct afb_stub_ws *stubws = closure;
	struct afb_event_x2 *event;
	int rc;

	rc = u16id2ptr_get(stubws->event_proxies, event_id, (void**)&event);
	if (rc >= 0 && event)
		rc = afb_evt_event_x2_push(event, data);
	else
		ERROR("unreadable push event");
	if (rc <= 0)
		afb_proto_ws_client_event_unexpected(stubws->proto, event_id);
}

static void client_on_event_broadcast_cb(void *closure, const char *event_name, struct json_object *data, const uuid_binary_t uuid, uint8_t hop)
{
	afb_evt_rebroadcast(event_name, data, uuid, hop);
}

/*****************************************************/

static struct afb_session *server_add_session(struct afb_stub_ws *stubws, uint16_t sessionid, const char *sessionstr)
{
	struct afb_session *session;
	int rc, created;

	session = afb_session_get(sessionstr, AFB_SESSION_TIMEOUT_DEFAULT, &created);
	if (session == NULL)
		ERROR("can't create session %s, out of memory", sessionstr);
	else {
		afb_session_set_autoclose(session, 1);
		rc = u16id2ptr_add(&stubws->session_proxies, sessionid, session);
		if (rc < 0) {
			ERROR("can't record session %s", sessionstr);
			afb_session_unref(session);
			session = NULL;
		}
	}
	return session;
}

static void server_on_session_create_cb(void *closure, uint16_t sessionid, const char *sessionstr)
{
	struct afb_stub_ws *stubws = closure;

	server_add_session(stubws, sessionid, sessionstr);
}

static void server_on_session_remove_cb(void *closure, uint16_t sessionid)
{
	struct afb_stub_ws *stubws = closure;
	struct afb_session *session;
	int rc;
	
	rc = u16id2ptr_drop(&stubws->session_proxies, sessionid, (void**)&session);
	if (rc == 0 && session)
		afb_session_unref(session);
}

static void server_on_token_create_cb(void *closure, uint16_t tokenid, const char *tokenstr)
{
	struct afb_stub_ws *stubws = closure;
	struct afb_token *token;
	int rc;

	rc = afb_token_get(&token, tokenstr);
	if (rc < 0)
		ERROR("can't create token %s, out of memory", tokenstr);
	else {
		rc = u16id2ptr_add(&stubws->token_proxies, tokenid, token);
		if (rc < 0) {
			ERROR("can't record token %s", tokenstr);
			afb_token_unref(token);
		}
	}
}

static void server_on_token_remove_cb(void *closure, uint16_t tokenid)
{
	struct afb_stub_ws *stubws = closure;
	struct afb_token *token;
	int rc;
	
	rc = u16id2ptr_drop(&stubws->token_proxies, tokenid, (void**)&token);
	if (rc == 0 && token)
		afb_token_unref(token);
}

static void server_on_event_unexpected_cb(void *closure, uint16_t eventid)
{
	struct afb_stub_ws *stubws = closure;

	afb_evt_listener_unwatch_id(stubws->listener, eventid);
}

static void server_on_call_cb(void *closure, struct afb_proto_ws_call *call, const char *verb, struct json_object *args, uint16_t sessionid, uint16_t tokenid, const char *user_creds)
{
	const char *errstr = afb_error_text_internal_error;
	struct afb_stub_ws *stubws = closure;
	struct server_req *wreq;
	struct afb_session *session;
	struct afb_token *token;
	int rc;

	afb_stub_ws_addref(stubws);

	/* get tokens and sessions */
	rc = u16id2ptr_get(stubws->session_proxies, sessionid, (void**)&session);
	if (rc < 0) {
		if (sessionid != 0)
			goto no_session;
		session = server_add_session(stubws, sessionid, NULL);
		if (!session)
			goto out_of_memory;
	}
	if (!tokenid || u16id2ptr_get(stubws->token_proxies, tokenid, (void**)&token) < 0)
		token = NULL;

	/* create the request */
	wreq = malloc(sizeof *wreq);
	if (wreq == NULL)
		goto out_of_memory;

	afb_xreq_init(&wreq->xreq, &server_req_xreq_itf);
	wreq->stubws = stubws;
	wreq->call = call;

	/* init the context */
	afb_context_init(&wreq->xreq.context, session, token, stubws->cred);
	afb_context_on_behalf_import(&wreq->xreq.context, user_creds);

	/* makes the call */
	wreq->xreq.request.called_api = stubws->apiname;
	wreq->xreq.request.called_verb = verb;
	wreq->xreq.json = args;
	afb_xreq_process(&wreq->xreq, stubws->apiset);
	return;

no_session:
	errstr = afb_error_text_unknown_session;
out_of_memory:
	json_object_put(args);
	afb_stub_ws_unref(stubws);
	afb_proto_ws_call_reply(call, NULL, errstr, NULL);
	afb_proto_ws_call_unref(call);
}

static void server_on_description_cb(void *closure, struct json_object *description)
{
	struct afb_proto_ws_describe *describe = closure;
	afb_proto_ws_describe_put(describe, description);
	json_object_put(description);
}


static void server_on_describe_cb(void *closure, struct afb_proto_ws_describe *describe)
{
	struct afb_stub_ws *stubws = closure;

	afb_apiset_describe(stubws->apiset, stubws->apiname, server_on_description_cb, describe);
}

/*****************************************************/

static const struct afb_proto_ws_client_itf client_itf =
{
	.on_reply = client_on_reply_cb,
	.on_event_create = client_on_event_create_cb,
	.on_event_remove = client_on_event_remove_cb,
	.on_event_subscribe = client_on_event_subscribe_cb,
	.on_event_unsubscribe = client_on_event_unsubscribe_cb,
	.on_event_push = client_on_event_push_cb,
	.on_event_broadcast = client_on_event_broadcast_cb,
};

static struct afb_api_itf client_api_itf = {
	.call = client_api_call_cb,
	.describe = client_api_describe_cb
};

static const struct afb_proto_ws_server_itf server_itf =
{
	.on_session_create = server_on_session_create_cb,
	.on_session_remove = server_on_session_remove_cb,
	.on_token_create = server_on_token_create_cb,
	.on_token_remove = server_on_token_remove_cb,
	.on_call = server_on_call_cb,
	.on_describe = server_on_describe_cb,
	.on_event_unexpected = server_on_event_unexpected_cb
};

/* the interface for events pushing */
static const struct afb_evt_itf server_event_itf = {
	.broadcast = server_event_broadcast_cb,
	.push = server_event_push_cb,
	.add = server_event_add_cb,
	.remove = server_event_remove_cb
};

/*****************************************************/
/*****************************************************/

static void release_all_sessions_cb(void*closure, uint16_t id, void *ptr)
{
	struct afb_session *session = ptr;
	afb_session_unref(session);
}

static void release_all_tokens_cb(void*closure, uint16_t id, void *ptr)
{
	struct afb_token *token = ptr;
	afb_token_unref(token);
}

static void release_all_events_cb(void*closure, uint16_t id, void *ptr)
{
	struct afb_event_x2 *eventid = ptr;
	afb_evt_event_x2_unref(eventid);
}

/* disconnect */
static void disconnect(struct afb_stub_ws *stubws)
{
	struct u16id2ptr *i2p;
	struct u16id2bool *i2b;

	afb_proto_ws_unref(__atomic_exchange_n(&stubws->proto, NULL, __ATOMIC_RELAXED));
	if (stubws->is_client) {
		i2p = __atomic_exchange_n(&stubws->event_proxies, NULL, __ATOMIC_RELAXED);
		if (i2p) {
			u16id2ptr_forall(i2p, release_all_events_cb, NULL);
			u16id2ptr_destroy(&i2p);
		}
		i2b = __atomic_exchange_n(&stubws->session_flags, NULL, __ATOMIC_RELAXED);
		u16id2bool_destroy(&i2b);
		i2b = __atomic_exchange_n(&stubws->token_flags, NULL, __ATOMIC_RELAXED);
		u16id2bool_destroy(&i2b);
	} else {
		afb_evt_listener_unref(__atomic_exchange_n(&stubws->listener, NULL, __ATOMIC_RELAXED));
		afb_cred_unref(__atomic_exchange_n(&stubws->cred, NULL, __ATOMIC_RELAXED));
		i2b = __atomic_exchange_n(&stubws->event_flags, NULL, __ATOMIC_RELAXED);
		u16id2bool_destroy(&i2b);
		i2p = __atomic_exchange_n(&stubws->session_proxies, NULL, __ATOMIC_RELAXED);
		if (i2p) {
			u16id2ptr_forall(i2p, release_all_sessions_cb, NULL);
			u16id2ptr_destroy(&i2p);
		}
		i2p = __atomic_exchange_n(&stubws->token_proxies, NULL, __ATOMIC_RELAXED);
		if (i2p) {
			u16id2ptr_forall(i2p, release_all_tokens_cb, NULL);
			u16id2ptr_destroy(&i2p);
		}
	}
}

/* callback when receiving a hangup */
static void on_hangup(void *closure)
{
	struct afb_stub_ws *stubws = closure;

	if (stubws->proto) {
		afb_stub_ws_addref(stubws);
		disconnect(stubws);
		if (stubws->on_hangup)
			stubws->on_hangup(stubws);
		afb_stub_ws_unref(stubws);
	}
}

static int enqueue_processing(struct afb_proto_ws *proto, void (*callback)(int signum, void* arg), void *arg)
{
	return jobs_queue(proto, 0, callback, arg);
}

/*****************************************************/

static struct afb_proto_ws *afb_stub_ws_create_proto(struct afb_stub_ws *stubws, struct fdev *fdev, uint8_t is_client)
{
	struct afb_proto_ws *proto;

	stubws->proto = proto = is_client
		  ? afb_proto_ws_create_client(fdev, &client_itf, stubws)
		  : afb_proto_ws_create_server(fdev, &server_itf, stubws);
	if (proto) {
		afb_proto_ws_on_hangup(proto, on_hangup);
		afb_proto_ws_set_queuing(proto, enqueue_processing);
	}

	return proto;
}

static struct afb_stub_ws *afb_stub_ws_create(struct fdev *fdev, const char *apiname, struct afb_apiset *apiset, uint8_t is_client)
{
	struct afb_stub_ws *stubws;

	stubws = calloc(1, sizeof *stubws + 1 + strlen(apiname));
	if (stubws == NULL)
		errno = ENOMEM;
	else {
		if (afb_stub_ws_create_proto(stubws, fdev, is_client)) {
			stubws->refcount = 1;
			stubws->is_client = is_client;
			strcpy(stubws->apiname, apiname);
			stubws->apiset = afb_apiset_addref(apiset);
			return stubws;
		}
		free(stubws);
	}
	fdev_unref(fdev);
	return NULL;
}

struct afb_stub_ws *afb_stub_ws_create_client(struct fdev *fdev, const char *apiname, struct afb_apiset *apiset)
{
	return afb_stub_ws_create(fdev, apiname, apiset, 1);
}

struct afb_stub_ws *afb_stub_ws_create_server(struct fdev *fdev, const char *apiname, struct afb_apiset *apiset)
{
	struct afb_stub_ws *stubws;

	stubws = afb_stub_ws_create(fdev, apiname, apiset, 0);
	if (stubws) {
		stubws->cred = afb_cred_create_for_socket(fdev_fd(fdev));
		stubws->listener = afb_evt_listener_create(&server_event_itf, stubws);
		if (stubws->listener != NULL)
			return stubws;
		afb_stub_ws_unref(stubws);
	}
	return NULL;
}

void afb_stub_ws_unref(struct afb_stub_ws *stubws)
{
	if (stubws && !__atomic_sub_fetch(&stubws->refcount, 1, __ATOMIC_RELAXED)) {

		if (stubws->is_client) {
			stubws->robust.reopen = NULL;
			if (stubws->robust.release)
				stubws->robust.release(stubws->robust.closure);
		}

		disconnect(stubws);
		afb_apiset_unref(stubws->apiset);
		free(stubws);
	}
}

void afb_stub_ws_addref(struct afb_stub_ws *stubws)
{
	__atomic_add_fetch(&stubws->refcount, 1, __ATOMIC_RELAXED);
}

void afb_stub_ws_set_on_hangup(struct afb_stub_ws *stubws, void (*on_hangup)(struct afb_stub_ws*))
{
	stubws->on_hangup = on_hangup;
}

const char *afb_stub_ws_name(struct afb_stub_ws *stubws)
{
	return stubws->apiname;
}

struct afb_api_item afb_stub_ws_client_api(struct afb_stub_ws *stubws)
{
	struct afb_api_item api;

	assert(stubws->is_client); /* check client */
	api.closure = stubws;
	api.itf = &client_api_itf;
	api.group = stubws; /* serialize for reconnections */
	return api;
}

int afb_stub_ws_client_add(struct afb_stub_ws *stubws, struct afb_apiset *apiset)
{
	return afb_apiset_add(apiset, stubws->apiname, afb_stub_ws_client_api(stubws));
}

void afb_stub_ws_client_robustify(struct afb_stub_ws *stubws, struct fdev *(*reopen)(void*), void *closure, void (*release)(void*))
{
	assert(stubws->is_client); /* check client */

	if (stubws->robust.release)
		stubws->robust.release(stubws->robust.closure);

	stubws->robust.reopen = reopen;
	stubws->robust.closure = closure;
	stubws->robust.release = release;
}
