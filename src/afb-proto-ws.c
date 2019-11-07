/*
 * Copyright (C) 2015-2019 "IoT.bzh"
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

#include "afb-ws.h"
#include "afb-msg-json.h"
#include "afb-proto-ws.h"
#include "fdev.h"
#include "verbose.h"

struct afb_proto_ws;

/******** implementation of internal binder protocol per api **************/
/*

This protocol is asymetric: there is a client and a server

The client can require the following actions:

  - call a verb

  - ask for description

The server must reply to the previous actions by

  - answering success or failure of the call

  - answering the required description

The server can also within the context of a call

  - subscribe or unsubscribe an event

For the purpose of handling events the server can:

  - create/destroy an event

  - push or brodcast data as an event

*/
/************** constants for protocol definition *************************/

#define CHAR_FOR_CALL             'C'
#define CHAR_FOR_REPLY            'Y'
#define CHAR_FOR_EVT_BROADCAST    '*'
#define CHAR_FOR_EVT_ADD          '+'
#define CHAR_FOR_EVT_DEL          '-'
#define CHAR_FOR_EVT_PUSH         '!'
#define CHAR_FOR_EVT_SUBSCRIBE    'S'
#define CHAR_FOR_EVT_UNSUBSCRIBE  'U'
#define CHAR_FOR_DESCRIBE         'D'
#define CHAR_FOR_DESCRIPTION      'd'

/******************* handling calls *****************************/

/*
 * structure for recording calls on client side
 */
struct client_call {
	struct client_call *next;	/* the next call */
	struct afb_proto_ws *protows;	/* the proto_ws */
	void *request;			/* the request closure */
	uint32_t callid;		/* the message identifier */
};

/*
 * structure for a ws request
 */
struct afb_proto_ws_call {
	struct client_call *next;	/* the next call */
	struct afb_proto_ws *protows;	/* the client of the request */
	uint32_t refcount;		/* reference count */
	uint32_t callid;		/* the incoming request callid */
	char *buffer;			/* the incoming buffer */
};

/*
 * structure for recording describe requests
 */
struct client_describe
{
	struct client_describe *next;
	struct afb_proto_ws *protows;
	void (*callback)(void*, struct json_object*);
	void *closure;
	uint32_t descid;
};

/*
 * structure for jobs of describing
 */
struct afb_proto_ws_describe
{
	struct afb_proto_ws *protows;
	uint32_t descid;
};

/******************* proto description for client or servers ******************/

struct afb_proto_ws
{
	/* count of references */
	int refcount;

	/* resource control */
	pthread_mutex_t mutex;

	/* websocket */
	struct afb_ws *ws;

	/* the client closure */
	void *closure;

	/* the client side interface */
	const struct afb_proto_ws_client_itf *client_itf;

	/* the server side interface */
	const struct afb_proto_ws_server_itf *server_itf;

	/* emitted calls (client side) */
	struct client_call *calls;

	/* pending description (client side) */
	struct client_describe *describes;

	/* on hangup callback */
	void (*on_hangup)(void *closure);

	/* queuing facility for processing messages */
	int (*queuing)(struct afb_proto_ws *proto, void (*process)(int s, void *c), void *closure);
};

/******************* streaming objects **********************************/

#define WRITEBUF_COUNT_MAX	32
#define WRITEBUF_BUFSZ		(WRITEBUF_COUNT_MAX * sizeof(uint32_t))

struct writebuf
{
	int iovcount, bufcount;
	struct iovec iovec[WRITEBUF_COUNT_MAX];
	char buf[WRITEBUF_BUFSZ];
};

struct readbuf
{
	char *base, *head, *end;
};

struct binary
{
	struct afb_proto_ws *protows;
	struct readbuf rb;
};

/******************* common useful tools **********************************/

/**
 * translate a pointer to some integer
 * @param ptr the pointer to translate
 * @return an integer
 */
static inline uint32_t ptr2id(void *ptr)
{
	return (uint32_t)(((intptr_t)ptr) >> 6);
}

/******************* serialisation part **********************************/

static char *readbuf_get(struct readbuf *rb, uint32_t length)
{
	char *before = rb->head;
	char *after = before + length;
	if (after > rb->end)
		return 0;
	rb->head = after;
	return before;
}

__attribute__((unused))
static int readbuf_char(struct readbuf *rb, char *value)
{
	if (rb->head >= rb->end)
		return 0;
	*value = *rb->head++;
	return 1;
}

static int readbuf_uint32(struct readbuf *rb, uint32_t *value)
{
	char *after = rb->head + sizeof *value;
	if (after > rb->end)
		return 0;
	memcpy(value, rb->head, sizeof *value);
	rb->head = after;
	*value = le32toh(*value);
	return 1;
}

static int _readbuf_string_(struct readbuf *rb, const char **value, size_t *length, int nulok)
{
	uint32_t len;
	if (!readbuf_uint32(rb, &len))
		return 0;
	if (!len) {
		if (!nulok)
			return 0;
		*value = NULL;
		if (length)
			*length = 0;
		return 1;
	}
	if (length)
		*length = (size_t)(len - 1);
	return (*value = readbuf_get(rb, len)) != NULL &&  rb->head[-1] == 0;
}


static int readbuf_string(struct readbuf *rb, const char **value, size_t *length)
{
	return _readbuf_string_(rb, value, length, 0);
}

static int readbuf_nullstring(struct readbuf *rb, const char **value, size_t *length)
{
	return _readbuf_string_(rb, value, length, 1);
}

static int readbuf_object(struct readbuf *rb, struct json_object **object)
{
	const char *string;
	struct json_object *o;
	enum json_tokener_error jerr;
	int rc = readbuf_string(rb, &string, NULL);
	if (rc) {
		o = json_tokener_parse_verbose(string, &jerr);
		if (jerr != json_tokener_success)
			o = json_object_new_string(string);
		*object = o;
	}
	return rc;
}

static int writebuf_put(struct writebuf *wb, const void *value, size_t length)
{
	int i = wb->iovcount;
	if (i == WRITEBUF_COUNT_MAX)
		return 0;
	wb->iovec[i].iov_base = (void*)value;
	wb->iovec[i].iov_len = length;
	wb->iovcount = i + 1;
	return 1;
}

static int writebuf_putbuf(struct writebuf *wb, const void *value, int length)
{
	char *p;
	int i = wb->iovcount, n = wb->bufcount, nafter;

	/* check enough length */
	nafter = n + length;
	if (nafter > WRITEBUF_BUFSZ)
		return 0;

	/* get where to store */
	p = &wb->buf[n];
	if (i && p == (((char*)wb->iovec[i - 1].iov_base) + wb->iovec[i - 1].iov_len))
		/* increase previous iovec */
		wb->iovec[i - 1].iov_len += (size_t)length;
	else if (i == WRITEBUF_COUNT_MAX)
		/* no more iovec */
		return 0;
	else {
		/* new iovec */
		wb->iovec[i].iov_base = p;
		wb->iovec[i].iov_len = (size_t)length;
		wb->iovcount = i + 1;
	}
	/* store now */
	memcpy(p, value, (size_t)length);
	wb->bufcount = nafter;
	return 1;
}

static int writebuf_char(struct writebuf *wb, char value)
{
	return writebuf_putbuf(wb, &value, 1);
}

static int writebuf_uint32(struct writebuf *wb, uint32_t value)
{
	value = htole32(value);
	return writebuf_putbuf(wb, &value, (int)sizeof value);
}

static int writebuf_string_length(struct writebuf *wb, const char *value, size_t length)
{
	uint32_t len = (uint32_t)++length;
	return (size_t)len == length && len && writebuf_uint32(wb, len) && writebuf_put(wb, value, length);
}

static int writebuf_string(struct writebuf *wb, const char *value)
{
	return writebuf_string_length(wb, value, strlen(value));
}

static int writebuf_nullstring(struct writebuf *wb, const char *value)
{
	return value ? writebuf_string_length(wb, value, strlen(value)) : writebuf_uint32(wb, 0);
}

static int writebuf_object(struct writebuf *wb, struct json_object *object)
{
	const char *string = json_object_to_json_string_ext(object, JSON_C_TO_STRING_PLAIN);
	return string != NULL && writebuf_string(wb, string);
}

/******************* queuing of messages *****************/

/* queue the processing of the received message (except if size=0 cause it's not a valid message) */
static void queue_message_processing(struct afb_proto_ws *protows, char *data, size_t size, void (*processing)(int,void*))
{
	struct binary *binary;

	if (size) {
		binary = malloc(sizeof *binary);
		if (!binary) {
			/* TODO process the problem */
			errno = ENOMEM;
		} else {
			binary->protows = protows;
			binary->rb.base = data;
			binary->rb.head = data;
			binary->rb.end = data + size;
			if (!protows->queuing
			 || protows->queuing(protows, processing, binary) < 0)
				processing(0, binary);
			return;
		}
	}
	free(data);
}

/******************* sending messages *****************/

static int proto_write(struct afb_proto_ws *protows, struct writebuf *wb)
{
	int rc;
	struct afb_ws *ws;

	pthread_mutex_lock(&protows->mutex);
	ws = protows->ws;
	if (ws == NULL) {
		errno = EPIPE;
		rc = -1;
	} else {
		rc = afb_ws_binary_v(ws, wb->iovec, wb->iovcount);
		if (rc > 0)
			rc = 0;
	}
	pthread_mutex_unlock(&protows->mutex);
	return rc;
}

/******************* ws request part for server *****************/

void afb_proto_ws_call_addref(struct afb_proto_ws_call *call)
{
	__atomic_add_fetch(&call->refcount, 1, __ATOMIC_RELAXED);
}

void afb_proto_ws_call_unref(struct afb_proto_ws_call *call)
{
	if (__atomic_sub_fetch(&call->refcount, 1, __ATOMIC_RELAXED))
		return;

	afb_proto_ws_unref(call->protows);
	free(call->buffer);
	free(call);
}

int afb_proto_ws_call_reply(struct afb_proto_ws_call *call, struct json_object *obj, const char *error, const char *info)
{
	int rc = -1;
	struct writebuf wb = { .iovcount = 0, .bufcount = 0 };
	struct afb_proto_ws *protows = call->protows;

	if (writebuf_char(&wb, CHAR_FOR_REPLY)
	 && writebuf_uint32(&wb, call->callid)
	 && writebuf_nullstring(&wb, error)
	 && writebuf_nullstring(&wb, info)
	 && writebuf_object(&wb, obj))
		rc = proto_write(protows, &wb);
	return rc;
}

int afb_proto_ws_call_subscribe(struct afb_proto_ws_call *call, const char *event_name, int event_id)
{
	int rc = -1;
	struct writebuf wb = { .iovcount = 0, .bufcount = 0 };
	struct afb_proto_ws *protows = call->protows;

	if (writebuf_char(&wb, CHAR_FOR_EVT_SUBSCRIBE)
	 && writebuf_uint32(&wb, call->callid)
	 && writebuf_uint32(&wb, (uint32_t)event_id)
	 && writebuf_string(&wb, event_name))
		rc = proto_write(protows, &wb);
	return rc;
}

int afb_proto_ws_call_unsubscribe(struct afb_proto_ws_call *call, const char *event_name, int event_id)
{
	int rc = -1;
	struct writebuf wb = { .iovcount = 0, .bufcount = 0 };
	struct afb_proto_ws *protows = call->protows;

	if (writebuf_char(&wb, CHAR_FOR_EVT_UNSUBSCRIBE)
	 && writebuf_uint32(&wb, call->callid)
	 && writebuf_uint32(&wb, (uint32_t)event_id)
	 && writebuf_string(&wb, event_name))
		rc = proto_write(protows, &wb);
	return rc;
}

/******************* client part **********************************/

/* search a memorized call */
static struct client_call *client_call_search_locked(struct afb_proto_ws *protows, uint32_t callid)
{
	struct client_call *call;

	call = protows->calls;
	while (call != NULL && call->callid != callid)
		call = call->next;

	return call;
}

static struct client_call *client_call_search_unlocked(struct afb_proto_ws *protows, uint32_t callid)
{
	struct client_call *result;

	pthread_mutex_lock(&protows->mutex);
	result = client_call_search_locked(protows, callid);
	pthread_mutex_unlock(&protows->mutex);
	return result;
}

/* free and release the memorizing call */
static void client_call_destroy(struct client_call *call)
{
	struct client_call **prv;
	struct afb_proto_ws *protows = call->protows;

	pthread_mutex_lock(&protows->mutex);
	prv = &call->protows->calls;
	while (*prv != NULL) {
		if (*prv == call) {
			*prv = call->next;
			break;
		}
		prv = &(*prv)->next;
	}
	pthread_mutex_unlock(&protows->mutex);
	free(call);
}

/* get event data from the message */
static int client_msg_event_read(struct readbuf *rb, uint32_t *eventid, const char **name)
{
	return readbuf_uint32(rb, eventid) && readbuf_string(rb, name, NULL);
}

/* get event from the message */
static int client_msg_call_get(struct afb_proto_ws *protows, struct readbuf *rb, struct client_call **call)
{
	uint32_t callid;

	/* get event data from the message */
	if (!readbuf_uint32(rb, &callid)) {
		return 0;
	}

	/* get the call */
	*call = client_call_search_unlocked(protows, callid);
	if (*call == NULL) {
		return 0;
	}

	return 1;
}

/* adds an event */
static void client_on_event_create(struct afb_proto_ws *protows, struct readbuf *rb)
{
	const char *event_name;
	uint32_t event_id;

	if (protows->client_itf->on_event_create && client_msg_event_read(rb, &event_id, &event_name))
		protows->client_itf->on_event_create(protows->closure, event_name, (int)event_id);
	else
		ERROR("Ignoring creation of event");
}

/* removes an event */
static void client_on_event_remove(struct afb_proto_ws *protows, struct readbuf *rb)
{
	const char *event_name;
	uint32_t event_id;

	if (protows->client_itf->on_event_remove && client_msg_event_read(rb, &event_id, &event_name))
		protows->client_itf->on_event_remove(protows->closure, event_name, (int)event_id);
	else
		ERROR("Ignoring deletion of event");
}

/* subscribes an event */
static void client_on_event_subscribe(struct afb_proto_ws *protows, struct readbuf *rb)
{
	const char *event_name;
	uint32_t event_id;
	struct client_call *call;

	if (protows->client_itf->on_event_subscribe && client_msg_call_get(protows, rb, &call) && client_msg_event_read(rb, &event_id, &event_name))
		protows->client_itf->on_event_subscribe(protows->closure, call->request, event_name, (int)event_id);
	else
		ERROR("Ignoring subscription to event");
}

/* unsubscribes an event */
static void client_on_event_unsubscribe(struct afb_proto_ws *protows, struct readbuf *rb)
{
	const char *event_name;
	uint32_t event_id;
	struct client_call *call;

	if (protows->client_itf->on_event_unsubscribe && client_msg_call_get(protows, rb, &call) && client_msg_event_read(rb, &event_id, &event_name))
		protows->client_itf->on_event_unsubscribe(protows->closure, call->request, event_name, (int)event_id);
	else
		ERROR("Ignoring unsubscription to event");
}

/* receives broadcasted events */
static void client_on_event_broadcast(struct afb_proto_ws *protows, struct readbuf *rb)
{
	const char *event_name, *uuid;
	char hop;
	struct json_object *object;

	if (protows->client_itf->on_event_broadcast && readbuf_string(rb, &event_name, NULL) && readbuf_object(rb, &object) && (uuid = readbuf_get(rb, 16)) && readbuf_char(rb, &hop))
		protows->client_itf->on_event_broadcast(protows->closure, event_name, object, (unsigned char*)uuid, (uint8_t)hop);
	else
		ERROR("Ignoring broadcast of event");
}

/* pushs an event */
static void client_on_event_push(struct afb_proto_ws *protows, struct readbuf *rb)
{
	const char *event_name;
	uint32_t event_id;
	struct json_object *object;

	if (protows->client_itf->on_event_push && client_msg_event_read(rb, &event_id, &event_name) && readbuf_object(rb, &object))
		protows->client_itf->on_event_push(protows->closure, event_name, (int)event_id, object);
	else
		ERROR("Ignoring push of event");
}

static void client_on_reply(struct afb_proto_ws *protows, struct readbuf *rb)
{
	struct client_call *call;
	struct json_object *object;
	const char *error, *info;

	if (!client_msg_call_get(protows, rb, &call))
		return;

	if (readbuf_nullstring(rb, &error, NULL) && readbuf_nullstring(rb, &info, NULL) && readbuf_object(rb, &object)) {
		protows->client_itf->on_reply(protows->closure, call->request, object, error, info);
	} else {
		protows->client_itf->on_reply(protows->closure, call->request, NULL, "proto-error", "can't process success");
	}
	client_call_destroy(call);
}

static void client_on_description(struct afb_proto_ws *protows, struct readbuf *rb)
{
	uint32_t descid;
	struct client_describe *desc, **prv;
	struct json_object *object;

	if (readbuf_uint32(rb, &descid)) {
		pthread_mutex_lock(&protows->mutex);
		prv = &protows->describes;
		while ((desc = *prv) && desc->descid != descid)
			prv = &desc->next;
		if (!desc)
			pthread_mutex_unlock(&protows->mutex);
		else {
			*prv = desc->next;
			pthread_mutex_unlock(&protows->mutex);
			if (!readbuf_object(rb, &object))
				object = NULL;
			desc->callback(desc->closure, object);
			free(desc);
		}
	}
}

/* callback when receiving binary data */
static void client_on_binary_job(int sig, void *closure)
{
	struct binary *binary = closure;

	if (!sig) {
		switch (*binary->rb.head++) {
		case CHAR_FOR_REPLY: /* reply */
			client_on_reply(binary->protows, &binary->rb);
			break;
		case CHAR_FOR_EVT_BROADCAST: /* broadcast */
			client_on_event_broadcast(binary->protows, &binary->rb);
			break;
		case CHAR_FOR_EVT_ADD: /* creates the event */
			client_on_event_create(binary->protows, &binary->rb);
			break;
		case CHAR_FOR_EVT_DEL: /* removes the event */
			client_on_event_remove(binary->protows, &binary->rb);
			break;
		case CHAR_FOR_EVT_PUSH: /* pushs the event */
			client_on_event_push(binary->protows, &binary->rb);
			break;
		case CHAR_FOR_EVT_SUBSCRIBE: /* subscribe event for a request */
			client_on_event_subscribe(binary->protows, &binary->rb);
			break;
		case CHAR_FOR_EVT_UNSUBSCRIBE: /* unsubscribe event for a request */
			client_on_event_unsubscribe(binary->protows, &binary->rb);
			break;
		case CHAR_FOR_DESCRIPTION: /* description */
			client_on_description(binary->protows, &binary->rb);
			break;
		default: /* unexpected message */
			/* TODO: close the connection */
			break;
		}
	}
	free(binary->rb.base);
	free(binary);
}

/* callback when receiving binary data */
static void client_on_binary(void *closure, char *data, size_t size)
{
	struct afb_proto_ws *protows = closure;

	queue_message_processing(protows, data, size, client_on_binary_job);
}

int afb_proto_ws_client_call(
		struct afb_proto_ws *protows,
		const char *verb,
		struct json_object *args,
		const char *sessionid,
		void *request,
		const char *user_creds
)
{
	int rc = -1;
	struct client_call *call;
	struct writebuf wb = { .iovcount = 0, .bufcount = 0 };

	/* allocate call data */
	call = malloc(sizeof *call);
	if (call == NULL) {
		errno = ENOMEM;
		return -1;
	}
	call->request = request;

	/* init call data */
	pthread_mutex_lock(&protows->mutex);
	call->callid = ptr2id(call);
	while(client_call_search_locked(protows, call->callid) != NULL)
		call->callid++;
	call->protows = protows;
	call->next = protows->calls;
	protows->calls = call;
	pthread_mutex_unlock(&protows->mutex);

	/* creates the call message */
	if (!writebuf_char(&wb, CHAR_FOR_CALL)
	 || !writebuf_uint32(&wb, call->callid)
	 || !writebuf_string(&wb, verb)
	 || !writebuf_string(&wb, sessionid)
	 || !writebuf_object(&wb, args)
	 || !writebuf_nullstring(&wb, user_creds)) {
		errno = EINVAL;
		goto clean;
	}

	/* send */
	rc = proto_write(protows, &wb);
	if (!rc)
		goto end;

clean:
	client_call_destroy(call);
end:
	return rc;
}

/* get the description */
int afb_proto_ws_client_describe(struct afb_proto_ws *protows, void (*callback)(void*, struct json_object*), void *closure)
{
	struct client_describe *desc, *d;
	struct writebuf wb = { .iovcount = 0, .bufcount = 0 };

	desc = malloc(sizeof *desc);
	if (!desc) {
		errno = ENOMEM;
		goto error;
	}

	/* fill in stack the description of the task */
	pthread_mutex_lock(&protows->mutex);
	desc->descid = ptr2id(desc);
	d = protows->describes;
	while (d) {
		if (d->descid != desc->descid)
			d = d->next;
		else {
			desc->descid++;
			d = protows->describes;
		}
	}
	desc->callback = callback;
	desc->closure = closure;
	desc->protows = protows;
	desc->next = protows->describes;
	protows->describes = desc;

	/* send */
	if (writebuf_char(&wb, CHAR_FOR_DESCRIBE)
	 && writebuf_uint32(&wb, desc->descid)
	 && protows->ws != NULL
	 && afb_ws_binary_v(protows->ws, wb.iovec, wb.iovcount) >= 0) {
		pthread_mutex_unlock(&protows->mutex);
		return 0;
	}

	d = protows->describes;
	if (d == desc)
		protows->describes = desc->next;
	else {
		while(d && d->next != desc)
			d = d->next;
		if (d)
			d->next = desc->next;
	}
	pthread_mutex_unlock(&protows->mutex);
	free(desc);
error:
	/* TODO? callback(closure, NULL); */
	return -1;
}

/******************* client description part for server *****************************/

/* on call, propagate it to the ws service */
static void server_on_call(struct afb_proto_ws *protows, struct readbuf *rb)
{
	struct afb_proto_ws_call *call;
	const char *uuid, *verb, *user_creds;
	uint32_t callid;
	size_t lenverb;
	struct json_object *object;

	afb_proto_ws_addref(protows);

	/* reads the call message data */
	if (!readbuf_uint32(rb, &callid)
	 || !readbuf_string(rb, &verb, &lenverb)
	 || !readbuf_string(rb, &uuid, NULL)
	 || !readbuf_object(rb, &object)
	 || !readbuf_nullstring(rb, &user_creds, NULL))
		goto overflow;

	/* create the request */
	call = malloc(sizeof *call);
	if (call == NULL)
		goto out_of_memory;

	call->protows = protows;
	call->callid = callid;
	call->refcount = 1;
	call->buffer = rb->base;
	rb->base = NULL; /* don't free the buffer */

	protows->server_itf->on_call(protows->closure, call, verb, object, uuid, user_creds);
	return;

out_of_memory:
	json_object_put(object);

overflow:
	afb_proto_ws_unref(protows);
}

static int server_send_description(struct afb_proto_ws *protows, uint32_t descid, struct json_object *descobj)
{
	int rc = -1;
	struct writebuf wb = { .iovcount = 0, .bufcount = 0 };

	if (writebuf_char(&wb, CHAR_FOR_DESCRIPTION)
	 && writebuf_uint32(&wb, descid)
	 && writebuf_object(&wb, descobj))
		rc = proto_write(protows, &wb);
	return rc;
}

int afb_proto_ws_describe_put(struct afb_proto_ws_describe *describe, struct json_object *description)
{
	int rc = server_send_description(describe->protows, describe->descid, description);
	afb_proto_ws_unref(describe->protows);
	free(describe);
	return rc;
}

/* on describe, propagate it to the ws service */
static void server_on_describe(struct afb_proto_ws *protows, struct readbuf *rb)
{
	uint32_t descid;
	struct afb_proto_ws_describe *desc;

	/* reads the descid */
	if (readbuf_uint32(rb, &descid)) {
		if (protows->server_itf->on_describe) {
			/* create asynchronous job */
			desc = malloc(sizeof *desc);
			if (desc) {
				desc->descid = descid;
				desc->protows = protows;
				afb_proto_ws_addref(protows);
				protows->server_itf->on_describe(protows->closure, desc);
				return;
			}
		}
		server_send_description(protows, descid, NULL);
	}
}

/* callback when receiving binary data */
static void server_on_binary_job(int sig, void *closure)
{
	struct binary *binary = closure;

	if (!sig) {
		switch (*binary->rb.head++) {
		case CHAR_FOR_CALL:
			server_on_call(binary->protows, &binary->rb);
			break;
		case CHAR_FOR_DESCRIBE:
			server_on_describe(binary->protows, &binary->rb);
			break;
		default: /* unexpected message */
			/* TODO: close the connection */
			break;
		}
	}
	free(binary->rb.base);
	free(binary);
}

static void server_on_binary(void *closure, char *data, size_t size)
{
	struct afb_proto_ws *protows = closure;

	queue_message_processing(protows, data, size, server_on_binary_job);
}

/******************* server part: manage events **********************************/

static int server_event_send(struct afb_proto_ws *protows, char order, const char *event_name, int event_id, struct json_object *data)
{
	struct writebuf wb = { .iovcount = 0, .bufcount = 0 };
	int rc = -1;

	if (writebuf_char(&wb, order)
	 && writebuf_uint32(&wb, event_id)
	 && writebuf_string(&wb, event_name)
	 && (order != CHAR_FOR_EVT_PUSH || writebuf_object(&wb, data)))
		rc = proto_write(protows, &wb);
	return rc;
}

int afb_proto_ws_server_event_create(struct afb_proto_ws *protows, const char *event_name, int event_id)
{
	return server_event_send(protows, CHAR_FOR_EVT_ADD, event_name, event_id, NULL);
}

int afb_proto_ws_server_event_remove(struct afb_proto_ws *protows, const char *event_name, int event_id)
{
	return server_event_send(protows, CHAR_FOR_EVT_DEL, event_name, event_id, NULL);
}

int afb_proto_ws_server_event_push(struct afb_proto_ws *protows, const char *event_name, int event_id, struct json_object *data)
{
	return server_event_send(protows, CHAR_FOR_EVT_PUSH, event_name, event_id, data);
}

int afb_proto_ws_server_event_broadcast(struct afb_proto_ws *protows, const char *event_name, struct json_object *data, const unsigned char uuid[16], uint8_t hop)
{
	struct writebuf wb = { .iovcount = 0, .bufcount = 0 };
	int rc = -1;

	if (!hop)
		return 0;

	if (writebuf_char(&wb, CHAR_FOR_EVT_BROADCAST)
	 && writebuf_string(&wb, event_name)
	 && writebuf_object(&wb, data)
	 && writebuf_put(&wb, uuid, 16)
	 && writebuf_char(&wb, (char)(hop - 1)))
		rc = proto_write(protows, &wb);
	return rc;
}

/*****************************************************/

/* callback when receiving a hangup */
static void on_hangup(void *closure)
{
	struct afb_proto_ws *protows = closure;
	struct client_describe *cd, *ncd;
	struct client_call *call, *ncall;
	struct afb_ws *ws;

	pthread_mutex_lock(&protows->mutex);
	ncd = protows->describes;
	protows->describes = NULL;
	ncall = protows->calls;
	protows->calls = NULL;
	ws = protows->ws;
	protows->ws = NULL;
	pthread_mutex_unlock(&protows->mutex);

	while (ncall) {
		call= ncall;
		ncall = call->next;
		protows->client_itf->on_reply(protows->closure, call->request, NULL, "disconnected", "server hung up");
		free(call);
	}

	while (ncd) {
		cd= ncd;
		ncd = cd->next;
		cd->callback(cd->closure, NULL);
		free(cd);
	}

	if (ws) {
		afb_ws_destroy(ws);
		if (protows->on_hangup)
			protows->on_hangup(protows->closure);
	}
}

/*****************************************************/

static const struct afb_ws_itf proto_ws_client_ws_itf =
{
	.on_close = NULL,
	.on_text = NULL,
	.on_binary = client_on_binary,
	.on_error = NULL,
	.on_hangup = on_hangup
};

static const struct afb_ws_itf server_ws_itf =
{
	.on_close = NULL,
	.on_text = NULL,
	.on_binary = server_on_binary,
	.on_error = NULL,
	.on_hangup = on_hangup
};

/*****************************************************/

static struct afb_proto_ws *afb_proto_ws_create(struct fdev *fdev, const struct afb_proto_ws_server_itf *itfs, const struct afb_proto_ws_client_itf *itfc, void *closure, const struct afb_ws_itf *itf)
{
	struct afb_proto_ws *protows;

	protows = calloc(1, sizeof *protows);
	if (protows == NULL)
		errno = ENOMEM;
	else {
		fcntl(fdev_fd(fdev), F_SETFD, FD_CLOEXEC);
		fcntl(fdev_fd(fdev), F_SETFL, O_NONBLOCK);
		protows->ws = afb_ws_create(fdev, itf, protows);
		if (protows->ws != NULL) {
			protows->refcount = 1;
			protows->closure = closure;
			protows->server_itf = itfs;
			protows->client_itf = itfc;
			pthread_mutex_init(&protows->mutex, NULL);
			return protows;
		}
		free(protows);
	}
	return NULL;
}

struct afb_proto_ws *afb_proto_ws_create_client(struct fdev *fdev, const struct afb_proto_ws_client_itf *itf, void *closure)
{
	return afb_proto_ws_create(fdev, NULL, itf, closure, &proto_ws_client_ws_itf);
}

struct afb_proto_ws *afb_proto_ws_create_server(struct fdev *fdev, const struct afb_proto_ws_server_itf *itf, void *closure)
{
	return afb_proto_ws_create(fdev, itf, NULL, closure, &server_ws_itf);
}

void afb_proto_ws_unref(struct afb_proto_ws *protows)
{
	if (protows && !__atomic_sub_fetch(&protows->refcount, 1, __ATOMIC_RELAXED)) {
		afb_proto_ws_hangup(protows);
		pthread_mutex_destroy(&protows->mutex);
		free(protows);
	}
}

void afb_proto_ws_addref(struct afb_proto_ws *protows)
{
	__atomic_add_fetch(&protows->refcount, 1, __ATOMIC_RELAXED);
}

int afb_proto_ws_is_client(struct afb_proto_ws *protows)
{
	return !!protows->client_itf;
}

int afb_proto_ws_is_server(struct afb_proto_ws *protows)
{
	return !!protows->server_itf;
}

void afb_proto_ws_hangup(struct afb_proto_ws *protows)
{
	if (protows->ws)
		afb_ws_hangup(protows->ws);
}

void afb_proto_ws_on_hangup(struct afb_proto_ws *protows, void (*on_hangup)(void *closure))
{
	protows->on_hangup = on_hangup;
}

void afb_proto_ws_set_queuing(struct afb_proto_ws *protows, int (*queuing)(struct afb_proto_ws*, void (*)(int,void*), void*))
{
	protows->queuing = queuing;
}
