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
#include <stdio.h>
#include <pthread.h>

#include <json-c/json.h>
#if !defined(JSON_C_TO_STRING_NOSLASHESCAPE)
#define JSON_C_TO_STRING_NOSLASHESCAPE 0
#endif

#include "afb-ws.h"
#include "afb-wsj1.h"
#include "fdev.h"

#define CALL 2
#define RETOK 3
#define RETERR 4
#define EVENT 5

#define WEBSOCKET_CODE_POLICY_VIOLATION  1008
#define WEBSOCKET_CODE_INTERNAL_ERROR    1011

static void wsj1_on_hangup(struct afb_wsj1 *wsj1);
static void wsj1_on_text(struct afb_wsj1 *wsj1, char *text, size_t size);
static struct afb_wsj1_msg *wsj1_msg_make(struct afb_wsj1 *wsj1, char *text, size_t size);

static struct afb_ws_itf wsj1_itf = {
	.on_hangup = (void*)wsj1_on_hangup,
	.on_text = (void*)wsj1_on_text
};

struct wsj1_call
{
	struct wsj1_call *next;
	void (*callback)(void *, struct afb_wsj1_msg *);
	void *closure;
	char id[16];
};

struct afb_wsj1_msg
{
	int refcount;
	struct afb_wsj1 *wsj1;
	struct afb_wsj1_msg *next, *previous;
	char *text;
	int code;
	const char *id;
	const char *api;
	const char *verb;
	const char *event;
	const char *object_s;
	size_t object_s_length;
	const char *token;
	struct json_object *object_j;
};

struct afb_wsj1
{
	int refcount;
	int genid;
	struct afb_wsj1_itf *itf;
	void *closure;
	struct json_tokener *tokener;
	struct afb_ws *ws;
	struct afb_wsj1_msg *messages;
	struct wsj1_call *calls;
	pthread_mutex_t mutex;
};

struct afb_wsj1 *afb_wsj1_create(struct fdev *fdev, struct afb_wsj1_itf *itf, void *closure)
{
	struct afb_wsj1 *result;

	assert(fdev);
	assert(itf);
	assert(itf->on_call);

	result = calloc(1, sizeof * result);
	if (result == NULL)
		goto error;

	result->refcount = 1;
	result->itf = itf;
	result->closure = closure;
	pthread_mutex_init(&result->mutex, NULL);

	result->tokener = json_tokener_new();
	if (result->tokener == NULL)
		goto error2;

	result->ws = afb_ws_create(fdev, &wsj1_itf, result);
	if (result->ws == NULL)
		goto error3;

	return result;

error3:
	json_tokener_free(result->tokener);
error2:
	free(result);
error:
	fdev_unref(fdev);
	return NULL;
}

void afb_wsj1_addref(struct afb_wsj1 *wsj1)
{
	if (wsj1)
		__atomic_add_fetch(&wsj1->refcount, 1, __ATOMIC_RELAXED);
}

void afb_wsj1_unref(struct afb_wsj1 *wsj1)
{
	if (wsj1 && !__atomic_sub_fetch(&wsj1->refcount, 1, __ATOMIC_RELAXED)) {
		afb_ws_destroy(wsj1->ws);
		json_tokener_free(wsj1->tokener);
		free(wsj1);
	}
}

static void wsj1_on_hangup(struct afb_wsj1 *wsj1)
{
	struct wsj1_call *call, *ncall;
	struct afb_wsj1_msg *msg;
	char *text;
	int len;

	static const char error_object_str[] = "{"
		"\"jtype\":\"afb-reply\","
		"\"request\":{"
			"\"status\":\"disconnected\","
			"\"info\":\"server hung up\"}}";

	ncall = __atomic_exchange_n(&wsj1->calls, NULL, __ATOMIC_RELAXED);
	while (ncall) {
		call = ncall;
		ncall = call->next;
		len = asprintf(&text, "[%d,\"%s\",%s]", RETERR, call->id, error_object_str);
		if (len > 0) {
			msg = wsj1_msg_make(wsj1, text, (size_t)len);
			if (msg != NULL) {
				call->callback(call->closure, msg);
				afb_wsj1_msg_unref(msg);
			}
		}
		free(call);
	}

	if (wsj1->itf->on_hangup != NULL)
		wsj1->itf->on_hangup(wsj1->closure, wsj1);
}


static struct wsj1_call *wsj1_locked_call_search(struct afb_wsj1 *wsj1, const char *id, int remove)
{
	struct wsj1_call *r, **p;

	p = &wsj1->calls;
	while((r = *p) != NULL) {
		if (strcmp(r->id, id) == 0) {
			if (remove)
				*p = r->next;
			break;
		}
		p = &r->next;
	}

	return r;
}

static struct wsj1_call *wsj1_call_search(struct afb_wsj1 *wsj1, const char *id, int remove)
{
	struct wsj1_call *r;

	pthread_mutex_lock(&wsj1->mutex);
	r = wsj1_locked_call_search(wsj1, id, remove);
	pthread_mutex_unlock(&wsj1->mutex);

	return r;
}

static struct wsj1_call *wsj1_call_create(struct afb_wsj1 *wsj1, void (*on_reply)(void*,struct afb_wsj1_msg*), void *closure)
{
	struct wsj1_call *call = malloc(sizeof *call);
	if (call == NULL)
		errno = ENOMEM;
	else {
		pthread_mutex_lock(&wsj1->mutex);
		do {
			if (wsj1->genid == 0)
				wsj1->genid = 999999;
			sprintf(call->id, "%d", wsj1->genid--);
		} while (wsj1_locked_call_search(wsj1, call->id, 0) != NULL);
		call->callback = on_reply;
		call->closure = closure;
		call->next = wsj1->calls;
		wsj1->calls = call;
		pthread_mutex_unlock(&wsj1->mutex);
	}
	return call;
}


static int wsj1_msg_scan(char *text, size_t items[10][2])
{
	char *pos, *beg, *end, c;
	int aux, n = 0;

	/* scan */
	pos = text;

	/* scans: [ */
	while(*pos == ' ') pos++;
	if (*pos++ != '[') goto bad_scan;

	/* scans list */
	while(*pos == ' ') pos++;
	if (*pos != ']') {
		for (;;) {
			if (n == 10)
				goto bad_scan;
			beg = pos;
			aux = 0;
			while (aux != 0 || (*pos != ',' && *pos != ']')) {
				switch(*pos++) {
				case '{': case '[': aux++; break;
				case '}': case ']': if (aux--) break;
				case 0: goto bad_scan;
				case '"':
					do {
						switch(c = *pos++) {
						case '\\': if (*pos++) break;
						case 0: goto bad_scan;
						}
					} while(c != '"');
				}
			}
			end = pos;
			while (end > beg && end[-1] == ' ')
				end--;
			items[n][0] = beg - text; /* start offset */
			items[n][1] = end - beg;  /* length */
			n++;
			if (*pos == ']')
				break;
			while(*++pos == ' ');
		}
	}
	while(*++pos == ' ');
	if (*pos) goto bad_scan;
	return n;

bad_scan:
	return -1;
}

static char *wsj1_msg_parse_extract(char *text, size_t offset, size_t size)
{
	text[offset + size] = 0;
	return text + offset;
}

static char *wsj1_msg_parse_string(char *text, size_t offset, size_t size)
{
	if (size > 1 && text[offset] == '"') {
		offset += 1;
		size -= 2;
	}
	return wsj1_msg_parse_extract(text, offset, size);
}

static struct afb_wsj1_msg *wsj1_msg_make(struct afb_wsj1 *wsj1, char *text, size_t size)
{
	size_t items[10][2];
	int n;
	struct afb_wsj1_msg *msg;
	char *verb;

	/* allocate */
	msg = calloc(1, sizeof *msg);
	if (msg == NULL) {
		errno = ENOMEM;
		goto alloc_error;
	}

	/* scan */
	n = wsj1_msg_scan(text, items);
	if (n <= 0)
		goto bad_header;

	/* scans code: 2|3|4|5 */
	if (items[0][1] != 1)
		goto bad_header;

	switch (text[items[0][0]]) {
	case '2': msg->code = CALL; break;
	case '3': msg->code = RETOK; break;
	case '4': msg->code = RETERR; break;
	case '5': msg->code = EVENT; break;
	default: goto bad_header;
	}

	/* fills the message */
	switch (msg->code) {
	case CALL:
		if (n != 4 && n != 5) goto bad_header;
		msg->id = wsj1_msg_parse_string(text, items[1][0], items[1][1]);
		msg->api = wsj1_msg_parse_string(text, items[2][0], items[2][1]);
		verb = strchr(msg->api, '/');
		if (verb == NULL) goto bad_header;
		*verb++ = 0;
		if (!*verb || *verb == '/') goto bad_header;
		msg->verb = verb;
		msg->object_s = wsj1_msg_parse_extract(text, items[3][0], items[3][1]);
		msg->object_s_length = items[3][1];
		msg->token = n == 5 ? wsj1_msg_parse_string(text, items[4][0], items[4][1]) : NULL;
		break;
	case RETOK:
	case RETERR:
		if (n != 3 && n != 4) goto bad_header;
		msg->id = wsj1_msg_parse_string(text, items[1][0], items[1][1]);
		msg->object_s = wsj1_msg_parse_extract(text, items[2][0], items[2][1]);
		msg->object_s_length = items[2][1];
		msg->token = n == 5 ? wsj1_msg_parse_string(text, items[3][0], items[3][1]) : NULL;
		break;
	case EVENT:
		if (n != 3) goto bad_header;
		msg->event = wsj1_msg_parse_string(text, items[1][0], items[1][1]);
		msg->object_s = wsj1_msg_parse_extract(text, items[2][0], items[2][1]);
		msg->object_s_length = items[2][1];
		break;
	}
	/* done */
	msg->text = text;

	/* fill and record the request */
	msg->refcount = 1;
	afb_wsj1_addref(wsj1);
	msg->wsj1 = wsj1;
	pthread_mutex_lock(&wsj1->mutex);
	msg->next = wsj1->messages;
	if (msg->next != NULL)
		msg->next->previous = msg;
	wsj1->messages = msg;
	pthread_mutex_unlock(&wsj1->mutex);

	return msg;

bad_header:
	errno = EBADMSG;
	free(msg);

alloc_error:
	free(text);
	return NULL;
}

static void wsj1_on_text(struct afb_wsj1 *wsj1, char *text, size_t size)
{
	struct wsj1_call *call;
	struct afb_wsj1_msg *msg;

	/* allocate */
	msg = wsj1_msg_make(wsj1, text, size);
	if (msg == NULL) {
		afb_ws_close(wsj1->ws, errno == EBADMSG
			? WEBSOCKET_CODE_POLICY_VIOLATION
			: WEBSOCKET_CODE_INTERNAL_ERROR, NULL);
		return;
	}

	/* handle the message */
	switch (msg->code) {
	case CALL:
		wsj1->itf->on_call(wsj1->closure, msg->api, msg->verb, msg);
		break;
	case RETOK:
	case RETERR:
		call = wsj1_call_search(wsj1, msg->id, 1);
		if (call == NULL)
			afb_ws_close(wsj1->ws, WEBSOCKET_CODE_POLICY_VIOLATION, NULL);
		else
			call->callback(call->closure, msg);
		free(call);
		break;
	case EVENT:
		if (wsj1->itf->on_event != NULL)
			wsj1->itf->on_event(wsj1->closure, msg->event, msg);
		break;
	}
	afb_wsj1_msg_unref(msg);
}

void afb_wsj1_msg_addref(struct afb_wsj1_msg *msg)
{
	if (msg != NULL)
		__atomic_add_fetch(&msg->refcount, 1, __ATOMIC_RELAXED);
}

void afb_wsj1_msg_unref(struct afb_wsj1_msg *msg)
{
	if (msg != NULL && !__atomic_sub_fetch(&msg->refcount, 1, __ATOMIC_RELAXED)) {
		/* unlink the message */
		pthread_mutex_lock(&msg->wsj1->mutex);
		if (msg->next != NULL)
			msg->next->previous = msg->previous;
		if (msg->previous == NULL)
			msg->wsj1->messages = msg->next;
		else
			msg->previous->next = msg->next;
		pthread_mutex_unlock(&msg->wsj1->mutex);
		/* free ressources */
		afb_wsj1_unref(msg->wsj1);
		json_object_put(msg->object_j);
		free(msg->text);
		free(msg);
	}
}

const char *afb_wsj1_msg_object_s(struct afb_wsj1_msg *msg)
{
	return msg->object_s;
}

struct json_object *afb_wsj1_msg_object_j(struct afb_wsj1_msg *msg)
{
	enum json_tokener_error jerr;
	struct json_object *object = msg->object_j;
	if (object == NULL) {
		pthread_mutex_lock(&msg->wsj1->mutex);
		json_tokener_reset(msg->wsj1->tokener);
		object = json_tokener_parse_ex(msg->wsj1->tokener, msg->object_s, 1 + (int)msg->object_s_length);
		jerr = json_tokener_get_error(msg->wsj1->tokener);
		pthread_mutex_unlock(&msg->wsj1->mutex);
		if (jerr != json_tokener_success) {
			/* lazy error detection of json request. Is it to improve? */
			object = json_object_new_string_len(msg->object_s, (int)msg->object_s_length);
		}
		msg->object_j = object;
	}
	return object;
}

int afb_wsj1_msg_is_call(struct afb_wsj1_msg *msg)
{
	return msg->code == CALL;
}

int afb_wsj1_msg_is_reply(struct afb_wsj1_msg *msg)
{
	return msg->code == RETOK || msg->code == RETERR;
}

int afb_wsj1_msg_is_reply_ok(struct afb_wsj1_msg *msg)
{
	return msg->code == RETOK;
}

int afb_wsj1_msg_is_reply_error(struct afb_wsj1_msg *msg)
{
	return msg->code == RETERR;
}

int afb_wsj1_msg_is_event(struct afb_wsj1_msg *msg)
{
	return msg->code == EVENT;
}

const char *afb_wsj1_msg_api(struct afb_wsj1_msg *msg)
{
	return msg->api;
}

const char *afb_wsj1_msg_verb(struct afb_wsj1_msg *msg)
{
	return msg->verb;
}

const char *afb_wsj1_msg_event(struct afb_wsj1_msg *msg)
{
	return msg->event;
}

const char *afb_wsj1_msg_token(struct afb_wsj1_msg *msg)
{
	return msg->token;
}

struct afb_wsj1 *afb_wsj1_msg_wsj1(struct afb_wsj1_msg *msg)
{
	return msg->wsj1;
}

int afb_wsj1_close(struct afb_wsj1 *wsj1, uint16_t code, const char *text)
{
	return afb_ws_close(wsj1->ws, code, text);
}

static int wsj1_send_isot(struct afb_wsj1 *wsj1, int i1, const char *s1, const char *o1, const char *t1)
{
	char code[2] = { (char)('0' + i1), 0 };
	return afb_ws_texts(wsj1->ws, "[", code, ",\"", s1, "\",", o1 == NULL ? "null" : o1, t1 != NULL ? ",\"" : "]", t1, "\"]", NULL);
}

static int wsj1_send_issot(struct afb_wsj1 *wsj1, int i1, const char *s1, const char *s2, const char *o1, const char *t1)
{
	char code[2] = { (char)('0' + i1), 0 };
	return afb_ws_texts(wsj1->ws, "[", code, ",\"", s1, "\",\"", s2, "\",", o1 == NULL ? "null" : o1, t1 != NULL ? ",\"" : "]", t1, "\"]", NULL);
}

int afb_wsj1_send_event_j(struct afb_wsj1 *wsj1, const char *event, struct json_object *object)
{
	const char *objstr = json_object_to_json_string_ext(object, JSON_C_TO_STRING_PLAIN|JSON_C_TO_STRING_NOSLASHESCAPE);
	int rc = afb_wsj1_send_event_s(wsj1, event, objstr);
	json_object_put(object);
	return rc;
}

int afb_wsj1_send_event_s(struct afb_wsj1 *wsj1, const char *event, const char *object)
{
	return wsj1_send_isot(wsj1, EVENT, event, object, NULL);
}

int afb_wsj1_call_j(struct afb_wsj1 *wsj1, const char *api, const char *verb, struct json_object *object, void (*on_reply)(void *closure, struct afb_wsj1_msg *msg), void *closure)
{
	const char *objstr = json_object_to_json_string_ext(object, JSON_C_TO_STRING_PLAIN|JSON_C_TO_STRING_NOSLASHESCAPE);
	int rc = afb_wsj1_call_s(wsj1, api, verb, objstr, on_reply, closure);
	json_object_put(object);
	return rc;
}

int afb_wsj1_call_s(struct afb_wsj1 *wsj1, const char *api, const char *verb, const char *object, void (*on_reply)(void *closure, struct afb_wsj1_msg *msg), void *closure)
{
	int rc;
	struct wsj1_call *call;
	char *tag;

	/* allocates the call */
	call = wsj1_call_create(wsj1, on_reply, closure);
	if (call == NULL) {
		errno = ENOMEM;
		return -1;
	}

	/* makes the tag */
	tag = alloca(2 + strlen(api) + strlen(verb));
	stpcpy(stpcpy(stpcpy(tag, api), "/"), verb);

	/* makes the call */
	rc = wsj1_send_issot(wsj1, CALL, call->id, tag, object, NULL);
	if (rc < 0) {
		wsj1_call_search(wsj1, call->id, 1);
		free(call);
	}
	return rc;
}

int afb_wsj1_reply_j(struct afb_wsj1_msg *msg, struct json_object *object, const char *token, int iserror)
{
	const char *objstr = json_object_to_json_string_ext(object, JSON_C_TO_STRING_PLAIN|JSON_C_TO_STRING_NOSLASHESCAPE);
	int rc = afb_wsj1_reply_s(msg, objstr, token, iserror);
	json_object_put(object);
	return rc;
}

int afb_wsj1_reply_s(struct afb_wsj1_msg *msg, const char *object, const char *token, int iserror)
{
	return wsj1_send_isot(msg->wsj1, iserror ? RETERR : RETOK, msg->id, object, token);
}

