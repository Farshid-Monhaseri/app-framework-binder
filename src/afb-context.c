/*
 * Copyright (C) 2015-2019 "IoT.bzh"
 * Author "Fulup Ar Foll"
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

#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>

#include "afb-session.h"
#include "afb-context.h"

static void init_context(struct afb_context *context, struct afb_session *session, const char *token)
{
	assert(session != NULL);

	/* reset the context for the session */
	context->session = session;
	context->flags = 0;
	context->super = NULL;
	context->api_key = NULL;

	/* check the token */
	if (token != NULL) {
		if (afb_session_check_token(session, token))
			context->validated = 1;
		else
			context->invalidated = 1;
	}
}

void afb_context_init(struct afb_context *context, struct afb_session *session, const char *token)
{
	init_context(context, afb_session_addref(session), token);
}

void afb_context_init_validated(struct afb_context *context, struct afb_session *session)
{
	afb_context_init(context, session, NULL);
	context->validated = 1;
}

void afb_context_subinit(struct afb_context *context, struct afb_context *super)
{
	context->session = super->session;
	context->flags = 0;
	context->super = super;
	context->api_key = NULL;
	context->token = NULL;
	context->validated = super->validated;
}

int afb_context_connect(struct afb_context *context, const char *uuid, const char *token)
{
	int created;
	struct afb_session *session;

	session = afb_session_get (uuid, AFB_SESSION_TIMEOUT_DEFAULT, &created);
	if (session == NULL)
		return -1;
	init_context(context, session, token);
	if (created) {
		context->created = 1;
		/* context->refreshing = 1; */
	}
	return 0;
}

int afb_context_connect_validated(struct afb_context *context, const char *uuid)
{
	int rc = afb_context_connect(context, uuid, NULL);
	if (!rc)
		context->validated = 1;
	return rc;
}

void afb_context_disconnect(struct afb_context *context)
{
	if (context->session && !context->super) {
		if (context->refreshing && !context->refreshed) {
			afb_session_new_token (context->session);
			context->refreshed = 1;
		}
		if (context->closing && !context->closed) {
			afb_context_change_loa(context, 0);
			afb_context_set(context, NULL, NULL);
			context->closed = 1;
		}
		afb_session_unref(context->session);
		context->session = NULL;
	}
}

const char *afb_context_sent_token(struct afb_context *context)
{
	if (context->session == NULL || context->closing || context->super)
		return NULL;
	if (!context->refreshing)
		return NULL;
	if (!context->refreshed) {
		afb_session_new_token (context->session);
		context->refreshed = 1;
	}
	return afb_session_token(context->session);
}

const char *afb_context_uuid(struct afb_context *context)
{
	return context->session ? afb_session_uuid(context->session) : "";
}

const char *afb_context_sent_uuid(struct afb_context *context)
{
	if (context->session == NULL || context->closing || context->super)
		return NULL;
	if (!context->created)
		return NULL;
	return afb_session_uuid(context->session);
}

void *afb_context_make(struct afb_context *context, int replace, void *(*make_value)(void *closure), void (*free_value)(void *item), void *closure)
{
	assert(context->session != NULL);
	return afb_session_cookie(context->session, context->api_key, make_value, free_value, closure, replace);
}

void *afb_context_get(struct afb_context *context)
{
	assert(context->session != NULL);
	return afb_session_get_cookie(context->session, context->api_key);
}

int afb_context_set(struct afb_context *context, void *value, void (*free_value)(void*))
{
	assert(context->session != NULL);
	return afb_session_set_cookie(context->session, context->api_key, value, free_value);
}

void afb_context_close(struct afb_context *context)
{
	context->closing = 1;
}

void afb_context_refresh(struct afb_context *context)
{
	if (context->super)
		afb_context_refresh(context->super);
	else {
		assert(context->validated);
		context->refreshing = 1;
		if (!context->refreshed) {
			afb_session_new_token (context->session);
			context->refreshed = 1;
		}
	}
}

int afb_context_check(struct afb_context *context)
{
	if (context->super)
		return afb_context_check(context);
	return context->validated;
}

int afb_context_check_loa(struct afb_context *context, unsigned loa)
{
	return afb_context_get_loa(context) >= loa;
}

static inline const void *loa_key(struct afb_context *context)
{
	return (const void*)(1+(intptr_t)(context->api_key));
}

static inline void *loa2ptr(unsigned loa)
{
	return (void*)(intptr_t)loa;
}

static inline unsigned ptr2loa(void *ptr)
{
	return (unsigned)(intptr_t)ptr;
}

int afb_context_change_loa(struct afb_context *context, unsigned loa)
{
	if (!context->validated || loa > 7) {
		errno = EINVAL;
		return -1;
	}

	return afb_session_set_cookie(context->session, loa_key(context), loa2ptr(loa), NULL);
}

unsigned afb_context_get_loa(struct afb_context *context)
{
	assert(context->session != NULL);
	return ptr2loa(afb_session_get_cookie(context->session, loa_key(context)));
}
