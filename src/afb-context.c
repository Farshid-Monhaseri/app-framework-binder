/*
 * Copyright (C) 2015, 2016, 2017 "IoT.bzh"
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

#include "session.h"
#include "afb-context.h"

static void init_context(struct afb_context *context, struct AFB_clientCtx *session, const char *token)
{
	assert(session != NULL);

	/* reset the context for the session */
	context->session = session;
	context->flags = 0;
	context->api_index = -1;
	context->loa_in = ctxClientGetLOA(session) & 7;

	/* check the token */
	if (token != NULL) {
		if (ctxTokenCheck(session, token))
			context->validated = 1;
		else
			context->invalidated = 1;
	}
}

void afb_context_init(struct afb_context *context, struct AFB_clientCtx *session, const char *token)
{
	init_context(context, ctxClientAddRef(session), token);
}

int afb_context_connect(struct afb_context *context, const char *uuid, const char *token)
{
	int created;
	struct AFB_clientCtx *session;

	session = ctxClientGetSession (uuid, &created);
	if (session == NULL)
		return -1;
	init_context(context, session, token);
	if (created) {
		context->created = 1;
		/* context->refreshing = 1; */
	}
	return 0;
}

void afb_context_disconnect(struct afb_context *context)
{
	if (context->session != NULL) {
		if (context->refreshing && !context->refreshed) {
			ctxTokenNew (context->session);
			context->refreshed = 1;
		}
		if (context->loa_changing && !context->loa_changed) {
			ctxClientSetLOA (context->session, context->loa_out);
			context->loa_changed = 1;
		}
		if (context->closing && !context->closed) {
			ctxClientClose(context->session);
			context->closed = 1;
		}
		ctxClientUnref(context->session);
		context->session = NULL;
	}
}

const char *afb_context_sent_token(struct afb_context *context)
{
	if (context->session == NULL || context->closing)
		return NULL;
	if (!context->refreshing)
		return NULL;
	if (!context->refreshed) {
		ctxTokenNew (context->session);
		context->refreshed = 1;
	}
	return ctxClientGetToken(context->session);
}

const char *afb_context_sent_uuid(struct afb_context *context)
{
	if (context->session == NULL || context->closing)
		return NULL;
	if (!context->created)
		return NULL;
	return ctxClientGetUuid(context->session);
}

void *afb_context_get(struct afb_context *context)
{
	assert(context->session != NULL);
	return ctxClientValueGet(context->session, context->api_index);
}

void afb_context_set(struct afb_context *context, void *value, void (*free_value)(void*))
{
	assert(context->session != NULL);
	return ctxClientValueSet(context->session, context->api_index, value, free_value);
}

void afb_context_close(struct afb_context *context)
{
	context->closing = 1;
}

void afb_context_refresh(struct afb_context *context)
{
	assert(context->validated);
	context->refreshing = 1;
}

int afb_context_check(struct afb_context *context)
{
	return context->validated;
}

int afb_context_check_loa(struct afb_context *context, unsigned loa)
{
	return context->loa_in >= loa;
}

int afb_context_change_loa(struct afb_context *context, unsigned loa)
{
	if (!context->validated || loa > 7)
		return 0;

	if (loa == context->loa_in && !context->loa_changed)
		context->loa_changing = 0;
	else {
		context->loa_out = loa & 7;
		context->loa_changing = 1;
		context->loa_changed = 0;
	}
	return 1;
}


