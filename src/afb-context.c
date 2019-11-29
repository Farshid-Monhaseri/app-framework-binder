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
#include "afb-token.h"
#include "afb-cred.h"
#include "afb-permission-text.h"
#include "verbose.h"

static void init_context(struct afb_context *context, struct afb_session *session, struct afb_token *token, struct afb_cred *cred)
{
	assert(session != NULL);

	/* reset the context for the session */
	context->session = session;
	context->flags = 0;
	context->super = NULL;
	context->api_key = NULL;
	context->token = afb_token_addref(token);
	context->credentials = afb_cred_addref(cred);

	/* check the token */
	if (token != NULL) {
		if (afb_token_check(token))
			context->validated = 1;
		else
			context->invalidated = 1;
	}
}

void afb_context_init(struct afb_context *context, struct afb_session *session, struct afb_token *token, struct afb_cred *cred)
{
	init_context(context, afb_session_addref(session), token, cred);
}

void afb_context_init_validated(struct afb_context *context, struct afb_session *session, struct afb_token *token, struct afb_cred *cred)
{
	afb_context_init(context, session, token, cred);
	context->validated = 1;
}

void afb_context_subinit(struct afb_context *context, struct afb_context *super)
{
	context->session = afb_session_addref(super->session);
	context->flags = 0;
	context->super = super;
	context->api_key = NULL;
	context->token = afb_token_addref(super->token);
	context->credentials = afb_cred_addref(super->credentials);
}

int afb_context_connect(struct afb_context *context, const char *uuid, struct afb_token *token, struct afb_cred *cred)
{
	int created;
	struct afb_session *session;

	session = afb_session_get (uuid, AFB_SESSION_TIMEOUT_DEFAULT, &created);
	if (session == NULL)
		return -1;
	init_context(context, session, token, cred);
	if (created) {
		context->created = 1;
	}
	return 0;
}

int afb_context_connect_validated(struct afb_context *context, const char *uuid, struct afb_token *token, struct afb_cred *cred)
{
	int rc = afb_context_connect(context, uuid, token, cred);
	if (!rc)
		context->validated = 1;
	return rc;
}

void afb_context_disconnect(struct afb_context *context)
{
	if (context->session && !context->super && context->closing && !context->closed) {
		afb_context_change_loa(context, 0);
		afb_context_set(context, NULL, NULL);
		context->closed = 1;
	}
	afb_session_unref(context->session);
	context->session = NULL;
	afb_cred_unref(context->credentials);
	context->credentials = NULL;
	afb_token_unref(context->token);
	context->token = NULL;
}

void afb_context_change_cred(struct afb_context *context, struct afb_cred *cred)
{
	struct afb_cred *ocred = context->credentials;
	if (ocred != cred) {
		context->credentials = afb_cred_addref(cred);
		afb_cred_unref(ocred);
	}
}

void afb_context_change_token(struct afb_context *context, struct afb_token *token)
{
	struct afb_token *otoken = context->token;
	if (otoken != token) {
		context->validated = 0;
		context->invalidated = 0;
		context->token = afb_token_addref(token);
		afb_token_unref(otoken);
	}
}

const char *afb_context_on_behalf_export(struct afb_context *context)
{
	return context->credentials ? afb_cred_export(context->credentials) : NULL;
}

int afb_context_on_behalf_import(struct afb_context *context, const char *exported)
{
	int rc;
	struct afb_cred *imported, *ocred;

	if (!exported || !*exported)
		rc = 0;
	else {
		if (afb_context_has_permission(context, afb_permission_on_behalf_credential)) {
			imported = afb_cred_import(exported);
			if (!imported) {
				ERROR("Can't import on behalf credentials: %m");
				rc = -1;
			} else {
				ocred = context->credentials;
				context->credentials = imported;
				afb_cred_unref(ocred);
				rc = 0;
			}
		} else {
			ERROR("On behalf credentials refused");
			rc = -1;
		}
	}
	return rc;
}

void afb_context_on_behalf_other_context(struct afb_context *context, struct afb_context *other)
{
	afb_context_change_cred(context, other->credentials);
	afb_context_change_token(context, other->token);
}

int afb_context_has_permission(struct afb_context *context, const char *permission)
{
	return afb_cred_has_permission(context->credentials, permission, context);
}

const char *afb_context_uuid(struct afb_context *context)
{
	return context->session ? afb_session_uuid(context->session) : NULL;
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
