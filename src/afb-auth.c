/*
 * Copyright (C) 2016-2019 "IoT.bzh"
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

#include <stdlib.h>

#include <json-c/json.h>
#include <afb/afb-auth.h>
#include <afb/afb-session-x2.h>

#include "afb-auth.h"
#include "afb-context.h"
#include "afb-xreq.h"
#include "afb-cred.h"
#include "verbose.h"

int afb_auth_check(struct afb_xreq *xreq, const struct afb_auth *auth)
{
	switch (auth->type) {
	default:
	case afb_auth_No:
		return 0;

	case afb_auth_Token:
		return afb_context_check(&xreq->context);

	case afb_auth_LOA:
		return afb_context_check_loa(&xreq->context, auth->loa);

	case afb_auth_Permission:
		return afb_auth_has_permission(xreq, auth->text);

	case afb_auth_Or:
		return afb_auth_check(xreq, auth->first) || afb_auth_check(xreq, auth->next);

	case afb_auth_And:
		return afb_auth_check(xreq, auth->first) && afb_auth_check(xreq, auth->next);

	case afb_auth_Not:
		return !afb_auth_check(xreq, auth->first);

	case afb_auth_Yes:
		return 1;
	}
}

int afb_auth_has_permission(struct afb_xreq *xreq, const char *permission)
{
	return afb_cred_has_permission(xreq->cred, permission, afb_context_uuid(&xreq->context));
}

/*********************************************************************************/

static struct json_object *addperm(struct json_object *o, struct json_object *x)
{
	struct json_object *a;

	if (!o)
		return x;

	if (!json_object_object_get_ex(o, "allOf", &a)) {
		a = json_object_new_array();
		json_object_array_add(a, o);
		o = json_object_new_object();
		json_object_object_add(o, "allOf", a);
	}
	json_object_array_add(a, x);
	return o;
}

static struct json_object *addperm_key_val(struct json_object *o, const char *key, struct json_object *val)
{
	struct json_object *x = json_object_new_object();
	json_object_object_add(x, key, val);
	return addperm(o, x);
}

static struct json_object *addperm_key_valstr(struct json_object *o, const char *key, const char *val)
{
	return addperm_key_val(o, key, json_object_new_string(val));
}

static struct json_object *addperm_key_valint(struct json_object *o, const char *key, int val)
{
	return addperm_key_val(o, key, json_object_new_int(val));
}

static struct json_object *addauth_or_array(struct json_object *o, const struct afb_auth *auth);

static struct json_object *addauth(struct json_object *o, const struct afb_auth *auth)
{
	switch(auth->type) {
	case afb_auth_No: return addperm(o, json_object_new_boolean(0));
	case afb_auth_Token: return addperm_key_valstr(o, "session", "check");
	case afb_auth_LOA: return addperm_key_valint(o, "LOA", auth->loa);
	case afb_auth_Permission: return addperm_key_valstr(o, "permission", auth->text);
	case afb_auth_Or: return addperm_key_val(o, "anyOf", addauth_or_array(json_object_new_array(), auth));
	case afb_auth_And: return addauth(addauth(o, auth->first), auth->next);
	case afb_auth_Not: return addperm_key_val(o, "not", addauth(NULL, auth->first));
	case afb_auth_Yes: return addperm(o, json_object_new_boolean(1));
	}
	return o;
}

static struct json_object *addauth_or_array(struct json_object *o, const struct afb_auth *auth)
{
	if (auth->type != afb_auth_Or)
		json_object_array_add(o, addauth(NULL, auth));
	else {
		addauth_or_array(o, auth->first);
		addauth_or_array(o, auth->next);
	}

	return o;
}

struct json_object *afb_auth_json_v2(const struct afb_auth *auth, int session)
{
	struct json_object *result = NULL;

	if (session & AFB_SESSION_CLOSE_X2)
		result = addperm_key_valstr(result, "session", "close");

	if (session & AFB_SESSION_CHECK_X2)
		result = addperm_key_valstr(result, "session", "check");

	if (session & AFB_SESSION_REFRESH_X2)
		result = addperm_key_valstr(result, "token", "refresh");

	if (session & AFB_SESSION_LOA_MASK_X2)
		result = addperm_key_valint(result, "LOA", session & AFB_SESSION_LOA_MASK_X2);

	if (auth)
		result = addauth(result, auth);

	return result;
}

