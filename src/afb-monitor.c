/*
 * Copyright (C) 2016-2019 "IoT.bzh"
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

#include <string.h>

#include <json-c/json.h>

#define AFB_BINDING_VERSION 3
#include <afb/afb-binding.h>

#include "afb-api.h"
#include "afb-apiset.h"
#include "afb-api-v3.h"
#include "afb-evt.h"
#include "afb-xreq.h"
#include "afb-trace.h"
#include "afb-session.h"
#include "verbose.h"
#include "wrap-json.h"

#include "monitor-api.inc"

static struct afb_apiset *target_set;

int afb_monitor_init(struct afb_apiset *declare_set, struct afb_apiset *call_set)
{
	target_set = call_set;
	return -!afb_api_v3_from_binding(&_afb_binding_monitor, declare_set, call_set);
}

/******************************************************************************
**** Monitoring verbosity
******************************************************************************/

static const char _debug_[] = "debug";
static const char _info_[] = "info";
static const char _notice_[] = "notice";
static const char _warning_[] = "warning";
static const char _error_[] = "error";

/**
 * Translate verbosity indication to an integer value.
 * @param v the verbosity indication
 * @return the verbosity level (0, 1, 2 or 3) or -1 in case of error
 */
static int decode_verbosity(struct json_object *v)
{
	const char *s;
	int level = -1;

	if (!wrap_json_unpack(v, "i", &level)) {
		level = level < _VERBOSITY_(Log_Level_Error) ? _VERBOSITY_(Log_Level_Error) : level > _VERBOSITY_(Log_Level_Debug) ? _VERBOSITY_(Log_Level_Debug) : level;
	} else if (!wrap_json_unpack(v, "s", &s)) {
		switch(*s&~' ') {
		case 'D':
			if (!strcasecmp(s, _debug_))
				level = _VERBOSITY_(Log_Level_Debug);
			break;
		case 'I':
			if (!strcasecmp(s, _info_))
				level = _VERBOSITY_(Log_Level_Info);
			break;
		case 'N':
			if (!strcasecmp(s, _notice_))
				level = _VERBOSITY_(Log_Level_Notice);
			break;
		case 'W':
			if (!strcasecmp(s, _warning_))
				level = _VERBOSITY_(Log_Level_Warning);
			break;
		case 'E':
			if (!strcasecmp(s, _error_))
				level = _VERBOSITY_(Log_Level_Error);
			break;
		}
	}
	return level;
}

/**
 * callback for setting verbosity on all apis
 * @param set the apiset
 * @param the name of the api to set
 * @param closure the verbosity to set as an integer casted to a pointer
 */
static void set_verbosity_to_all_cb(void *closure, struct afb_apiset *set, const char *name, int isalias)
{
	if (!isalias)
		afb_apiset_set_logmask(set, name, (int)(intptr_t)closure);
}

/**
 * set the verbosity 'level' of the api of 'name'
 * @param name the api name or "*" for any api or NULL or "" for global verbosity
 * @param level the verbosity level to set
 */
static void set_verbosity_to(const char *name, int level)
{
	int mask = verbosity_to_mask(level);
	if (!name || !name[0])
		verbosity_set(level);
	else if (name[0] == '*' && !name[1])
		afb_apiset_enum(target_set, 1, set_verbosity_to_all_cb, (void*)(intptr_t)mask);
	else
		afb_apiset_set_logmask(target_set, name, mask);
}

/**
 * Set verbosities accordling to specification in 'spec'
 * @param spec specification of the verbosity to set
 */
static void set_verbosity(struct json_object *spec)
{
	int l;
	struct json_object_iterator it, end;

	if (json_object_is_type(spec, json_type_object)) {
		it = json_object_iter_begin(spec);
		end = json_object_iter_end(spec);
		while (!json_object_iter_equal(&it, &end)) {
			l = decode_verbosity(json_object_iter_peek_value(&it));
			if (l >= 0)
				set_verbosity_to(json_object_iter_peek_name(&it), l);
			json_object_iter_next(&it);
		}
	} else {
		l = decode_verbosity(spec);
		if (l >= 0) {
			set_verbosity_to("", l);
			set_verbosity_to("*", l);
		}
	}
}

/**
 * Translate verbosity level to a protocol indication.
 * @param level the verbosity
 * @return the encoded verbosity
 */
static struct json_object *encode_verbosity(int level)
{
	switch(_DEVERBOSITY_(level)) {
	case Log_Level_Error:	return json_object_new_string(_error_);
	case Log_Level_Warning:	return json_object_new_string(_warning_);
	case Log_Level_Notice:	return json_object_new_string(_notice_);
	case Log_Level_Info:	return json_object_new_string(_info_);
	case Log_Level_Debug:	return json_object_new_string(_debug_);
	default: return json_object_new_int(level);
	}
}

/**
 * callback for getting verbosity of all apis
 * @param set the apiset
 * @param the name of the api to set
 * @param closure the json object to build
 */
static void get_verbosity_of_all_cb(void *closure, struct afb_apiset *set, const char *name, int isalias)
{
	struct json_object *resu = closure;
	int m = afb_apiset_get_logmask(set, name);
	if (m >= 0)
		json_object_object_add(resu, name, encode_verbosity(verbosity_from_mask(m)));
}

/**
 * get in resu the verbosity of the api of 'name'
 * @param resu the json object to build
 * @param name the api name or "*" for any api or NULL or "" for global verbosity
 */
static void get_verbosity_of(struct json_object *resu, const char *name)
{
	int m;
	if (!name || !name[0])
		json_object_object_add(resu, "", encode_verbosity(verbosity_get()));
	else if (name[0] == '*' && !name[1])
		afb_apiset_enum(target_set, 1, get_verbosity_of_all_cb, resu);
	else {
		m = afb_apiset_get_logmask(target_set, name);
		if (m >= 0)
			json_object_object_add(resu, name, encode_verbosity(verbosity_from_mask(m)));
	}
}

/**
 * get verbosities accordling to specification in 'spec'
 * @param resu the json object to build
 * @param spec specification of the verbosity to set
 */
static struct json_object *get_verbosity(struct json_object *spec)
{
	int i, n;
	struct json_object *resu;
	struct json_object_iterator it, end;

	resu = json_object_new_object();
	if (json_object_is_type(spec, json_type_object)) {
		it = json_object_iter_begin(spec);
		end = json_object_iter_end(spec);
		while (!json_object_iter_equal(&it, &end)) {
			get_verbosity_of(resu, json_object_iter_peek_name(&it));
			json_object_iter_next(&it);
		}
	} else if (json_object_is_type(spec, json_type_array)) {
		n = (int)json_object_array_length(spec);
		for (i = 0 ; i < n ; i++)
			get_verbosity_of(resu, json_object_get_string(json_object_array_get_idx(spec, i)));
	} else if (json_object_is_type(spec, json_type_string)) {
		get_verbosity_of(resu, json_object_get_string(spec));
	} else if (json_object_get_boolean(spec)) {
		get_verbosity_of(resu, "");
		get_verbosity_of(resu, "*");
	}
	return resu;
}

/******************************************************************************
**** Monitoring apis
******************************************************************************/

/**
 * get apis accordling to specification in 'spec'
 * @param resu the json object to build
 * @param spec specification of the verbosity to set
 */
static void get_one_api(struct json_object *resu, const char *name, struct json_object *spec)
{
	struct json_object *o;

	o = afb_apiset_describe(target_set, name);
	if (o || afb_apiset_lookup(target_set, name, 1))
		json_object_object_add(resu, name, o);
}

/**
 * callback for getting verbosity of all apis
 * @param set the apiset
 * @param the name of the api to set
 * @param closure the json object to build
 */
static void get_apis_of_all_cb(void *closure, struct afb_apiset *set, const char *name, int isalias)
{
	struct json_object *resu = closure;
	get_one_api(resu, name, NULL);
}

/**
 * get apis accordling to specification in 'spec'
 * @param resu the json object to build
 * @param spec specification of the verbosity to set
 */
static struct json_object *get_apis(struct json_object *spec)
{
	int i, n;
	struct json_object *resu;
	struct json_object_iterator it, end;

	resu = json_object_new_object();
	if (json_object_is_type(spec, json_type_object)) {
		it = json_object_iter_begin(spec);
		end = json_object_iter_end(spec);
		while (!json_object_iter_equal(&it, &end)) {
			get_one_api(resu, json_object_iter_peek_name(&it), json_object_iter_peek_value(&it));
			json_object_iter_next(&it);
		}
	} else if (json_object_is_type(spec, json_type_array)) {
		n = (int)json_object_array_length(spec);
		for (i = 0 ; i < n ; i++)
			get_one_api(resu, json_object_get_string(json_object_array_get_idx(spec, i)), NULL);
	} else if (json_object_is_type(spec, json_type_string)) {
		get_one_api(resu, json_object_get_string(spec), NULL);
	} else if (json_object_get_boolean(spec)) {
		afb_apiset_enum(target_set, 1, get_apis_of_all_cb, resu);
	}
	return resu;
}

/******************************************************************************
**** Implementation monitoring verbs
******************************************************************************/

static const char _verbosity_[] = "verbosity";
static const char _apis_[] = "apis";

static void f_get(afb_req_t req)
{
	struct json_object *r;
	struct json_object *apis = NULL;
	struct json_object *verbosity = NULL;

	wrap_json_unpack(afb_req_json(req), "{s?:o,s?:o}", _verbosity_, &verbosity, _apis_, &apis);
	if (verbosity)
		verbosity = get_verbosity(verbosity);
	if (apis)
		apis = get_apis(apis);

	wrap_json_pack(&r, "{s:o*,s:o*}", _verbosity_, verbosity, _apis_, apis);
	afb_req_success(req, r, NULL);
}

static void f_set(afb_req_t req)
{
	struct json_object *verbosity = NULL;

	wrap_json_unpack(afb_req_json(req), "{s?:o}", _verbosity_, &verbosity);
	if (verbosity)
		set_verbosity(verbosity);

	afb_req_success(req, NULL, NULL);
}

#if WITH_AFB_TRACE
static void *context_create(void *closure)
{
	return afb_trace_create(_afb_binding_monitor.api, NULL);
}

static void context_destroy(void *pointer)
{
	struct afb_trace *trace = pointer;
	afb_trace_unref(trace);
}

static void f_trace(afb_req_t req)
{
	int rc;
	struct json_object *add = NULL;
	struct json_object *drop = NULL;
	struct afb_trace *trace;

	trace = afb_req_context(req, 0, context_create, context_destroy, NULL);
	wrap_json_unpack(afb_req_json(req), "{s?o s?o}", "add", &add, "drop", &drop);
	if (add) {
		rc = afb_trace_add(req, add, trace);
		if (rc)
			goto end;
	}
	if (drop) {
		rc = afb_trace_drop(req, drop, trace);
		if (rc)
			goto end;
	}
	afb_req_success(req, NULL, NULL);
end:
	afb_apiset_update_hooks(target_set, NULL);
	afb_evt_update_hooks();
	return;
}
#else
static void f_trace(afb_req_t req)
{
	afb_req_reply(req, NULL, "not-available", NULL);
}
#endif

static void f_session(afb_req_t req)
{
	struct json_object *r = NULL;
	struct afb_xreq *xreq = xreq_from_req_x2(req);

	/* check right to call it */
	if (xreq->context.super) {
		afb_req_fail(req, "invalid", "reserved to direct clients");
		return;
	}

	/* make the result */
	wrap_json_pack(&r, "{s:s,s:i,s:i}",
			"uuid", afb_session_uuid(xreq->context.session),
			"timeout", afb_session_timeout(xreq->context.session),
			"remain", afb_session_what_remains(xreq->context.session));
	afb_req_success(req, r, NULL);
}

