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

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <fnmatch.h>

#include <json-c/json.h>

#define AFB_BINDING_VERSION 0
#include <afb/afb-binding.h>

#include "afb-api.h"
#include "afb-api-v3.h"
#include "afb-apiset.h"
#include "afb-auth.h"
#include "afb-export.h"
#include "afb-xreq.h"
#include "verbose.h"
#include "sig-monitor.h"

/*
 * Description of a binding
 */
struct afb_api_v3 {
	int refcount;
	int count;
	struct afb_verb_v3 **verbs;
#if WITH_LEGACY_BINDING_V2
	const struct afb_verb_v2 *verbsv2;
#endif
	const struct afb_verb_v3 *verbsv3;
	struct afb_export *export;
	const char *info;
};

static const char nulchar = 0;

static int verb_name_compare(const struct afb_verb_v3 *verb, const char *name)
{
	return verb->glob
		? fnmatch(verb->verb, name, FNM_NOESCAPE|FNM_PATHNAME|FNM_CASEFOLD|FNM_PERIOD)
		: strcasecmp(verb->verb, name);
}

static struct afb_verb_v3 *search_dynamic_verb(struct afb_api_v3 *api, const char *name)
{
	struct afb_verb_v3 **v, **e, *i;

	v = api->verbs;
	e = &v[api->count];
	while (v != e) {
		i = *v;
		if (!verb_name_compare(i, name))
			return i;
		v++;
	}
	return 0;
}

void afb_api_v3_process_call(struct afb_api_v3 *api, struct afb_xreq *xreq)
{
	const struct afb_verb_v3 *verbsv3;
#if WITH_LEGACY_BINDING_V2
	const struct afb_verb_v2 *verbsv2;
#endif
	const char *name;

	name = xreq->request.called_verb;

	/* look first in dynamic set */
	verbsv3 = search_dynamic_verb(api, name);
	if (!verbsv3) {
		/* look then in static set */
		verbsv3 = api->verbsv3;
		while (verbsv3) {
			if (!verbsv3->verb)
				verbsv3 = 0;
			else if (!verb_name_compare(verbsv3, name))
				break;
			else
				verbsv3++;
		}
	}
	/* is it a v3 verb ? */
	if (verbsv3) {
		/* yes */
		xreq->request.vcbdata = verbsv3->vcbdata;
		afb_xreq_call_verb_v3(xreq, verbsv3);
		return;
	}

#if WITH_LEGACY_BINDING_V2
	/* look in legacy set */
	verbsv2 = api->verbsv2;
	if (verbsv2) {
		while (verbsv2->verb) {
			if (strcasecmp(verbsv2->verb, name))
				verbsv2++;
			else {
				afb_xreq_call_verb_v2(xreq, verbsv2);
				return;
			}
		}
	}
#endif
	afb_xreq_reply_unknown_verb(xreq);
}

static struct json_object *describe_verb_v3(const struct afb_verb_v3 *verb)
{
	struct json_object *f, *a, *g;

	f = json_object_new_object();

	g = json_object_new_object();
	json_object_object_add(f, "get", g);

	a = afb_auth_json_x2(verb->auth, verb->session);
	if (a)
		json_object_object_add(g, "x-permissions", a);

	a = json_object_new_object();
	json_object_object_add(g, "responses", a);
	g = json_object_new_object();
	json_object_object_add(a, "200", g);
	json_object_object_add(g, "description", json_object_new_string(verb->info?:verb->verb));

	return f;
}

struct json_object *afb_api_v3_make_description_openAPIv3(struct afb_api_v3 *api, const char *apiname)
{
	char buffer[256];
	struct afb_verb_v3 **iter, **end;
	const struct afb_verb_v3 *verb;
	struct json_object *r, *i, *p;

	r = json_object_new_object();
	json_object_object_add(r, "openapi", json_object_new_string("3.0.0"));

	i = json_object_new_object();
	json_object_object_add(r, "info", i);
	json_object_object_add(i, "title", json_object_new_string(apiname));
	json_object_object_add(i, "version", json_object_new_string("0.0.0"));
	json_object_object_add(i, "description", json_object_new_string(api->info));

	buffer[0] = '/';
	buffer[sizeof buffer - 1] = 0;

	p = json_object_new_object();
	json_object_object_add(r, "paths", p);
	iter = api->verbs;
	end = iter + api->count;
	while (iter != end) {
		verb = *iter++;
		strncpy(buffer + 1, verb->verb, sizeof buffer - 2);
		json_object_object_add(p, buffer, describe_verb_v3(verb));
	}
	verb = api->verbsv3;
	if (verb)
		while(verb->verb) {
			strncpy(buffer + 1, verb->verb, sizeof buffer - 2);
			json_object_object_add(p, buffer, describe_verb_v3(verb));
			verb++;
		}
	return r;
}

struct afb_api_v3 *afb_api_v3_create(struct afb_apiset *declare_set,
		struct afb_apiset *call_set,
		const char *apiname,
		const char *info,
		int noconcurrency,
		int (*preinit)(void*, struct afb_api_x3 *),
		void *closure,
		int copy_info,
		struct afb_export* creator,
		const char* path)
{
	struct afb_api_v3 *api;

	/* allocates the description */
	api = calloc(1, sizeof *api + (copy_info && info ? 1 + strlen(info) : 0));
	if (!api) {
		ERROR("out of memory");
		goto oom;
	}
	api->refcount = 1;
	if (!info)
		api->info = &nulchar;
	else if (copy_info)
		api->info = strcpy((char*)(api + 1), info);
	else
		api->info = info;

	api->export = afb_export_create_v3(declare_set, call_set, apiname, api, creator, path);
	if (!api->export)
		goto oom2;

	if (afb_export_declare(api->export, noconcurrency) < 0)
		goto oom3;

	if (preinit && afb_export_preinit_x3(api->export, preinit, closure) < 0)
		goto oom4;

	return api;

oom4:
	afb_export_undeclare(api->export);
oom3:
	afb_export_unref(api->export);
oom2:
	free(api);
oom:
	return NULL;
}

struct afb_api_v3 *afb_api_v3_addref(struct afb_api_v3 *api)
{
	if (api)
		__atomic_add_fetch(&api->refcount, 1, __ATOMIC_RELAXED);
	return api;
}

void afb_api_v3_unref(struct afb_api_v3 *api)
{
	if (api && !__atomic_sub_fetch(&api->refcount, 1, __ATOMIC_RELAXED)) {
		afb_export_destroy(api->export);
		while (api->count)
			free(api->verbs[--api->count]);
		free(api->verbs);
		free(api);
	}
}

struct afb_export *afb_api_v3_export(struct afb_api_v3 *api)
{
	return api->export;
}

#if WITH_LEGACY_BINDING_V2
void afb_api_v3_set_verbs_v2(
		struct afb_api_v3 *api,
		const struct afb_verb_v2 *verbs)
{
	api->verbsv2 = verbs;
}
#endif

void afb_api_v3_set_verbs_v3(
		struct afb_api_v3 *api,
		const struct afb_verb_v3 *verbs)
{
	api->verbsv3 = verbs;
}

int afb_api_v3_add_verb(
		struct afb_api_v3 *api,
		const char *verb,
		const char *info,
		void (*callback)(struct afb_req_x2 *req),
		void *vcbdata,
		const struct afb_auth *auth,
		uint16_t session,
		int glob)
{
	struct afb_verb_v3 *v, **vv;
	char *txt;
	int i;

	for (i = 0 ; i < api->count ; i++) {
		v = api->verbs[i];
		if (glob == v->glob && !strcasecmp(verb, v->verb)) {
			/* refuse to redefine a dynamic verb */
			errno = EEXIST;
			return -1;
		}
	}

	vv = realloc(api->verbs, (1 + api->count) * sizeof *vv);
	if (!vv)
		goto oom;
	api->verbs = vv;

	v = malloc(sizeof *v + (1 + strlen(verb)) + (info ? 1 + strlen(info) : 0));
	if (!v)
		goto oom;

	v->callback = callback;
	v->vcbdata = vcbdata;
	v->auth = auth;
	v->session = session;
	v->glob = !!glob;

	txt = (char*)(v + 1);
	v->verb = txt;
	txt = stpcpy(txt, verb);
	if (!info)
		v->info = NULL;
	else {
		v->info = ++txt;
		strcpy(txt, info);
	}

	api->verbs[api->count++] = v;
	return 0;
oom:
	errno = ENOMEM;
	return -1;
}

int afb_api_v3_del_verb(
		struct afb_api_v3 *api,
		const char *verb,
		void **vcbdata)
{
	struct afb_verb_v3 *v;
	int i;

	for (i = 0 ; i < api->count ; i++) {
		v = api->verbs[i];
		if (!strcasecmp(verb, v->verb)) {
			api->verbs[i] = api->verbs[--api->count];
			if (vcbdata)
				*vcbdata = v->vcbdata;
			free(v);
			return 0;
		}
	}

	errno = ENOENT;
	return -1;
}

int afb_api_v3_set_binding_fields(const struct afb_binding_v3 *desc, struct afb_api_x3 *api)
{
	int rc = 0;
	if (desc->verbs)
		rc =  afb_api_x3_set_verbs_v3(api, desc->verbs);
	if (!rc && desc->onevent)
		rc =  afb_api_x3_on_event(api, desc->onevent);
	if (!rc && desc->init)
		rc =  afb_api_x3_on_init(api, desc->init);
	if (!rc && desc->provide_class)
		rc =  afb_api_x3_provide_class(api, desc->provide_class);
	if (!rc && desc->require_class)
		rc =  afb_api_x3_require_class(api, desc->require_class);
	if (!rc && desc->require_api)
		rc =  afb_api_x3_require_api(api, desc->require_api, 0);
	return rc;
}

struct safe_preinit_data
{
	int (*preinit)(struct afb_api_x3 *);
	struct afb_api_x3 *api;
	int result;
};

static void safe_preinit(int sig, void *closure)
{
	struct safe_preinit_data *spd = closure;
	if (!sig)
		spd->result = spd->preinit(spd->api);
	else {
		spd->result = -1;
		errno = EFAULT;
	}
}

int afb_api_v3_safe_preinit(struct afb_api_x3 *api, int (*preinit)(struct afb_api_x3 *))
{
	struct safe_preinit_data spd;

	spd.preinit = preinit;
	spd.api = api;
	sig_monitor(60, safe_preinit, &spd);
	return spd.result;
}

static int init_binding(void *closure, struct afb_api_x3 *api)
{
	const struct afb_binding_v3 *desc = closure;
	int rc = afb_api_v3_set_binding_fields(desc, api);
	if (!rc && desc->preinit)
		rc = afb_api_v3_safe_preinit(api, desc->preinit);
	return rc;
}

struct afb_api_v3 *afb_api_v3_from_binding(const struct afb_binding_v3 *desc, struct afb_apiset *declare_set, struct afb_apiset * call_set)
{
	return afb_api_v3_create(declare_set, call_set, desc->api, desc->info, desc->noconcurrency, init_binding, (void*)desc, 0, NULL, NULL);
}

