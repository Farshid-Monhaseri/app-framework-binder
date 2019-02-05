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


#pragma once

struct afb_apiset;
struct afb_api_v3;
struct afb_api_x3;
struct afb_auth;
struct afb_req_x2;
struct afb_verb_v2;
struct afb_verb_v3;
struct afb_binding_v3;
struct afb_xreq;
struct json_object;
struct afb_export;

extern struct afb_api_v3 *afb_api_v3_create(struct afb_apiset *declare_set,
		struct afb_apiset *call_set,
		const char *apiname,
		const char *info,
		int noconcurrency,
		int (*preinit)(void*, struct afb_api_x3 *),
		void *closure,
		int copy_info,
		struct afb_export* creator,
		const char* path);

extern struct afb_api_v3 *afb_api_v3_from_binding(
		const struct afb_binding_v3 *desc,
		struct afb_apiset *declare_set,
		struct afb_apiset * call_set);

extern int afb_api_v3_safe_preinit(
		struct afb_api_x3 *api,
		int (*preinit)(struct afb_api_x3 *));

extern int afb_api_v3_set_binding_fields(const struct afb_binding_v3 *desc, struct afb_api_x3 *api);

extern struct afb_api_v3 *afb_api_v3_addref(struct afb_api_v3 *api);
extern void afb_api_v3_unref(struct afb_api_v3 *api);

extern struct afb_export *afb_api_v3_export(struct afb_api_v3 *api);

extern void afb_api_v3_set_verbs_v2(
		struct afb_api_v3 *api,
		const struct afb_verb_v2 *verbs);

extern void afb_api_v3_set_verbs_v3(
		struct afb_api_v3 *api,
		const struct afb_verb_v3 *verbs);

extern int afb_api_v3_add_verb(
		struct afb_api_v3 *api,
		const char *verb,
		const char *info,
		void (*callback)(struct afb_req_x2 *req),
		void *vcbdata,
		const struct afb_auth *auth,
		uint16_t session,
		int glob);

extern int afb_api_v3_del_verb(
		struct afb_api_v3 *api,
		const char *verb,
		void **vcbdata);

extern void afb_api_v3_process_call(struct afb_api_v3 *api, struct afb_xreq *xreq);
extern struct json_object *afb_api_v3_make_description_openAPIv3(struct afb_api_v3 *api, const char *apiname);

