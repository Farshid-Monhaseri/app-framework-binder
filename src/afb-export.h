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

struct json_object;

struct afb_export;
struct afb_apiset;
struct afb_context;
struct afb_xreq;

struct afb_binding_v2;
struct afb_binding_data_v2;
struct afb_api_v3;
struct afb_api_x3;
struct afb_event_x2;

extern void afb_export_set_config(struct json_object *config);

extern struct afb_export *afb_export_create_none_for_path(
				struct afb_apiset *declare_set,
				struct afb_apiset *call_set,
				const char *path,
				int (*creator)(void*, struct afb_api_x3*),
				void *closure);

extern struct afb_export *afb_export_create_v2(struct afb_apiset *declare_set,
				struct afb_apiset *call_set,
				const char *apiname,
				const struct afb_binding_v2 *binding,
				struct afb_binding_data_v2 *data,
				int (*init)(),
				void (*onevent)(const char*, struct json_object*),
				const char* path);

extern struct afb_export *afb_export_create_v3(struct afb_apiset *declare_set,
				struct afb_apiset *call_set,
				const char *apiname,
				struct afb_api_v3 *api,
				struct afb_export* creator,
				const char* path);

extern struct afb_export *afb_export_addref(struct afb_export *export);
extern void afb_export_unref(struct afb_export *export);

extern void afb_export_destroy(struct afb_export *export);

extern int afb_export_declare(struct afb_export *export, int noconcurrency);
extern void afb_export_undeclare(struct afb_export *export);

extern const char *afb_export_apiname(const struct afb_export *export);
extern int afb_export_add_alias(struct afb_export *export, const char *apiname, const char *aliasname);
extern int afb_export_rename(struct afb_export *export, const char *apiname);

extern int afb_export_unshare_session(struct afb_export *export);

extern int afb_export_preinit_x3(
				struct afb_export *export,
				int (*preinit)(void *,struct afb_api_x3*),
				void *closure);

extern int afb_export_handle_events_v12(
				struct afb_export *export,
				void (*on_event)(const char *event, struct json_object *object));


extern int afb_export_handle_events_v3(
				struct afb_export *export,
				void (*on_event)(struct afb_api_x3 *api, const char *event, struct json_object *object));


extern int afb_export_handle_init_v3(
				struct afb_export *export,
				int (*oninit)(struct afb_api_x3 *api));

extern int afb_export_start(struct afb_export *export);

extern int afb_export_logmask_get(const struct afb_export *export);
extern void afb_export_logmask_set(struct afb_export *export, int mask);

extern void *afb_export_userdata_get(const struct afb_export *export);
extern void afb_export_userdata_set(struct afb_export *export, void *data);

extern int afb_export_event_handler_add(
			struct afb_export *export,
			const char *pattern,
			void (*callback)(void *, const char*, struct json_object*, struct afb_api_x3*),
			void *closure);

extern int afb_export_event_handler_del(
			struct afb_export *export,
			const char *pattern,
			void **closure);

extern int afb_export_subscribe(struct afb_export *export, struct afb_event_x2 *event);
extern int afb_export_unsubscribe(struct afb_export *export, struct afb_event_x2 *event);
extern void afb_export_process_xreq(struct afb_export *export, struct afb_xreq *xreq);
extern void afb_export_context_init(struct afb_export *export, struct afb_context *context);
extern struct afb_export *afb_export_from_api_x3(struct afb_api_x3 *api);
extern struct afb_api_x3 *afb_export_to_api_x3(struct afb_export *export);

#if WITH_AFB_HOOK
extern void afb_export_update_hooks(struct afb_export *export);
#endif

#if WITH_LEGACY_BINDING_V1

struct afb_service_x1;
struct afb_binding_interface_v1;

extern struct afb_export *afb_export_create_v1(struct afb_apiset *declare_set,
				struct afb_apiset *call_set,
				const char *apiname,
				int (*init)(struct afb_service_x1),
				void (*onevent)(const char*, struct json_object*),
				const char* path);

extern struct afb_binding_v1 *afb_export_register_v1(
				struct afb_export *export,
				struct afb_binding_v1 *(*regfun)(const struct afb_binding_interface_v1*));

#endif

