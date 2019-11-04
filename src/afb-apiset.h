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

struct afb_api_item;
struct afb_apiset;
struct json_object;

extern struct afb_apiset *afb_apiset_create(const char *name, int timeout);
extern struct afb_apiset *afb_apiset_create_subset_last(struct afb_apiset *set, const char *name, int timeout);
extern struct afb_apiset *afb_apiset_create_subset_first(struct afb_apiset *set, const char *name, int timeout);
extern struct afb_apiset *afb_apiset_addref(struct afb_apiset *set);
extern void afb_apiset_unref(struct afb_apiset *set);

extern const char *afb_apiset_name(struct afb_apiset *set);

extern int afb_apiset_timeout_get(struct afb_apiset *set);
extern void afb_apiset_timeout_set(struct afb_apiset *set, int to);

extern void afb_apiset_onlack_set(
		struct afb_apiset *set,
		int (*callback)(void *closure, struct afb_apiset *set, const char *name),
		void *closure,
		void (*cleanup)(void*closure));

extern int afb_apiset_subset_set(struct afb_apiset *set, struct afb_apiset *subset);
extern struct afb_apiset *afb_apiset_subset_get(struct afb_apiset *set);

extern int afb_apiset_add(struct afb_apiset *set, const char *name, struct afb_api_item api);
extern int afb_apiset_del(struct afb_apiset *set, const char *name);

extern int afb_apiset_add_alias(struct afb_apiset *set, const char *name, const char *alias);
extern int afb_apiset_is_alias(struct afb_apiset *set, const char *name);
extern const char *afb_apiset_unalias(struct afb_apiset *set, const char *name);

extern const struct afb_api_item *afb_apiset_lookup(struct afb_apiset *set, const char *name, int rec);
extern const struct afb_api_item *afb_apiset_lookup_started(struct afb_apiset *set, const char *name, int rec);

extern int afb_apiset_start_service(struct afb_apiset *set, const char *name);
extern int afb_apiset_start_all_services(struct afb_apiset *set);

#if WITH_AFB_HOOK
extern void afb_apiset_update_hooks(struct afb_apiset *set, const char *name);
#endif
extern void afb_apiset_set_logmask(struct afb_apiset *set, const char *name, int mask);
extern int afb_apiset_get_logmask(struct afb_apiset *set, const char *name);

extern void afb_apiset_describe(struct afb_apiset *set, const char *name, void (*describecb)(void *, struct json_object *), void *closure);

extern const char **afb_apiset_get_names(struct afb_apiset *set, int rec, int type);
extern void afb_apiset_enum(
			struct afb_apiset *set,
			int rec,
			void (*callback)(void *closure, struct afb_apiset *set, const char *name, int isalias),
			void *closure);

extern int afb_apiset_require(struct afb_apiset *set, const char *name, const char *required);
extern int afb_apiset_require_class(struct afb_apiset *set, const char *apiname, const char *classname);
extern int afb_apiset_provide_class(struct afb_apiset *set, const char *apiname, const char *classname);
extern int afb_apiset_class_start(const char *classname);
