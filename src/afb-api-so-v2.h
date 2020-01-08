/*
 * Copyright (C) 2015-2020 "IoT.bzh"
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

#if WITH_LEGACY_BINDING_V2 && WITH_DYNAMIC_BINDING

struct afb_apiset;
struct afb_binding_v2;
struct afb_binding_data_v2;
struct afb_xreq;
struct json_object;

extern int afb_api_so_v2_add(const char *path, void *handle, struct afb_apiset *declare_set, struct afb_apiset * call_set);
extern int afb_api_so_v2_add_binding(const struct afb_binding_v2 *binding, void *handle, struct afb_apiset *declare_set, struct afb_apiset * call_set, struct afb_binding_data_v2 *data, const char *path);

extern void afb_api_so_v2_process_call(const struct afb_binding_v2 *binding, struct afb_xreq *xreq);
extern struct json_object *afb_api_so_v2_make_description_openAPIv3(const struct afb_binding_v2 *binding, const char *apiname);

#endif
