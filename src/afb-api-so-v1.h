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

#if WITH_LEGACY_BINDING_V1

struct afb_apiset;
struct afb_binding_v1;
struct afb_xreq;
struct json_object;

extern int afb_api_so_v1_add(const char *path, void *handle, struct afb_apiset *declare_set, struct afb_apiset * call_set);

extern void afb_api_so_v1_process_call(struct afb_binding_v1 *binding, struct afb_xreq *xreq);
extern struct json_object *afb_api_so_v1_make_description_openAPIv3(struct afb_binding_v1 *binding, const char *apiname);

#endif
