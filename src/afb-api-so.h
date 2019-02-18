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

#if WITH_DYNAMIC_BINDING

struct afb_apiset;

extern int afb_api_so_add_binding(const char *path, struct afb_apiset *declare_set, struct afb_apiset * call_set);

extern int afb_api_so_add_directory(const char *path, struct afb_apiset *declare_set, struct afb_apiset * call_set, int failstops);

extern int afb_api_so_add_path(const char *path, struct afb_apiset *declare_set, struct afb_apiset * call_set, int failstops);

extern int afb_api_so_add_pathset(const char *pathset, struct afb_apiset *declare_set, struct afb_apiset * call_set, int failstops);

extern int afb_api_so_add_pathset_fails(const char *pathset, struct afb_apiset *declare_set, struct afb_apiset * call_set);
extern int afb_api_so_add_pathset_nofails(const char *pathset, struct afb_apiset *declare_set, struct afb_apiset * call_set);

#endif
