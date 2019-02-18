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

#pragma once

struct afb_apiset;

extern int afb_autoset_add_ws(const char *path, struct afb_apiset *declare_set, struct afb_apiset *call_set);
#if WITH_DYNAMIC_BINDING
extern int afb_autoset_add_so(const char *path, struct afb_apiset *declare_set, struct afb_apiset *call_set);
#endif
extern int afb_autoset_add_any(const char *path, struct afb_apiset *declare_set, struct afb_apiset *call_set);
