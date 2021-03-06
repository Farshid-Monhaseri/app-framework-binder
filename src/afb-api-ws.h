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

struct afb_apiset;

extern int afb_api_ws_add_client(const char *uri, struct afb_apiset *declare_set, struct afb_apiset *call_set, int strong);
extern int afb_api_ws_add_client_strong(const char *uri, struct afb_apiset *declare_set, struct afb_apiset *call_set);
extern int afb_api_ws_add_client_weak(const char *uri, struct afb_apiset *declare_set, struct afb_apiset *call_set);

extern int afb_api_ws_add_server(const char *uri, struct afb_apiset *declare_set, struct afb_apiset *call_set);


