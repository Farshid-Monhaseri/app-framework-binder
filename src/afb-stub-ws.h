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

struct fdev;
struct afb_stub_ws;
struct afb_apiset;
struct afb_api_item;

extern struct afb_stub_ws *afb_stub_ws_create_client(struct fdev *fdev, const char *apiname, struct afb_apiset *apiset);

extern struct afb_stub_ws *afb_stub_ws_create_server(struct fdev *fdev, const char *apiname, struct afb_apiset *apiset);

extern void afb_stub_ws_unref(struct afb_stub_ws *stubws);

extern void afb_stub_ws_addref(struct afb_stub_ws *stubws);

extern void afb_stub_ws_set_on_hangup(struct afb_stub_ws *stubws, void (*on_hangup)(struct afb_stub_ws*));

extern const char *afb_stub_ws_name(struct afb_stub_ws *stubws);

extern struct afb_api_item afb_stub_ws_client_api(struct afb_stub_ws *stubws);

extern int afb_stub_ws_client_add(struct afb_stub_ws *stubws, struct afb_apiset *apiset);

extern void afb_stub_ws_client_robustify(struct afb_stub_ws *stubws, struct fdev *(*reopen)(void*), void *closure, void (*release)(void*));

