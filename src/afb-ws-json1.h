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

struct afb_ws_json1;
struct afb_context;
struct afb_apiset;
struct fdev;

extern struct afb_ws_json1 *afb_ws_json1_create(struct fdev *fdev, struct afb_apiset *apiset, struct afb_context *context, void (*cleanup)(void*), void *closure);
extern struct afb_ws_json1 *afb_ws_json1_addref(struct afb_ws_json1 *ws);
extern void afb_ws_json1_unref(struct afb_ws_json1 *ws);

