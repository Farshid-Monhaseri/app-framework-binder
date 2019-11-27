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

struct afb_auth;
struct afb_xreq;
struct json_object;

extern int afb_auth_check(struct afb_xreq *xreq, const struct afb_auth *auth);
extern int afb_auth_has_permission(struct afb_xreq *xreq, const char *permission);

extern int afb_auth_check_and_set_session_x2(struct afb_xreq *xreq, uint32_t session, const struct afb_auth *auth);
extern struct json_object *afb_auth_json_x2(const struct afb_auth *auth, uint32_t session);

#if WITH_LEGACY_BINDING_V1
extern int afb_auth_check_and_set_session_x1(struct afb_xreq *xreq, int session);
extern struct json_object *afb_auth_json_x1(int session);
#endif