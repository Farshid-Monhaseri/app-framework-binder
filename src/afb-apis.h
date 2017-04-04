/*
 * Copyright (C) 2016, 2017 "IoT.bzh"
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

struct afb_req;
struct afb_context;
struct afb_xreq;

struct afb_api
{
	void *closure;
	void (*call)(void *closure, struct afb_xreq *xreq);
	int (*service_start)(void *closure, int share_session, int onneed);
};


extern int afb_apis_is_valid_api_name(const char *name);

extern int afb_apis_add(const char *name, struct afb_api api);

extern int afb_apis_start_all_services(int share_session);
extern int afb_apis_start_service(const char *name, int share_session, int onneed);

extern void afb_apis_call(struct afb_xreq *xreq);


