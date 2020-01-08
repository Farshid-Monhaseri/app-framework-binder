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

struct afb_xreq;
struct afb_apiset;
struct json_object;

struct afb_api_itf
{
	void (*call)(void *closure, struct afb_xreq *xreq);
	int (*service_start)(void *closure);
#if WITH_AFB_HOOK
	void (*update_hooks)(void *closure);
#endif
	int (*get_logmask)(void *closure);
	void (*set_logmask)(void *closure, int level);
	void (*describe)(void *closure, void (*describecb)(void *, struct json_object *), void *clocb);
	void (*unref)(void *closure);
};

struct afb_api_item
{
	void *closure;
	struct afb_api_itf *itf;
	const void *group;
};

extern int afb_api_is_valid_name(const char *name);

static inline int afb_api_is_public(const char *name)
{
	return *name != '.';
}


