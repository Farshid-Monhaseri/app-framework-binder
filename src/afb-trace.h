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

#if !WITH_AFB_HOOK && WITH_AFB_TRACE
#  undef WITH_AFB_TRACE
#  define WITH_AFB_TRACE 0
#endif

#if WITH_AFB_TRACE

struct afb_trace;

extern struct afb_trace *afb_trace_create(const char *api, struct afb_session *bound);

extern void afb_trace_addref(struct afb_trace *trace);
extern void afb_trace_unref(struct afb_trace *trace);

extern int afb_trace_add(afb_req_t req, struct json_object *args, struct afb_trace *trace);
extern int afb_trace_drop(afb_req_t req, struct json_object *args, struct afb_trace *trace);

#endif

