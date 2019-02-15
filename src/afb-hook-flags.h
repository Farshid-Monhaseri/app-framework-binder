/*
 * Copyright (C) 2018, 2019 "IoT.bzh"
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

#if WITH_AFB_HOOK  /***********************************************************/

extern int afb_hook_flags_xreq_from_text(const char *text);
extern int afb_hook_flags_api_from_text(const char *text);
extern int afb_hook_flags_evt_from_text(const char *text);
extern int afb_hook_flags_session_from_text(const char *text);
extern int afb_hook_flags_global_from_text(const char *text);

extern char *afb_hook_flags_xreq_to_text(int value);
extern char *afb_hook_flags_api_to_text(int value);
extern char *afb_hook_flags_evt_to_text(int value);
extern char *afb_hook_flags_session_to_text(int value);

#if !defined(REMOVE_LEGACY_TRACE)
extern int afb_hook_flags_legacy_ditf_from_text(const char *text);
extern int afb_hook_flags_legacy_svc_from_text(const char *text);

extern char *afb_hook_flags_legacy_ditf_to_text(int value);
extern char *afb_hook_flags_legacy_svc_to_text(int value);
#endif

#endif /* WITH_AFB_HOOK *******************************************************/
