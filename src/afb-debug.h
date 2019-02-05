/*
 Copyright (C) 2017-2019 "IoT.bzh"

 author: José Bollo <jose.bollo@iot.bzh>

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
*/

#pragma once

#if defined(AGL_DEVEL) && !defined(AFB_INSERT_DEBUG_FEATURES)
# define AFB_INSERT_DEBUG_FEATURES
#endif

#if defined(AFB_INSERT_DEBUG_FEATURES)
extern void afb_debug(const char *key);
extern void afb_debug_wait(const char *key);
extern void afb_debug_break(const char *key);
#else
#define afb_debug(x)       ((void)0)
#define afb_debug_wait(x)  ((void)0)
#define afb_debug_break(x) ((void)0)
#endif
