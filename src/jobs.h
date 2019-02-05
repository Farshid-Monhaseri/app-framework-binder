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

struct jobloop;

extern int jobs_queue(
		const void *group,
		int timeout,
		void (*callback)(int signum, void* arg),
		void *arg);

extern int jobs_enter(
		const void *group,
		int timeout,
		void (*callback)(int signum, void *closure, struct jobloop *jobloop),
		void *closure);

extern int jobs_leave(struct jobloop *jobloop);

extern int jobs_call(
		const void *group,
		int timeout,
		void (*callback)(int, void*),
		void *arg);

extern void jobs_terminate();

extern int jobs_start(
		int allowed_count,
		int start_count,
		int waiter_count,
		void (*start)(int signum, void* arg),
		void *arg);

struct sd_event;
extern struct sd_event *jobs_get_sd_event();
