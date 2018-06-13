/*
 * Copyright (C) 2018 "IoT.bzh"
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

#include "fdev.h"

#if defined(WITH_SYSTEMD_EVENT)
#   define USE_SYSTEMD 1
#   define USE_EPOLL   0
#else
#   define USE_SYSTEMD 0
#   define USE_EPOLL   1
#endif

#if USE_SYSTEMD

#include "afb-systemd.h"
#include "fdev-systemd.h"

struct fdev *afb_fdev_create(int fd)
{
	return fdev_systemd_create(afb_systemd_get_event_loop(), fd);
}

#endif

#if USE_EPOLL

#include "jobs.h"
#include "fdev-epoll.h"

struct fdev *afb_fdev_create(int fd)
{
	return fdev_epoll_add(jobs_get_fdev_epoll(), fd);
}

#endif

