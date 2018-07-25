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

#if !defined(REMOVE_SYSTEMD_EVENT)

#include "afb-systemd.h"
#include "fdev-systemd.h"

struct fdev *afb_fdev_create(int fd)
{
	return fdev_systemd_create(afb_systemd_get_event_loop(), fd);
}

#else

#include "jobs.h"
#include "fdev-epoll.h"

struct fdev *afb_fdev_create(int fd)
{
	return fdev_epoll_add(jobs_get_fdev_epoll(), fd);
}

#endif

