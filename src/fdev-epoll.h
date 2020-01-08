/*
 * Copyright (C) 2015-2020 "IoT.bzh"
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

struct fdev;
struct fdev_epoll;

extern struct fdev_epoll *fdev_epoll_create();
extern void fdev_epoll_destroy(struct fdev_epoll *fdev_epoll);
extern int fdev_epoll_fd(struct fdev_epoll *fdev_epoll);
extern struct fdev *fdev_epoll_add(struct fdev_epoll *fdev_epoll, int fd);
extern int fdev_epoll_wait_and_dispatch(struct fdev_epoll *fdev_epoll, int timeout_ms);

