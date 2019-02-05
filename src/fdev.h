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

#include <sys/epoll.h>

struct fdev;

#if defined(FDEV_PROVIDER)
struct fdev_itf
{
	void (*unref)(void *closure);
	void (*disable)(void *closure, const struct fdev *fdev);
	void (*enable)(void *closure, const struct fdev *fdev);
	void (*update)(void *closure, const struct fdev *fdev);
};

extern struct fdev *fdev_create(int fd);
extern void fdev_set_itf(struct fdev *fdev, struct fdev_itf *itf, void *closure_itf);
extern void fdev_dispatch(struct fdev *fdev, uint32_t events);
#endif

extern struct fdev *fdev_addref(struct fdev *fdev);
extern void fdev_unref(struct fdev *fdev);

extern int fdev_fd(const struct fdev *fdev);
extern uint32_t fdev_events(const struct fdev *fdev);
extern int fdev_autoclose(const struct fdev *fdev);

extern void fdev_set_callback(struct fdev *fdev, void (*callback)(void*,uint32_t,struct fdev*), void *closure);
extern void fdev_set_events(struct fdev *fdev, uint32_t events);
extern void fdev_set_autoclose(struct fdev *fdev, int autoclose);
