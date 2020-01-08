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

#include <errno.h>
#include <unistd.h>
#include <sys/epoll.h>

#define FDEV_PROVIDER
#include "fdev.h"
#include "fdev-epoll.h"

/*
 * For sake of simplicity there is no struct fdev_epoll.
 * Instead, the file descriptor of the internal epoll is used
 * and wrapped in a pseudo pointer to a pseudo struct.
 */
#define epollfd(fdev_epoll)  ((int)(intptr_t)fdev_epoll)

/*
 * disable callback for fdev
 *
 * refs to fdev must not be counted here
 */
static void disable(void *closure, const struct fdev *fdev)
{
	struct fdev_epoll *fdev_epoll = closure;
	epoll_ctl(epollfd(fdev_epoll), EPOLL_CTL_DEL, fdev_fd(fdev), 0);
}

/*
 * enable callback for fdev
 *
 * refs to fdev must not be counted here
 */
static void enable_or_update(void *closure, const struct fdev *fdev, int op, int err)
{
	struct fdev_epoll *fdev_epoll = closure;
	struct epoll_event event;
	int rc, fd;

	fd = fdev_fd(fdev);
	event.events = fdev_events(fdev);
	event.data.ptr = (void*)fdev;
	rc = epoll_ctl(epollfd(fdev_epoll), op, fd, &event);
	if (rc < 0 && errno == err)
		epoll_ctl(epollfd(fdev_epoll), (EPOLL_CTL_MOD + EPOLL_CTL_ADD) - op, fd, &event);
}

/*
 * enable callback for fdev
 *
 * refs to fdev must not be counted here
 */
static void enable(void *closure, const struct fdev *fdev)
{
	enable_or_update(closure, fdev, EPOLL_CTL_ADD, EEXIST);
}

/*
 * update callback for fdev
 *
 * refs to fdev must not be counted here
 */
static void update(void *closure, const struct fdev *fdev)
{
	enable_or_update(closure, fdev, EPOLL_CTL_MOD, ENOENT);
}

/*
 * unref is not handled here
 */
static struct fdev_itf itf =
{
	.unref = 0,
	.disable = disable,
	.enable = enable,
	.update = update
};

/*
 * create an fdev_epoll
 */
struct fdev_epoll *fdev_epoll_create()
{
	int fd = epoll_create1(EPOLL_CLOEXEC);
	if (!fd) {
		fd = dup(fd);
		close(0);
	}
	return fd < 0 ? 0 : (struct fdev_epoll*)(intptr_t)fd;
}

/*
 * destroy the fdev_epoll
 */
void fdev_epoll_destroy(struct fdev_epoll *fdev_epoll)
{
	close(epollfd(fdev_epoll));
}

/*
 * get pollable fd for the fdev_epoll
 */
int fdev_epoll_fd(struct fdev_epoll *fdev_epoll)
{
	return epollfd(fdev_epoll);
}

/*
 * create an fdev linked to the 'fdev_epoll' for 'fd'
 */
struct fdev *fdev_epoll_add(struct fdev_epoll *fdev_epoll, int fd)
{
	struct fdev *fdev;

	fdev = fdev_create(fd);
	if (fdev)
		fdev_set_itf(fdev, &itf, fdev_epoll);
	return fdev;
}

/*
 * get pollable fd for the fdev_epoll
 */
int fdev_epoll_wait_and_dispatch(struct fdev_epoll *fdev_epoll, int timeout_ms)
{
	struct fdev *fdev;
	struct epoll_event events;
	int rc;

	rc = epoll_wait(epollfd(fdev_epoll), &events, 1, timeout_ms < 0 ? -1 : timeout_ms);
	if (rc == 1) {
		fdev = events.data.ptr;
		fdev_dispatch(fdev, events.events);
	}
	return rc;
}

