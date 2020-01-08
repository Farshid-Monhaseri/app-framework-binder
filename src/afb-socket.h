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

extern int afb_socket_open_scheme(const char *uri, int server, const char *scheme);

extern struct fdev *afb_socket_open_fdev_scheme(const char *uri, int server, const char *scheme);

extern const char *afb_socket_api(const char *uri);

static inline int afb_socket_open(const char *uri, int server)
{
	return afb_socket_open_scheme(uri, server, 0);
}

static inline struct fdev *afb_socket_open_fdev(const char *uri, int server)
{
	return afb_socket_open_fdev_scheme(uri, server, 0);
}
