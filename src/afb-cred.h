/*
 * Copyright (C) 2017-2019 "IoT.bzh"
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

#include <sys/types.h>

struct afb_cred
{
	int refcount;
	uid_t uid;
	gid_t gid;
	pid_t pid;
	const char *user;
	const char *label;
	const char *id;
	const char *exported;
};

extern struct afb_cred *afb_cred_current();
extern struct afb_cred *afb_cred_create(uid_t uid, gid_t gid, pid_t pid, const char *label);
extern struct afb_cred *afb_cred_create_for_socket(int fd);
extern struct afb_cred *afb_cred_addref(struct afb_cred *cred);
extern void afb_cred_unref(struct afb_cred *cred);

extern int afb_cred_has_permission(struct afb_cred *cred, const char *permission, const char *context);

extern const char *afb_cred_export(struct afb_cred *cred);
extern struct afb_cred *afb_cred_import(const char *string);

extern struct afb_cred *afb_cred_mixed_on_behalf_import(struct afb_cred *cred, const char *context, const char *exported);

