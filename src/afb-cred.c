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

#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "afb-cred.h"
#include "verbose.h"

#define MAX_LABEL_LENGTH  1024

#if !defined(NO_DEFAULT_PEERCRED) && !defined(ADD_DEFAULT_PEERCRED)
#  define NO_DEFAULT_PEERCRED
#endif

#if !defined(DEFAULT_PEERSEC_LABEL)
#  define DEFAULT_PEERSEC_LABEL "NoLabel"
#endif
#if !defined(DEFAULT_PEERCRED_UID)
#  define DEFAULT_PEERCRED_UID 99 /* nobody */
#endif
#if !defined(DEFAULT_PEERCRED_GID)
#  define DEFAULT_PEERCRED_GID 99 /* nobody */
#endif
#if !defined(DEFAULT_PEERCRED_PID)
#  define DEFAULT_PEERCRED_PID 0  /* no process */
#endif

static char export_format[] = "%x:%x:%x-%s";
static char import_format[] = "%x:%x:%x-%n";

static struct afb_cred *current;

static struct afb_cred *mkcred(uid_t uid, gid_t gid, pid_t pid, const char *label, size_t size)
{
	struct afb_cred *cred;
	char *dest, user[64];
	size_t i;
	uid_t u;

	i = 0;
	u = uid;
	do {
		user[i++] = (char)('0' + u % 10);
		u = u / 10;
	} while(u && i < sizeof user);

	cred = malloc(2 + i + size + sizeof *cred);
	if (!cred)
		errno = ENOMEM;
	else {
		cred->refcount = 1;
		cred->uid = uid;
		cred->gid = gid;
		cred->pid = pid;
		cred->exported = NULL;
		dest = (char*)(&cred[1]);
		cred->user = dest;
		while(i)
			*dest++ = user[--i];
		*dest++ = 0;
		cred->label = dest;
		cred->id = dest;
		memcpy(dest, label, size);
		dest[size] = 0;
		dest = strrchr(dest, ':');
		if (dest)
			cred->id = &dest[1];
	}
	return cred;
}

static struct afb_cred *mkcurrent()
{
	char label[MAX_LABEL_LENGTH];
	int fd;
	ssize_t rc;

	fd = open("/proc/self/attr/current", O_RDONLY);
	if (fd < 0)
		rc = 0;
	else {
		rc = read(fd, label, sizeof label);
		if (rc < 0)
			rc = 0;
		close(fd);
	}

	return mkcred(getuid(), getgid(), getpid(), label, (size_t)rc);
}

struct afb_cred *afb_cred_create(uid_t uid, gid_t gid, pid_t pid, const char *label)
{
	label = label ? : DEFAULT_PEERSEC_LABEL;
	return mkcred(uid, gid, pid, label, strlen(label));
}

struct afb_cred *afb_cred_create_for_socket(int fd)
{
	int rc;
	socklen_t length;
	struct ucred ucred;
	char label[MAX_LABEL_LENGTH];

	/* get the credentials */
	length = (socklen_t)(sizeof ucred);
	rc = getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &ucred, &length);
	if (rc < 0 || length != (socklen_t)(sizeof ucred) || !~ucred.uid) {
#if !defined(NO_DEFAULT_PEERCRED)
		ucred.uid = DEFAULT_PEERCRED_UID;
		ucred.gid = DEFAULT_PEERCRED_GID;
		ucred.pid = DEFAULT_PEERCRED_PID;
#else
		if (!rc)
			errno = EINVAL;
		return NULL;
#endif
	}

	/* get the security label */
	length = (socklen_t)(sizeof label);
	rc = getsockopt(fd, SOL_SOCKET, SO_PEERSEC, label, &length);
	if (rc < 0 || length > (socklen_t)(sizeof label)) {
#if !defined(NO_DEFAULT_PEERSEC)
		length = (socklen_t)strlen(DEFAULT_PEERSEC_LABEL);
		strcpy (label, DEFAULT_PEERSEC_LABEL);
#else
		if (!rc)
			errno = EINVAL;
		return NULL;
#endif
	}

	/* makes the result */
	return mkcred(ucred.uid, ucred.gid, ucred.pid, label, (size_t)length);
}

struct afb_cred *afb_cred_addref(struct afb_cred *cred)
{
	if (cred)
		__atomic_add_fetch(&cred->refcount, 1, __ATOMIC_RELAXED);
	return cred;
}

void afb_cred_unref(struct afb_cred *cred)
{
	if (cred && !__atomic_sub_fetch(&cred->refcount, 1, __ATOMIC_RELAXED)) {
		if (cred == current)
			cred->refcount = 1;
		else {
			free((void*)cred->exported);
			free(cred);
		}
	}
}

struct afb_cred *afb_cred_current()
{
	if (!current)
		current = mkcurrent();
	return afb_cred_addref(current);
}

const char *afb_cred_export(struct afb_cred *cred)
{
	int rc;

	if (!cred->exported) {
		rc = asprintf((char**)&cred->exported,
			export_format,
				(int)cred->uid,
				(int)cred->gid,
				(int)cred->pid,
				cred->label);
		if (rc < 0) {
			errno = ENOMEM;
			cred->exported = NULL;
		}
	}
	return cred->exported;
}

struct afb_cred *afb_cred_import(const char *string)
{
	struct afb_cred *cred;
	int rc, uid, gid, pid, pos;

	rc = sscanf(string, import_format, &uid, &gid, &pid, &pos);
	if (rc == 3)
		cred = afb_cred_create((uid_t)uid, (gid_t)gid, (pid_t)pid, &string[pos]);
	else {
		errno = EINVAL;
		cred = NULL;
	}
	return cred;
}
