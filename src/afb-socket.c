/*
 * Copyright (C) 2015-2018 "IoT.bzh"
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

#define _GNU_SOURCE

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <endian.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "afb-fdev.h"
#include "afb-socket.h"
#include "afb-systemd.h"
#include "fdev.h"
#include "verbose.h"

#define BACKLOG  5

/******************************************************************************/

/**
 * known types
 */
enum type {
	/** type internet */
	Type_Inet,

	/** type systemd */
	Type_Systemd,

	/** type Unix */
	Type_Unix
};

/**
 * Structure for known entries
 */
struct entry
{
	/** the known prefix */
	const char *prefix;

	/** the type of the entry */
	unsigned type: 2;

	/** should not set SO_REUSEADDR for servers */
	unsigned noreuseaddr: 1;

	/** should not call listen for servers */
	unsigned nolisten: 1;
};

/**
 * The known entries with the default one at the first place
 */
static struct entry entries[] = {
	{
		.prefix = "tcp:",
		.type = Type_Inet
	},
	{
		.prefix = "sd:",
		.type = Type_Systemd,
		.noreuseaddr = 1,
		.nolisten = 1
	},
	{
		.prefix = "unix:",
		.type = Type_Unix
	}
};

/**
 * It is possible to set explicit api name instead of using the
 * default one.
 */
static const char as_api[] = "?as-api=";

/******************************************************************************/

/**
 * open a unix domain socket for client or server
 *
 * @param spec the specification of the path (prefix with @ for abstract)
 * @param server 0 for client, server otherwise
 *
 * @return the file descriptor number of the socket or -1 in case of error
 */
static int open_unix(const char *spec, int server)
{
	int fd, rc, abstract;
	struct sockaddr_un addr;
	size_t length;

	abstract = spec[0] == '@';

	/* check the length */
	length = strlen(spec);
	if (length >= 108) {
		errno = ENAMETOOLONG;
		return -1;
	}

	/* remove the file on need */
	if (server && !abstract)
		unlink(spec);

	/* create a  socket */
	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		return fd;

	/* prepare address  */
	memset(&addr, 0, sizeof addr);
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, spec);
	if (abstract)
		addr.sun_path[0] = 0; /* implement abstract sockets */

	if (server) {
		rc = bind(fd, (struct sockaddr *) &addr, (socklen_t)(sizeof addr));
	} else {
		rc = connect(fd, (struct sockaddr *) &addr, (socklen_t)(sizeof addr));
	}
	if (rc < 0) {
		close(fd);
		return rc;
	}
	return fd;
}

/**
 * open a tcp socket for client or server
 *
 * @param spec the specification of the host:port/...
 * @param server 0 for client, server otherwise
 *
 * @return the file descriptor number of the socket or -1 in case of error
 */
static int open_tcp(const char *spec, int server)
{
	int rc, fd;
	const char *service, *host, *tail;
	struct addrinfo hint, *rai, *iai;

	/* scan the uri */
	tail = strchrnul(spec, '/');
	service = strchr(spec, ':');
	if (tail == NULL || service == NULL || tail < service) {
		errno = EINVAL;
		return -1;
	}
	host = strndupa(spec, service++ - spec);
	service = strndupa(service, tail - service);

	/* get addr */
	memset(&hint, 0, sizeof hint);
	hint.ai_family = AF_INET;
	hint.ai_socktype = SOCK_STREAM;
	if (server) {
		hint.ai_flags = AI_PASSIVE;
		if (host[0] == 0 || (host[0] == '*' && host[1] == 0))
			host = NULL;
	}
	rc = getaddrinfo(host, service, &hint, &rai);
	if (rc != 0) {
		errno = EINVAL;
		return -1;
	}

	/* get the socket */
	iai = rai;
	while (iai != NULL) {
		fd = socket(iai->ai_family, iai->ai_socktype, iai->ai_protocol);
		if (fd >= 0) {
			if (server) {
				rc = bind(fd, iai->ai_addr, iai->ai_addrlen);
			} else {
				rc = connect(fd, iai->ai_addr, iai->ai_addrlen);
			}
			if (rc == 0) {
				freeaddrinfo(rai);
				return fd;
			}
			close(fd);
		}
		iai = iai->ai_next;
	}
	freeaddrinfo(rai);
	return -1;
}

/**
 * open a systemd socket for server
 *
 * @param spec the specification of the systemd name
 *
 * @return the file descriptor number of the socket or -1 in case of error
 */
static int open_systemd(const char *spec)
{
#if defined(NO_SYSTEMD_ACTIVATION)
	errno = EAFNOSUPPORT;
	return -1;
#else
	return afb_systemd_fds_for(spec);
#endif
}

/******************************************************************************/

/**
 * Get the entry of the uri by searching to its prefix
 *
 * @param uri the searched uri
 * @param offset where to store the prefix length
 *
 * @return the found entry or the default one
 */
static struct entry *get_entry(const char *uri, int *offset)
{
	int l, i = (int)(sizeof entries / sizeof * entries);

	for (;;) {
		if (!i) {
			l = 0;
			break;
		}
		i--;
		l = (int)strlen(entries[i].prefix);
		if (!strncmp(uri, entries[i].prefix, l))
			break;
	}

	*offset = l;
	return &entries[i];
}

/**
 * open socket for client or server
 *
 * @param uri the specification of the socket
 * @param server 0 for client, server otherwise
 *
 * @return the file descriptor number of the socket or -1 in case of error
 */
static int open_uri(const char *uri, int server)
{
	int fd, rc, offset;
	struct entry *e;
	const char *api;

	/* search for the entry */
	e = get_entry(uri, &offset);

	/* get the names */
	uri += offset;
	api = strstr(uri, as_api);
	if (api)
		uri = strndupa(uri, api - uri);

	/* open the socket */
	switch (e->type) {
	case Type_Unix:
		fd = open_unix(uri, server);
		break;
	case Type_Inet:
		fd = open_tcp(uri, server);
		break;
	case Type_Systemd:
		if (server)
			fd = open_systemd(uri);
		else {
			errno = EINVAL;
			fd = -1;
		}
		break;
	default:
		errno = EAFNOSUPPORT;
		fd = -1;
		break;
	}
	if (fd < 0)
		return -1;

	/* set it up */
	fcntl(fd, F_SETFD, FD_CLOEXEC);
	fcntl(fd, F_SETFL, O_NONBLOCK);
	if (server) {
		if (!e->noreuseaddr) {
			rc = 1;
			setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &rc, sizeof rc);
		}
		if (!e->nolisten)
			listen(fd, BACKLOG);
	}
	return fd;
}

/**
 * open socket for client or server
 *
 * @param uri the specification of the socket
 * @param server 0 for client, server otherwise
 *
 * @return the file descriptor number of the socket or -1 in case of error
 */
int afb_socket_open(const char *uri, int server)
{
	int fd = open_uri(uri, server);
	if (fd < 0)
		ERROR("can't open %s socket for %s", server ? "server" : "client", uri);
	return fd;
}

/**
 * open socket for client or server
 *
 * @param uri the specification of the socket
 * @param server 0 for client, server otherwise
 *
 * @return the fdev of the socket or NULL in case of error
 */
struct fdev *afb_socket_open_fdev(const char *uri, int server)
{
	struct fdev *fdev;
	int fd;

	fd = afb_socket_open(uri, server);
	if (fd < 0)
		fdev = NULL;
	else {
		fdev = afb_fdev_create(fd);
		if (!fdev) {
			close(fd);
			ERROR("can't make %s socket for %s", server ? "server" : "client", uri);
		}
	}
	return fdev;
}

/**
 * Get the api name of the uri
 *
 * @param uri the specification of the socket
 *
 * @return the api name or NULL if none can be deduced
 */
const char *afb_socket_api(const char *uri)
{
	int offset;
	const char *api;
	struct entry *entry;

	entry = get_entry(uri, &offset);
	uri += offset;
	uri += (entry->type == Type_Unix && *uri == '@');
	api = strstr(uri, as_api);
	if (api)
		api += sizeof as_api - 1;
	else {
		api = strrchr(uri, '/');
		if (api)
			api++;
		else
			api = uri;
		if (strchr(api, ':'))
			api = NULL;
	}
	return api;
}
