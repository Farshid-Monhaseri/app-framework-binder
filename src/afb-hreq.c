/*
 * Copyright (C) 2016-2019 "IoT.bzh"
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
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <microhttpd.h>
#include <json-c/json.h>
#if !defined(JSON_C_TO_STRING_NOSLASHESCAPE)
#define JSON_C_TO_STRING_NOSLASHESCAPE 0
#endif

#if defined(USE_MAGIC_MIME_TYPE)
#include <magic.h>
#endif

#include "afb-method.h"
#include "afb-msg-json.h"
#include "afb-context.h"
#include "afb-hreq.h"
#include "afb-hsrv.h"
#include "afb-session.h"
#include "afb-cred.h"
#include "afb-token.h"
#include "verbose.h"
#include "locale-root.h"

#define SIZE_RESPONSE_BUFFER   8192

static int global_reqids = 0;

static char empty_string[] = "";

static const char long_key_for_uuid[] = "x-afb-uuid";
static const char short_key_for_uuid[] = "uuid";

static const char long_key_for_token[] = "x-afb-token";
static const char short_key_for_token[] = "token";

static const char long_key_for_reqid[] = "x-afb-reqid";
static const char short_key_for_reqid[] = "reqid";

static const char key_for_bearer[] = "Bearer";
static const char key_for_access_token[] = "access_token";

static char *cookie_name = NULL;
static char *cookie_setter = NULL;
static char *tmp_pattern = NULL;

/*
 * Structure for storing key/values read from POST requests
 */
struct hreq_data {
	struct hreq_data *next;	/* chain to next data */
	char *key;		/* key name */
	size_t length;		/* length of the value (used for appending) */
	char *value;		/* the value (or original filename) */
	char *path;		/* path of the file saved */
};

static struct json_object *req_json(struct afb_xreq *xreq);
static struct afb_arg req_get(struct afb_xreq *xreq, const char *name);
static void req_reply(struct afb_xreq *xreq, struct json_object *object, const char *error, const char *info);
static void req_destroy(struct afb_xreq *xreq);

const struct afb_xreq_query_itf afb_hreq_xreq_query_itf = {
	.json = req_json,
	.get = req_get,
	.reply = req_reply,
	.unref = req_destroy
};

static struct hreq_data *get_data(struct afb_hreq *hreq, const char *key, int create)
{
	struct hreq_data *data = hreq->data;
	while (data != NULL) {
		if (!strcasecmp(data->key, key))
			return data;
		data = data->next;
	}
	if (create) {
		data = calloc(1, sizeof *data);
		if (data != NULL) {
			data->key = strdup(key);
			if (data->key == NULL) {
				free(data);
				data = NULL;
			} else {
				data->next = hreq->data;
				hreq->data = data;
			}
		}
	}
	return data;
}

/* a valid subpath is a relative path not looking deeper than root using .. */
static int validsubpath(const char *subpath)
{
	int l = 0, i = 0;

	while (subpath[i]) {
		switch (subpath[i++]) {
		case '.':
			if (!subpath[i])
				break;
			if (subpath[i] == '/') {
				i++;
				break;
			}
			if (subpath[i++] == '.') {
				if (!subpath[i]) {
					if (--l < 0)
						return 0;
					break;
				}
				if (subpath[i++] == '/') {
					if (--l < 0)
						return 0;
					break;
				}
			}
		default:
			while (subpath[i] && subpath[i] != '/')
				i++;
			l++;
		case '/':
			break;
		}
	}
	return 1;
}

static void afb_hreq_reply_v(struct afb_hreq *hreq, unsigned status, struct MHD_Response *response, va_list args)
{
	char *cookie;
	const char *k, *v;

	if (hreq->replied != 0)
		return;

	k = va_arg(args, const char *);
	while (k != NULL) {
		v = va_arg(args, const char *);
		MHD_add_response_header(response, k, v);
		k = va_arg(args, const char *);
	}

	v = afb_context_uuid(&hreq->xreq.context);
	if (v != NULL && asprintf(&cookie, cookie_setter, v) > 0) {
		MHD_add_response_header(response, MHD_HTTP_HEADER_SET_COOKIE, cookie);
		free(cookie);
	}
	MHD_queue_response(hreq->connection, status, response);
	MHD_destroy_response(response);

	hreq->replied = 1;
	if (hreq->suspended != 0) {
		MHD_resume_connection (hreq->connection);
		hreq->suspended = 0;
		afb_hsrv_run(hreq->hsrv);
	}
}

void afb_hreq_reply(struct afb_hreq *hreq, unsigned status, struct MHD_Response *response, ...)
{
	va_list args;
	va_start(args, response);
	afb_hreq_reply_v(hreq, status, response, args);
	va_end(args);
}

void afb_hreq_reply_empty(struct afb_hreq *hreq, unsigned status, ...)
{
	va_list args;
	va_start(args, status);
	afb_hreq_reply_v(hreq, status, MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_PERSISTENT), args);
	va_end(args);
}

void afb_hreq_reply_static(struct afb_hreq *hreq, unsigned status, size_t size, const char *buffer, ...)
{
	va_list args;
	va_start(args, buffer);
	afb_hreq_reply_v(hreq, status, MHD_create_response_from_buffer((unsigned)size, (char*)buffer, MHD_RESPMEM_PERSISTENT), args);
	va_end(args);
}

void afb_hreq_reply_copy(struct afb_hreq *hreq, unsigned status, size_t size, const char *buffer, ...)
{
	va_list args;
	va_start(args, buffer);
	afb_hreq_reply_v(hreq, status, MHD_create_response_from_buffer((unsigned)size, (char*)buffer, MHD_RESPMEM_MUST_COPY), args);
	va_end(args);
}

void afb_hreq_reply_free(struct afb_hreq *hreq, unsigned status, size_t size, char *buffer, ...)
{
	va_list args;
	va_start(args, buffer);
	afb_hreq_reply_v(hreq, status, MHD_create_response_from_buffer((unsigned)size, buffer, MHD_RESPMEM_MUST_FREE), args);
	va_end(args);
}

#if defined(USE_MAGIC_MIME_TYPE)

#if !defined(MAGIC_DB)
#define MAGIC_DB "/usr/share/misc/magic.mgc"
#endif

static magic_t lazy_libmagic()
{
	static int done = 0;
	static magic_t result = NULL;

	if (!done) {
		done = 1;
		/* MAGIC_MIME tells magic to return a mime of the file,
			 but you can specify different things */
		INFO("Loading mimetype default magic database");
		result = magic_open(MAGIC_MIME_TYPE);
		if (result == NULL) {
			ERROR("unable to initialize magic library");
		}
		/* Warning: should not use NULL for DB
				[libmagic bug wont pass efence check] */
		else if (magic_load(result, MAGIC_DB) != 0) {
			ERROR("cannot load magic database: %s", magic_error(result));
			magic_close(result);
			result = NULL;
		}
	}

	return result;
}

static const char *magic_mimetype_fd(int fd)
{
	magic_t lib = lazy_libmagic();
	return lib ? magic_descriptor(lib, fd) : NULL;
}

#endif

static const char *mimetype_fd_name(int fd, const char *filename)
{
	const char *result = NULL;

#if defined(INFER_EXTENSION)
	/*
	 * Set some well-known extensions
	 * Note that it is mandatory for example for css files in order to provide
	 * right mimetype that must be text/css (otherwise chrome browser will not
	 * load correctly css file) while libmagic returns text/plain.
	 */
	const char *extension = strrchr(filename, '.');
	if (extension) {
		static const char *const known[][2] = {
			/* keep it sorted for dichotomic search */
			{ ".css",	"text/css" },
			{ ".gif",	"image/gif" },
			{ ".html",	"text/html" },
			{ ".htm",	"text/html" },
			{ ".ico",	"image/x-icon"},
			{ ".jpeg",	"image/jpeg" },
			{ ".jpg",	"image/jpeg" },
			{ ".js",	"text/javascript" },
			{ ".json",	"application/json" },
			{ ".mp3",	"audio/mpeg" },
			{ ".png",	"image/png" },
			{ ".svg",	"image/svg+xml" },
			{ ".ttf",	"application/x-font-ttf"},
			{ ".txt",	"text/plain" },
			{ ".wav",	"audio/x-wav" },
			{ ".xht",	"application/xhtml+xml" },
			{ ".xhtml",	"application/xhtml+xml" },
			{ ".xml",	"application/xml" }
		};
		int i, c, l = 0, u = sizeof known / sizeof *known;
		while (l < u) {
			i = (l + u) >> 1;
			c = strcasecmp(extension, known[i][0]);
			if (!c) {
				result = known[i][1];
				break;
			}
			if (c < 0)
				u = i;
			else
				l = i + 1;
		}
	}
#endif
#if defined(USE_MAGIC_MIME_TYPE)
	if (result == NULL)
		result = magic_mimetype_fd(fd);
#endif
	return result;
}

static void req_destroy(struct afb_xreq *xreq)
{
	struct afb_hreq *hreq = CONTAINER_OF_XREQ(struct afb_hreq, xreq);
	struct hreq_data *data;

	if (hreq->postform != NULL)
		MHD_destroy_post_processor(hreq->postform);
	if (hreq->tokener != NULL)
		json_tokener_free(hreq->tokener);

	for (data = hreq->data; data; data = hreq->data) {
		hreq->data = data->next;
		if (data->path) {
			unlink(data->path);
			free(data->path);
		}
		free(data->key);
		free(data->value);
		free(data);
	}
	afb_context_disconnect(&hreq->xreq.context);
	json_object_put(hreq->json);
	free((char*)hreq->xreq.request.called_api);
	free((char*)hreq->xreq.request.called_verb);
	afb_cred_unref(hreq->xreq.cred);
	free(hreq);
}

void afb_hreq_addref(struct afb_hreq *hreq)
{
	afb_xreq_unhooked_addref(&hreq->xreq);
}

void afb_hreq_unref(struct afb_hreq *hreq)
{
	if (hreq->replied)
		hreq->xreq.replied = 1;
	afb_xreq_unhooked_unref(&hreq->xreq);
}

/*
 * Removes the 'prefix' of 'length' from the tail of 'hreq'
 * if and only if the prefix exists and is terminated by a leading
 * slash
 */
int afb_hreq_unprefix(struct afb_hreq *hreq, const char *prefix, size_t length)
{
	/* check the prefix ? */
	if (length > hreq->lentail || (hreq->tail[length] && hreq->tail[length] != '/')
	    || strncasecmp(prefix, hreq->tail, length))
		return 0;

	/* removes successives / */
	while (length < hreq->lentail && hreq->tail[length + 1] == '/')
		length++;

	/* update the tail */
	hreq->lentail -= length;
	hreq->tail += length;
	return 1;
}

int afb_hreq_valid_tail(struct afb_hreq *hreq)
{
	return validsubpath(hreq->tail);
}

void afb_hreq_reply_error(struct afb_hreq *hreq, unsigned int status)
{
	afb_hreq_reply_empty(hreq, status, NULL);
}

int afb_hreq_redirect_to_ending_slash_if_needed(struct afb_hreq *hreq)
{
	char *tourl;

	if (hreq->url[hreq->lenurl - 1] == '/')
		return 0;

	/* the redirect is needed for reliability of relative path */
	tourl = alloca(hreq->lenurl + 2);
	memcpy(tourl, hreq->url, hreq->lenurl);
	tourl[hreq->lenurl] = '/';
	tourl[hreq->lenurl + 1] = 0;
	afb_hreq_redirect_to(hreq, tourl, 1);
	return 1;
}

int afb_hreq_reply_file_if_exist(struct afb_hreq *hreq, int dirfd, const char *filename)
{
	int rc;
	int fd;
	unsigned int status;
	struct stat st;
	char etag[1 + 2 * 8];
	const char *inm;
	struct MHD_Response *response;
	const char *mimetype;

	/* Opens the file or directory */
	if (filename[0]) {
		fd = openat(dirfd, filename, O_RDONLY);
		if (fd < 0) {
			if (errno == ENOENT)
				return 0;
			afb_hreq_reply_error(hreq, MHD_HTTP_FORBIDDEN);
			return 1;
		}
	} else {
		fd = dup(dirfd);
		if (fd < 0) {
			afb_hreq_reply_error(hreq, MHD_HTTP_INTERNAL_SERVER_ERROR);
			return 1;
		}
	}

	/* Retrieves file's status */
	if (fstat(fd, &st) != 0) {
		close(fd);
		afb_hreq_reply_error(hreq, MHD_HTTP_INTERNAL_SERVER_ERROR);
		return 1;
	}

	/* serve directory */
	if (S_ISDIR(st.st_mode)) {
		rc = afb_hreq_redirect_to_ending_slash_if_needed(hreq);
		if (rc == 0) {
			static const char *indexes[] = { "index.html", NULL };
			int i = 0;
			while (indexes[i] != NULL) {
				if (faccessat(fd, indexes[i], R_OK, 0) == 0) {
					rc = afb_hreq_reply_file_if_exist(hreq, fd, indexes[i]);
					break;
				}
				i++;
			}
		}
		close(fd);
		return rc;
	}

	/* Don't serve special files */
	if (!S_ISREG(st.st_mode)) {
		close(fd);
		afb_hreq_reply_error(hreq, MHD_HTTP_FORBIDDEN);
		return 1;
	}

	/* Check the method */
	if ((hreq->method & (afb_method_get | afb_method_head)) == 0) {
		close(fd);
		afb_hreq_reply_error(hreq, MHD_HTTP_METHOD_NOT_ALLOWED);
		return 1;
	}

	/* computes the etag */
	sprintf(etag, "%08X%08X", ((int)(st.st_mtim.tv_sec) ^ (int)(st.st_mtim.tv_nsec)), (int)(st.st_size));

	/* checks the etag */
	inm = MHD_lookup_connection_value(hreq->connection, MHD_HEADER_KIND, MHD_HTTP_HEADER_IF_NONE_MATCH);
	if (inm && 0 == strcmp(inm, etag)) {
		/* etag ok, return NOT MODIFIED */
		close(fd);
		DEBUG("Not Modified: [%s]", filename);
		response = MHD_create_response_from_buffer(0, empty_string, MHD_RESPMEM_PERSISTENT);
		status = MHD_HTTP_NOT_MODIFIED;
	} else {
		/* check the size */
		if (st.st_size != (off_t) (size_t) st.st_size) {
			close(fd);
			afb_hreq_reply_error(hreq, MHD_HTTP_INTERNAL_SERVER_ERROR);
			return 1;
		}

		/* create the response */
		response = MHD_create_response_from_fd((size_t) st.st_size, fd);
		status = MHD_HTTP_OK;

		/* set the type */
		mimetype = mimetype_fd_name(fd, filename);
		if (mimetype != NULL)
			MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE, mimetype);
	}

	/* fills the value and send */
	afb_hreq_reply(hreq, status, response,
			MHD_HTTP_HEADER_CACHE_CONTROL, hreq->cacheTimeout,
			MHD_HTTP_HEADER_ETAG, etag,
			NULL);
	return 1;
}

int afb_hreq_reply_file(struct afb_hreq *hreq, int dirfd, const char *filename)
{
	int rc = afb_hreq_reply_file_if_exist(hreq, dirfd, filename);
	if (rc == 0)
		afb_hreq_reply_error(hreq, MHD_HTTP_NOT_FOUND);
	return 1;
}

int afb_hreq_reply_locale_file_if_exist(struct afb_hreq *hreq, struct locale_search *search, const char *filename)
{
	int rc;
	int fd;
	unsigned int status;
	struct stat st;
	char etag[1 + 2 * 8];
	const char *inm;
	struct MHD_Response *response;
	const char *mimetype;

	/* Opens the file or directory */
	fd = locale_search_open(search, filename[0] ? filename : ".", O_RDONLY);
	if (fd < 0) {
		if (errno == ENOENT)
			return 0;
		afb_hreq_reply_error(hreq, MHD_HTTP_FORBIDDEN);
		return 1;
	}

	/* Retrieves file's status */
	if (fstat(fd, &st) != 0) {
		close(fd);
		afb_hreq_reply_error(hreq, MHD_HTTP_INTERNAL_SERVER_ERROR);
		return 1;
	}

	/* serve directory */
	if (S_ISDIR(st.st_mode)) {
		rc = afb_hreq_redirect_to_ending_slash_if_needed(hreq);
		if (rc == 0) {
			static const char *indexes[] = { "index.html", NULL };
			int i = 0;
			size_t length = strlen(filename);
			char *extname = alloca(length + 30); /* 30 is enough to old data of indexes */
			memcpy(extname, filename, length);
			if (length && extname[length - 1] != '/')
				extname[length++] = '/';
			while (rc == 0 && indexes[i] != NULL) {
				strcpy(extname + length, indexes[i++]);
				rc = afb_hreq_reply_locale_file_if_exist(hreq, search, extname);
			}
		}
		close(fd);
		return rc;
	}

	/* Don't serve special files */
	if (!S_ISREG(st.st_mode)) {
		close(fd);
		afb_hreq_reply_error(hreq, MHD_HTTP_FORBIDDEN);
		return 1;
	}

	/* Check the method */
	if ((hreq->method & (afb_method_get | afb_method_head)) == 0) {
		close(fd);
		afb_hreq_reply_error(hreq, MHD_HTTP_METHOD_NOT_ALLOWED);
		return 1;
	}

	/* computes the etag */
	sprintf(etag, "%08X%08X", ((int)(st.st_mtim.tv_sec) ^ (int)(st.st_mtim.tv_nsec)), (int)(st.st_size));

	/* checks the etag */
	inm = MHD_lookup_connection_value(hreq->connection, MHD_HEADER_KIND, MHD_HTTP_HEADER_IF_NONE_MATCH);
	if (inm && 0 == strcmp(inm, etag)) {
		/* etag ok, return NOT MODIFIED */
		close(fd);
		DEBUG("Not Modified: [%s]", filename);
		response = MHD_create_response_from_buffer(0, empty_string, MHD_RESPMEM_PERSISTENT);
		status = MHD_HTTP_NOT_MODIFIED;
	} else {
		/* check the size */
		if (st.st_size != (off_t) (size_t) st.st_size) {
			close(fd);
			afb_hreq_reply_error(hreq, MHD_HTTP_INTERNAL_SERVER_ERROR);
			return 1;
		}

		/* create the response */
		response = MHD_create_response_from_fd((size_t) st.st_size, fd);
		status = MHD_HTTP_OK;

		/* set the type */
		mimetype = mimetype_fd_name(fd, filename);
		if (mimetype != NULL)
			MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE, mimetype);
	}

	/* fills the value and send */
	afb_hreq_reply(hreq, status, response,
			MHD_HTTP_HEADER_CACHE_CONTROL, hreq->cacheTimeout,
			MHD_HTTP_HEADER_ETAG, etag,
			NULL);
	return 1;
}

int afb_hreq_reply_locale_file(struct afb_hreq *hreq, struct locale_search *search, const char *filename)
{
	int rc = afb_hreq_reply_locale_file_if_exist(hreq, search, filename);
	if (rc == 0)
		afb_hreq_reply_error(hreq, MHD_HTTP_NOT_FOUND);
	return 1;
}

struct _mkq_ {
	int count;
	size_t length;
	size_t alloc;
	char *text;
};

static void _mkq_add_(struct _mkq_ *mkq, char value)
{
	char *text = mkq->text;
	if (text != NULL) {
		if (mkq->length == mkq->alloc) {
			mkq->alloc += 100;
			text = realloc(text, mkq->alloc);
			if (text == NULL) {
				free(mkq->text);
				mkq->text = NULL;
				return;
			}
			mkq->text = text;
		}
		text[mkq->length++] = value;
	}
}

static void _mkq_add_hex_(struct _mkq_ *mkq, char value)
{
	_mkq_add_(mkq, (char)(value < 10 ? value + '0' : value + 'A' - 10));
}

static void _mkq_add_esc_(struct _mkq_ *mkq, char value)
{
	_mkq_add_(mkq, '%');
	_mkq_add_hex_(mkq, (char)((value >> 4) & 15));
	_mkq_add_hex_(mkq, (char)(value & 15));
}

static void _mkq_add_char_(struct _mkq_ *mkq, char value)
{
	if (value <= ' ' || value >= 127)
		_mkq_add_esc_(mkq, value);
	else
		switch(value) {
		case '=':
		case '&':
		case '%':
			_mkq_add_esc_(mkq, value);
			break;
		default:
			_mkq_add_(mkq, value);
		}
}

static void _mkq_append_(struct _mkq_ *mkq, const char *value)
{
	while(*value)
		_mkq_add_char_(mkq, *value++);
}

static int _mkquery_(struct _mkq_ *mkq, enum MHD_ValueKind kind, const char *key, const char *value)
{
	_mkq_add_(mkq, mkq->count++ ? '&' : '?');
	_mkq_append_(mkq, key);
	if (value != NULL) {
		_mkq_add_(mkq, '=');
		_mkq_append_(mkq, value);
	}
	return 1;
}

static char *url_with_query(struct afb_hreq *hreq, const char *url)
{
	struct _mkq_ mkq;

	mkq.count = 0;
	mkq.length = strlen(url);
	mkq.alloc = mkq.length + 1000;
	mkq.text = malloc(mkq.alloc);
	if (mkq.text != NULL) {
		strcpy(mkq.text, url);
		MHD_get_connection_values(hreq->connection, MHD_GET_ARGUMENT_KIND, (void*)_mkquery_, &mkq);
		_mkq_add_(&mkq, 0);
	}
	return mkq.text;
}

void afb_hreq_redirect_to(struct afb_hreq *hreq, const char *url, int add_query_part)
{
	const char *to;
	char *wqp;

	wqp = add_query_part ? url_with_query(hreq, url) : NULL;
	to = wqp ? : url;
	afb_hreq_reply_static(hreq, MHD_HTTP_MOVED_PERMANENTLY, 0, NULL,
			MHD_HTTP_HEADER_LOCATION, to, NULL);
	DEBUG("redirect from [%s] to [%s]", hreq->url, url);
	free(wqp);
}

const char *afb_hreq_get_cookie(struct afb_hreq *hreq, const char *name)
{
	return MHD_lookup_connection_value(hreq->connection, MHD_COOKIE_KIND, name);
}

const char *afb_hreq_get_argument(struct afb_hreq *hreq, const char *name)
{
	struct hreq_data *data = get_data(hreq, name, 0);
	return data ? data->value : MHD_lookup_connection_value(hreq->connection, MHD_GET_ARGUMENT_KIND, name);
}

const char *afb_hreq_get_header(struct afb_hreq *hreq, const char *name)
{
	return MHD_lookup_connection_value(hreq->connection, MHD_HEADER_KIND, name);
}

const char *afb_hreq_get_authorization_bearer(struct afb_hreq *hreq)
{
	const char *value = afb_hreq_get_header(hreq, MHD_HTTP_HEADER_AUTHORIZATION);
	if (value) {
		if (strncasecmp(value, key_for_bearer, sizeof key_for_bearer - 1) == 0) {
			value += sizeof key_for_bearer - 1;
			if (isblank(*value++)) {
				while (isblank(*value))
					value++;
				if (*value)
					return value;
			}
		}
	}
	return NULL;
}

int afb_hreq_post_add(struct afb_hreq *hreq, const char *key, const char *data, size_t size)
{
	void *p;
	struct hreq_data *hdat = get_data(hreq, key, 1);
	if (hdat->path != NULL) {
		return 0;
	}
	p = realloc(hdat->value, hdat->length + size + 1);
	if (p == NULL) {
		return 0;
	}
	hdat->value = p;
	memcpy(&hdat->value[hdat->length], data, size);
	hdat->length += size;
	hdat->value[hdat->length] = 0;
	return 1;
}

int afb_hreq_init_download_path(const char *directory)
{
	struct stat st;
	size_t n;
	char *p;

	if (access(directory, R_OK|W_OK)) {
		/* no read/write access */
		return -1;
	}
	if (stat(directory, &st)) {
		/* can't get info */
		return -1;
	}
	if (!S_ISDIR(st.st_mode)) {
		/* not a directory */
		errno = ENOTDIR;
		return -1;
	}
	n = strlen(directory);
	while(n > 1 && directory[n-1] == '/') n--;
	p = malloc(n + 8);
	if (p == NULL) {
		/* can't allocate memory */
		errno = ENOMEM;
		return -1;
	}
	memcpy(p, directory, n);
	p[n++] = '/';
	p[n++] = 'X';
	p[n++] = 'X';
	p[n++] = 'X';
	p[n++] = 'X';
	p[n++] = 'X';
	p[n++] = 'X';
	p[n] = 0;
	free(tmp_pattern);
	tmp_pattern = p;
	return 0;
}

static int opentempfile(char **path)
{
	int fd;
	char *fname;

	fname = strdup(tmp_pattern ? : "XXXXXX"); /* TODO improve the path */
	if (fname == NULL)
		return -1;

	fd = mkostemp(fname, O_CLOEXEC|O_WRONLY);
	if (fd < 0)
		free(fname);
	else
		*path = fname;
	return fd;
}

int afb_hreq_post_add_file(struct afb_hreq *hreq, const char *key, const char *file, const char *data, size_t size)
{
	int fd;
	ssize_t sz;
	struct hreq_data *hdat = get_data(hreq, key, 1);

	if (hdat->value == NULL) {
		hdat->value = strdup(file);
		if (hdat->value == NULL)
			return 0;
		fd = opentempfile(&hdat->path);
	} else if (strcmp(hdat->value, file) || hdat->path == NULL) {
		return 0;
	} else {
		fd = open(hdat->path, O_WRONLY|O_APPEND);
	}
	if (fd < 0)
		return 0;
	while (size) {
		sz = write(fd, data, size);
		if (sz >= 0) {
			hdat->length += (size_t)sz;
			size -= (size_t)sz;
			data += sz;
		} else if (errno != EINTR)
			break;
	}
	close(fd);
	return !size;
}

static struct afb_arg req_get(struct afb_xreq *xreq, const char *name)
{
	const char *value;
	struct afb_hreq *hreq = CONTAINER_OF_XREQ(struct afb_hreq, xreq);
	struct hreq_data *hdat = get_data(hreq, name, 0);
	if (hdat)
		return (struct afb_arg){
			.name = hdat->key,
			.value = hdat->value,
			.path = hdat->path
		};

	value = MHD_lookup_connection_value(hreq->connection, MHD_GET_ARGUMENT_KIND, name);
	return (struct afb_arg){
		.name = value == NULL ? NULL : name,
		.value = value,
		.path = NULL
	};
}

static int _iterargs_(struct json_object *obj, enum MHD_ValueKind kind, const char *key, const char *value)
{
	json_object_object_add(obj, key, value ? json_object_new_string(value) : NULL);
	return 1;
}

static struct json_object *req_json(struct afb_xreq *xreq)
{
	struct hreq_data *hdat;
	struct json_object *obj, *val;
	struct afb_hreq *hreq = CONTAINER_OF_XREQ(struct afb_hreq, xreq);

	obj = hreq->json;
	if (obj == NULL) {
		hreq->json = obj = json_object_new_object();
		if (obj == NULL) {
		} else {
			MHD_get_connection_values (hreq->connection, MHD_GET_ARGUMENT_KIND, (void*)_iterargs_, obj);
			for (hdat = hreq->data ; hdat ; hdat = hdat->next) {
				if (hdat->path == NULL)
					val = hdat->value ? json_object_new_string(hdat->value) : NULL;
				else {
					val = json_object_new_object();
					if (val == NULL) {
					} else {
						json_object_object_add(val, "file", json_object_new_string(hdat->value));
						json_object_object_add(val, "path", json_object_new_string(hdat->path));
					}
				}
				json_object_object_add(obj, hdat->key, val);
			}
		}
	}
	return obj;
}

static ssize_t send_json_cb(json_object *obj, uint64_t pos, char *buf, size_t max)
{
	ssize_t len = stpncpy(buf, json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN|JSON_C_TO_STRING_NOSLASHESCAPE)+pos, max) - buf;
	return len ? : (ssize_t)MHD_CONTENT_READER_END_OF_STREAM;
}

static void req_reply(struct afb_xreq *xreq, struct json_object *object, const char *error, const char *info)
{
	struct afb_hreq *hreq = CONTAINER_OF_XREQ(struct afb_hreq, xreq);
	struct json_object *sub, *reply;
	const char *reqid;
	struct MHD_Response *response;

	/* create the reply */
	reply = afb_msg_json_reply(object, error, info, &xreq->context);

	/* append the req id on need */
	reqid = afb_hreq_get_argument(hreq, long_key_for_reqid);
	if (reqid == NULL)
		reqid = afb_hreq_get_argument(hreq, short_key_for_reqid);
	if (reqid != NULL && json_object_object_get_ex(reply, "request", &sub))
		json_object_object_add(sub, "reqid", json_object_new_string(reqid));

	response = MHD_create_response_from_callback((uint64_t)strlen(json_object_to_json_string_ext(reply, JSON_C_TO_STRING_PLAIN|JSON_C_TO_STRING_NOSLASHESCAPE)), SIZE_RESPONSE_BUFFER, (void*)send_json_cb, reply, (void*)json_object_put);
	afb_hreq_reply(hreq, MHD_HTTP_OK, response, NULL);
}

void afb_hreq_call(struct afb_hreq *hreq, struct afb_apiset *apiset, const char *api, size_t lenapi, const char *verb, size_t lenverb)
{
	hreq->xreq.request.called_api = strndup(api, lenapi);
	hreq->xreq.request.called_verb = strndup(verb, lenverb);
	if (hreq->xreq.request.called_api == NULL || hreq->xreq.request.called_verb == NULL) {
		ERROR("Out of memory");
		afb_hreq_reply_error(hreq, MHD_HTTP_INTERNAL_SERVER_ERROR);
	} else if (afb_hreq_init_context(hreq) < 0) {
		afb_hreq_reply_error(hreq, MHD_HTTP_INTERNAL_SERVER_ERROR);
	} else {
		afb_xreq_unhooked_addref(&hreq->xreq);
		afb_xreq_process(&hreq->xreq, apiset);
	}
}

int afb_hreq_init_context(struct afb_hreq *hreq)
{
	const char *uuid;
	const char *token;
	struct afb_token *tok;

	if (hreq->xreq.context.session != NULL)
		return 0;

	/* get the uuid of the session */
	uuid = afb_hreq_get_header(hreq, long_key_for_uuid);
	if (uuid == NULL) {
		uuid = afb_hreq_get_argument(hreq, long_key_for_uuid);
		if (uuid == NULL) {
			uuid = afb_hreq_get_cookie(hreq, cookie_name);
			if (uuid == NULL)
				uuid = afb_hreq_get_argument(hreq, short_key_for_uuid);
		}
	}

	/* get the authorisation token */
	token = afb_hreq_get_authorization_bearer(hreq);
	if (token == NULL) {
		token = afb_hreq_get_argument(hreq, key_for_access_token);
		if (token == NULL) {
			token = afb_hreq_get_header(hreq, long_key_for_token);
			if (token == NULL) {
				token = afb_hreq_get_argument(hreq, long_key_for_token);
				if (token == NULL)
					token = afb_hreq_get_argument(hreq, short_key_for_token);
			}
		}
	}
	tok = NULL;
	if (token)
		afb_token_get(&tok, token);

	return afb_context_connect(&hreq->xreq.context, uuid, tok);
}

int afb_hreq_init_cookie(int port, const char *path, int maxage)
{
	int rc;

	free(cookie_name);
	free(cookie_setter);
	cookie_name = NULL;
	cookie_setter = NULL;

	path = path ? : "/";
	rc = asprintf(&cookie_name, "%s-%d", long_key_for_uuid, port);
	if (rc < 0)
		return 0;
	rc = asprintf(&cookie_setter, "%s=%%s; Path=%s; Max-Age=%d; HttpOnly",
			cookie_name, path, maxage);
	if (rc < 0)
		return 0;
	return 1;
}

struct afb_xreq *afb_hreq_to_xreq(struct afb_hreq *hreq)
{
	return &hreq->xreq;
}

struct afb_hreq *afb_hreq_create()
{
	struct afb_hreq *hreq = calloc(1, sizeof *hreq);
	if (hreq) {
		/* init the request */
		afb_xreq_init(&hreq->xreq, &afb_hreq_xreq_query_itf);
		hreq->reqid = ++global_reqids;
	}
	return hreq;
}

