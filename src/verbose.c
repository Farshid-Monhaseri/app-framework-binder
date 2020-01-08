/*
 Copyright (C) 2015-2020 "IoT.bzh"

 author: José Bollo <jose.bollo@iot.bzh>

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
*/

#include <stdio.h>
#include <stdarg.h>

#include "verbose.h"

#define MASKOF(x)		(1 << (x))

#if !defined(DEFAULT_LOGLEVEL)
# define DEFAULT_LOGLEVEL	Log_Level_Warning
#endif

#if !defined(DEFAULT_LOGMASK)
# define DEFAULT_LOGMASK	(MASKOF((DEFAULT_LOGLEVEL) + 1) - 1)
#endif

#if !defined(MINIMAL_LOGLEVEL)
# define MINIMAL_LOGLEVEL	Log_Level_Error
#endif

#if !defined(MINIMAL_LOGMASK)
# define MINIMAL_LOGMASK	(MASKOF((MINIMAL_LOGLEVEL) + 1) - 1)
#endif

static const char *names[] = {
	"emergency",
	"alert",
	"critical",
	"error",
	"warning",
	"notice",
	"info",
	"debug"
};

static const char asort[] = { 1, 2, 7, 0, 3, 6, 5, 4 };

int logmask = DEFAULT_LOGMASK | MINIMAL_LOGMASK;

void (*verbose_observer)(int loglevel, const char *file, int line, const char *function, const char *fmt, va_list args);

#define CROP_LOGLEVEL(x) \
	((x) < Log_Level_Emergency ? Log_Level_Emergency \
	                           : (x) > Log_Level_Debug ? Log_Level_Debug : (x))

#if defined(VERBOSE_WITH_SYSLOG)

#include <syslog.h>

static void _vverbose_(int loglevel, const char *file, int line, const char *function, const char *fmt, va_list args)
{
	char *p;

	if (file == NULL || vasprintf(&p, fmt, args) < 0)
		vsyslog(loglevel, fmt, args);
	else {
		syslog(CROP_LOGLEVEL(loglevel), "%s [%s:%d, %s]", p, file, line, function?:"?");
		free(p);
	}
}

void verbose_set_name(const char *name, int authority)
{
	openlog(name, LOG_PERROR, authority ? LOG_AUTH : LOG_USER);
}

#elif defined(VERBOSE_WITH_SYSTEMD)

#define SD_JOURNAL_SUPPRESS_LOCATION

#include <systemd/sd-journal.h>

static const char *appname;

static int appauthority;

static void _vverbose_(int loglevel, const char *file, int line, const char *function, const char *fmt, va_list args)
{
	char lino[20];

	if (file == NULL) {
		sd_journal_printv(loglevel, fmt, args);
	} else {
		sprintf(lino, "%d", line);
		sd_journal_printv_with_location(loglevel, file, lino, function, fmt, args);
	}
}

void verbose_set_name(const char *name, int authority)
{
	appname = name;
	appauthority = authority;
}

#else

#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/uio.h>
#include <pthread.h>

static const char *appname;

static int appauthority;

static const char *prefixes[] = {
	"<0> EMERGENCY",
	"<1> ALERT",
	"<2> CRITICAL",
	"<3> ERROR",
	"<4> WARNING",
	"<5> NOTICE",
	"<6> INFO",
	"<7> DEBUG"
};

static const char *prefixes_colorized[] = {
	"<0> " COLOR_EMERGENCY	"EMERGENCY"	COLOR_DEFAULT,
	"<1> " COLOR_ALERT	"ALERT"		COLOR_DEFAULT,
	"<2> " COLOR_CRITICAL	"CRITICAL"	COLOR_DEFAULT,
	"<3> " COLOR_ERROR	"ERROR"		COLOR_DEFAULT,
	"<4> " COLOR_WARNING	"WARNING"	COLOR_DEFAULT,
	"<5> " COLOR_NOTICE	"NOTICE"	COLOR_DEFAULT,
	"<6> " COLOR_INFO	"INFO"		COLOR_DEFAULT,
	"<7> " COLOR_DEBUG	"DEBUG"		COLOR_DEFAULT
};

static int colorize = 0;

static int tty;

static const char chars[] = { '\n', '?', ':', ' ', '[', ',', ']' };

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

static void _vverbose_(int loglevel, const char *file, int line, const char *function, const char *fmt, va_list args)
{
	char buffer[4000];
	char lino[40];
	int saverr, n, rc;
	struct iovec iov[20];

	/* save errno */
	saverr = errno;

	/* check if tty (2) or not (1) */
	if (!tty)
		tty = 1 + isatty(STDERR_FILENO);

	/* prefix */
	if (colorize)
		iov[0].iov_base = (void*)prefixes_colorized[CROP_LOGLEVEL(loglevel)] + (tty - 1 ? 4 : 0);
	else
		iov[0].iov_base = (void*)prefixes[CROP_LOGLEVEL(loglevel)] + (tty - 1 ? 4 : 0);
	iov[0].iov_len = strlen(iov[0].iov_base);

	/* " " */
	iov[1].iov_base = (void*)&chars[2];
	iov[1].iov_len = 2;

	n = 2;
	if (fmt) {
		iov[n].iov_base = buffer;
		errno = saverr;
		rc = vsnprintf(buffer, sizeof buffer, fmt, args);
		if (rc < 0)
			rc = 0;
		else if ((size_t)rc > sizeof buffer) {
			/* if too long, ellipsis the end with ... */
			rc = (int)sizeof buffer;
			buffer[rc - 1] = buffer[rc - 2]  = buffer[rc - 3] = '.';
		}
		iov[n++].iov_len = (size_t)rc;
	}
	if (file && (!fmt || tty == 1 || loglevel <= Log_Level_Warning)) {

		if (colorize)
		{
			iov[n].iov_base = (void*)COLOR_FILE;
			iov[n++].iov_len = strlen(COLOR_FILE);
		}

		/* "[" (!fmt) or " [" (fmt) */
		iov[n].iov_base = (void*)&chars[3 + !fmt];
		iov[n++].iov_len = 2 - !fmt;
		/* file */
		iov[n].iov_base = (void*)file;
		iov[n++].iov_len = strlen(file);
		/* ":" */
		iov[n].iov_base = (void*)&chars[2];
		iov[n++].iov_len = 1;
		if (line) {
			/* line number */
			iov[n].iov_base = lino;
			iov[n++].iov_len = snprintf(lino, sizeof lino, "%d", line);
		} else {
			/* "?" */
			iov[n].iov_base = (void*)&chars[1];
			iov[n++].iov_len = 1;
		}
		/* "," */
		iov[n].iov_base = (void*)&chars[5];
		iov[n++].iov_len = 1;
		if (function) {
			/* function name */
			iov[n].iov_base = (void*)function;
			iov[n++].iov_len = strlen(function);
		} else {
			/* "?" */
			iov[n].iov_base = (void*)&chars[1];
			iov[n++].iov_len = 1;
		}
		iov[n].iov_base = (void*)&chars[6];
		iov[n++].iov_len = 1;

		if (colorize)
		{
			iov[n].iov_base = (void*)COLOR_DEFAULT;
			iov[n++].iov_len = strlen(COLOR_DEFAULT);
		}
	}
	if (n == 2) {
		/* "?" */
		iov[n].iov_base = (void*)&chars[1];
		iov[n++].iov_len = 1;
	}
	/* "\n" */
	iov[n].iov_base = (void*)&chars[0];
	iov[n++].iov_len = 1;

	/* emit the message */
	pthread_mutex_lock(&mutex);
	writev(STDERR_FILENO, iov, n);
	pthread_mutex_unlock(&mutex);

	/* restore errno */
	errno = saverr;
}

void verbose_set_name(const char *name, int authority)
{
	appname = name;
	appauthority = authority;
}

#endif

void vverbose(int loglevel, const char *file, int line, const char *function, const char *fmt, va_list args)
{
	void (*observer)(int loglevel, const char *file, int line, const char *function, const char *fmt, va_list args) = verbose_observer;

	if (!observer)
		_vverbose_(loglevel, file, line, function, fmt, args);
	else {
		va_list ap;
		va_copy(ap, args);
		_vverbose_(loglevel, file, line, function, fmt, args);
		observer(loglevel, file, line, function, fmt, ap);
		va_end(ap);
	}
}

void verbose(int loglevel, const char *file, int line, const char *function, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vverbose(loglevel, file, line, function, fmt, ap);
	va_end(ap);
}

void set_logmask(int lvl)
{
	logmask = lvl | MINIMAL_LOGMASK;
}

void verbose_add(int level)
{
	set_logmask(logmask | MASKOF(level));
}

void verbose_sub(int level)
{
	set_logmask(logmask & ~MASKOF(level));
}

void verbose_clear()
{
	set_logmask(0);
}

void verbose_dec()
{
	verbosity_set(verbosity_get() - 1);
}

void verbose_inc()
{
	verbosity_set(verbosity_get() + 1);
}

int verbosity_to_mask(int verbo)
{
	int x = verbo + Log_Level_Error;
	int l = CROP_LOGLEVEL(x);
	return (1 << (l + 1)) - 1;
}

int verbosity_from_mask(int mask)
{
	int v = 0;
	while (mask > verbosity_to_mask(v))
		v++;
	return v;
}

void verbosity_set(int verbo)
{
	set_logmask(verbosity_to_mask(verbo));
}

int verbosity_get()
{
	return verbosity_from_mask(logmask);
}

int verbose_level_of_name(const char *name)
{
	int c, i, r, l = 0, u = sizeof names / sizeof * names;
	while (l < u) {
		i = (l + u) >> 1;
		r = (int)asort[i];
		c = strcasecmp(names[r], name);
		if (!c)
			return r;
		if (c < 0)
			l = i + 1;
		else
			u = i;
	}
	return -1;
}

const char *verbose_name_of_level(int level)
{
	return level == CROP_LOGLEVEL(level) ? names[level] : NULL;
}

void verbose_colorize()
{
	colorize = 1;
}

int verbose_is_colorized()
{
	return colorize;
}
