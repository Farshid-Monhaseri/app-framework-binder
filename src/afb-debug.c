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

#include "afb-debug.h"

#if defined(AFB_INSERT_DEBUG_FEATURES)

#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#if !defined(NO_CALL_PERSONALITY)
#include <sys/personality.h>
#endif

#include "verbose.h"

static char key_env_break[] = "AFB_DEBUG_BREAK";
static char key_env_wait[] = "AFB_DEBUG_WAIT";
static char separs[] = ", \t\n";

/*
 * Checks whether the 'key' is in the 'list'
 * Return 1 if it is in or 0 otherwise
 */
static int has_key(const char *key, const char *list)
{
	if (list && key) {
		list += strspn(list, separs);
		while (*list) {
			size_t s = strcspn(list, separs);
			if (!strncasecmp(list, key, s) && !key[s])
				return 1;
			list += s;
			list += strspn(list, separs);
		}
	}
	return 0;
}

static void indicate(const char *key)
{
#if !defined(NO_AFB_DEBUG_FILE_INDICATION)
	char filename[200];
	int fd;

	snprintf(filename, sizeof filename, "/tmp/afb-debug-%ld", (long)getpid());
	if (key) {
		fd = creat(filename, 0644);
		write(fd, key, strlen(key));
		close(fd);
	} else {
		unlink(filename);
	}
#endif
}

static void handler(int signum)
{
}

void afb_debug_wait(const char *key)
{
	struct sigaction sa, psa;
	sigset_t ss, oss;

	key = key ?: "NULL";
	NOTICE("DEBUG WAIT before %s", key);
	sigfillset(&ss);
	sigdelset(&ss, SIGINT);
	sigprocmask(SIG_SETMASK, &ss, &oss);
	sigemptyset(&ss);
	sigaddset(&ss, SIGINT);
	memset(&sa, 0, sizeof sa);
	sa.sa_handler = handler;
	sigaction(SIGINT, &sa, &psa);
	indicate(key);
	sigwaitinfo(&ss, NULL);
	sigaction(SIGINT, &psa, NULL);
	indicate(NULL);
	sigprocmask(SIG_SETMASK, &oss, NULL);
	NOTICE("DEBUG WAIT after %s", key);
#if !defined(NO_CALL_PERSONALITY)
	personality((unsigned long)-1L);
#endif
}

void afb_debug_break(const char *key)
{
	struct sigaction sa, psa;

	key = key ?: "NULL";
	NOTICE("DEBUG BREAK before %s", key);
	memset(&sa, 0, sizeof sa);
	sa.sa_handler = handler;
	sigaction(SIGINT, &sa, &psa);
	raise(SIGINT);
	sigaction(SIGINT, &psa, NULL);
	NOTICE("DEBUG BREAK after %s", key);
}

void afb_debug(const char *key)
{
	if (has_key(key, secure_getenv(key_env_wait)))
		afb_debug_wait(key);
	if (has_key(key, secure_getenv(key_env_break)))
		afb_debug_break(key);
}

#endif

