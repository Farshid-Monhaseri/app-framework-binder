/*
 * Copyright (C) 2015-2020 "IoT.bzh"
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

#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/prctl.h>

#include "process-name.h"

int process_name_set_name(const char *name)
{
	return prctl(PR_SET_NAME, name);
}

int process_name_replace_cmdline(char **argv, const char *name)
{
	char *beg, *end, **av, c;

	/* update the command line */
	av = argv;
	if (!av) {
		errno = EINVAL;
		return -1; /* no command line update required */
	}

	/* longest prefix */
	end = beg = *av;
	while (*av)
		if (*av++ == end)
			while(*end++)
				;
	if (end == beg) {
		errno = EINVAL;
		return -1; /* nothing to change */
	}

	/* patch the command line */
	av = &argv[1];
	end--;
	while (beg != end && (c = *name++)) {
		if (c != ' ' || !*av)
			*beg++ = c;
		else {
			*beg++ = 0;
			*av++ = beg;
		}
	}
	/* terminate last arg */
	if (beg != end)
		*beg++ = 0;
	/* update remaining args (for keeping initial length correct) */
	while (*av)
		*av++ = beg;
	/* fulfill last arg with spaces */
	while (beg != end)
		*beg++ = ' ';
	*beg = 0;

	return 0;
}

