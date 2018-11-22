/*
 * Copyright (C) 2018 "IoT.bzh"
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

struct globset_handler
{
	/* callback of the handler */
	void *callback;

	/* closure of the handler */
	void *closure;

	/* the pattern */
	char pattern[1];
};

struct globset;

extern struct globset *globset_create();

extern void globset_destroy(struct globset *set);

extern int globset_add(
			struct globset *set,
			const char *pattern,
			void *callback,
			void *closure);

extern int globset_del(
			struct globset *set,
			const char *pattern,
			void **closure);

extern struct globset_handler *globset_search(
			struct globset *set,
			const char *pattern);

extern const struct globset_handler *globset_match(
			struct globset *set,
			const char *text);

