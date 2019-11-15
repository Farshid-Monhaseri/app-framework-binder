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

#pragma once

struct afb_session;
struct afb_token;

struct afb_context
{
	struct afb_session *session;
	struct afb_token *token;
	const void *api_key;
	struct afb_context *super;
	union {
		unsigned flags;
		struct {
			unsigned created: 1;
			unsigned validated: 1;
			unsigned invalidated: 1;
			unsigned closing: 1;
			unsigned closed: 1;
		};
	};
};

extern void afb_context_init(struct afb_context *context, struct afb_session *session, struct afb_token *token);
extern void afb_context_init_validated(struct afb_context *context, struct afb_session *session);
extern void afb_context_subinit(struct afb_context *context, struct afb_context *super);
extern int afb_context_connect(struct afb_context *context, const char *uuid, struct afb_token *token);
extern int afb_context_connect_validated(struct afb_context *context, const char *uuid);
extern void afb_context_disconnect(struct afb_context *context);
extern const char *afb_context_uuid(struct afb_context *context);

extern void *afb_context_get(struct afb_context *context);
extern int afb_context_set(struct afb_context *context, void *value, void (*free_value)(void*));
extern void *afb_context_make(struct afb_context *context, int replace, void *(*make_value)(void *closure), void (*free_value)(void *item), void *closure);

extern void afb_context_close(struct afb_context *context);
extern int afb_context_check(struct afb_context *context);
extern int afb_context_check_loa(struct afb_context *context, unsigned loa);
extern int afb_context_change_loa(struct afb_context *context, unsigned loa);
extern unsigned afb_context_get_loa(struct afb_context *context);

