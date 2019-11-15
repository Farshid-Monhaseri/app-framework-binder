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

#define AFB_SESSION_TIMEOUT_INFINITE  -1
#define AFB_SESSION_TIMEOUT_DEFAULT   -2
#define AFB_SESSION_TIMEOUT_IS_VALID(x) ((x) >= AFB_SESSION_TIMEOUT_DEFAULT)

extern int afb_session_init(int max_session_count, int timeout, const char *initok);
extern void afb_session_purge();
extern const char *afb_session_initial_token();
extern void afb_session_foreach(void (*callback)(void *closure, struct afb_session *session), void *closure);

extern struct afb_session *afb_session_create (int timeout);
extern struct afb_session *afb_session_search (const char *uuid);
extern struct afb_session *afb_session_get (const char *uuid, int timeout, int *created);
extern const char *afb_session_uuid (struct afb_session *session);
extern uint16_t afb_session_id (struct afb_session *session);

extern struct afb_session *afb_session_addref(struct afb_session *session);
extern void afb_session_unref(struct afb_session *session);
extern void afb_session_set_autoclose(struct afb_session *session, int autoclose);

extern void afb_session_close(struct afb_session *session);
extern int afb_session_is_closed (struct afb_session *session);

extern int afb_session_timeout(struct afb_session *session);
extern int afb_session_what_remains(struct afb_session *session);

extern void *afb_session_get_cookie(struct afb_session *session, const void *key);
extern void *afb_session_cookie(struct afb_session *session, const void *key, void *(*makecb)(void *closure), void (*freecb)(void *item), void *closure, int replace);
extern int afb_session_set_cookie(struct afb_session *session, const void *key, void *value, void (*freecb)(void*));

extern int afb_session_set_language(struct afb_session *session, const char *lang);
extern const char *afb_session_get_language(struct afb_session *session, const char *lang);
