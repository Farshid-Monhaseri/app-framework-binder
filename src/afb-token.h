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

struct afb_token;

extern int afb_token_get(struct afb_token **token, const char *tokenstring);
extern struct afb_token *afb_token_addref(struct afb_token *token);
extern void afb_token_unref(struct afb_token *token);

extern const char *afb_token_string(const struct afb_token *token);
extern uint16_t afb_token_id(const struct afb_token *token);
