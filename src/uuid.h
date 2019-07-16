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

#define UUID_BINARY_LENGTH   16
#define UUID_STRINGZ_LENGTH  37

typedef unsigned char uuid_binary_t[UUID_BINARY_LENGTH];
typedef char uuid_stringz_t[UUID_STRINGZ_LENGTH];

void uuid_new_binary(uuid_binary_t uuid);
void uuid_new_stringz(uuid_stringz_t uuid);
