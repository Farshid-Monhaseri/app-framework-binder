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

#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include <uuid/uuid.h>

#include "uuid.h"

/**
 * generate a new fresh 'uuid'
 */
void uuid_new_binary(uuid_binary_t uuid)
{
#if defined(USE_UUID_GENERATE)
	uuid_generate(uuid);
#else
	struct timespec ts;
	static uint16_t pid;
	static uint16_t counter;
	static char state[32];
	static struct random_data rdata;

	int32_t x;
	clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
	if (pid == 0) {
		pid = (uint16_t)getpid();
		counter = (uint16_t)(ts.tv_nsec >> 8);
		rdata.state = NULL;
		initstate_r((((unsigned)pid) << 16) + ((unsigned)counter),
					state, sizeof state, &rdata);
	}
	ts.tv_nsec ^= (long)ts.tv_sec;
	if (++counter == 0)
		counter = 1;

	uuid[0] = (char)(ts.tv_nsec >> 24);
	uuid[1] = (char)(ts.tv_nsec >> 16);
	uuid[2] = (char)(ts.tv_nsec >> 8);
	uuid[3] = (char)(ts.tv_nsec);

	uuid[4] = (char)(pid >> 8);
	uuid[5] = (char)(pid);

	random_r(&rdata, &x);
	uuid[6] = (char)(((x >> 16) & 0x0f) | 0x40); /* pseudo-random version */
	uuid[7] = (char)(x >> 8);

	random_r(&rdata, &x);
	uuid[8] = (char)(((x >> 16) & 0x3f) | 0x80); /* variant RFC4122 */
	uuid[9] = (char)(x >> 8);

	random_r(&rdata, &x);
	uuid[10] = (char)(x >> 16);
	uuid[11] = (char)(x >> 8);

	random_r(&rdata, &x);
	uuid[12] = (char)(x >> 16);
	uuid[13] = (char)(x >> 8);

	uuid[14] = (char)(counter >> 8);
	uuid[15] = (char)(counter);
#endif
}

void uuid_new_stringz(uuid_stringz_t uuid)
{
	uuid_t newuuid;
	uuid_new_binary(newuuid);
	uuid_unparse_lower(newuuid, uuid);
}
