/*
 * Copyright (C) 2015-2020 "IoT.bzh"
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

#include "afb-context.h"
#include "afb-cred.h"
#include "afb-token.h"
#include "afb-session.h"
#include "verbose.h"

/*********************************************************************************/

static inline const char *session_of_context(struct afb_context *context)
{
	return context->token ? afb_token_string(context->token)
                : context->session ? afb_session_uuid(context->session)
                : "";
}

/*********************************************************************************/
#ifdef BACKEND_PERMISSION_IS_CYNARA

#include <pthread.h>
#include <cynara-client.h>

static cynara *handle;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

int afb_perm_check(struct afb_context *context, const char *permission)
{
	int rc;

	if (!context->credentials) {
		/* case of permission for self */
		return 1;
	}
	if (!permission) {
		ERROR("Got a null permission!");
		return 0;
	}

	/* cynara isn't reentrant */
	pthread_mutex_lock(&mutex);

	/* lazy initialisation */
	if (!handle) {
		rc = cynara_initialize(&handle, NULL);
		if (rc != CYNARA_API_SUCCESS) {
			handle = NULL;
			ERROR("cynara initialisation failed with code %d", rc);
			return 0;
		}
	}

	/* query cynara permission */
	rc = cynara_check(handle, context->credentials->label, session_of_context(context), context->credentials->user, permission);

	pthread_mutex_unlock(&mutex);
	return rc == CYNARA_API_ACCESS_ALLOWED;
}
/*********************************************************************************/
#else
int afb_perm_check(struct afb_context *context, const char *permission)
{
	NOTICE("Granting permission %s by default of backend", permission ?: "(null)");
	return !!permission;
}
#endif

void afb_perm_check_async(
	struct afb_context *context,
	const char *permission,
	void (*callback)(void *closure, int status),
	void *closure
)
{
	callback(closure, afb_perm_check(context, permission));
}
