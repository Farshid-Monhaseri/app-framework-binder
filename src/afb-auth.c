/*
 * Copyright (C) 2016, 2017 "IoT.bzh"
 * Author "Fulup Ar Foll"
 * Author José Bollo <jose.bollo@iot.bzh>
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

#define _GNU_SOURCE
#define AFB_BINDING_PRAGMA_NO_VERBOSE_MACRO

#include <stdlib.h>

#include <afb/afb-auth.h>

#include "afb-auth.h"
#include "afb-context.h"
#include "afb-xreq.h"
#include "afb-cred.h"
#include "verbose.h"

static int check_permission(const char *permission, struct afb_xreq *xreq);

int afb_auth_check(const struct afb_auth *auth, struct afb_xreq *xreq)
{
	switch (auth->type) {
	default:
	case afb_auth_No:
		return 0;

	case afb_auth_Token:
		return afb_context_check(&xreq->context);

	case afb_auth_LOA:
		return afb_context_check_loa(&xreq->context, auth->loa);

	case afb_auth_Permission:
		return xreq->cred && auth->text && check_permission(auth->text, xreq);

	case afb_auth_Or:
		return afb_auth_check(auth->first, xreq) || afb_auth_check(auth->next, xreq);

	case afb_auth_And:
		return afb_auth_check(auth->first, xreq) && afb_auth_check(auth->next, xreq);

	case afb_auth_Not:
		return !afb_auth_check(auth->first, xreq);

	case afb_auth_Yes:
		return 1;
	}
}

/*********************************************************************************/
#ifdef BACKEND_PERMISSION_IS_CYNARA

#include <pthread.h>
#include <cynara-client.h>

static cynara *handle;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

static int check_permission(const char *permission, struct afb_xreq *xreq)
{
	int rc;

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
	rc = cynara_check(handle, xreq->cred->label, afb_context_uuid(&xreq->context), xreq->cred->user, permission);

	pthread_mutex_unlock(&mutex);
	return rc == CYNARA_API_ACCESS_ALLOWED;
}

/*********************************************************************************/
#else
static int check_permission(const char *permission, struct afb_xreq *xreq)
{
	WARNING("Granting permission %s by default of backend", permission);
	return 1;
}
#endif

