/*
 * Copyright (C) 2015-2020 "IoT.bzh"
 * Author "Fulup Ar Foll"
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

#define _GNU_SOURCE

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>

#include "afb-token.h"

/**
 * structure for recording a token
 */
struct afb_token
{
	/** link to the next token of the list */
	struct afb_token *next;

	/** reference of the token */
	uint16_t refcount;

	/** local numeric id of the token */
	uint16_t id;

	/** string value of the token */
	char text[];
};

struct tokenset
{
	struct afb_token *first;
	pthread_mutex_t mutex;
	uint16_t idgen;
};

static struct tokenset tokenset = {
	.first = 0,
	.mutex = PTHREAD_MUTEX_INITIALIZER,
	.idgen = 0
};

static struct afb_token *searchid(uint16_t id)
{
	struct afb_token *r = tokenset.first;
	while (r && r->id != id)
		r = r->next;
	return r;
}

/**
 * Get a token for the given value
 *
 * @param token address to return the pointer to the gotten token
 * @param tokenstring string value of the token to get
 * @return 0 in case of success or a -errno like negative code
 */
int afb_token_get(struct afb_token **token, const char *tokenstring)
{
	int rc;
	struct afb_token *tok;
	size_t length;

	/* get length of the token string */
	length =  + strlen(tokenstring);

	/* concurrency */
	pthread_mutex_lock(&tokenset.mutex);

	/* search the token */
	tok = tokenset.first;
	while (tok && (memcmp(tokenstring, tok->text, length) || tokenstring[length]))
		tok = tok->next;

	/* search done */
	if (tok) {
		/* found */
		tok = afb_token_addref(tok);
		rc = 0;
	} else {
		/* not found, create */
		tok = malloc(length + 1 + sizeof *tok);
		if (!tok)
			/* creation failed */
			rc = -ENOMEM;
		else {
			while(!++tokenset.idgen || searchid(tokenset.idgen));
			tok->next = tokenset.first;
			tokenset.first = tok;
			tok->id = tokenset.idgen;
			tok->refcount = 1;
			memcpy(tok->text, tokenstring, length + 1);
			rc = 0;
		}
	}
	pthread_mutex_unlock(&tokenset.mutex);
	*token = tok;
	return rc;
}

/**
 * Add a reference count to the given token
 *
 * @param token the token to reference
 * @return the token with the reference added
 */
struct afb_token *afb_token_addref(struct afb_token *token)
{
	if (token)
		__atomic_add_fetch(&token->refcount, 1, __ATOMIC_RELAXED);
	return token;
}

/**
 * Remove a reference to the given token and clean the memory if needed
 *
 * @param token the token that is unreferenced
 */
void afb_token_unref(struct afb_token *token)
{
	struct afb_token **pt;
	if (token && !__atomic_sub_fetch(&token->refcount, 1, __ATOMIC_RELAXED)) {
		pthread_mutex_lock(&tokenset.mutex);
		pt = &tokenset.first;
		while (*pt && *pt != token)
			pt = &(*pt)->next;
		if (*pt)
			*pt = token->next;
		pthread_mutex_unlock(&tokenset.mutex);
		free(token);
	}
}

/**
 * Get the string value of the token
 *
 * @param token the token whose string value is queried
 * @return the string value of the token
 */
const char *afb_token_string(const struct afb_token *token)
{
	return token->text;
}

/**
 * Get the "local" numeric id of the token
 *
 * @param token the token whose id is queried
 * @return the numeric id of the token
 */
uint16_t afb_token_id(const struct afb_token *token)
{
	return token->id;
}
