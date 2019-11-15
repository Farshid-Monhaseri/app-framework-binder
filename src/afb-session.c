/*
 * Copyright (C) 2015-2019 "IoT.bzh"
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
#include <stdio.h>
#include <time.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>
#include <string.h>
#include <errno.h>

#include "afb-session.h"
#include "afb-hook.h"
#include "afb-token.h"
#include "verbose.h"
#include "pearson.h"
#include "uuid.h"

#define SESSION_COUNT_MIN 5
#define SESSION_COUNT_MAX 1000

/*
 * Handling of  cookies.
 * Cookies are stored by session.
 * The cookie count COOKIECOUNT must be a power of 2, possible values: 1, 2, 4, 8, 16, 32, 64, ...
 * For low memory profile, small values are better, 1 is possible.
 */
#define COOKIECOUNT	8
#define COOKIEMASK	(COOKIECOUNT - 1)

#define _MAXEXP_	((time_t)(~(time_t)0))
#define _MAXEXP2_	((time_t)((((unsigned long long)_MAXEXP_) >> 1)))
#define MAX_EXPIRATION	(_MAXEXP_ >= 0 ? _MAXEXP_ : _MAXEXP2_)
#define NOW		(time_now())

/**
 * structure for a cookie added to sessions
 */
struct cookie
{
	struct cookie *next;	/**< link to next cookie */
	const void *key;	/**< pointer key */
	void *value;		/**< value */
	void (*freecb)(void*);	/**< function to call when session is closed */
};

/**
 * structure for session
 */
struct afb_session
{
	struct afb_session *next; /**< link to the next */
	uint16_t refcount;      /**< count of reference to the session */
	uint16_t id;		/**< local id of the session */
	int timeout;            /**< timeout of the session */
	time_t expiration;	/**< expiration time of the session */
	pthread_mutex_t mutex;  /**< mutex of the session */
	struct cookie *cookies[COOKIECOUNT]; /**< cookies of the session */
	char *lang;		/**< current language setting for the session */
	uint8_t closed: 1;      /**< is the session closed ? */
	uint8_t autoclose: 1;   /**< close the session when unreferenced */
	uint8_t notinset: 1;	/**< session removed from the set of sessions */
	uint8_t hash;		/**< hash value of the uuid */
	uuid_stringz_t uuid;	/**< identification of client session */
};

/**
 * structure for managing sessions
 */
static struct {
	uint16_t count;		/**< current number of sessions */
	uint16_t max;		/**< maximum count of sessions */
	uint16_t genid;		/**< for generating ids */
	int timeout;		/**< common initial timeout */
	struct afb_session *first; /**< sessions */
	struct afb_token *initok;/**< common initial token */
	pthread_mutex_t mutex;	/**< declare a mutex to protect hash table */
} sessions = {
	.count = 0,
	.max = 10,
	.genid = 1,
	.timeout = 3600,
	.first = 0,
	.initok = 0,
	.mutex = PTHREAD_MUTEX_INITIALIZER
};

/**
 * Get the actual raw time
 */
static inline time_t time_now()
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
	return ts.tv_sec;
}

/* lock the set of sessions for exclusive access */
static inline void sessionset_lock()
{
	pthread_mutex_lock(&sessions.mutex);
}

/* unlock the set of sessions of exclusive access */
static inline void sessionset_unlock()
{
	pthread_mutex_unlock(&sessions.mutex);
}

/*
 * search within the set of sessions the session of 'uuid'.
 * 'hashidx' is the precomputed hash for 'uuid'
 * return the session or NULL
 */
static struct afb_session *sessionset_search(const char *uuid, uint8_t hashidx)
{
	struct afb_session *session;

	session = sessions.first;
	while (session && hashidx != session->hash && strcmp(uuid, session->uuid))
		session = session->next;

	return session;
}

/*
 * search within the set of sessions the session of 'id'.
 * return the session or NULL
 */
static struct afb_session *sessionset_search_id(uint16_t id)
{
	struct afb_session *session;

	session = sessions.first;
	while (session && id != session->id)
		session = session->next;

	return session;
}

/* add 'session' to the set of sessions */
static int sessionset_add(struct afb_session *session, uint8_t hashidx)
{
	/* check availability */
	if (sessions.max && sessions.count >= sessions.max) {
		errno = EBUSY;
		return -1;
	}

	/* add the session */
	session->next = sessions.first;
	sessions.first = session;
	sessions.count++;
	return 0;
}

/* make a new uuid not used in the set of sessions */
static uint8_t sessionset_make_uuid (uuid_stringz_t uuid)
{
	uint8_t hashidx;

	do {
		uuid_new_stringz(uuid);
		hashidx = pearson4(uuid);
	} while(sessionset_search(uuid, hashidx));
	return hashidx;
}

/* lock the 'session' for exclusive access */
static inline void session_lock(struct afb_session *session)
{
	pthread_mutex_lock(&session->mutex);
}

/* unlock the 'session' of exclusive access */
static inline void session_unlock(struct afb_session *session)
{
	pthread_mutex_unlock(&session->mutex);
}

/* close the 'session' */
static void session_close(struct afb_session *session)
{
	int idx;
	struct cookie *cookie;

	/* close only one time */
	if (!session->closed) {
		/* close it now */
		session->closed = 1;

#if WITH_AFB_HOOK
		/* emit the hook */
		afb_hook_session_close(session);
#endif

		/* release cookies */
		for (idx = 0 ; idx < COOKIECOUNT ; idx++) {
			while ((cookie = session->cookies[idx])) {
				session->cookies[idx] = cookie->next;
				if (cookie->freecb != NULL)
					cookie->freecb(cookie->value);
				free(cookie);
			}
		}
	}
}

/* destroy the 'session' */
static void session_destroy (struct afb_session *session)
{
#if WITH_AFB_HOOK
	afb_hook_session_destroy(session);
#endif
	pthread_mutex_destroy(&session->mutex);
	free(session->lang);
	free(session);
}

/* update expiration of 'session' according to 'now' */
static void session_update_expiration(struct afb_session *session, time_t now)
{
	time_t expiration;

	/* compute expiration */
	expiration = now + afb_session_timeout(session);
	if (expiration < 0)
		expiration = MAX_EXPIRATION;

	/* record the expiration */
	session->expiration = expiration;
}

/*
 * Add a new session with the 'uuid' (of 'hashidx')
 * and the 'timeout' starting from 'now'.
 * Add it to the set of sessions
 * Return the created session
 */
static struct afb_session *session_add(const char *uuid, int timeout, time_t now, uint8_t hashidx)
{
	struct afb_session *session;

	/* check arguments */
	if (!AFB_SESSION_TIMEOUT_IS_VALID(timeout)
	 || (uuid && strlen(uuid) >= sizeof session->uuid)) {
		errno = EINVAL;
		return NULL;
	}

	/* allocates a new one */
	session = calloc(1, sizeof *session);
	if (session == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	/* initialize */
	pthread_mutex_init(&session->mutex, NULL);
	session->refcount = 1;
	strcpy(session->uuid, uuid);
	session->timeout = timeout;
	session_update_expiration(session, now);
	session->id = ++sessions.genid;
	while (session->id == 0 || sessionset_search_id(session->id) != NULL)
		session->id = ++sessions.genid;

	/* add */
	if (sessionset_add(session, hashidx)) {
		free(session);
		return NULL;
	}

#if WITH_AFB_HOOK
	afb_hook_session_create(session);
#endif

	return session;
}

/* Remove expired sessions and return current time (now) */
static time_t sessionset_cleanup (int force)
{
	struct afb_session *session, **prv;
	time_t now;

	/* Loop on Sessions Table and remove anything that is older than timeout */
	now = NOW;
	prv = &sessions.first;
	while ((session = *prv)) {
		session_lock(session);
		if (force || session->expiration < now)
			session_close(session);
		if (!session->closed) {
			prv = &session->next;
			session_unlock(session);
		} else {
			*prv = session->next;
			sessions.count--;
			session->notinset = 1;
			if (session->refcount)
				session_unlock(session);
			else
				session_destroy(session);
		}
	}
	return now;
}

/**
 * Initialize the session manager with a 'max_session_count',
 * an initial common 'timeout' and an initial common token 'initok'.
 *
 * @param max_session_count  maximum allowed session count in the same time
 * @param timeout            the initial default timeout of sessions
 * @param initok             the initial default token of sessions
 */
int afb_session_init (int max_session_count, int timeout, const char *initok)
{
	int rc;
	uuid_stringz_t uuid;

	/* check parameters */
	if (initok && strlen(initok) >= sizeof sessions.initok) {
		ERROR("initial token '%s' too long (max length %d)",
			initok, ((int)(sizeof sessions.initok)) - 1);
		errno = EINVAL;
		return -1;
	}

	/* init the sessionset (after cleanup) */
	sessionset_lock();
	sessionset_cleanup(1);
	if (max_session_count > SESSION_COUNT_MAX)
		sessions.max = SESSION_COUNT_MAX;
	else if (max_session_count < SESSION_COUNT_MIN)
		sessions.max = SESSION_COUNT_MIN;
	else
		sessions.max = (uint16_t)max_session_count;
	sessions.timeout = timeout;
	if (initok == NULL) {
		uuid_new_stringz(uuid);
		initok = uuid;
	}
	sessions.initok = 0;
	if (*initok) {
		rc = afb_token_get(&sessions.initok, initok);
		if (rc < 0)
			return rc;
	}
	sessionset_unlock();
	return 0;
}

/**
 * Iterate the sessions and call 'callback' with
 * the 'closure' for each session.
 */
void afb_session_foreach(void (*callback)(void *closure, struct afb_session *session), void *closure)
{
	struct afb_session *session;

	/* Loop on Sessions Table and remove anything that is older than timeout */
	sessionset_lock();
	session = sessions.first;
	while (session) {
		if (!session->closed)
			callback(closure, session);
		session = session->next;
	}
	sessionset_unlock();
}

/**
 * Cleanup the sessionset of its closed or expired sessions
 */
void afb_session_purge()
{
	sessionset_lock();
	sessionset_cleanup(0);
	sessionset_unlock();
}

/**
 * @return the initial token set at initialization
 */
const char *afb_session_initial_token()
{
	return sessions.initok ? afb_token_string(sessions.initok) : "";
}

/* Searchs the session of 'uuid' */
struct afb_session *afb_session_search (const char *uuid)
{
	struct afb_session *session;

	sessionset_lock();
	sessionset_cleanup(0);
	session = sessionset_search(uuid, pearson4(uuid));
	session = afb_session_addref(session);
	sessionset_unlock();
	return session;

}

/**
 * Creates a new session with 'timeout'
 */
struct afb_session *afb_session_create (int timeout)
{
	return afb_session_get(NULL, timeout, NULL);
}

/**
 * Returns the timeout of 'session' in seconds
 */
int afb_session_timeout(struct afb_session *session)
{
	int timeout;

	/* compute timeout */
	timeout = session->timeout;
	if (timeout == AFB_SESSION_TIMEOUT_DEFAULT)
		timeout = sessions.timeout;
	if (timeout < 0)
		timeout = INT_MAX;
	return timeout;
}

/**
 * Returns the second remaining before expiration of 'session'
 */
int afb_session_what_remains(struct afb_session *session)
{
	int diff = (int)(session->expiration - NOW);
	return diff < 0 ? 0 : diff;
}

/* This function will return exiting session or newly created session */
struct afb_session *afb_session_get (const char *uuid, int timeout, int *created)
{
	uuid_stringz_t _uuid_;
	uint8_t hashidx;
	struct afb_session *session;
	time_t now;
	int c;

	/* cleaning */
	sessionset_lock();
	now = sessionset_cleanup(0);

	/* search for an existing one not too old */
	if (!uuid) {
		hashidx = sessionset_make_uuid(_uuid_);
		uuid = _uuid_;
	} else {
		hashidx = pearson4(uuid);
		session = sessionset_search(uuid, hashidx);
		if (session) {
			/* session found */
			afb_session_addref(session);
			c = 0;
			goto end;
		}
	}
	/* create the session */
	session = session_add(uuid, timeout, now, hashidx);
	c = 1;
end:
	sessionset_unlock();
	if (created)
		*created = c;

	return session;
}

/* increase the use count on 'session' (can be NULL) */
struct afb_session *afb_session_addref(struct afb_session *session)
{
	if (session != NULL) {
#if WITH_AFB_HOOK
		afb_hook_session_addref(session);
#endif
		session_lock(session);
		session->refcount++;
		session_unlock(session);
	}
	return session;
}

/* decrease the use count of 'session' (can be NULL) */
void afb_session_unref(struct afb_session *session)
{
	if (session == NULL)
		return;

#if WITH_AFB_HOOK
	afb_hook_session_unref(session);
#endif
	session_lock(session);
	if (!--session->refcount) {
		if (session->autoclose)
			session_close(session);
		if (session->notinset) {
			session_destroy(session);
			return;
		}
	}
	session_unlock(session);
}

/* close 'session' */
void afb_session_close (struct afb_session *session)
{
	session_lock(session);
	session_close(session);
	session_unlock(session);
}

/**
 * Set the 'autoclose' flag of the 'session'
 *
 * A session whose autoclose flag is true will close as
 * soon as it is no more referenced.
 *
 * @param session    the session to set
 * @param autoclose  the value to set
 */
void afb_session_set_autoclose(struct afb_session *session, int autoclose)
{
	session->autoclose = !!autoclose;
}

/* is 'session' closed? */
int afb_session_is_closed (struct afb_session *session)
{
	return session->closed;
}

/* Returns the uuid of 'session' */
const char *afb_session_uuid (struct afb_session *session)
{
	return session->uuid;
}

/* Returns the local id of 'session' */
uint16_t afb_session_id (struct afb_session *session)
{
	return session->id;
}

/**
 * Get the index of the 'key' in the cookies array.
 * @param key the key to scan
 * @return the index of the list for key within cookies
 */
#if COOKIEMASK
static int cookeyidx(const void *key)
{
	intptr_t x = (intptr_t)key;
	unsigned r = (unsigned)((x >> 5) ^ (x >> 15));
	return r & COOKIEMASK;
}
#else
#  define cookeyidx(key) 0
#endif

/**
 * Set, get, replace, remove a cookie of 'key' for the 'session'
 *
 * The behaviour of this function depends on its parameters:
 *
 * @param session	the session
 * @param key		the key of the cookie
 * @param makecb	the creation function or NULL
 * @param freecb	the release function or NULL
 * @param closure	an argument for makecb or the value if makecb==NULL
 * @param replace	a boolean enforcing replacement of the previous value
 *
 * @return the value of the cookie
 *
 * The 'key' is a pointer and compared as pointers.
 *
 * For getting the current value of the cookie:
 *
 *   afb_session_cookie(session, key, NULL, NULL, NULL, 0)
 *
 * For storing the value of the cookie
 *
 *   afb_session_cookie(session, key, NULL, NULL, value, 1)
 */
void *afb_session_cookie(struct afb_session *session, const void *key, void *(*makecb)(void *closure), void (*freecb)(void *item), void *closure, int replace)
{
	int idx;
	void *value;
	struct cookie *cookie, **prv;

	/* get key hashed index */
	idx = cookeyidx(key);

	/* lock session and search for the cookie of 'key' */
	session_lock(session);
	prv = &session->cookies[idx];
	for (;;) {
		cookie = *prv;
		if (!cookie) {
			/* 'key' not found, create value using 'closure' and 'makecb' */
			value = makecb ? makecb(closure) : closure;
			/* store the the only if it has some meaning */
			if (replace || makecb || freecb) {
				cookie = malloc(sizeof *cookie);
				if (!cookie) {
					errno = ENOMEM;
					/* calling freecb if there is no makecb may have issue */
					if (makecb && freecb)
						freecb(value);
					value = NULL;
				} else {
					cookie->key = key;
					cookie->value = value;
					cookie->freecb = freecb;
					cookie->next = NULL;
					*prv = cookie;
				}
			}
			break;
		} else if (cookie->key == key) {
			/* cookie of key found */
			if (!replace)
				/* not replacing, get the value */
				value = cookie->value;
			else {
				/* create value using 'closure' and 'makecb' */
				value = makecb ? makecb(closure) : closure;

				/* free previous value is needed */
				if (cookie->value != value && cookie->freecb)
					cookie->freecb(cookie->value);

				/* if both value and freecb are NULL drop the cookie */
				if (!value && !freecb) {
					*prv = cookie->next;
					free(cookie);
				} else {
					/* store the value and its releaser */
					cookie->value = value;
					cookie->freecb = freecb;
				}
			}
			break;
		} else {
			prv = &(cookie->next);
		}
	}

	/* unlock the session and return the value */
	session_unlock(session);
	return value;
}

/**
 * Get the cookie of 'key' in the 'session'.
 *
 * @param session  the session to search in
 * @param key      the key of the data to retrieve
 *
 * @return the data staored for the key or NULL if the key isn't found
 */
void *afb_session_get_cookie(struct afb_session *session, const void *key)
{
	return afb_session_cookie(session, key, NULL, NULL, NULL, 0);
}

/**
 * Set the cookie of 'key' in the 'session' to the 'value' that can be
 * cleaned using 'freecb' (if not null).
 *
 * @param session  the session to set
 * @param key      the key of the data to store
 * @param value    the value to store at key
 * @param freecb   a function to use when the cookie value is to remove (or null)
 *
 * @return 0 in case of success or -1 in case of error
 */
int afb_session_set_cookie(struct afb_session *session, const void *key, void *value, void (*freecb)(void*))
{
	return -(value != afb_session_cookie(session, key, NULL, freecb, value, 1));
}

/**
 * Set the language attached to the session
 *
 * @param session the session to set
 * @param lang    the language specifiction to set to session
 *
 * @return 0 in case of success or -1 in case of error
 */
int afb_session_set_language(struct afb_session *session, const char *lang)
{
	char *oldl, *newl;

	newl = strdup(lang);
	if (newl == NULL)
		return -1;

	oldl = session->lang;
	session->lang = newl;
	free(oldl);
	return 0;
}

/**
 * Get the language attached to the session
 *
 * @param session the session to query
 * @param lang    a default language specifiction
 *
 * @return the langauage specification to use for session
 */
const char *afb_session_get_language(struct afb_session *session, const char *lang)
{
	return session->lang ?: lang;
}
