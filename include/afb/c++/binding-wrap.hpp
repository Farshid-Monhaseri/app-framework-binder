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

#include <cstddef>
#include <cstdlib>
#include <cstdarg>
#include <functional>

/* ensure version */
#ifndef AFB_BINDING_VERSION
# define AFB_BINDING_VERSION   3
#endif

/* check the version */
#if AFB_BINDING_VERSION < 3
# error "AFB_BINDING_VERSION must be at least 3"
#endif

/* get C definitions of bindings */
extern "C" {
#include <afb/afb-binding.h>
}

namespace afb {
/*************************************************************************/
/* pre-declaration of classes                                            */
/*************************************************************************/

class arg;
class event;
class req;

/*************************************************************************/
/* declaration of functions                                              */
/*************************************************************************/

int broadcast_event(const char *name, json_object *object = nullptr);

event make_event(const char *name);

void verbose(int level, const char *file, int line, const char * func, const char *fmt, va_list args);

void verbose(int level, const char *file, int line, const char * func, const char *fmt, ...);

int rootdir_get_fd();

int rootdir_open_locale_fd(const char *filename, int flags, const char *locale = nullptr);

int queue_job(void (*callback)(int signum, void *arg), void *argument, void *group, int timeout);

int require_api(const char *apiname, bool initialized = true);

int add_alias(const char *apiname, const char *aliasname);

int verbosity();

bool wants_errors();
bool wants_warnings();
bool wants_notices();
bool wants_infos();
bool wants_debugs();

void call(const char *api, const char *verb, struct json_object *args, void (*callback)(void*closure, int iserror, struct json_object *result, afb_api_t api), void *closure);

template <class T> void call(const char *api, const char *verb, struct json_object *args, void (*callback)(T*closure, int iserror, struct json_object *result, afb_api_t api), T *closure);

bool callsync(const char *api, const char *verb, struct json_object *args, struct json_object *&result);

/*************************************************************************/
/* effective declaration of classes                                      */
/*************************************************************************/

/* events */
class event
{
	afb_event_t event_;
public:
	event();
	event(afb_event_t e);
	event(const event &other);
	event(event &&other);
	~event();
	event &operator=(const event &other);
	event &operator=(event &&other);

	operator afb_event_t() const;
	afb_event_t operator->() const;

	operator bool() const;
	bool is_valid() const;

	int broadcast(json_object *object) const;
	int push(json_object *object) const;

	void unref();
	void addref();
	const char *name() const;
};

/* args */
class arg
{
	struct afb_arg arg_;
public:
	arg() = delete;
	arg(const struct afb_arg &a);
	arg(const arg &other);
	arg &operator=(const arg &other);

	operator const struct afb_arg&() const;

	bool has_name() const;
	bool has_value() const;
	bool has_path() const;

	const char *name() const;
	const char *value() const;
	const char *path() const;
};

/* req(uest) */
class req
{
	afb_req_t req_;

public:
	req() = delete;
	req(afb_req_t r);
	req(const req &other);
	req &operator=(const req &other);

	operator afb_req_t() const;
	afb_req_t operator->() const;

	operator bool() const;
	bool is_valid() const;

	arg get(const char *name) const;

	const char *value(const char *name) const;

	const char *path(const char *name) const;

	json_object *json() const;

	void reply(json_object *obj = nullptr, const char *error = nullptr, const char *info = nullptr) const;
	void replyf(json_object *obj, const char *error, const char *info, ...) const;
	void replyv(json_object *obj, const char *error, const char *info, va_list args) const;

	void success(json_object *obj = nullptr, const char *info = nullptr) const;
	void successf(json_object *obj, const char *info, ...) const;
	void successv(json_object *obj, const char *info, va_list args) const;

	void fail(const char *error = "failed", const char *info = nullptr) const;
	void failf(const char *error, const char *info, ...) const;
	void failv(const char *error, const char *info, va_list args) const;

	template < class T > T *context() const;

	void addref() const;

	void unref() const;

	void session_close() const;

	bool session_set_LOA(unsigned level) const;

	bool subscribe(const event &event) const;

	bool unsubscribe(const event &event) const;

	void subcall(const char *api, const char *verb, json_object *args, void (*callback)(void *closure, int iserror, json_object *result, afb_req_t req), void *closure) const;
	template <class T> void subcall(const char *api, const char *verb, json_object *args, void (*callback)(T *closure, int iserror, json_object *result, afb_req_t req), T *closure) const;

	bool subcallsync(const char *api, const char *verb, json_object *args, struct json_object *&result) const;

	void subcall(const char *api, const char *verb, json_object *args, int flags, void (*callback)(void *closure, json_object *object, const char *error, const char *info, afb_req_t req), void *closure) const;

	template <class T> void subcall(const char *api, const char *verb, json_object *args, int flags, void (*callback)(T *closure, json_object *object, const char *error, const char *info, afb_req_t req), T *closure) const;

	bool subcallsync(const char *api, const char *verb, json_object *args, int flags, struct json_object *&object, char *&error, char *&info) const;

	void verbose(int level, const char *file, int line, const char * func, const char *fmt, va_list args) const;

	void verbose(int level, const char *file, int line, const char * func, const char *fmt, ...) const;

	bool has_permission(const char *permission) const;

	char *get_application_id() const;

	int get_uid() const;

	json_object *get_client_info() const;
};

/*************************************************************************/
/* effective declaration of classes                                      */
/*************************************************************************/
/////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////


/*************************************************************************/
/* effective declaration of classes                                      */
/*************************************************************************/

/* events */
inline event::event() : event_{nullptr} { }
inline event::event(afb_event_t e) : event_{e} { }
inline event::event(event &&other) : event_{other.event_} { other.event_ = nullptr; }
inline event::event(const event &other) : event_{other.event_} { addref(); }
inline event::~event() { unref(); }
inline event &event::operator=(const event &other) { event_ = other.event_; return *this; }
inline event &event::operator=(event &&other) { event_ = other.event_; other.event_ = nullptr; return *this;}

inline event::operator afb_event_t() const { return event_; }
inline afb_event_t event::operator->() const { return event_; }

inline event::operator bool() const { return is_valid(); }
inline bool event::is_valid() const { return afb_event_is_valid(event_); }

inline int event::broadcast(json_object *object) const { return afb_event_broadcast(event_, object); }
inline int event::push(json_object *object) const { return afb_event_push(event_, object); }

inline void event::unref() { if (event_) { afb_event_unref(event_); } event_ = nullptr; }
inline void event::addref() { afb_event_addref(event_); }
inline const char *event::name() const { return afb_event_name(event_); }

/* args */
inline arg::arg(const struct afb_arg &a) : arg_(a) {}
inline arg::arg(const arg &other) : arg_(other.arg_) {}
inline arg &arg::operator=(const arg &other) { arg_ = other.arg_; return *this; }

inline arg::operator const struct afb_arg&() const { return arg_; }

inline bool arg::has_name() const { return !!arg_.name; }
inline bool arg::has_value() const { return !!arg_.value; }
inline bool arg::has_path() const { return !!arg_.path; }

inline const char *arg::name() const { return arg_.name; }
inline const char *arg::value() const { return arg_.value; }
inline const char *arg::path() const { return arg_.path; }

/* req(uests)s */


inline req::req(afb_req_t r) : req_(r) {}
inline req::req(const req &other) : req_(other.req_) {}
inline req &req::operator=(const req &other) { req_ = other.req_; return *this; }

inline req::operator afb_req_t() const { return req_; }
inline afb_req_t req::operator->() const { return req_; }

inline req::operator bool() const { return is_valid(); }
inline bool req::is_valid() const { return afb_req_is_valid(req_); }

inline arg req::get(const char *name) const { return arg(afb_req_get(req_, name)); }

inline const char *req::value(const char *name) const { return afb_req_value(req_, name); }

inline const char *req::path(const char *name) const { return afb_req_path(req_, name); }

inline json_object *req::json() const { return afb_req_json(req_); }

inline void req::reply(json_object *obj, const char *error, const char *info) const { afb_req_reply(req_, obj, error, info); }
inline void req::replyv(json_object *obj, const char *error, const char *info, va_list args) const { afb_req_reply_v(req_, obj, error, info, args); }
inline void req::replyf(json_object *obj, const char *error, const char *info, ...) const
{
	va_list args;
	va_start(args, info);
	replyv(obj, error, info, args);
	va_end(args);
}

inline void req::success(json_object *obj, const char *info) const { reply(obj, nullptr, info); }
inline void req::successv(json_object *obj, const char *info, va_list args) const { replyv(obj, nullptr, info, args); }
inline void req::successf(json_object *obj, const char *info, ...) const
{
	va_list args;
	va_start(args, info);
	successv(obj, info, args);
	va_end(args);
}

inline void req::fail(const char *error, const char *info) const { reply(nullptr, error, info); }
inline void req::failv(const char *error, const char *info, va_list args) const { replyv(nullptr, error, info, args); }
inline void req::failf(const char *error, const char *info, ...) const
{
	va_list args;
	va_start(args, info);
	failv(error, info, args);
	va_end(args);
}

template < class T >
inline T *req::context() const
{
	T* (*creater)(void*) = [](){return new T();};
	void (*freer)(T*) = [](T*t){delete t;};
	return reinterpret_cast<T*>(afb_req_context(req_, 0,
			reinterpret_cast<void *(*)(void*)>(creater),
			reinterpret_cast<void (*)(void*)>(freer), nullptr));
}

inline void req::addref() const { afb_req_addref(req_); }

inline void req::unref() const { afb_req_unref(req_); }

inline void req::session_close() const { afb_req_session_close(req_); }

inline bool req::session_set_LOA(unsigned level) const { return !afb_req_session_set_LOA(req_, level); }

inline bool req::subscribe(const event &event) const { return !afb_req_subscribe(req_, event); }

inline bool req::unsubscribe(const event &event) const { return !afb_req_unsubscribe(req_, event); }

inline void req::subcall(const char *api, const char *verb, json_object *args, int flags, void (*callback)(void *closure, json_object *result, const char *error, const char *info, afb_req_t req), void *closure) const
{
	afb_req_subcall(req_, api, verb, args, flags, callback, closure);
}

template <class T>
inline void req::subcall(const char *api, const char *verb, json_object *args, int flags, void (*callback)(T *closure, json_object *result, const char *error, const char *info, afb_req_t req), T *closure) const
{
	subcall(api, verb, args, flags, reinterpret_cast<void(*)(void*,json_object*,const char*,const char*,afb_req_t)>(callback), reinterpret_cast<void*>(closure));
}

inline bool req::subcallsync(const char *api, const char *verb, json_object *args, int flags, struct json_object *&object, char *&error, char *&info) const
{
	return !afb_req_subcall_sync(req_, api, verb, args, flags, &object, &error, &info);
}

inline void req::subcall(const char *api, const char *verb, json_object *args, void (*callback)(void *closure, int iserror, json_object *result, afb_req_t req), void *closure) const
{
	afb_req_subcall_legacy(req_, api, verb, args, callback, closure);
}

template <class T>
inline void req::subcall(const char *api, const char *verb, json_object *args, void (*callback)(T *closure, int iserror, json_object *result, afb_req_t req), T *closure) const
{
	subcall(api, verb, args, reinterpret_cast<void(*)(void*,int,json_object*,afb_req_t)>(callback), reinterpret_cast<void*>(closure));
}

inline bool req::subcallsync(const char *api, const char *verb, json_object *args, struct json_object *&result) const
{
	return !afb_req_subcall_sync_legacy(req_, api, verb, args, &result);
}

inline void req::verbose(int level, const char *file, int line, const char * func, const char *fmt, va_list args) const
{
	afb_req_verbose(req_, level, file, line, func, fmt, args);
}

inline void req::verbose(int level, const char *file, int line, const char * func, const char *fmt, ...) const
{
	va_list args;
	va_start(args, fmt);
	afb_req_verbose(req_, level, file, line, func, fmt, args);
	va_end(args);
}

inline bool req::has_permission(const char *permission) const
{
	return bool(afb_req_has_permission(req_, permission));
}

inline char *req::get_application_id() const
{
	return afb_req_get_application_id(req_);
}

inline int req::get_uid() const
{
	return afb_req_get_uid(req_);
}

inline json_object *req::get_client_info() const
{
	return afb_req_get_client_info(req_);
}

/* commons */
inline int broadcast_event(const char *name, json_object *object)
	{ return afb_daemon_broadcast_event(name, object); }

inline event make_event(const char *name)
	{ return afb_daemon_make_event(name); }

inline void verbose(int level, const char *file, int line, const char * func, const char *fmt, va_list args)
	{ afb_daemon_verbose(level, file, line, func, fmt, args); }

inline void verbose(int level, const char *file, int line, const char * func, const char *fmt, ...)
	{ va_list args; va_start(args, fmt); verbose(level, file, line, func, fmt, args); va_end(args); }

inline int rootdir_get_fd()
	{ return afb_daemon_rootdir_get_fd(); }

inline int rootdir_open_locale_fd(const char *filename, int flags, const char *locale)
	{ return afb_daemon_rootdir_open_locale(filename, flags, locale); }

inline int queue_job(void (*callback)(int signum, void *arg), void *argument, void *group, int timeout)
	{ return afb_daemon_queue_job(callback, argument, group, timeout); }

inline int require_api(const char *apiname, bool initialized)
	{ return afb_daemon_require_api(apiname, int(initialized)); }

inline int add_alias(const char *apiname, const char *aliasname)
	{ return afb_daemon_add_alias(apiname, aliasname); }

inline int logmask()
	{ return afb_get_logmask(); }

inline bool wants_errors()
	{ return AFB_SYSLOG_MASK_WANT_ERROR(logmask()); }

inline bool wants_warnings()
	{ return AFB_SYSLOG_MASK_WANT_WARNING(logmask()); }

inline bool wants_notices()
	{ return AFB_SYSLOG_MASK_WANT_NOTICE(logmask()); }

inline bool wants_infos()
	{ return AFB_SYSLOG_MASK_WANT_INFO(logmask()); }

inline bool wants_debugs()
	{ return AFB_SYSLOG_MASK_WANT_DEBUG(logmask()); }

inline void call(const char *api, const char *verb, struct json_object *args, void (*callback)(void*closure, struct json_object *result, const char *error, const char *info, afb_api_t api), void *closure)
{
	afb_service_call(api, verb, args, callback, closure);
}

template <class T>
inline void call(const char *api, const char *verb, struct json_object *args, void (*callback)(T*closure, struct json_object *result, const char *error, const char *info, afb_api_t api), T *closure)
{
	afb_service_call(api, verb, args, reinterpret_cast<void(*)(void*,json_object*,const char*, const char*,afb_api_t)>(callback), reinterpret_cast<void*>(closure));
}

inline bool callsync(const char *api, const char *verb, struct json_object *args, struct json_object *&result, char *&error, char *&info)
{
	return !!afb_service_call_sync(api, verb, args, &result, &error, &info);
}

/*************************************************************************/
/* declaration of the binding's authorization s                          */
/*************************************************************************/

constexpr afb_auth auth_no()
{
	afb_auth r = { afb_auth_No, 0, 0};
	r.type = afb_auth_No;
	return r;
}

constexpr afb_auth auth_yes()
{
	afb_auth r = { afb_auth_No, 0, 0};
	r.type = afb_auth_Yes;
	return r;
}

constexpr afb_auth auth_token()
{
	afb_auth r = { afb_auth_No, 0, 0};
	r.type = afb_auth_Token;
	return r;
}

constexpr afb_auth auth_LOA(unsigned loa)
{
	afb_auth r = { afb_auth_No, 0, 0};
	r.type = afb_auth_LOA;
	r.loa = loa;
	return r;
}

constexpr afb_auth auth_permission(const char *permission)
{
	afb_auth r = { afb_auth_No, 0, 0};
	r.type = afb_auth_Permission;
	r.text = permission;
	return r;
}

constexpr afb_auth auth_not(const afb_auth *other)
{
	afb_auth r = { afb_auth_No, 0, 0};
	r.type = afb_auth_Not;
	r.first = other;
	return r;
}

constexpr afb_auth auth_not(const afb_auth &other)
{
	return auth_not(&other);
}

constexpr afb_auth auth_or(const afb_auth *first, const afb_auth *next)
{
	afb_auth r = { afb_auth_No, 0, 0};
	r.type = afb_auth_Or;
	r.first = first;
	r.next = next;
	return r;
}

constexpr afb_auth auth_or(const afb_auth &first, const afb_auth &next)
{
	return auth_or(&first, &next);
}

constexpr afb_auth auth_and(const afb_auth *first, const afb_auth *next)
{
	afb_auth r = { afb_auth_No, 0, 0};
	r.type = afb_auth_And;
	r.first = first;
	r.next = next;
	return r;
}

constexpr afb_auth auth_and(const afb_auth &first, const afb_auth &next)
{
	return auth_and(&first, &next);
}

constexpr afb_verb_t verb(
	const char *name,
	void (*callback)(afb_req_t),
	const char *info = nullptr,
	uint16_t session = 0,
	const afb_auth *auth = nullptr,
	bool glob = false,
	void *vcbdata = nullptr
)
{
	afb_verb_t r = { 0, 0, 0, 0, 0, 0, 0 };
	r.verb = name;
	r.callback = callback;
	r.info = info;
	r.session = session;
	r.auth = auth;
	r.glob = (unsigned)glob;
	r.vcbdata = vcbdata;
	return r;
}

void __attribute__((weak)) __afb__verb__cb__for__global__(afb_req_t r)
{
	void *vcbdata;
	void (*callback)(req);

	vcbdata = afb_req_get_vcbdata(r);
	callback = reinterpret_cast<void(*)(req)>(vcbdata);
	callback(req(r));
}

constexpr afb_verb_t verb(
	const char *name,
	void (&callback)(req),
	const char *info = nullptr,
	uint16_t session = 0,
	const afb_auth *auth = nullptr,
	bool glob = false,
	void *vcbdata = nullptr
)
{
	return verb(
		name,
		__afb__verb__cb__for__global__,
		info,
		session,
		auth,
		glob,
		(void*)(&callback)
	);
}

constexpr afb_verb_t verbend()
{
	afb_verb_t r = verb(nullptr, nullptr);
	return r;
}

constexpr afb_binding_t binding(
	const char *name,
	const afb_verb_t *verbs,
	const char *info = nullptr,
	int (*init)(afb_api_t) = nullptr,
	const char *specification = nullptr,
	void (*onevent)(afb_api_t, const char*, struct json_object*) = nullptr,
	bool noconcurrency = false,
	int (*preinit)(afb_api_t) = nullptr,
	void *userdata = nullptr
)
{
	afb_binding_t r = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	r.api = name;
	r.specification = specification;
	r.info = info;
	r.verbs = verbs;
	r.preinit = preinit;
	r.init = init;
	r.onevent = onevent;
	r.noconcurrency = noconcurrency ? 1 : 0;
	r.userdata = userdata;
	return r;
};

/*************************************************************************/
/***                         E N D                                     ***/
/*************************************************************************/
}
