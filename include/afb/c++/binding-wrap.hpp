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

#pragma once

#include <cstddef>
#include <cstdlib>
#include <cstdarg>
#include <functional>
#include <string>

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

class api;
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

/* apis */
class api
{
protected:
	afb_api_t api_;
public:
	using call_cb = void (*)(void *closure, struct json_object *object, const char *error, const char *info, afb_api_t api);
	using queue_cb = void (*)(int signum, void *arg);
	using event_cb = void (*)(void *, const char *, struct json_object *, afb_api_t);
	using preinit_cb = int (*)(void *, afb_api_t);
	using verb_cb = void (*)(afb_req_t req);
	using onevent_cb = void (*)(afb_api_t api, const char *event, struct json_object *object);
	using oninit_cb = int (*)(afb_api_t api);

	api();
	api(afb_api_t a);
	api(const api &other) = delete;
	api(api &&other);
	~api();
	api &operator=(const api &other) = delete;
	api &operator=(api &&other);

	operator afb_api_t() const;
	afb_api_t operator->() const;

	/* General functions */
	const char *name() const;
	void *get_userdata() const;
	void set_userdata(void *value) const;
	int require_api(const char *name, int initialized) const;
	int require_api(const std::string &name, int initialized) const;

	/* Verbosity functions */
	int wants_log_level(int level) const;
	void vverbose(int level, const char *file, int line, const char *func, const char *fmt, va_list args) const;
	void verbose(int level, const char *file, int line, const char *func, const char *fmt, ...) const;

	/* Data retrieval functions */
	int rootdir_get_fd() const;
	int rootdir_open_locale(const char *filename, int flags, const char *locale) const;
	int rootdir_open_locale(const std::string &filename, int flags, const std::string &locale) const;
	struct json_object *settings() const;

	/* Calls and job functions */
	void call(const char *apiname, const char *verb, struct json_object *args, call_cb callback, void *closure) const;
	void call(const std::string &apiname, const std::string &verb, struct json_object *args, call_cb callback, void *closure) const;
	int call_sync(const char *apiname, const char *verb, struct json_object *args, struct json_object **object, char **error, char **info) const;
	int call_sync(const std::string &apiname, const std::string &verb, struct json_object *args, struct json_object **object, std::string &error, std::string &info) const;
	int queue_job(queue_cb callback, void *argument, void *group, int timeout) const;

	/* Event functions */
	int broadcast_event(const char *name, struct json_object *object) const;
	int broadcast_event(const std::string &name, struct json_object *object) const;
	event make_event(const char *name) const;
	event make_event(const std::string &name) const;
	int event_handler_add(const char *pattern, event_cb callback, void *closure) const;
	int event_handler_add(const std::string &pattern, event_cb callback, void *closure) const;
	int event_handler_del(const char *pattern, void **closure) const;
	int event_handler_del(const std::string &pattern, void **closure) const;

	/* Systemd functions */
	struct sd_event *get_event_loop() const;
	struct sd_bus *get_user_bus() const;
	struct sd_bus *get_system_bus() const;

	/* Dynamic api functions */
	api new_api(const char *apiname, const char *info, int noconcurrency, preinit_cb preinit, void *closure) const;
	api new_api(const std::string &apiname, const std::string &info, int noconcurrency, preinit_cb preinit, void *closure) const;
	int set_verbs(const struct afb_verb_v2 *verbs) const;
	int set_verbs(const struct afb_verb_v3 *verbs) const;
	int add_verb(const char *verb, const char *info, verb_cb callback, void *vcbdata, const struct afb_auth *auth, uint32_t session, int glob) const;
	int add_verb(const std::string &verb, const std::string &info, verb_cb callback, void *vcbdata, const struct afb_auth *auth, uint32_t session, int glob) const;
	int del_verb(const char *verb, void **vcbdata) const;
	int del_verb(const std::string &verb, void **vcbdata) const;
	int on_event(onevent_cb onevent) const;
	int on_init(oninit_cb oninit) const;
	int provide_class(const char *name) const;
	int provide_class(const std::string &name) const;
	int require_class(const char *name) const;
	int require_class(const std::string &name) const;
	void seal() const;
	int delete_api() const;
	int add_alias(const char *name, const char *as_name) const;
	int add_alias(const std::string &name, const std::string &as_name) const;
};

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

	template < class T = void >
	class contextclass {

		friend class req;
		afb_req_t req_;
		contextclass(afb_req_t r) : req_(r) {}

	public:
		inline operator T *() const { return get(); }
		inline operator T &() const { return *get(); }
		inline T* get() const {
			return reinterpret_cast<T*>(
				afb_req_context(req_, 0,
					nullptr,
					nullptr,
					nullptr));
		}

		inline void set(T *value, void (*destroyer)(T*) = [](T*t){delete t;}) const {
			afb_req_context(req_, 1,
				nullptr,
				reinterpret_cast<void(*)(void*)>(destroyer),
				reinterpret_cast<void*>(value));
		}

		inline void unset() { set(nullptr); }
		inline void clear() { set(nullptr); }

		inline T *lazy(T *(*allocator)() = []()->T*{return new T();}, void (*destroyer)(T*) = [](T*t){delete t;}) const {
			return reinterpret_cast<T*>(
				afb_req_context(req_, 0,
					[allocator](void*)->T*{return allocator();},
					reinterpret_cast<void(*)(void*)>(destroyer),
					nullptr));
		}

		template <class I>
		inline T *lazy(I *i, T *(*allocator)(I*) = [](I*i)->T*{return new T(i);}, void (*destroyer)(T*) = [](T*t){delete t;}) const {
			return reinterpret_cast<T*>(
				afb_req_context(req_, 0,
					[allocator](void*i)->T*{return allocator(reinterpret_cast<I*>(i));},
					reinterpret_cast<void(*)(void*)>(destroyer),
					reinterpret_cast<void*>(i)));
		}
	};

	template < class T > contextclass<T> context() const { return contextclass<T>(req_); }
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

/* apis */
inline api::api() : api_{nullptr} { }
inline api::api(afb_api_t a) : api_{a} { }
inline api::api(api &&other) : api_{other.api_} { other.api_ = nullptr; }
inline api::~api() { api_ = nullptr; }
inline api &api::operator=(api &&other) { api_ = other.api_; other.api_ = nullptr; return *this;}
inline api::operator afb_api_t() const { return api_; }
inline afb_api_t api::operator->() const { return api_; }
inline const char *api::name() const { return afb_api_name(api_); }
inline void *api::get_userdata() const { return afb_api_get_userdata(api_); }
inline void api::set_userdata(void *value) const { afb_api_set_userdata(api_, value); }
inline int api::require_api(const char *name, int initialized) const { return afb_api_require_api(api_, name, initialized); }
inline int api::require_api(const std::string& name, int initialized) const { return afb_api_require_api(api_, name.c_str(), initialized); }
inline int api::wants_log_level(int level) const { return afb_api_wants_log_level(api_, level); }
inline void api::vverbose(int level, const char *file, int line, const char *func, const char *fmt, va_list args) const { afb_api_vverbose(api_, level, file, line, func, fmt, args); }
inline void api::verbose(int level, const char *file, int line, const char *func, const char *fmt, ...) const
{
	va_list args;
	va_start(args, fmt);
	vverbose(level, file, line, func, fmt, args);
	va_end(args);
}
inline int api::rootdir_get_fd() const { return afb_api_rootdir_get_fd(api_); }
inline int api::rootdir_open_locale(const char *filename, int flags, const char *locale) const { return afb_api_rootdir_open_locale(api_, filename, flags, locale); }
inline int api::rootdir_open_locale(const std::string &filename, int flags, const std::string &locale) const { return afb_api_rootdir_open_locale(api_, filename.c_str(), flags, locale.c_str()); }
inline struct json_object *api::settings() const { return afb_api_settings(api_); }
inline void api::call(const char *apiname, const char *verb, struct json_object *args, call_cb callback, void *closure) const { afb_api_call(api_, apiname, verb, args, callback, closure); }
inline void api::call(const std::string &apiname, const std::string &verb, struct json_object *args, call_cb callback, void *closure) const { afb_api_call(api_, apiname.c_str(), verb.c_str(), args, callback, closure); }
inline int api::call_sync(const char *apiname, const char *verb, struct json_object *args, struct json_object **object, char **error, char **info) const { return afb_api_call_sync(api_, apiname, verb, args, object, error, info); }
inline int api::call_sync(const std::string &apiname, const std::string &verb, struct json_object *args, struct json_object **object, std::string &error, std::string& info) const
{
	char *err, *inf;
	int ret = afb_api_call_sync(api_, apiname.c_str(), verb.c_str(), args, object, &err, &inf);
	error = err;
	info = inf;
	return ret;
}
inline int api::queue_job(queue_cb callback, void *argument, void *group, int timeout) const { return afb_api_queue_job(api_, callback, argument, group, timeout); }
inline int api::broadcast_event(const char *name, struct json_object *object) const { return afb_api_broadcast_event(api_, name, object); }
inline int api::broadcast_event(const std::string &name, struct json_object *object) const { return afb_api_broadcast_event(api_, name.c_str(), object); }
inline event api::make_event(const char *name) const { return event(afb_api_make_event(api_, name)); }
inline event api::make_event(const std::string &name) const { return event(afb_api_make_event(api_, name.c_str())); }
inline int api::event_handler_add(const char *pattern, event_cb callback, void *closure) const { return afb_api_event_handler_add(api_, pattern, callback, closure); }
inline int api::event_handler_add(const std::string &pattern, event_cb callback, void *closure) const { return afb_api_event_handler_add(api_, pattern.c_str(), callback, closure); }
inline int api::event_handler_del(const char *pattern, void **closure) const { return afb_api_event_handler_del(api_, pattern, closure); }
inline int api::event_handler_del(const std::string &pattern, void **closure) const { return afb_api_event_handler_del(api_, pattern.c_str(), closure); }
inline struct sd_event *api::get_event_loop() const { return afb_api_get_event_loop(api_); }
inline struct sd_bus *api::get_user_bus() const { return afb_api_get_user_bus(api_); }
inline struct sd_bus *api::get_system_bus() const { return afb_api_get_system_bus(api_); }
inline api api::new_api(const char *apiname, const char *info, int noconcurrency, preinit_cb preinit, void *closure) const { return api(afb_api_new_api(api_, apiname, info, noconcurrency, preinit, closure)); }
inline api api::new_api(const std::string &apiname, const std::string &info, int noconcurrency, preinit_cb preinit, void *closure) const { return api(afb_api_new_api(api_, apiname.c_str(), info.c_str(), noconcurrency, preinit, closure)); }
inline int api::set_verbs(const struct afb_verb_v2 *verbs) const { return afb_api_set_verbs_v2(api_, verbs); }
inline int api::set_verbs(const struct afb_verb_v3 *verbs) const { return afb_api_set_verbs_v3(api_, verbs); }
inline int api::add_verb(const char *verb, const char *info, verb_cb callback, void *vcbdata, const struct afb_auth *auth, uint32_t session, int glob) const { return afb_api_add_verb(api_, verb, info, callback, vcbdata, auth, session, glob); }
inline int api::add_verb(const std::string &verb, const std::string &info, verb_cb callback, void *vcbdata, const struct afb_auth *auth, uint32_t session, int glob) const { return afb_api_add_verb(api_, verb.c_str(), info.c_str(), callback, vcbdata, auth, session, glob); }
inline int api::del_verb(const char *verb, void **vcbdata) const { return afb_api_del_verb(api_, verb, vcbdata); }
inline int api::del_verb(const std::string &verb, void **vcbdata) const { return afb_api_del_verb(api_, verb.c_str(), vcbdata); }
inline int api::on_event(onevent_cb onevent) const { return afb_api_on_event(api_, onevent); }
inline int api::on_init(oninit_cb oninit) const { return afb_api_on_init(api_, oninit); }
inline int api::provide_class(const char *name) const { return afb_api_provide_class(api_, name); }
inline int api::provide_class(const std::string &name) const { return afb_api_provide_class(api_, name.c_str()); }
inline int api::require_class(const char *name) const { return afb_api_require_class(api_, name); }
inline int api::require_class(const std::string &name) const { return afb_api_require_class(api_, name.c_str()); }
inline void api::seal() const { afb_api_seal(api_); }
inline int api::delete_api() const { return afb_api_delete_api(api_); }
inline int api::add_alias(const char *name, const char *as_name) const { return afb_api_add_alias(api_, name, as_name); }
inline int api::add_alias(const std::string &name, const std::string &as_name) const { return afb_api_add_alias(api_, name.c_str(), as_name.c_str()); }

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
	afb_auth r = { afb_auth_No, {0}, nullptr};
	r.type = afb_auth_No;
	return r;
}

constexpr afb_auth auth_yes()
{
	afb_auth r = { afb_auth_No, {0}, nullptr};
	r.type = afb_auth_Yes;
	return r;
}

constexpr afb_auth auth_token()
{
	afb_auth r = { afb_auth_No, {0}, nullptr};
	r.type = afb_auth_Token;
	return r;
}

constexpr afb_auth auth_LOA(unsigned loa)
{
	afb_auth r = { afb_auth_No, {0}, nullptr};
	r.type = afb_auth_LOA;
	r.loa = loa;
	return r;
}

constexpr afb_auth auth_permission(const char *permission)
{
	afb_auth r = { afb_auth_No, {0}, nullptr};
	r.type = afb_auth_Permission;
	r.text = permission;
	return r;
}

constexpr afb_auth auth_not(const afb_auth *other)
{
	afb_auth r = { afb_auth_No, {0}, nullptr};
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
	afb_auth r = { afb_auth_No, {0}, nullptr};
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
	afb_auth r = { afb_auth_No, {0}, nullptr};
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
	return { name, callback, auth, info, vcbdata, session, glob };
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
	void (*callback)(req),
	const char *info = nullptr,
	uint16_t session = 0,
	const afb_auth *auth = nullptr,
	bool glob = false
)
{
	return verb(
		name,
		__afb__verb__cb__for__global__,
		info,
		session,
		auth,
		glob,
		*(void**)(&callback)
	);
}

constexpr afb_verb_t verbend()
{
	return { 0, 0, 0, 0, 0, 0, 0 };
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
	return {
		name, specification, info, verbs, preinit, init, onevent, userdata,
		nullptr, nullptr, nullptr, static_cast<unsigned int>(noconcurrency) };
};

/*************************************************************************/
/***                         E N D                                     ***/
/*************************************************************************/
}
