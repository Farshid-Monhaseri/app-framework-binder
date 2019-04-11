#include <afb/c++/binding>
#include <json-c/json.h>
#include <string.h>

class tuto5
	: public afb::base_api_t<tuto5>
{
private:
	afb::event event_login;
	afb::event event_logout;

public:
	void login(afb::req req)
	{
		json_object *user, *passwd;

		json_object* args = req.json();
		if (!json_object_object_get_ex(args, "user", &user)
		|| !json_object_object_get_ex(args, "password", &passwd)) {
			AFB_REQ_ERROR(req, "login, bad request: %s", json_object_get_string(args));
			req.fail("bad-request");
		} else if (afb_req_context_get(req)) {
			AFB_REQ_ERROR(req, "login, bad state, logout first");
			req.fail("bad-state");
		} else if (std::string(json_object_get_string(passwd)) != std::string("please")) {
			AFB_REQ_ERROR(req, "login, unauthorized: %s", json_object_get_string(args));
			req.fail("unauthorized");
		} else {
			char* username = strdup(json_object_get_string(user));
			AFB_REQ_NOTICE(req, "login user: %s", username);
			req.session_set_LOA(1);
			afb_req_context_set(req, username, free);
			req.success();
			event_login.push(json_object_new_string(username));
		}
	}

	void action(afb::req req) const
	{
		json_object* val;
		json_object* args = req.json();
		char* username = reinterpret_cast<char*>(afb_req_context_get(req));
		AFB_REQ_NOTICE(req, "action for user %s: %s", username, json_object_get_string(args));
		if (json_object_object_get_ex(args, "subscribe", &val)) {
			if (json_object_get_boolean(val)) {
				AFB_REQ_NOTICE(req, "user %s subscribes to events", username);
				req.subscribe(event_login);
				req.subscribe(event_logout);
			} else {
				AFB_REQ_NOTICE(req, "user %s unsubscribes to events", username);
				req.unsubscribe(event_login);
				req.unsubscribe(event_logout);
			}
		}
		req.success(json_object_get(args));
	}

	void logout(afb::req req)
	{
		char* username = reinterpret_cast<char*>(afb_req_context_get(req));
		AFB_REQ_NOTICE(req, "login user %s out", username);
		event_logout.push(json_object_new_string(username));
		req.session_set_LOA(0);
		afb_req_context_clear(req);
		req.success();
	}

	int preinit(afb_api_t h) override
	{
		return !(
			(add_verb<&tuto5::login>("login", "log in the system") == 0) &&
			(add_verb<&tuto5::action>("action", "perform an action", nullptr, nullptr, AFB_SESSION_LOA_1) == 0) &&
			(add_verb<&tuto5::logout>("logout", "log out the system", nullptr, nullptr, AFB_SESSION_LOA_1) == 0)
		);
	}

	int init() override
	{
		AFB_API_NOTICE(api_, "init");
		event_login = make_event("login");
		event_logout = make_event("logout");
		if (event_login.is_valid() && event_logout.is_valid())
			return 0;
		AFB_API_ERROR(api_, "Can't create events");
		return -1;
	}
};

int afbBindingEntry(afb_api_t h)
{
	afb::new_api<tuto5>(h, "tuto-5", "fifth tutorial: C++");
	return 0;
}
