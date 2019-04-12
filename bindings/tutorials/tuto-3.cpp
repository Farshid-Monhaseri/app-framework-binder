#include <string>

#include <string.h>
#include <json-c/json.h>

#define AFB_BINDING_VERSION 3
#include <afb/afb-binding>

afb::event event_login, event_logout;

class session
{
private:
	std::string user_;
public:
	session(const char *user) : user_(user) {}
	~session() {}
	operator const char *() const { return user_.c_str(); }
};

void login(afb::req req)
{
	json_object *args, *user, *passwd;
	const char *usr;

	args = req.json();
	if (!json_object_object_get_ex(args, "user", &user)
	 || !json_object_object_get_ex(args, "password", &passwd)) {
		AFB_REQ_ERROR(req, "login, bad request: %s", json_object_get_string(args));
		req.fail("bad-request");
	} else if (afb_req_context_get(req)) {
		AFB_REQ_ERROR(req, "login, bad state, logout first");
		req.fail("bad-state");
	} else if (strcmp(json_object_get_string(passwd), "please")) {
		AFB_REQ_ERROR(req, "login, unauthorized: %s", json_object_get_string(args));
		req.fail("unauthorized");
	} else {
		usr = json_object_get_string(user);
		AFB_REQ_NOTICE(req, "login user: %s", usr);
		req.context<session>().set(new session(usr));
		req.session_set_LOA(1);
		req.success();
		event_login.push(json_object_new_string(usr));
	}
}

void action(afb::req req)
{
	json_object *args, *val;
	session &usr = req.context<session>();

	args = req.json();
	AFB_REQ_NOTICE(req, "action for user %s: %s", (const char*)usr, json_object_get_string(args));
	if (json_object_object_get_ex(args, "subscribe", &val)) {
		if (json_object_get_boolean(val)) {
			AFB_REQ_NOTICE(req, "user %s subscribes to events", (const char*)usr);
			req.subscribe(event_login);
			req.subscribe(event_logout);
		} else {
			AFB_REQ_NOTICE(req, "user %s unsubscribes to events", (const char*)usr);
			req.unsubscribe(event_login);
			req.unsubscribe(event_logout);
		}
	}
	req.success(json_object_get(args));
}

void logout(afb::req req)
{
	session &usr = req.context<session>();

	AFB_REQ_NOTICE(req, "login user %s out", (const char*)usr);
	event_logout.push(json_object_new_string((const char*)usr));
	req.session_set_LOA(0);
	req.context<session>().clear();
	req.success();
}

int init(afb_api_t api)
{
	AFB_NOTICE("init");
	event_login = afb_daemon_make_event("login");
	event_logout = afb_daemon_make_event("logout");
	if (afb_event_is_valid(event_login) && afb_event_is_valid(event_logout))
		return 0;
	AFB_ERROR("Can't create events");
	return -1;
}

const afb_verb_t verbs[] = {
	afb::verb("login", login, "log in the system"),
	afb::verb("action", action, "perform an action", AFB_SESSION_LOA_1),
	afb::verb("logout", logout, "log out the system", AFB_SESSION_LOA_1),
	afb::verbend()
};

const afb_binding_t afbBindingExport = afb::binding("tuto-3", verbs, "third tutorial: C++", init);

