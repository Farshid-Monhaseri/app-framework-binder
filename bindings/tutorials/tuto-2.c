#include <string.h>
#include <json-c/json.h>

#define AFB_BINDING_VERSION 3
#include <afb/afb-binding.h>

afb_event_t event_login, event_logout;

void login(afb_req_t req)
{
        json_object *args, *user, *passwd;
        char *usr;

        args = afb_req_json(req);
        if (!json_object_object_get_ex(args, "user", &user)
         || !json_object_object_get_ex(args, "password", &passwd)) {
                AFB_REQ_ERROR(req, "login, bad request: %s", json_object_get_string(args));
                afb_req_reply(req, NULL, "bad-request", NULL);
        } else if (afb_req_context_get(req)) {
                AFB_REQ_ERROR(req, "login, bad state, logout first");
                afb_req_reply(req, NULL, "bad-state", NULL);
        } else if (strcmp(json_object_get_string(passwd), "please")) {
                AFB_REQ_ERROR(req, "login, unauthorized: %s", json_object_get_string(args));
                afb_req_reply(req, NULL, "unauthorized", NULL);
        } else {
                usr = strdup(json_object_get_string(user));
                AFB_REQ_NOTICE(req, "login user: %s", usr);
                afb_req_session_set_LOA(req, 1);
                afb_req_context_set(req, usr, free);
                afb_req_reply(req, NULL, NULL, NULL);
                afb_event_push(event_login, json_object_new_string(usr));
        }
}

void action(afb_req_t req)
{
        json_object *args, *val;
        char *usr;

        args = afb_req_json(req);
        usr = afb_req_context_get(req);
        AFB_REQ_NOTICE(req, "action for user %s: %s", usr, json_object_get_string(args));
        if (json_object_object_get_ex(args, "subscribe", &val)) {
                if (json_object_get_boolean(val)) {
                        AFB_REQ_NOTICE(req, "user %s subscribes to events", usr);
                        afb_req_subscribe(req, event_login);
                        afb_req_subscribe(req, event_logout);
                } else {
                        AFB_REQ_NOTICE(req, "user %s unsubscribes to events", usr);
                        afb_req_unsubscribe(req, event_login);
                        afb_req_unsubscribe(req, event_logout);
                }
        }
        afb_req_reply(req, json_object_get(args), NULL, NULL);
}

void logout(afb_req_t req)
{
        char *usr;

        usr = afb_req_context_get(req);
        AFB_REQ_NOTICE(req, "login user %s out", usr);
        afb_event_push(event_logout, json_object_new_string(usr));
        afb_req_session_set_LOA(req, 0);
        afb_req_context_clear(req);
        afb_req_reply(req, NULL, NULL, NULL);
}

int preinit(afb_api_t api)
{
        AFB_API_NOTICE(api, "preinit");
        return 0;
}

int init(afb_api_t api)
{
        AFB_API_NOTICE(api, "init");
        event_login = afb_api_make_event(api, "login");
        event_logout = afb_api_make_event(api, "logout");
        if (afb_event_is_valid(event_login) && afb_event_is_valid(event_logout))
                return 0;
        AFB_API_ERROR(api, "Can't create events");
        return -1;
}

const afb_verb_t verbs[] = {
        { .verb="login", .callback=login },
        { .verb="action", .callback=action, .session=AFB_SESSION_LOA_1 },
        { .verb="logout", .callback=logout, .session=AFB_SESSION_LOA_1 },
        { .verb=NULL }
};

const afb_binding_t afbBindingExport = {
        .api = "tuto-2",
        .specification = NULL,
        .verbs = verbs,
        .preinit = preinit,
        .init = init,
        .noconcurrency = 0
};