#######################################################################################
# Script sed for migrating from AFB_BINDING_VERSION 2 to AFB_BINDING_VERSION 3
# See http://docs.automotivelinux.org/docs/apis_services/en/dev/reference/af-binder/afb-migration-to-ibinding-v3.html
#######################################################################################
# update the version
# ------------------
s:\(\<AFB_BINDING_VERSION[[:blank:]]\{1,\}\)2\>:\13:

# update common types
# -------------------
s:\<\(struct[[:blank:]]\{1,\}\)\{0,1\}afb_req\>:afb_req_t:g
s:\<\(struct[[:blank:]]\{1,\}\)\{0,1\}afb_event\>:afb_event_t:g
s:\<\(struct[[:blank:]]\{1,\}\)\{0,1\}afb_verb_v2\>:afb_verb_t:g
s:\<\(struct[[:blank:]]\{1,\}\)\{0,1\}afb_binding_v2\>:afb_binding_t:g

# update common names
# -------------------
s:\<afbBindingV2\>:afbBindingExport:g

# very special
# ------------
s:( *afb_req_t *) *{ *NULL *, *NULL *}:NULL:g

# special dynapi
# --------------
s:\(\<AFB_BINDING_VERSION[[:blank:]]\{1,\}\)0\>:\13:
/^[[:blank:]]*# *define *\<AFB_BINDING_WANT_DYNAPI\>/d
s:\<\(struct[[:blank:]]\{1,\}\)\{0,1\}afb_dynapi\>\([[:blank:]]*\)\*:afb_api_t\2:g
s:\<\(struct[[:blank:]]\{1,\}\)\{0,1\}afb_request\>\([[:blank:]]*\)\*:afb_req_t\2:g
s:\<\(struct[[:blank:]]\{1,\}\)\{0,1\}afb_eventid\>\([[:blank:]]*\)\*:afb_event_t\2:g
s:\<afb_request_:afb_req_:g
s:\<afb_dynapi_:afb_api_:g
s:\<afb_eventid_:afb_event_:g
s:\<AFB_DYNAPI_:AFB_API_:g
s:\<AFB_REQUEST_:AFB_REQ_:g
s:\<afbBindingVdyn\>:afbBindingV3entry:g
s:\<dynapi\>:api:g
s:\<eventid\>:event:g
s:\<afb_api_make_eventid\>:afb_api_make_event:g
s:\<afb_api_new_api\>:-!&:g
s:\<afb_api_sub_verb\>:afb_api_del_verb:g

# update legacy calls
# ------------------
s:\<afb_req_subcall\(_req\)\>:afb_req_subcall_legacy:g
s:\<afb_req_subcall_sync\>:afb_req_subcall_sync_legacy:g
s:\<afb_api_call\>:afb_api_call_legacy:g
s:\<afb_api_call_sync\>:afb_api_call_sync_legacy:g
s:\<afb_req_store\>:afb_req_addref:g
s:\<afb_req_unstore\> *( *\(.*\) *):\1:g
s:\<afb_event_drop\>:afb_event_unref:g

# optional but activated by default
# ---------------------------------
s:\<afb_daemon_get_\(event_loop\|user_bus\|system_bus\)[ \t]*(:afb_api_get_\1(afbBindingV3root:g
s:\<afb_daemon_\([a-z_0-9]* *(\):afb_api_\1afbBindingV3root, :g
s:\<afb_service_call_\([a-z_0-9]*\)\( *(\):afb_api_\1_legacy\2afbBindingV3root, :g
s:\<afb_service_\([a-z_0-9]* *(\):afb_api_\1afbBindingV3root, :g
s:\<AFB_\(\(ERROR\|WARNING\|NOTICE\|INFO\|DEBUG\)\> *(\):AFB_API_\1afbBindingV3root, :g

# special app-controller
# ----------------------
s:\<_\(AFB_SYSLOG_LEVEL_[A-Z]*\)_\>:\1:g

# UNSAFES (uncomment it if optimistic)
# --------------
#s:\<afb_req_fail\(_[fv]\)\{0,1\}\>\( *([^,]*\):afb_req_reply\1\2, NULL:g
#s:\<afb_req_success\(_[fv]\)\{0,1\}\>\( *([^,]*,[^,]*\):afb_req_reply\1\2, NULL:g
#
#s:\<afb_api_add_verb\>[^)]*:&, 0:g      ;# dynapi
#s:\<afb_api_del_verb\>[^)]*:&, NULL:g   ;# dynapi
#######################################################################################
