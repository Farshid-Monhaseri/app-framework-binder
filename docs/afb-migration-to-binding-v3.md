Migration to binding V3
=======================

The ***binding*** interface evolved from version 1 to version 2
for the following reasons:

- integration of the security requirements within the bindings
- simplification of the API (after developer feedbacks)
- removal of obscure features and cleanup

The ***binder*** can run ***bindings*** v1, v2 and/or v3 in any combination.  
Thus moving from v1 or v2 to v3 is not enforced at this time. But ...

In the face to face meeting in Karlsruhe it was decided to remove support
of bindings v1 and to deprecate the use of bindings v2.

So at the end, **IT IS HIGHLY NEEDED TO SWITCH TO VERSION 3**

This guide covers the migration of bindings from version 2 to version 3.

The migration from version 1 is not treated here because bindings version 1
are very old and probably do not exist anymore. If needed you can refer
to the old [guide to migrate bindings from v1 to v2](legacy/afb-migration-v1-to-v2.html).


Differences between version 2 and version 3
-------------------------------------------

### in v3 all is api

The version 3 introduces the concept of "API" that gather what was called before
the daemon and the service. This is the new concept that predates the 2 others.

The concept of API is intended to allow the definition of multiple APIs
by a same "binding" (a dynamically loaded library).

Because there is potentially several "API", the functions that were without
context in bindings version 2 need now to tell what API is consumer.

To be compatible with version 2, bindings v3 still have a default hidden
context: the default API named **afbBindingV3root**.

To summarize, the functions of class **daemon** and **service** use the default
hidden API.

It is encouraged to avoid use of functions of class **daemon** and **service**.
You should replace these implicit calls to explicit **api** calls that 
reference **afbBindingV3root**.

Same thing for the logging macros: **AFB_ERROR**, **AFB_WARNING**,
**AFB_NOTICE**, **AFB_INFO**, **AFB_DEBUG** that becomes respectively
**AFB_API_ERROR**, **AFB_API_WARNING**, **AFB_API_NOTICE**, **AFB_API_INFO**,
**AFB_API_DEBUG**.

Example of 2 equivalent writes:

```C
	AFB_NOTICE("send stress event");
        afb_daemon_broadcast_event(stressed_event, NULL);
```

or 

```C
	AFB_API_NOTICE(afbBindingV3root, "send stress event");
        afb_api_broadcast_event(afbBindingV3root, stressed_event, NULL);
```

### the reply mechanism predates success and fail

### subcall has more power

Task list for the migration
---------------------------

This task list is:

1. Use the automatic migration procedure described below
2. Adapt the functions **preinit**, **init** and **onevent**
3. Consider use of the new reply
4. Consider use of the new (sub)call
5. Consider use of event handlers

The remaining chapters explain these task with more details.

Automatic migration!
--------------------

A tiny **sed** script is intended to perform a first pass on the code that
you want to upgrade. It can be done using **curl** and applied using **sed**
as below.

```bash
BASE=https://git.automotivelinux.org/src/app-framework-binder/plain
SED=migration-to-binding-v3.sed
curl -o $SED $BASE/docs/$SED
sed -i -f $SED file1 file2 file3...
```

You can also follow
[this link](https://git.automotivelinux.org/src/app-framework-binder/plain/docs/migration-to-binding-v3.sed)
and save the file.

This automatic action does most of the boring job but not all the job.
The remaining of this guide explains the missing part.

Adapt the functions preinit, init and onevent
----------------------------------------------

The signature of the functions **preinit**, **init** and **onevent** changed
to include the target api.

The functions of the v2:

```C
int (*preinit)();
int (*init)();
void (*onevent)(const char *event, struct json_object *object);
```

Gain a new first argument of type **afb_api_t** as below:

```C
int (*preinit)(afb_api_t api);
int (*init)(afb_api_t api);
void (*onevent)(afb_api_t api, const char *event, struct json_object *object);
```

For the migration, it is enough to just add the new argument without
using it.

Consider use of the new reply
-----------------------------

The v3 allows error reply with JSON object. To achieve it, an unified
reply function's family is introduced:

```C
void afb_req_reply(afb_req_t req, json_object *obj, const char *error, const char *info);
void afb_req_reply_v(afb_req_t req, json_object *obj, const char *error, const char *info, va_list args);
void afb_req_reply_f(afb_req_t req, json_object *obj, const char *error, const char *info, ...);
```

The functions **success** and **fail** are still supported.
These functions are now implemented as the following macros:


```C
#define afb_req_success(r,o,i)		afb_req_reply(r,o,NULL,i)
#define afb_req_success_f(r,o,...)	afb_req_reply_f(r,o,NULL,__VA_ARGS__)
#define afb_req_success_v(r,o,f,v)	afb_req_reply_v(r,o,NULL,f,v)
#define afb_req_fail(r,e,i)		afb_req_reply(r,NULL,e,i)
#define afb_req_fail_f(r,e,...)		afb_req_reply_f(r,NULL,e,__VA_ARGS__)
#define afb_req_fail_v(r,e,f,v)		afb_req_reply_v(r,NULL,e,f,v)
```

This is a decision of the developer to switch to the new family
**afb_req_reply** or to keep the good old functions **afb_req_fail**
and **afb_req_success**.

Consider use of the new (sub)call
---------------------------------

The new call and subcall (the functions **afb_api_call**, **afb_api_call_sync**,
**afb_req_subcall** and **afb_req_subcall_sync**) functions are redesigned
to better fit the new reply behaviour. In most case the developer will benefit
of the new behavior that directly gives result and error without enforcing
to parse the JSON object result.

The subcall functions are also fully redesigned to allow precise handling
of the context and event subscriptions. The new design allows you to specify:

 - whether the subcall is made in the session of the caller or in the session
   of the service
 - whether the credentials to use are those of the caller or those of the
   service
 - whether the caller or the service or both or none will receive the
   eventually events during the subcall.

See [calls](reference-v3/func-api.html#calls-and-job-functions) and
[subcalls](reference-v3/func-req.html#subcall-functions).

The table below list the changes to apply:

| Name in Version 2      | New name of Version 3
|:----------------------:|:----------------------------------------------------:
| afb_req_subcall        | afb_req_subcall_legacy
| afb_req_subcall_sync   | afb_req_subcall_sync_legacy
| afb_service_call       | afb_service_call_legacy
| afb_service_call_sync  | afb_service_call_sync_legacy
| afb_req_subcall_req    | afb_req_subcall_req (same but obsolete)


Consider use of event handlers
------------------------------

Binding V3 brings new ways of handling event in services. You can register
functions that will handle specific events and that accept closure arguments.

See [**afb_api_event_handler_add** and **afb_api_event_handler_del**](reference-v3/func-api.html#event-functions)
