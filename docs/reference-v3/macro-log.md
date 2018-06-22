Macro for logging
=================

The final behaviour of macros can be tuned using 2 defines that must be defined
before including **<afb/afb-binding.h>**.

| define                                | action
|---------------------------------------|--------------------
| AFB_BINDING_PRAGMA_NO_VERBOSE_DATA    | show file and line, remove function and text message
| AFB_BINDING_PRAGMA_NO_VERBOSE_DETAILS | show text, remove function, line and file

## Logging for an api

The following macros must be used for logging for an **api** of type
**afb_api_t**.

```C
AFB_API_ERROR(api,fmt,...)
AFB_API_WARNING(api,fmt,...)
AFB_API_NOTICE(api,fmt,...)
AFB_API_INFO(api,fmt,...)
AFB_API_DEBUG(api,fmt,...)
```

## Logging for a request


The following macros can be used for logging in the context
of a request **req** of type **afb_req_t**:

```C
AFB_REQ_ERROR(req,fmt,...)
AFB_REQ_WARNING(req,fmt,...)
AFB_REQ_NOTICE(req,fmt,...)
AFB_REQ_INFO(req,fmt,...)
AFB_REQ_DEBUG(req,fmt,...)
```

By default, the logging macros add file, line and function
indication.

## Logging legacy

The following macros are provided for legacy.

```C
AFB_ERROR(fmt,...)
AFB_WARNING(fmt,...)
AFB_NOTICE(fmt,...)
AFB_INFO(fmt,...)
AFB_DEBUG(fmt,...)
```
