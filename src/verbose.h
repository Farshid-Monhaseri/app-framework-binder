/*
 Copyright (C) 2016-2019 "IoT.bzh"

 author: José Bollo <jose.bollo@iot.bzh>

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
*/

#pragma once

#include <stdarg.h>

/*
  verbosity tune the count of reported messages

   verbosity value : reported messages
   ----------------+------------------------
    lesser than 0  : no message at all
         0         : ERROR
         1         : ERROR, WARNING
         2         : ERROR, WARNING, NOTICE
         3         : ERROR, WARNING, NOTICE, INFO
    greater than 3 : ERROR, WARNING, NOTICE, INFO, DEBUG

extern int verbosity;

enum verbosity_levels
{
	Verbosity_Level_Error = 0,
	Verbosity_Level_Warning = 1,
	Verbosity_Level_Notice = 2,
	Verbosity_Level_Info = 3,
	Verbosity_Level_Debug = 4
};
*/

extern void verbose_set_name(const char *name, int authority);

/*
 Log level is defined by syslog standard:
       KERN_EMERG             0        System is unusable
       KERN_ALERT             1        Action must be taken immediately
       KERN_CRIT              2        Critical conditions
       KERN_ERR               3        Error conditions
       KERN_WARNING           4        Warning conditions
       KERN_NOTICE            5        Normal but significant condition
       KERN_INFO              6        Informational
       KERN_DEBUG             7        Debug-level messages
*/

enum
{
	Log_Level_Emergency = 0,
	Log_Level_Alert = 1,
	Log_Level_Critical = 2,
	Log_Level_Error = 3,
	Log_Level_Warning = 4,
	Log_Level_Notice = 5,
	Log_Level_Info = 6,
	Log_Level_Debug = 7
};

extern int logmask;

extern void verbose(int loglevel, const char *file, int line, const char *function, const char *fmt, ...) __attribute__((format(printf, 5, 6)));
extern void vverbose(int loglevel, const char *file, int line, const char *function, const char *fmt, va_list args);

#if defined(VERBOSE_NO_DATA)
# define __VERBOSE__(lvl,...)      do{if((lvl)<=Log_Level_Error) verbose(lvl, __FILE__, __LINE__, NULL, __VA_ARGS__)\
					else verbose(lvl, __FILE__, __LINE__, NULL, NULL);}while(0)
#elif defined(VERBOSE_NO_DETAILS)
# define __VERBOSE__(lvl,...)      verbose(lvl, NULL, 0, NULL, __VA_ARGS__)
#else
# define __VERBOSE__(lvl,...)      verbose(lvl, __FILE__, __LINE__, __func__, __VA_ARGS__)
#endif

#define _LOGMASK_(lvl)		((lvl) < 0 ? -1 : (1 << (lvl)))
#define _WANTLOG_(lvl)		(logmask & _LOGMASK_(lvl))
#define _VERBOSE_(lvl,...)	do{ if (_WANTLOG_(lvl)) __VERBOSE__((lvl), __VA_ARGS__); } while(0)

#define EMERGENCY(...)            _VERBOSE_(Log_Level_Emergency, __VA_ARGS__)
#define ALERT(...)                _VERBOSE_(Log_Level_Alert, __VA_ARGS__)
#define CRITICAL(...)             _VERBOSE_(Log_Level_Critical, __VA_ARGS__)
#define ERROR(...)                _VERBOSE_(Log_Level_Error, __VA_ARGS__)
#define WARNING(...)              _VERBOSE_(Log_Level_Warning, __VA_ARGS__)
#define NOTICE(...)               _VERBOSE_(Log_Level_Notice, __VA_ARGS__)
#define INFO(...)                 _VERBOSE_(Log_Level_Info, __VA_ARGS__)
#define DEBUG(...)                _VERBOSE_(Log_Level_Debug, __VA_ARGS__)

#define LOGUSER(app)              verbose_set_name(app,0)
#define LOGAUTH(app)              verbose_set_name(app,1)

extern void (*verbose_observer)(int loglevel, const char *file, int line, const char *function, const char *fmt, va_list args);

static inline int verbose_wants(int lvl) { return _WANTLOG_(lvl); }

extern void verbose_dec();
extern void verbose_inc();
extern void verbose_clear();
extern void verbose_add(int level);
extern void verbose_sub(int level);
extern void verbose_colorize();
extern int verbose_is_colorized();

extern int verbose_level_of_name(const char *name);
extern const char *verbose_name_of_level(int level);

#define _DEVERBOSITY_(vlvl)	((vlvl) + Log_Level_Error)
#define _VERBOSITY_(llvl)	((llvl) - Log_Level_Error)
extern int verbosity_get();
extern void verbosity_set(int verbo);
extern int verbosity_from_mask(int mask);
extern int verbosity_to_mask(int verbo);

#define COLOR_EMERGENCY	"\x1B[101m"
#define COLOR_ALERT	"\x1B[43m"
#define COLOR_CRITICAL	"\x1B[41m"
#define COLOR_ERROR	"\x1B[91m"
#define COLOR_WARNING	"\x1B[93m"
#define COLOR_NOTICE	"\x1B[94m"
#define COLOR_INFO	"\x1B[96m"
#define COLOR_DEBUG	"\x1B[95m"
#define COLOR_API	"\x1B[1m"
#define COLOR_FILE	"\x1B[90m"
#define COLOR_DEFAULT	"\x1B[0m"

