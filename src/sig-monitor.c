/*
 * Copyright (C) 2017-2019 "IoT.bzh"
 * Author José Bollo <jose.bollo@iot.bzh>
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

/*******************************************************************************
*  sig-monitor is under the control of several compilation flags
*******************************************************************************/

/* controls whether to dump stack or not */
#if !defined(WITH_SIG_MONITOR_DUMPSTACK)
#  define WITH_SIG_MONITOR_DUMPSTACK 1
#endif

/* control whether to monitor signals */
#if !defined(WITH_SIG_MONITOR_SIGNALS)
#  define WITH_SIG_MONITOR_SIGNALS 1
#endif

/* controls whether to monitor calls */
#if !defined(WITH_SIG_MONITOR_FOR_CALL)
#  define WITH_SIG_MONITOR_FOR_CALL 1
#endif

/* control whether to monitor timers */
#if !defined(WITH_SIG_MONITOR_TIMERS)
#  define WITH_SIG_MONITOR_TIMERS 1
#endif

#if !WITH_SIG_MONITOR_SIGNALS
#  undef WITH_SIG_MONITOR_FOR_CALL
#  define WITH_SIG_MONITOR_FOR_CALL 0
#endif

#if !WITH_SIG_MONITOR_FOR_CALL
#  undef WITH_SIG_MONITOR_TIMERS
#  define WITH_SIG_MONITOR_TIMERS 0
#endif

/******************************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "sig-monitor.h"

#include "verbose.h"

/******************************************************************************/
#if !WITH_SIG_MONITOR_DUMPSTACK

static inline void dumpstack(int crop, int signum) {}

#else

#include <execinfo.h>

/*
 * Dumps the current stack
 */
static void dumpstack(int crop, int signum)
{
	int idx, count, rc;
	void *addresses[100];
	char **locations;
	char buffer[8000];
	size_t pos, length;

	count = backtrace(addresses, sizeof addresses / sizeof *addresses);
	if (count <= crop)
		crop = 0;
	count -= crop;
	locations = backtrace_symbols(&addresses[crop], count);
	if (locations == NULL)
		ERROR("can't get the backtrace (returned %d addresses)", count);
	else {
		length = sizeof buffer - 1;
		pos = 0;
		idx = 0;
		while (pos < length && idx < count) {
			rc = snprintf(&buffer[pos], length - pos, " [%d/%d] %s\n", idx + 1, count, locations[idx]);
			pos += rc >= 0 ? rc : 0;
			idx++;
		}
		buffer[length] = 0;
		if (signum)
			ERROR("BACKTRACE due to signal %s/%d:\n%s", strsignal(signum), signum, buffer);
		else
			ERROR("BACKTRACE:\n%s", buffer);
		free(locations);
	}
}

#endif
/******************************************************************************/
#if !WITH_SIG_MONITOR_TIMERS

static inline int timeout_create() { return 0; }
static inline int timeout_arm(int timeout) { return 0; }
static inline void timeout_disarm() {}
static inline void timeout_delete() {}

#define SIG_FOR_TIMER   0

#else

#include <time.h>
#include <sys/syscall.h>
#include <signal.h>

#define SIG_FOR_TIMER   SIGVTALRM

/* local per thread timers */
static _Thread_local int thread_timer_set;
static _Thread_local timer_t thread_timerid;

/*
 * Creates a timer for the current thread
 *
 * Returns 0 in case of success
 */
static inline int timeout_create()
{
	int rc;
	struct sigevent sevp;

	if (thread_timer_set)
		rc = 0;
	else {
		sevp.sigev_notify = SIGEV_THREAD_ID;
		sevp.sigev_signo = SIG_FOR_TIMER;
		sevp.sigev_value.sival_ptr = NULL;
#if defined(sigev_notify_thread_id)
		sevp.sigev_notify_thread_id = (pid_t)syscall(SYS_gettid);
#else
		sevp._sigev_un._tid = (pid_t)syscall(SYS_gettid);
#endif
		rc = timer_create(CLOCK_THREAD_CPUTIME_ID, &sevp, &thread_timerid);
		thread_timer_set = !rc;
	}
	return rc;
}

/*
 * Arms the alarm in timeout seconds for the current thread
 */
static inline int timeout_arm(int timeout)
{
	int rc;
	struct itimerspec its;

	rc = timeout_create();
	if (rc == 0) {
		its.it_interval.tv_sec = 0;
		its.it_interval.tv_nsec = 0;
		its.it_value.tv_sec = timeout;
		its.it_value.tv_nsec = 0;
		rc = timer_settime(thread_timerid, 0, &its, NULL);
	}

	return rc;
}

/*
 * Disarms the current alarm
 */
static inline void timeout_disarm()
{
	if (thread_timer_set)
		timeout_arm(0);
}

/*
 * Destroy any alarm resource for the current thread
 */
static inline void timeout_delete()
{
	if (thread_timer_set) {
		timer_delete(thread_timerid);
		thread_timer_set = 0;
	}
}
#endif
/******************************************************************************/
#if !WITH_SIG_MONITOR_FOR_CALL

static inline void monitor_raise(int signum) {}

#else

#include <setjmp.h>

/* local handler */
static _Thread_local sigjmp_buf *error_handler;

static void monitor(int timeout, void (*function)(int sig, void*), void *arg)
{
	volatile int signum, signum2;
	sigjmp_buf jmpbuf, *older;

	older = error_handler;
	signum = setjmp(jmpbuf);
	if (signum == 0) {
		error_handler = &jmpbuf;
		if (timeout) {
			timeout_create();
			timeout_arm(timeout);
		}
		function(0, arg);
	} else {
		signum2 = setjmp(jmpbuf);
		if (signum2 == 0)
			function(signum, arg);
	}
	if (timeout)
		timeout_disarm();
	error_handler = older;
}

static inline void monitor_raise(int signum)
{
	if (error_handler != NULL)
		longjmp(*error_handler, signum);
}
#endif
/******************************************************************************/
#if !WITH_SIG_MONITOR_SIGNALS

static inline int enable_signal_handling() { return 0; }

#else

#include <signal.h>

/* internal signal lists */
static int sigerr[] = { SIGSEGV, SIGFPE, SIGILL, SIGBUS, SIG_FOR_TIMER, 0 };
static int sigterm[] = { SIGINT, SIGABRT, SIGTERM, 0 };

static int exiting = 0;
static int enabled = 0;

/* install the handlers */
static int set_signals_handler(void (*handler)(int), int *signals)
{
	int result = 1;
	struct sigaction sa;

	sa.sa_handler = handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_NODEFER;
	while(*signals > 0) {
		if (sigaction(*signals, &sa, NULL) < 0) {
			ERROR("failed to install signal handler for signal %s: %m", strsignal(*signals));
			result = 0;
		}
		signals++;
	}
	return result;
}

/*
 * rescue exit
 */
static void on_rescue_exit(int signum)
{
	ERROR("Rescue exit for signal %d: %s", signum, strsignal(signum));
	_exit(exiting);
}

/*
 * Do a safe exit
 */
static void safe_exit(int code)
{
	set_signals_handler(on_rescue_exit, sigerr);
	set_signals_handler(on_rescue_exit, sigterm);
	exiting = code;
	exit(code);
}

#if !WITH_SIG_MONITOR_DUMPSTACK

static inline void safe_dumpstack(int crop, int signum) {}
#define in_safe_dumpstack (0)

#else

static _Thread_local int in_safe_dumpstack;

static void safe_dumpstack_cb(int signum, void *closure)
{
	int *args = closure;
	if (signum)
		ERROR("Can't provide backtrace: raised signal %s", strsignal(signum));
	else
		dumpstack(args[0], args[1]);
}

static void safe_dumpstack(int crop, int signum)
{
	int args[2] = { crop + 3, signum };

	in_safe_dumpstack = 1;
	sig_monitor(0, safe_dumpstack_cb, args);
	in_safe_dumpstack = 0;
}
#endif

/* Handles signals that terminate the process */
static void on_signal_terminate (int signum)
{
	if (!in_safe_dumpstack) {
		ERROR("Terminating signal %d received: %s", signum, strsignal(signum));
		if (signum == SIGABRT)
			safe_dumpstack(3, signum);
	}
	safe_exit(1);
}

/* Handles monitored signals that can be continued */
static void on_signal_error(int signum)
{
	if (!in_safe_dumpstack) {
		ERROR("ALERT! signal %d received: %s", signum, strsignal(signum));

		safe_dumpstack(3, signum);
	}
	monitor_raise(signum);

	if (signum != SIG_FOR_TIMER) {
		ERROR("Unmonitored signal %d received: %s", signum, strsignal(signum));
		safe_exit(2);
	}
}

/*
static void disable_signal_handling()
{
	set_signals_handler(SIG_DFL, sigerr);
	set_signals_handler(SIG_DFL, sigterm);
	enabled = 0;
}
*/

static int enable_signal_handling()
{
	if (!set_signals_handler(on_signal_error, sigerr)
	     || !set_signals_handler(on_signal_terminate, sigterm)) {
		return -1;
	}
	enabled = 1;
	return 0;
}
#endif
/******************************************************************************/

int sig_monitor_init(int enable)
{
	return enable ? enable_signal_handling() : 0;
}

int sig_monitor_init_timeouts()
{
	return timeout_create();
}

void sig_monitor_clean_timeouts()
{
	timeout_delete();
}

void sig_monitor(int timeout, void (*function)(int sig, void*), void *arg)
{
#if WITH_SIG_MONITOR_SIGNALS && WITH_SIG_MONITOR_FOR_CALL
	if (enabled)
		monitor(timeout, function, arg);
	else
#endif
		function(0, arg);
}

void sig_monitor_dumpstack()
{
	return dumpstack(1, 0);
}
