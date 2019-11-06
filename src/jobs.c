/*
 * Copyright (C) 2016-2019 "IoT.bzh"
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

#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <sys/syscall.h>
#include <pthread.h>
#include <errno.h>
#include <assert.h>
#include <sys/eventfd.h>

#include <systemd/sd-event.h>

#include "jobs.h"
#include "evmgr.h"
#include "sig-monitor.h"
#include "verbose.h"
#include "systemd.h"

#define EVENT_TIMEOUT_TOP  	((uint64_t)-1)
#define EVENT_TIMEOUT_CHILD	((uint64_t)10000)

/** Internal shortcut for callback */
typedef void (*job_cb_t)(int, void*);

/** starting mode for jobs */
enum start_mode
{
	Start_Default,  /**< Start a thread if more than one jobs is pending */
	Start_Urgent,   /**< Always start a thread */
	Start_Lazy      /**< Never start a thread */
};

/** Description of a pending job */
struct job
{
	struct job *next;    /**< link to the next job enqueued */
	const void *group;   /**< group of the request */
	job_cb_t callback;   /**< processing callback */
	void *arg;           /**< argument */
	int timeout;         /**< timeout in second for processing the request */
	unsigned blocked: 1; /**< is an other request blocking this one ? */
	unsigned dropped: 1; /**< is removed ? */
};

/** Description of threads */
struct thread
{
	struct thread *next;   /**< next thread of the list */
	struct thread *upper;  /**< upper same thread */
	struct thread *nholder;/**< next holder for evloop */
	pthread_cond_t *cwhold;/**< condition wait for holding */
	struct job *job;       /**< currently processed job */
	pthread_t tid;         /**< the thread id */
	volatile unsigned stop: 1;      /**< stop requested */
	volatile unsigned waits: 1;     /**< is waiting? */
	volatile unsigned leaved: 1;    /**< was leaved? */
};

/**
 * Description of synchronous callback
 */
struct sync
{
	struct thread thread;	/**< thread loop data */
	union {
		void (*callback)(int, void*);	/**< the synchronous callback */
		void (*enter)(int signum, void *closure, struct jobloop *jobloop);
				/**< the entering synchronous routine */
	};
	void *arg;		/**< the argument of the callback */
};

/* synchronisation of threads */
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  cond = PTHREAD_COND_INITIALIZER;

/* counts for threads */
static int allowed_thread_count = 0; /** allowed count of threads */
static int started_thread_count = 0; /** started count of threads */
static int busy_thread_count = 0;    /** count of busy threads */

/* list of threads */
static struct thread *threads;
static _Thread_local struct thread *current_thread;

/* counts for jobs */
static int remaining_job_count = 0;  /** count of job that can be created */
static int allowed_job_count = 0;    /** allowed count of pending jobs */

/* queue of pending jobs */
static struct job *first_pending_job;
static struct job *first_free_job;

/* event loop */
static struct evmgr *evmgr;

static void (*exit_handler)();

/**
 * Create a new job with the given parameters
 * @param group    the group of the job
 * @param timeout  the timeout of the job (0 if none)
 * @param callback the function that achieves the job
 * @param arg      the argument of the callback
 * @return the created job unblock or NULL when no more memory
 */
static struct job *job_create(
		const void *group,
		int timeout,
		job_cb_t callback,
		void *arg)
{
	struct job *job;

	/* try recyle existing job */
	job = first_free_job;
	if (job)
		first_free_job = job->next;
	else {
		/* allocation without blocking */
		pthread_mutex_unlock(&mutex);
		job = malloc(sizeof *job);
		pthread_mutex_lock(&mutex);
		if (!job) {
			ERROR("out of memory");
			errno = ENOMEM;
			goto end;
		}
	}
	/* initialises the job */
	job->group = group;
	job->timeout = timeout;
	job->callback = callback;
	job->arg = arg;
	job->blocked = 0;
	job->dropped = 0;
end:
	return job;
}

/**
 * Adds 'job' at the end of the list of jobs, marking it
 * as blocked if an other job with the same group is pending.
 * @param job the job to add
 */
static void job_add(struct job *job)
{
	const void *group;
	struct job *ijob, **pjob;

	/* prepare to add */
	group = job->group;
	job->next = NULL;

	/* search end and blockers */
	pjob = &first_pending_job;
	ijob = first_pending_job;
	while (ijob) {
		if (group && ijob->group == group)
			job->blocked = 1;
		pjob = &ijob->next;
		ijob = ijob->next;
	}

	/* queue the jobs */
	*pjob = job;
	remaining_job_count--;
}

/**
 * Get the next job to process or NULL if none.
 * @return the first job that isn't blocked or NULL
 */
static inline struct job *job_get()
{
	struct job *job = first_pending_job;
	while (job && job->blocked)
		job = job->next;
	if (job)
		remaining_job_count++;
	return job;
}

/**
 * Releases the processed 'job': removes it
 * from the list of jobs and unblock the first
 * pending job of the same group if any.
 * @param job the job to release
 */
static inline void job_release(struct job *job)
{
	struct job *ijob, **pjob;
	const void *group;

	/* first unqueue the job */
	pjob = &first_pending_job;
	ijob = first_pending_job;
	while (ijob != job) {
		pjob = &ijob->next;
		ijob = ijob->next;
	}
	*pjob = job->next;

	/* then unblock jobs of the same group */
	group = job->group;
	if (group) {
		ijob = job->next;
		while (ijob && ijob->group != group)
			ijob = ijob->next;
		if (ijob)
			ijob->blocked = 0;
	}

	/* recycle the job */
	job->next = first_free_job;
	first_free_job = job;
}

/**
 * Monitored cancel callback for a job.
 * This function is called by the monitor
 * to cancel the job when the safe environment
 * is set.
 * @param signum 0 on normal flow or the number
 *               of the signal that interrupted the normal
 *               flow, isn't used
 * @param arg    the job to run
 */
__attribute__((unused))
static void job_cancel(int signum, void *arg)
{
	struct job *job = arg;
	job->callback(SIGABRT, job->arg);
}

/**
 * wakeup the event loop if needed by sending
 * an event.
 */
static void evloop_wakeup()
{
	if (evmgr)
		evmgr_wakeup(evmgr);
}

/**
 * Release the currently held event loop
 */
static void evloop_release()
{
	struct thread *nh, *ct = current_thread;

	if (ct && evmgr && evmgr_release_if(evmgr, ct)) {
		nh = ct->nholder;
		ct->nholder = 0;
		if (nh) {
			evmgr_try_hold(evmgr, nh);
			pthread_cond_signal(nh->cwhold);
		}
	}
}

/**
 * get the eventloop for the current thread
 */
static int evloop_get()
{
	return evmgr && evmgr_try_hold(evmgr, current_thread);
}

/**
 * acquire the eventloop for the current thread
 */
static void evloop_acquire()
{
	struct thread *pwait, *ct;
	pthread_cond_t cond;

	/* try to get the evloop */
	if (!evloop_get()) {
		/* failed, init waiting state */
		ct = current_thread;
		ct->nholder = NULL;
		ct->cwhold = &cond;
		pthread_cond_init(&cond, NULL);

		/* queue current thread in holder list */
		pwait = evmgr_holder(evmgr);
		while (pwait->nholder)
			pwait = pwait->nholder;
		pwait->nholder = ct;

		/* wake up the evloop */
		evloop_wakeup();

		/* wait to acquire the evloop */
		pthread_cond_wait(&cond, &mutex);
		pthread_cond_destroy(&cond);
	}
}

/**
 * Enter the thread
 * @param me the description of the thread to enter
 */
static void thread_enter(volatile struct thread *me)
{
	evloop_release();
	/* initialize description of itself and link it in the list */
	me->tid = pthread_self();
	me->stop = 0;
	me->waits = 0;
	me->leaved = 0;
	me->nholder = 0;
	me->upper = current_thread;
	me->next = threads;
	threads = (struct thread*)me;
	current_thread = (struct thread*)me;
}

/**
 * leave the thread
 * @param me the description of the thread to leave
 */
static void thread_leave()
{
	struct thread **prv, *me;

	/* unlink the current thread and cleanup */
	me = current_thread;
	prv = &threads;
	while (*prv != me)
		prv = &(*prv)->next;
	*prv = me->next;

	current_thread = me->upper;
}

/**
 * Main processing loop of internal threads with processing jobs.
 * The loop must be called with the mutex locked
 * and it returns with the mutex locked.
 * @param me the description of the thread to use
 * TODO: how are timeout handled when reentering?
 */
static void thread_run_internal(volatile struct thread *me)
{
	struct job *job;

	/* enter thread */
	thread_enter(me);

	/* loop until stopped */
	while (!me->stop) {
		/* release the current event loop */
		evloop_release();

		/* get a job */
		job = job_get();
		if (job) {
			/* prepare running the job */
			job->blocked = 1; /* mark job as blocked */
			me->job = job; /* record the job (only for terminate) */

			/* run the job */
			pthread_mutex_unlock(&mutex);
			sig_monitor(job->timeout, job->callback, job->arg);
			pthread_mutex_lock(&mutex);

			/* release the run job */
			job_release(job);
		/* no job, check event loop wait */
		} else if (evloop_get()) {
			if (!evmgr_can_run(evmgr)) {
				/* busy ? */
				CRITICAL("Can't enter dispatch while in dispatch!");
				abort();
			}
			/* run the events */
			evmgr_prepare_run(evmgr);
			pthread_mutex_unlock(&mutex);
			sig_monitor(0, (void(*)(int,void*))evmgr_job_run, evmgr);
			pthread_mutex_lock(&mutex);
		} else {
			/* no job and no event loop */
			busy_thread_count--;
			if (!busy_thread_count)
				ERROR("Entering job deep sleep! Check your bindings.");
			me->waits = 1;
			pthread_cond_wait(&cond, &mutex);
			me->waits = 0;
			busy_thread_count++;
		}
	}
	/* cleanup */
	evloop_release();
	thread_leave();
}

/**
 * Main processing loop of external threads.
 * The loop must be called with the mutex locked
 * and it returns with the mutex locked.
 * @param me the description of the thread to use
 */
static void thread_run_external(volatile struct thread *me)
{
	/* enter thread */
	thread_enter(me);

	/* loop until stopped */
	me->waits = 1;
	while (!me->stop)
		pthread_cond_wait(&cond, &mutex);
	me->waits = 0;
	thread_leave();
}

/**
 * Root for created threads.
 */
static void thread_main()
{
	struct thread me;

	busy_thread_count++;
	started_thread_count++;
	sig_monitor_init_timeouts();
	thread_run_internal(&me);
	sig_monitor_clean_timeouts();
	started_thread_count--;
	busy_thread_count--;
}

/**
 * Entry point for created threads.
 * @param data not used
 * @return NULL
 */
static void *thread_starter(void *data)
{
	pthread_mutex_lock(&mutex);
	thread_main();
	pthread_mutex_unlock(&mutex);
	return NULL;
}

/**
 * Starts a new thread
 * @return 0 in case of success or -1 in case of error
 */
static int start_one_thread()
{
	pthread_t tid;
	int rc;

	rc = pthread_create(&tid, NULL, thread_starter, NULL);
	if (rc != 0) {
		/* errno = rc; */
		WARNING("not able to start thread: %m");
		rc = -1;
	}
	return rc;
}

/**
 * Queues a new asynchronous job represented by 'callback' and 'arg'
 * for the 'group' and the 'timeout'.
 * Jobs are queued FIFO and are possibly executed in parallel
 * concurrently except for job of the same group that are
 * executed sequentially in FIFO order.
 * @param group    The group of the job or NULL when no group.
 * @param timeout  The maximum execution time in seconds of the job
 *                 or 0 for unlimited time.
 * @param callback The function to execute for achieving the job.
 *                 Its first parameter is either 0 on normal flow
 *                 or the signal number that broke the normal flow.
 *                 The remaining parameter is the parameter 'arg1'
 *                 given here.
 * @param arg      The second argument for 'callback'
 * @param start    The start mode for threads
 * @return 0 in case of success or -1 in case of error
 */
static int queue_job_internal(
		const void *group,
		int timeout,
		void (*callback)(int, void*),
		void *arg,
		enum start_mode start_mode)
{
	struct job *job;
	int rc, busy;

	/* check availability */
	if (remaining_job_count <= 0) {
		ERROR("can't process job with threads: too many jobs");
		errno = EBUSY;
		goto error;
	}

	/* allocates the job */
	job = job_create(group, timeout, callback, arg);
	if (!job)
		goto error;

	/* start a thread if needed */
	busy = busy_thread_count == started_thread_count;
	if (start_mode != Start_Lazy
	 && busy
	 && (start_mode == Start_Urgent || remaining_job_count + started_thread_count < allowed_job_count)
	 && started_thread_count < allowed_thread_count) {
		/* all threads are busy and a new can be started */
		rc = start_one_thread();
		if (rc < 0 && started_thread_count == 0) {
			ERROR("can't start initial thread: %m");
			goto error2;
		}
		busy = 0;
	}

	/* queues the job */
	job_add(job);

	/* wakeup an evloop if needed */
	if (busy)
		evloop_wakeup();

	pthread_cond_signal(&cond);
	return 0;

error2:
	job->next = first_free_job;
	first_free_job = job;
error:
	return -1;
}

/**
 * Queues a new asynchronous job represented by 'callback' and 'arg'
 * for the 'group' and the 'timeout'.
 * Jobs are queued FIFO and are possibly executed in parallel
 * concurrently except for job of the same group that are
 * executed sequentially in FIFO order.
 * @param group    The group of the job or NULL when no group.
 * @param timeout  The maximum execution time in seconds of the job
 *                 or 0 for unlimited time.
 * @param callback The function to execute for achieving the job.
 *                 Its first parameter is either 0 on normal flow
 *                 or the signal number that broke the normal flow.
 *                 The remaining parameter is the parameter 'arg1'
 *                 given here.
 * @param arg      The second argument for 'callback'
 * @param start    The start mode for threads
 * @return 0 in case of success or -1 in case of error
 */
static int queue_job(
		const void *group,
		int timeout,
		void (*callback)(int, void*),
		void *arg,
		enum start_mode start_mode)
{
	int rc;

	pthread_mutex_lock(&mutex);
	rc = queue_job_internal(group, timeout, callback, arg, start_mode);
	pthread_mutex_unlock(&mutex);
	return rc;

}

/**
 * Queues a new asynchronous job represented by 'callback' and 'arg'
 * for the 'group' and the 'timeout'.
 * Jobs are queued FIFO and are possibly executed in parallel
 * concurrently except for job of the same group that are
 * executed sequentially in FIFO order.
 * @param group    The group of the job or NULL when no group.
 * @param timeout  The maximum execution time in seconds of the job
 *                 or 0 for unlimited time.
 * @param callback The function to execute for achieving the job.
 *                 Its first parameter is either 0 on normal flow
 *                 or the signal number that broke the normal flow.
 *                 The remaining parameter is the parameter 'arg1'
 *                 given here.
 * @param arg      The second argument for 'callback'
 * @return 0 in case of success or -1 in case of error
 */
int jobs_queue(
		const void *group,
		int timeout,
		void (*callback)(int, void*),
		void *arg)
{
	return queue_job(group, timeout, callback, arg, Start_Default);
}

/**
 * Queues lazyly a new asynchronous job represented by 'callback' and 'arg'
 * for the 'group' and the 'timeout'.
 * Jobs are queued FIFO and are possibly executed in parallel
 * concurrently except for job of the same group that are
 * executed sequentially in FIFO order.
 * @param group    The group of the job or NULL when no group.
 * @param timeout  The maximum execution time in seconds of the job
 *                 or 0 for unlimited time.
 * @param callback The function to execute for achieving the job.
 *                 Its first parameter is either 0 on normal flow
 *                 or the signal number that broke the normal flow.
 *                 The remaining parameter is the parameter 'arg1'
 *                 given here.
 * @param arg      The second argument for 'callback'
 * @return 0 in case of success or -1 in case of error
 */
int jobs_queue_lazy(
		const void *group,
		int timeout,
		void (*callback)(int, void*),
		void *arg)
{
	return queue_job(group, timeout, callback, arg, Start_Lazy);
}

/**
 * Queues urgently a new asynchronous job represented by 'callback' and 'arg'
 * for the 'group' and the 'timeout'.
 * Jobs are queued FIFO and are possibly executed in parallel
 * concurrently except for job of the same group that are
 * executed sequentially in FIFO order.
 * @param group    The group of the job or NULL when no group.
 * @param timeout  The maximum execution time in seconds of the job
 *                 or 0 for unlimited time.
 * @param callback The function to execute for achieving the job.
 *                 Its first parameter is either 0 on normal flow
 *                 or the signal number that broke the normal flow.
 *                 The remaining parameter is the parameter 'arg1'
 *                 given here.
 * @param arg      The second argument for 'callback'
 * @return 0 in case of success or -1 in case of error
 */
int jobs_queue_urgent(
		const void *group,
		int timeout,
		void (*callback)(int, void*),
		void *arg)
{
	return queue_job(group, timeout, callback, arg, Start_Urgent);
}

/**
 * Internal helper function for 'jobs_enter'.
 * @see jobs_enter, jobs_leave
 */
static void enter_cb(int signum, void *closure)
{
	struct sync *sync = closure;
	sync->enter(signum, sync->arg, (void*)&sync->thread);
}

/**
 * Internal helper function for 'jobs_call'.
 * @see jobs_call
 */
static void call_cb(int signum, void *closure)
{
	struct sync *sync = closure;
	sync->callback(signum, sync->arg);
	jobs_leave((void*)&sync->thread);
}

/**
 * Internal helper for synchronous jobs. It enters
 * a new thread loop for evaluating the given job
 * as recorded by the couple 'sync_cb' and 'sync'.
 * @see jobs_call, jobs_enter, jobs_leave
 */
static int do_sync(
		const void *group,
		int timeout,
		void (*sync_cb)(int signum, void *closure),
		struct sync *sync
)
{
	int rc;

	pthread_mutex_lock(&mutex);

	rc = queue_job_internal(group, timeout, sync_cb, sync, Start_Default);
	if (rc == 0) {
		/* run until stopped */
		if (current_thread)
			thread_run_internal(&sync->thread);
		else
			thread_run_external(&sync->thread);
		if (!sync->thread.leaved) {
			errno = EINTR;
			rc = -1;
		}
	}
	pthread_mutex_unlock(&mutex);
	return rc;
}

/**
 * Enter a synchronisation point: activates the job given by 'callback'
 * and 'closure' using 'group' and 'timeout' to control sequencing and
 * execution time.
 * @param group the group for sequencing jobs
 * @param timeout the time in seconds allocated to the job
 * @param callback the callback that will handle the job.
 *                 it receives 3 parameters: 'signum' that will be 0
 *                 on normal flow or the catched signal number in case
 *                 of interrupted flow, the context 'closure' as given and
 *                 a 'jobloop' reference that must be used when the job is
 *                 terminated to unlock the current execution flow.
 * @param closure the argument to the callback
 * @return 0 on success or -1 in case of error
 */
int jobs_enter(
		const void *group,
		int timeout,
		void (*callback)(int signum, void *closure, struct jobloop *jobloop),
		void *closure
)
{
	struct sync sync;

	sync.enter = callback;
	sync.arg = closure;
	return do_sync(group, timeout, enter_cb, &sync);
}

/**
 * Unlocks the execution flow designed by 'jobloop'.
 * @param jobloop indication of the flow to unlock
 * @return 0 in case of success of -1 on error
 */
int jobs_leave(struct jobloop *jobloop)
{
	struct thread *t;

	pthread_mutex_lock(&mutex);
	t = threads;
	while (t && t != (struct thread*)jobloop)
		t = t->next;
	if (!t) {
		errno = EINVAL;
	} else {
		t->leaved = 1;
		t->stop = 1;
		if (t->waits)
			pthread_cond_broadcast(&cond);
		else
			evloop_wakeup();
	}
	pthread_mutex_unlock(&mutex);
	return -!t;
}

/**
 * Calls synchronously the job represented by 'callback' and 'arg1'
 * for the 'group' and the 'timeout' and waits for its completion.
 * @param group    The group of the job or NULL when no group.
 * @param timeout  The maximum execution time in seconds of the job
 *                 or 0 for unlimited time.
 * @param callback The function to execute for achieving the job.
 *                 Its first parameter is either 0 on normal flow
 *                 or the signal number that broke the normal flow.
 *                 The remaining parameter is the parameter 'arg1'
 *                 given here.
 * @param arg      The second argument for 'callback'
 * @return 0 in case of success or -1 in case of error
 */
int jobs_call(
		const void *group,
		int timeout,
		void (*callback)(int, void*),
		void *arg)
{
	struct sync sync;

	sync.callback = callback;
	sync.arg = arg;

	return do_sync(group, timeout, call_cb, &sync);
}

/**
 * Ensure that the current running thread can control the event loop.
 */
void jobs_acquire_event_manager()
{
	struct thread lt;

	/* ensure an existing thread environment */
	if (!current_thread) {
		memset(&lt, 0, sizeof lt);
		current_thread = &lt;
	}

	/* lock */
	pthread_mutex_lock(&mutex);

	/* creates the evloop on need */
	if (!evmgr)
		evmgr_create(&evmgr);

	/* acquire the event loop under lock */
	if (evmgr)
		evloop_acquire();

	/* unlock */
	pthread_mutex_unlock(&mutex);

	/* release the faked thread environment if needed */
	if (current_thread == &lt) {
		/*
		 * Releasing it is needed because there is no way to guess
		 * when it has to be released really. But here is where it is
		 * hazardous: if the caller modifies the eventloop when it
		 * is waiting, there is no way to make the change effective.
		 * A workaround to achieve that goal is for the caller to
		 * require the event loop a second time after having modified it.
		 */
		NOTICE("Requiring event manager/loop from outside of binder's callback is hazardous!");
		if (verbose_wants(Log_Level_Info))
			sig_monitor_dumpstack();
		evloop_release();
		current_thread = NULL;
	}
}

/**
 * Enter the jobs processing loop.
 * @param allowed_count Maximum count of thread for jobs including this one
 * @param start_count   Count of thread to start now, must be lower.
 * @param waiter_count  Maximum count of jobs that can be waiting.
 * @param start         The start routine to activate (can't be NULL)
 * @return 0 in case of success or -1 in case of error.
 */
int jobs_start(
	int allowed_count,
	int start_count,
	int waiter_count,
	void (*start)(int signum, void* arg),
	void *arg)
{
	int rc, launched;
	struct job *job;

	assert(allowed_count >= 1);
	assert(start_count >= 0);
	assert(waiter_count > 0);
	assert(start_count <= allowed_count);

	rc = -1;
	pthread_mutex_lock(&mutex);

	/* check whether already running */
	if (current_thread || allowed_thread_count) {
		ERROR("thread already started");
		errno = EINVAL;
		goto error;
	}

	/* records the allowed count */
	allowed_thread_count = allowed_count;
	started_thread_count = 0;
	busy_thread_count = 0;
	remaining_job_count = waiter_count;
	allowed_job_count = waiter_count;

	/* start at least one thread: the current one */
	launched = 1;
	while (launched < start_count) {
		if (start_one_thread() != 0) {
			ERROR("Not all threads can be started");
			goto error;
		}
		launched++;
	}

	/* queue the start job */
	job = job_create(NULL, 0, start, arg);
	if (!job)
		goto error;
	job_add(job);

	/* run until end */
	thread_main();
	rc = 0;
error:
	pthread_mutex_unlock(&mutex);
	if (exit_handler)
		exit_handler();
	return rc;
}

/**
 * Exit jobs threads and call handler if not NULL.
 */
void jobs_exit(void (*handler)())
{
	struct thread *t;

	/* request all threads to stop */
	pthread_mutex_lock(&mutex);

	/* set the handler */
	exit_handler = handler;

	/* stops the threads */
	t = threads;
	while (t) {
		t->stop = 1;
		t = t->next;
	}

	/* wake up the threads */
	evloop_wakeup();
	pthread_cond_broadcast(&cond);

	/* leave */
	pthread_mutex_unlock(&mutex);
}
