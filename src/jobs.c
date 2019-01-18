/*
 * Copyright (C) 2016, 2017, 2018 "IoT.bzh"
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

#if defined(NO_JOBS_WATCHDOG)
#   define HAS_WATCHDOG 0
#else
#   define HAS_WATCHDOG 1
#endif

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
#include "fdev.h"
#if HAS_WATCHDOG
#include <systemd/sd-daemon.h>
#endif

#include "jobs.h"
#include "sig-monitor.h"
#include "verbose.h"

#define EVENT_TIMEOUT_TOP  	((uint64_t)-1)
#define EVENT_TIMEOUT_CHILD	((uint64_t)10000)

struct thread;

/** Internal shortcut for callback */
typedef void (*job_cb_t)(int, void*);

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

/** Description of handled event loops */
struct evloop
{
	unsigned state;        /**< encoded state */
	int efd;               /**< event notification */
	struct sd_event *sdev; /**< the systemd event loop */
	struct fdev *fdev;     /**< handling of events */
	struct thread *holder; /**< holder of the evloop */
};

#define EVLOOP_STATE_WAIT           1U
#define EVLOOP_STATE_RUN            2U

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

/* count allowed, started and running threads */
static int allowed = 0; /** allowed count of threads */
static int started = 0; /** started count of threads */
static int running = 0; /** running count of threads */
static int remains = 0; /** allowed count of waiting jobs */

/* list of threads */
static struct thread *threads;
static _Thread_local struct thread *current_thread;

/* queue of pending jobs */
static struct job *first_job;
static struct job *free_jobs;

/* event loop */
static struct evloop evloop;

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
	job = free_jobs;
	if (job)
		free_jobs = job->next;
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
	pjob = &first_job;
	ijob = first_job;
	while (ijob) {
		if (group && ijob->group == group)
			job->blocked = 1;
		pjob = &ijob->next;
		ijob = ijob->next;
	}

	/* queue the jobs */
	*pjob = job;
	remains--;
}

/**
 * Get the next job to process or NULL if none.
 * @return the first job that isn't blocked or NULL
 */
static inline struct job *job_get()
{
	struct job *job = first_job;
	while (job && job->blocked)
		job = job->next;
	if (job)
		remains++;
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
	pjob = &first_job;
	ijob = first_job;
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
	job->next = free_jobs;
	free_jobs = job;
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
static void job_cancel(int signum, void *arg)
{
	struct job *job = arg;
	job->callback(SIGABRT, job->arg);
}

/**
 * Monitored normal callback for events.
 * This function is called by the monitor
 * to run the event loop when the safe environment
 * is set.
 * @param signum 0 on normal flow or the number
 *               of the signal that interrupted the normal
 *               flow
 * @param arg     the events to run
 */
static void evloop_run(int signum, void *arg)
{
	int rc;
	struct sd_event *se;

	if (!signum) {
		se = evloop.sdev;
		rc = sd_event_prepare(se);
		if (rc < 0) {
			errno = -rc;
			CRITICAL("sd_event_prepare returned an error (state: %d): %m", sd_event_get_state(se));
			abort();
		} else {
			if (rc == 0) {
				rc = sd_event_wait(se, (uint64_t)(int64_t)-1);
				if (rc < 0) {
					errno = -rc;
					ERROR("sd_event_wait returned an error (state: %d): %m", sd_event_get_state(se));
				}
			}
			evloop.state = EVLOOP_STATE_RUN;
			if (rc > 0) {
				rc = sd_event_dispatch(se);
				if (rc < 0) {
					errno = -rc;
					ERROR("sd_event_dispatch returned an error (state: %d): %m", sd_event_get_state(se));
				}
			}
		}
	}
}

/**
 * Internal callback for evloop management.
 * The effect of this function is hidden: it exits
 * the waiting poll if any.
 */
static void evloop_on_efd_event()
{
	uint64_t x;
	read(evloop.efd, &x, sizeof x);
}

/**
 * wakeup the event loop if needed by sending
 * an event.
 */
static void evloop_wakeup()
{
	uint64_t x;

	if (evloop.state & EVLOOP_STATE_WAIT) {
		x = 1;
		write(evloop.efd, &x, sizeof x);
	}
}

/**
 * Release the currently held event loop
 */
static void evloop_release()
{
	struct thread *nh, *ct = current_thread;

	if (evloop.holder == ct) {
		nh = ct->nholder;
		evloop.holder = nh;
		if (nh)
			pthread_cond_signal(nh->cwhold);
	}
}

/**
 * get the eventloop for the current thread
 */
static int evloop_get()
{
	struct thread *ct = current_thread;

	if (evloop.holder)
		return evloop.holder == ct;

	ct->nholder = NULL;
	evloop.holder = ct;
	return 1;
}

/**
 * acquire the eventloop for the current thread
 */
static void evloop_acquire()
{
	struct thread **pwait, *ct;
	pthread_cond_t cond;

	/* try to get the evloop */
	if (!evloop_get()) {
		/* failed, init waiting state */
		ct = current_thread;
		ct->nholder = NULL;
		ct->cwhold = &cond;
		pthread_cond_init(&cond, NULL);

		/* queue current thread in holder list */
		pwait = &evloop.holder;
		while (*pwait)
			pwait = &(*pwait)->nholder;
		*pwait = ct;

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
	/* initialize description of itself and link it in the list */
	me->tid = pthread_self();
	me->stop = 0;
	me->waits = 0;
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
			if (evloop.state != 0) {
				/* busy ? */
				CRITICAL("Can't enter dispatch while in dispatch!");
				abort();
			}
			/* run the events */
			evloop.state = EVLOOP_STATE_RUN|EVLOOP_STATE_WAIT;
			pthread_mutex_unlock(&mutex);
			sig_monitor(0, evloop_run, NULL);
			pthread_mutex_lock(&mutex);
			evloop.state = 0;
		} else {
			/* no job and no event loop */
			running--;
			if (!running)
				ERROR("Entering job deep sleep! Check your bindings.");
			me->waits = 1;
			pthread_cond_wait(&cond, &mutex);
			me->waits = 0;
			running++;
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

	running++;
	started++;
	sig_monitor_init_timeouts();
	thread_run_internal(&me);
	sig_monitor_clean_timeouts();
	started--;
	running--;
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
 * @return 0 in case of success or -1 in case of error
 */
int jobs_queue(
		const void *group,
		int timeout,
		void (*callback)(int, void*),
		void *arg)
{
	struct job *job;
	int rc;

	pthread_mutex_lock(&mutex);

	/* allocates the job */
	job = job_create(group, timeout, callback, arg);
	if (!job)
		goto error;

	/* check availability */
	if (remains <= 0) {
		ERROR("can't process job with threads: too many jobs");
		errno = EBUSY;
		goto error2;
	}

	/* start a thread if needed */
	if (running == started && started < allowed) {
		/* all threads are busy and a new can be started */
		rc = start_one_thread();
		if (rc < 0 && started == 0) {
			ERROR("can't start initial thread: %m");
			goto error2;
		}
	}

	/* queues the job */
	job_add(job);

	/* signal an existing job */
	pthread_cond_signal(&cond);
	pthread_mutex_unlock(&mutex);
	return 0;

error2:
	job->next = free_jobs;
	free_jobs = job;
error:
	pthread_mutex_unlock(&mutex);
	return -1;
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
	struct job *job;

	pthread_mutex_lock(&mutex);

	/* allocates the job */
	job = job_create(group, timeout, sync_cb, sync);
	if (!job) {
		pthread_mutex_unlock(&mutex);
		return -1;
	}

	/* queues the job */
	job_add(job);

	/* run until stopped */
	if (current_thread)
		thread_run_internal(&sync->thread);
	else
		thread_run_external(&sync->thread);
	pthread_mutex_unlock(&mutex);
	return 0;
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
 * Internal callback for evloop management.
 * The effect of this function is hidden: it exits
 * the waiting poll if any. Then it wakes up a thread
 * awaiting the evloop using signal.
 */
static int on_evloop_efd(sd_event_source *s, int fd, uint32_t revents, void *userdata)
{
	evloop_on_efd_event();
	return 1;
}

/**
 * Gets a sd_event item for the current thread.
 * @return a sd_event or NULL in case of error
 */
static struct sd_event *get_sd_event_locked()
{
	int rc;

	/* creates the evloop on need */
	if (!evloop.sdev) {
		/* start the creation */
		evloop.state = 0;
		/* creates the eventfd for waking up polls */
		evloop.efd = eventfd(0, EFD_CLOEXEC|EFD_SEMAPHORE);
		if (evloop.efd < 0) {
			ERROR("can't make eventfd for events");
			goto error1;
		}
		/* create the systemd event loop */
		rc = sd_event_new(&evloop.sdev);
		if (rc < 0) {
			ERROR("can't make new event loop");
			goto error2;
		}
		/* put the eventfd in the event loop */
		rc = sd_event_add_io(evloop.sdev, NULL, evloop.efd, EPOLLIN, on_evloop_efd, NULL);
		if (rc < 0) {
			ERROR("can't register eventfd");
			sd_event_unref(evloop.sdev);
			evloop.sdev = NULL;
error2:
			close(evloop.efd);
error1:
			return NULL;
		}
	}

	/* acquire the event loop */
	evloop_acquire();

	return evloop.sdev;
}

/**
 * Gets a sd_event item for the current thread.
 * @return a sd_event or NULL in case of error
 */
struct sd_event *jobs_get_sd_event()
{
	struct sd_event *result;
	struct thread lt;

	/* ensure an existing thread environment */
	if (!current_thread) {
		memset(&lt, 0, sizeof lt);
		current_thread = &lt;
	}

	/* process */
	pthread_mutex_lock(&mutex);
	result = get_sd_event_locked();
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
		NOTICE("Requiring sd_event loop out of binder callbacks is hazardous!");
		if (verbose_wants(Log_Level_Info))
			sig_monitor_dumpstack();
		evloop_release();
		current_thread = NULL;
	}

	return result;
}

/**
 * Enter the jobs processing loop.
 * @param allowed_count Maximum count of thread for jobs including this one
 * @param start_count   Count of thread to start now, must be lower.
 * @param waiter_count  Maximum count of jobs that can be waiting.
 * @param start         The start routine to activate (can't be NULL)
 * @return 0 in case of success or -1 in case of error.
 */
int jobs_start(int allowed_count, int start_count, int waiter_count, void (*start)(int signum, void* arg), void *arg)
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
	if (current_thread || allowed) {
		ERROR("thread already started");
		errno = EINVAL;
		goto error;
	}

	/* records the allowed count */
	allowed = allowed_count;
	started = 0;
	running = 0;
	remains = waiter_count;

#if HAS_WATCHDOG
	/* set the watchdog */
	if (sd_watchdog_enabled(0, NULL))
		sd_event_set_watchdog(get_sd_event_locked(), 1);
#endif

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
	return rc;
}

/**
 * Terminate all the threads and cancel all pending jobs.
 */
void jobs_terminate()
{
	struct job *job, *head, *tail;
	pthread_t me, *others;
	struct thread *t;
	int count;

	/* how am i? */
	me = pthread_self();

	/* request all threads to stop */
	pthread_mutex_lock(&mutex);
	allowed = 0;

	/* count the number of threads */
	count = 0;
	t = threads;
	while (t) {
		if (!t->upper && !pthread_equal(t->tid, me))
			count++;
		t = t->next;
	}

	/* fill the array of threads */
	others = alloca(count * sizeof *others);
	count = 0;
	t = threads;
	while (t) {
		if (!t->upper && !pthread_equal(t->tid, me))
			others[count++] = t->tid;
		t = t->next;
	}

	/* stops the threads */
	t = threads;
	while (t) {
		t->stop = 1;
		t = t->next;
	}

	/* wait the threads */
	pthread_cond_broadcast(&cond);
	pthread_mutex_unlock(&mutex);
	while (count)
		pthread_join(others[--count], NULL);
	pthread_mutex_lock(&mutex);

	/* cancel pending jobs of other threads */
	remains = 0;
	head = first_job;
	first_job = NULL;
	tail = NULL;
	while (head) {
		/* unlink the job */
		job = head;
		head = job->next;

		/* search if job is stacked for current */
		t = current_thread;
		while (t && t->job != job)
			t = t->upper;
		if (t) {
			/* yes, relink it at end */
			if (tail)
				tail->next = job;
			else
				first_job = job;
			tail = job;
			job->next = NULL;
		} else {
			/* no cancel the job */
			pthread_mutex_unlock(&mutex);
			sig_monitor(0, job_cancel, job);
			free(job);
			pthread_mutex_lock(&mutex);
		}
	}
	pthread_mutex_unlock(&mutex);
}

