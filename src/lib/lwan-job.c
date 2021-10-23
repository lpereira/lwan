/*
 * lwan - simple web server
 * Copyright (c) 2012, 2013 L. A. F. Pereira <l@tia.mat.br>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <ioprio.h>
#include <pthread.h>
#include <sched.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>

#include "lwan-private.h"
#include "lwan-status.h"
#include "list.h"

struct job {
    struct list_node jobs;
    bool (*cb)(void *data);
    void *data;
};

static pthread_t self;
static pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool running = false;
static struct list_head jobs;

static pthread_mutex_t job_wait_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t job_wait_cond = PTHREAD_COND_INITIALIZER;

static void
timedwait(bool had_job)
{
    static int secs = 1;
    struct timeval now;

    if (had_job)
        secs = 1;
    else if (secs <= 15)
        secs++;

    gettimeofday(&now, NULL);

    struct timespec rgtp = { now.tv_sec + secs, now.tv_usec * 1000 };
    pthread_cond_timedwait(&job_wait_cond, &job_wait_mutex, &rgtp);
}

void lwan_job_thread_main_loop(void)
{
    /* Idle priority for the calling thread.   Magic value of `7` obtained from
     * sample program in linux/Documentation/block/ioprio.txt.  This is a no-op
     * on anything but Linux.  */
    ioprio_set(IOPRIO_WHO_PROCESS, 0, IOPRIO_PRIO_VALUE(IOPRIO_CLASS_IDLE, 7));

    lwan_set_thread_name("job");

    if (pthread_mutex_lock(&job_wait_mutex))
        lwan_status_critical("Could not lock job wait mutex");
    
    while (running) {
        bool had_job = false;

        if (LIKELY(!pthread_mutex_lock(&queue_mutex))) {
            struct job *job;

            list_for_each(&jobs, job, jobs)
                had_job |= job->cb(job->data);

            pthread_mutex_unlock(&queue_mutex);
        }

        timedwait(had_job);
    }

    if (pthread_mutex_unlock(&job_wait_mutex))
        lwan_status_critical("Could not lock job wait mutex");
}

void lwan_job_thread_init(void)
{
    assert(!running);

    lwan_status_debug("Initializing low priority job thread");

    list_head_init(&jobs);

    self = pthread_self();
    running = true;

#ifdef SCHED_IDLE
    struct sched_param sched_param = {
        .sched_priority = 0
    };
    if (pthread_setschedparam(self, SCHED_IDLE, &sched_param) < 0)
        lwan_status_perror("pthread_setschedparam");
#endif  /* SCHED_IDLE */
}

void lwan_job_thread_shutdown(void)
{
    lwan_status_debug("Shutting down job thread");

    if (LIKELY(!pthread_mutex_lock(&queue_mutex))) {
        struct job *node, *next;
        int r;

        list_for_each_safe(&jobs, node, next, jobs) {
            list_del(&node->jobs);
            free(node);
        }
        running = false;

        pthread_cond_signal(&job_wait_cond);

        r = pthread_join(self, NULL);
        if (r) {
            errno = r;
            lwan_status_perror("pthread_join");
        }

        pthread_mutex_unlock(&queue_mutex);
    }
}

void lwan_job_add(bool (*cb)(void *data), void *data)
{
    assert(cb);

    struct job *job = calloc(1, sizeof(*job));
    if (!job)
        lwan_status_critical_perror("calloc");

    job->cb = cb;
    job->data = data;

    if (LIKELY(!pthread_mutex_lock(&queue_mutex))) {
        list_add(&jobs, &job->jobs);
        pthread_mutex_unlock(&queue_mutex);
    } else {
        lwan_status_warning("Couldn't lock job mutex");
        free(job);
    }
}

void lwan_job_del(bool (*cb)(void *data), void *data)
{
    struct job *node, *next;

    assert(cb);

    if (LIKELY(!pthread_mutex_lock(&queue_mutex))) {
        list_for_each_safe(&jobs, node, next, jobs) {
            if (cb == node->cb && data == node->data) {
                list_del(&node->jobs);
                free(node);
            }
        }
        pthread_mutex_unlock(&queue_mutex);
    }
}
