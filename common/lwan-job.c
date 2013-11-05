/*
 * lwan - simple web server
 * Copyright (c) 2012, 2013 Leandro A. F. Pereira <leandro@hardinfo.org>
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
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

#include "lwan.h"
#include "lwan-status.h"
#include "list.h"

struct job_t {
  struct list_node jobs;
  bool (*cb)(void *data);
  void *data;
};

static pthread_t self;
static pthread_mutex_t queue_mutex;
static bool running = false;
static struct list_head jobs;

static void*
job_thread(void *data __attribute__((unused)))
{
  struct timespec rgtp = { 1, 0 };

  while (running) {
    struct job_t *job;
    bool had_job = false;

    pthread_mutex_lock(&queue_mutex);
    list_for_each(&jobs, job, jobs)
      had_job |= job->cb(job->data);
    pthread_mutex_unlock(&queue_mutex);

    if (had_job)
      rgtp.tv_sec = 1;
    else if (rgtp.tv_sec <= 15)
      rgtp.tv_sec++;

    if (UNLIKELY(nanosleep(&rgtp, NULL) < 0)) {
      if (errno == EINTR)
        sleep(1);
    }
  }

  return NULL;
}

void lwan_job_thread_init(void)
{
  struct sched_param sched_param = {
    .sched_priority = 0
  };

  assert(!running);

  lwan_status_debug("Initializing low priority job thread");

  list_head_init(&jobs);

  running = true;
  if (pthread_create(&self, NULL, job_thread, NULL) < 0)
    lwan_status_critical_perror("pthread_create");
  if (pthread_setschedparam(self, 5 /* SCHED_IDLE */, &sched_param) < 0)
    lwan_status_perror("pthread_setschedparam");
}

void lwan_job_thread_shutdown(void)
{
  lwan_status_debug("Shutting down job thread");

  pthread_mutex_lock(&queue_mutex);
  struct job_t *node, *next;
  list_for_each_safe(&jobs, node, next, jobs) {
    list_del(&node->jobs);
    free(node);
  }
  running = false;
#ifdef __linux__
  if (pthread_tryjoin_np(self, NULL) < 0)
#else
  if (pthread_join(self, NULL) < 0)
#endif
    lwan_status_critical_perror("pthread_join");
  pthread_mutex_unlock(&queue_mutex);
}

void lwan_job_add(bool (*cb)(void *data), void *data)
{
  assert(cb);

  struct job_t *job = calloc(1, sizeof(*job));
  if (!job) {
    lwan_status_critical_perror("calloc");
    return;
  }

  job->cb = cb;
  job->data = data;

  pthread_mutex_lock(&queue_mutex);
  list_add(&jobs, &job->jobs);
  pthread_mutex_unlock(&queue_mutex);
}

void lwan_job_del(bool (*cb)(void *data), void *data)
{
  struct job_t *node, *next;

  assert(cb);

  pthread_mutex_lock(&queue_mutex);
  list_for_each_safe(&jobs, node, next, jobs) {
    if (cb == node->cb && data == node->data) {
      list_del(&node->jobs);
      free(node);
    }
  }
  pthread_mutex_unlock(&queue_mutex);
}
