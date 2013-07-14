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

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "lwan.h"
#include "lwan-status.h"

struct job_t {
  void (*cb)(void *data);
  void *data;
  struct job_t *next;
};

static pthread_t self;
static pthread_mutex_t queue_mutex;
static bool running = false;
static struct job_t *jobs = NULL;

static void*
job_thread(void *data __attribute__((unused)))
{
  static const struct timespec rgtp = { 1, 0 };

  while (running) {
    struct job_t *job;

    pthread_mutex_lock(&queue_mutex);
    for (job = jobs; job; job = job->next)
      job->cb(job->data);
    pthread_mutex_unlock(&queue_mutex);

    if (UNLIKELY(nanosleep(&rgtp, NULL) < 0)) {
      if (errno == EINTR)
        sleep(1);
    }
  }

  return NULL;
}

void lwan_job_thread_init(void)
{
  assert(!running);

  lwan_status_debug("Initializing low priority job thread");

  running = true;
  if (pthread_create(&self, NULL, job_thread, NULL) < 0)
    lwan_status_critical_perror("pthread_create");
}

void lwan_job_thread_shutdown(void)
{
  lwan_status_debug("Shutting down job thread");

  pthread_mutex_lock(&queue_mutex);
  struct job_t *job = jobs, *next;
  for (; job; job = next) {
    next = job->next;
    free(job);
  }
  jobs = NULL;
  running = false;
  if (pthread_join(self, NULL) < 0)
    lwan_status_critical_perror("pthread_join");
  pthread_mutex_unlock(&queue_mutex);
}

void lwan_job_add(void (*cb)(void *data), void *data)
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
  job->next = jobs;
  jobs = job;
  pthread_mutex_unlock(&queue_mutex);
}

void lwan_job_del(void (*cb)(void *data), void *data __attribute__((unused)))
{
  struct job_t *curr, *prev;

  assert(cb);

  pthread_mutex_lock(&queue_mutex);

  prev = NULL;
  for (curr = jobs; curr; prev = curr, curr = curr->next) {
    if (cb == curr->cb && data == curr->data) {
      if (!prev)
        jobs = curr->next;
      else
        prev->next = curr->next;
      free(curr);
      break;
    }
  }

  pthread_mutex_unlock(&queue_mutex);
}
