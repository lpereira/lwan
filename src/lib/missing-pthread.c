/*
 * lwan - web server
 * Copyright (c) 2018 L. A. F. Pereira <l@tia.mat.br>
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
#include <errno.h>
#include <string.h>
#include <pthread.h>

#ifdef __FreeBSD__
#include <pthread_np.h>
#endif

#include "lwan-private.h"

#ifndef LWAN_HAVE_PTHREADBARRIER
#define PTHREAD_BARRIER_SERIAL_THREAD -1

int
pthread_barrier_init(pthread_barrier_t *restrict barrier,
        const pthread_barrierattr_t *restrict attr __attribute__((unused)),
        unsigned int count) {
    if (count == 0) {
        return -1;
    }

    barrier->count = count;
    barrier->in = 0;

    if (pthread_mutex_init(&barrier->mutex, NULL) < 0)
        return -1;

    if (pthread_cond_init(&barrier->cond, NULL) < 0) {
        pthread_mutex_destroy(&barrier->mutex);
        return -1;
    }

    return 0;
}

int
pthread_barrier_destroy(pthread_barrier_t *barrier)
{
    pthread_mutex_destroy(&barrier->mutex);
    pthread_cond_destroy(&barrier->cond);
    barrier->in = 0;

    return 0;
}

int
pthread_barrier_wait(pthread_barrier_t *barrier)
{
    pthread_mutex_lock(&barrier->mutex);

    barrier->in++;
    if (barrier->in >= barrier->count) {
        barrier->in = 0;
        pthread_cond_broadcast(&barrier->cond);
        pthread_mutex_unlock(&barrier->mutex);

        return PTHREAD_BARRIER_SERIAL_THREAD;
    }

    pthread_cond_wait(&barrier->cond, &barrier->mutex);
    pthread_mutex_unlock(&barrier->mutex);

    return 0;
}
#endif

#if defined(__linux__)
int pthread_set_name_np(pthread_t thread, const char *name)
{
    return pthread_setname_np(thread, name);
}
#elif defined(__APPLE__)
int pthread_set_name_np(pthread_t thread, const char *name)
{
    if (!pthread_equal(thread, pthread_self()))
        return EPERM;

    /* macOS takes a char*; I don't know if it's modified or not, so
     * copy it on the stack. */
    return pthread_setname_np(strdupa(name));
}
#endif
