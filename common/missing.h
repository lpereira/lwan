/*
 * lwan - simple web server
 * Copyright (c) 2012 Leandro A. F. Pereira <leandro@hardinfo.org>
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

#pragma once

#include <time.h>

#undef static_assert
#if HAVE_STATIC_ASSERT
#define static_assert(expr, msg)	_Static_assert(expr, msg)
#else
#define static_assert(expr, msg)
#endif

#define strndupa_impl(s, l) ({ \
   char *strndupa_tmp_s = alloca(l + 1); \
   strndupa_tmp_s[l] = '\0'; \
   memcpy(strndupa_tmp_s, s, l); \
})

#ifndef strndupa
#define strndupa(s, l) strndupa_impl((s), strnlen((s), (l)))
#endif

#ifndef strdupa
#define strdupa(s) strndupa((s), strlen(s))
#endif

#ifndef HAS_RAWMEMCHR
#define rawmemchr(s, c) memchr((s), (c), SIZE_MAX)
#endif

#ifndef HAS_PTHREADBARRIER
#include <pthread.h>

typedef int pthread_barrierattr_t;
typedef struct pthread_barrier {
    unsigned int count;
    unsigned int in;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
} pthread_barrier_t;

int pthread_barrier_init(pthread_barrier_t *restrict barrier, const pthread_barrierattr_t *restrict attr, unsigned int count);
int pthread_barrier_destroy(pthread_barrier_t *barrier);
int pthread_barrier_wait(pthread_barrier_t *barrier);
#endif

#ifndef HAS_MEMPCPY
void *mempcpy(void *dest, const void *src, size_t len);
#endif

#ifndef HAS_MEMRCHR
void *memrchr(const void *s, int c, size_t n);
#endif

#ifndef HAS_PIPE2
int pipe2(int pipefd[2], int flags);
#endif

#ifndef HAS_ACCEPT4
int accept4(int sock, struct sockaddr *addr, socklen_t *addrlen, int flags);
#endif

#ifndef HAS_CLOCK_GETTIME
typedef int clockid_t;
int clock_gettime(clockid_t clk_id, struct timespec *ts);

# ifndef CLOCK_MONOTONIC_COARSE
#  define CLOCK_MONOTONIC_COARSE 0
# endif

# ifndef CLOCK_MONOTONIC
#  define CLOCK_MONOTONIC 1
# endif
#endif

#ifndef HAS_TIMEDJOIN
#include <pthread.h>
int pthread_timedjoin_np(pthread_t thread, void **retval, const struct timespec *abstime);
#endif

#ifndef MSG_MORE
#define MSG_MORE 0
#endif

#ifndef O_NOATIME
#define O_NOATIME 0
#endif

#ifndef O_PATH
#define O_PATH 0
#endif

#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 0
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#ifndef OPEN_MAX
#define OPEN_MAX 65535
#endif

#ifndef SOCK_NONBLOCK
#define SOCK_NONBLOCK 00004000
#endif
