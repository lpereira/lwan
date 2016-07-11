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

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "lwan.h"

#ifndef HAS_PTHREADBARRIER
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
    if (__sync_add_and_fetch(&barrier->in, 1) >= barrier->count) {
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

#ifndef HAS_MEMPCPY
void *
mempcpy(void *dest, const void *src, size_t len)
{
    char *p = memcpy(dest, src, len);
    return p + len;
}
#endif

#ifndef HAS_MEMRCHR
void *
memrchr(const void *s, int c, size_t n)
{
    const unsigned char *cp;
    unsigned char *p = (unsigned char *)s;
    unsigned char chr = (unsigned char)c;

    if (n != 0) {
        cp = p + n;
        do {
            if (*(--cp) == chr)
                return (void *)cp;
        } while (--n != 0);
    }

    return NULL;
}
#endif

#ifndef HAS_PIPE2
int
pipe2(int pipefd[2], int flags)
{
   int r;

   r = pipe(pipefd);
   if (r < 0)
      return r;

   if (fcntl(pipefd[0], F_SETFL, flags) < 0 || fcntl(pipefd[1], F_SETFL, flags) < 0) {
      int saved_errno = errno;

      close(pipefd[0]);
      close(pipefd[1]);

      errno = saved_errno;
      return -1;
   }

   return 0;
}
#endif

#ifndef HAS_ACCEPT4
int
accept4(int sock, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
   int fd = accept(sock, addr, addrlen);
   int newflags = 0;

   if (fd < 0)
       return fd;

   if (flags & SOCK_NONBLOCK) {
       newflags |= O_NONBLOCK;
       flags &= ~SOCK_NONBLOCK;
   }
   if (flags & SOCK_CLOEXEC) {
       newflags |= O_CLOEXEC;
       flags &= ~SOCK_CLOEXEC;
   }
   if (flags) {
       errno = -EINVAL;
       return -1;
   }

   if (fcntl(fd, F_SETFL, newflags) < 0) {
       int saved_errno = errno;

       close(fd);

       errno = saved_errno;
       return -1;
   }

   return fd;
}
#endif

#ifndef HAS_CLOCK_GETTIME
int
clock_gettime(clockid_t clk_id, struct timespec *ts)
{
   switch (clk_id) {
   case CLOCK_MONOTONIC:
   case CLOCK_MONOTONIC_COARSE:
       /* FIXME: time() isn't monotonic */
       ts->tv_sec = time(NULL);
       ts->tv_nsec = 0;
       return 0;
   }

   errno = EINVAL;
   return -1;
}
#endif

#ifndef HAS_TIMEDJOIN
int
pthread_timedjoin_np(pthread_t thread, void **retval,
   const struct timespec *abstime __attribute__((unused)))
{
   return pthread_join(thread, retval);
}
#endif

#if defined(__FreeBSD__) || defined(__APPLE__)
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>

#include "hash.h"

int
epoll_create1(int flags __attribute__((unused)))
{
    return kqueue();
}

int
epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
    struct kevent ev;

    switch (op) {
    case EPOLL_CTL_ADD:
    case EPOLL_CTL_MOD: {
        int events = 0;
        int flags = EV_ADD;

        if (event->events & EPOLLIN)
            events = EVFILT_READ;
        if (event->events & EPOLLOUT)
            events = EVFILT_WRITE;

        if (event->events & EPOLLONESHOT)
            flags |= EV_ONESHOT;
        if (event->events & EPOLLRDHUP)
            flags |= EV_EOF;
        if (event->events & EPOLLERR)
            flags |= EV_ERROR;
        if (event->events & EPOLLET)
            flags |= EV_CLEAR;

        EV_SET(&ev, fd, events, flags, 0, 0, event->data.ptr);
        break;
    }

    case EPOLL_CTL_DEL:
        EV_SET(&ev, fd, 0, EV_DELETE, 0, 0, 0);
        break;

    default:
        errno = EINVAL;
        return -1;
    }

    return kevent(epfd, &ev, 1, NULL, 0, NULL);
}

static struct timespec *
to_timespec(struct timespec *t, int ms)
{
    if (ms < 0)
        return NULL;

    t->tv_sec = ms / 1000;
    t->tv_nsec = (ms % 1000) * 1000000;

    return t;
}

int
epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)
{
    struct epoll_event *ev = events;
    struct kevent evs[maxevents];
    struct timespec tmspec;
    struct hash *coalesce;
    int i, r;

    coalesce = hash_int_new(NULL, NULL);
    if (!coalesce)
        return -1;

    r = kevent(epfd, NULL, 0, evs, maxevents, to_timespec(&tmspec, timeout));
    if (UNLIKELY(r < 0))
        return -1;

    for (i = 0; i < r; i++) {
        struct kevent *kev = &evs[i];
        uint32_t mask = (uint32_t)(uintptr_t)hash_find(coalesce,
            (void*)(intptr_t)evs[i].ident);

        if (kev->flags & EV_ERROR)
            mask |= EPOLLERR;
        if (kev->flags & EV_EOF)
            mask |= EPOLLRDHUP;

        if (kev->filter == EVFILT_READ)
            mask |= EPOLLIN;
        else if (kev->filter == EVFILT_WRITE)
            mask |= EPOLLOUT;

        hash_add(coalesce, (void*)(intptr_t)evs[i].ident, (void *)(uintptr_t)mask);
    }

    for (i = 0; i < r; i++) {
        void *maskptr = hash_find(coalesce, (void*)(intptr_t)evs[i].ident);

        if (maskptr) {
            struct kevent *kev = &evs[i];

            hash_del(coalesce, (void*)(intptr_t)evs[i].ident);

            ev->data.ptr = kev->udata;
            ev->events = (uint32_t)(uintptr_t)maskptr;
            ev++;
        }
    }

    hash_free(coalesce);
    return (int)(intptr_t)(ev - events);
}
#endif
