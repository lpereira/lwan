/*
 * lwan - web server
 * Copyright (c) 2012 L. A. F. Pereira <l@tia.mat.br>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <unistd.h>

#include "lwan.h"

#if !defined(LWAN_HAVE_EPOLL) && defined(LWAN_HAVE_KQUEUE)
#include <sys/event.h>
#include <sys/time.h>
#include <sys/types.h>

#include "hash.h"

int epoll_create1(int flags)
{
#if defined(LWAN_HAVE_KQUEUE1)
    return kqueue1(flags & EPOLL_CLOEXEC ? O_CLOEXEC : 0);
#else
    int fd = kqueue();

    if (flags & EPOLL_CLOEXEC) {
        int flags;

        flags = fcntl(fd, F_GETFD);
        if (flags < 0)
            return -1;

        if (fcntl(fd, F_SETFD, flags | O_CLOEXEC) < 0)
            return -1;
    }

    return fd;
#endif
}

static int epoll_no_event_marker;

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
    struct kevent ev;

    switch (op) {
    case EPOLL_CTL_ADD:
    case EPOLL_CTL_MOD: {
        int events = 0;
        void *udata = event->data.ptr;
        int flags = EV_ADD;

        if (event->events & EPOLLIN) {
            events = EVFILT_READ;
        } else if (event->events & EPOLLOUT) {
            events = EVFILT_WRITE;
        } else {
            events = EVFILT_WRITE;
            udata = &epoll_no_event_marker;
        }

        if (event->events & EPOLLONESHOT)
            flags |= EV_ONESHOT;
        if (event->events & EPOLLET)
            flags |= EV_CLEAR;

        flags |= EV_ERROR; /* EPOLLERR is always set. */
        flags |= EV_EOF;   /* EPOLLHUP is always set. */

        EV_SET(&ev, fd, events, flags, 0, 0, udata);
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

static struct timespec *to_timespec(struct timespec *t, int ms)
{
    if (ms < 0)
        return NULL;

    t->tv_sec = ms / 1000;
    t->tv_nsec = (ms % 1000) * 1000000;

    return t;
}

int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)
{
    struct epoll_event *ev = events;
    struct kevent evs[maxevents];
    struct timespec tmspec;
    struct hash *coalesce;
    int i, r;

    coalesce = hash_int_new(NULL, NULL);
    if (UNLIKELY(!coalesce))
        return -1;

    r = kevent(epfd, NULL, 0, evs, maxevents, to_timespec(&tmspec, timeout));
    if (UNLIKELY(r < 0)) {
        hash_free(coalesce);
        return -1;
    }

    for (i = 0; i < r; i++) {
        struct kevent *kev = &evs[i];
        uint32_t mask = (uint32_t)(uintptr_t)hash_find(
            coalesce, (void *)(intptr_t)evs[i].ident);

        if (kev->flags & EV_ERROR)
            mask |= EPOLLERR;
        if (kev->flags & EV_EOF)
            mask |= EPOLLRDHUP;

        if (kev->filter == EVFILT_READ)
            mask |= EPOLLIN;
        else if (kev->filter == EVFILT_WRITE && evs[i].udata != &epoll_no_event_marker)
            mask |= EPOLLOUT;

        hash_add(coalesce, (void *)(intptr_t)evs[i].ident,
                 (void *)(uintptr_t)mask);
    }

    for (i = 0; i < r; i++) {
        void *maskptr;

        maskptr = hash_find(coalesce, (void *)(intptr_t)evs[i].ident);
        if (maskptr) {
            struct kevent *kev = &evs[i];

            if (kev->udata == &epoll_no_event_marker)
                continue;

            ev->data.ptr = kev->udata;
            ev->events = (uint32_t)(uintptr_t)maskptr;
            ev++;
        }
    }

    hash_free(coalesce);
    return (int)(intptr_t)(ev - events);
}
#elif !defined(LWAN_HAVE_EPOLL)
#error epoll() not implemented for this platform
#endif

