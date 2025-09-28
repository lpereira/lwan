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

#include "lwan-private.h"

#if !defined(LWAN_HAVE_EPOLL) && defined(LWAN_HAVE_KQUEUE)
#include <sys/event.h>
#include <sys/time.h>
#include <sys/types.h>

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
            /* kqueue needs an event filter to track a file descriptor,
             * but epoll doesn't. So create a fake one here and check for
             * it when converting from kevents to epoll_events. */
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

static int kevent_ident_cmp(const void *ptr0, const void *ptr1)
{
    const struct kevent *ev0 = ptr0;
    const struct kevent *ev1 = ptr1;
    return (ev0->ident > ev1->ident) - (ev0->ident < ev1->ident);
}

int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)
{
    struct epoll_event *ev = events;
    struct kevent *evs = alloca(sizeof(*evs) * LWAN_MIN(1024, maxevents));
    struct timespec tmspec;
    int i, r;

    r = kevent(epfd, NULL, 0, evs, maxevents, to_timespec(&tmspec, timeout));
    if (UNLIKELY(r < 0)) {
        return -1;
    }

    qsort(evs, (size_t)r, sizeof(struct kevent), kevent_ident_cmp);

    uintptr_t last = (uintptr_t)&epoll_no_event_marker;
    for (i = 0; i < r; i++) {
        struct kevent *kev = &evs[i];

        if (kev->ident != last) {
            if (last != (uintptr_t)&epoll_no_event_marker)
                ev++;

            ev->events = 0;
            ev->data.ptr = kev->udata;
        }

        if (kev->flags & EV_ERROR) {
            ev->events |= EPOLLERR;
        }
        if (kev->flags & EV_EOF) {
            ev->events |= EPOLLRDHUP;
        }
        if (kev->filter == EVFILT_READ) {
            ev->events |= EPOLLIN;
        } else if (kev->filter == EVFILT_WRITE &&
                   kev->udata != &epoll_no_event_marker) {
            ev->events |= EPOLLOUT;
            ev->data.ptr = kev->udata;
        }

        last = kev->ident;
    }

    return (int)(intptr_t)(ev - events);
}
#elif !defined(LWAN_HAVE_EPOLL)
#error epoll() not implemented for this platform
#endif
