/*
 * lwan - simple web server
 * Copyright (c) 2016 Leandro A. F. Pereira <leandro@hardinfo.org>
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

#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "epoll-bsd.h"
#include "lwan-status.h"
#include "lwan.h"

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
        int flags = EV_ADD | EV_CLEAR;

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

static int
kevent_compare(const void *a, const void *b)
{
    const struct kevent *ka = a;
    const struct kevent *kb = b;

    if (ka->flags & (EV_ERROR | EV_EOF) || kb->flags & (EV_ERROR | EV_EOF))
        return 1;
    return (ka > kb) - (ka < kb);
}

int
epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)
{
    struct epoll_event *ev = events;
    struct kevent evs[maxevents];
    struct timespec tmspec;
    int i, r;

    r = kevent(epfd, NULL, 0, evs, maxevents, to_timespec(&tmspec, timeout));
    if (UNLIKELY(r < 0)) {
        if (errno != EINTR)
            lwan_status_perror("kevent");
        goto out;
    }

    qsort(evs, (size_t)r, sizeof(struct kevent), kevent_compare);

    for (i = 0; i < r; i++, ev++) {
        struct kevent *kev = &evs[i];

        ev->events = 0;
        ev->data.ptr = kev->udata;

        if (kev->flags & EV_ERROR)
            ev->events |= EPOLLERR;
        if (kev->flags & EV_EOF)
            ev->events |= EPOLLRDHUP;

        if (kev->filter == EVFILT_READ)
            ev->events |= EPOLLIN;
        else if (kev->filter == EVFILT_WRITE)
            ev->events |= EPOLLOUT;
    }

out:
    return r;
}
