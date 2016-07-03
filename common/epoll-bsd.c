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

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/event.h>
#include <sys/time.h>
#include <sys/types.h>

#include "epoll-bsd.h"
#include "lwan-status.h"
#include "lwan.h"

int
epoll_create1(int flags)
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
