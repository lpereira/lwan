/*
 * lwan - simple web server
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

#if !defined(HAVE_EPOLL)
#pragma once
#include <stdint.h>

enum epoll_event_flag {
    EPOLLIN = 1 << 0,
    EPOLLOUT = 1 << 1,
    EPOLLONESHOT = 1 << 2,
    EPOLLRDHUP = 1 << 3,
    EPOLLERR = 1 << 4,
    EPOLLET = 1 << 5,
    EPOLLHUP = EPOLLRDHUP
};

enum epoll_op { EPOLL_CTL_ADD, EPOLL_CTL_MOD, EPOLL_CTL_DEL };

enum epoll_create_flags { EPOLL_CLOEXEC = 1 << 0 };

struct epoll_event {
    uint32_t events;
    union {
        void *ptr;
        int fd;
        uint32_t u32;
        uint64_t u64;
    } data;
};

int epoll_create1(int flags);
int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
int epoll_wait(int epfd,
               struct epoll_event *events,
               int maxevents,
               int timeout);

#else
#include_next <sys/epoll.h>
#endif
