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

#pragma once

#include <stdint.h>

enum {
    EPOLLIN = 1<<0,
    EPOLLOUT = 1<<1,
    EPOLLONESHOT = 1<<2,
    EPOLLRDHUP = 1<<3,
    EPOLLERR = 1<<4,
    EPOLLET = 1<<5,
    EPOLLHUP = EPOLLRDHUP
} epoll_event_flag;

enum {
    EPOLL_CTL_ADD,
    EPOLL_CTL_MOD,
    EPOLL_CTL_DEL
} epoll_op;

enum {
    EPOLL_CLOEXEC = 1<<0
} epoll_create_flags;

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
int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);
