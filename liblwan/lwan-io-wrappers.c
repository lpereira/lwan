/*
 * lwan - simple web server
 * Copyright (c) 2013 Leandro A. F. Pereira <leandro@hardinfo.org>
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

#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

#include "lwan.h"
#include "lwan-io-wrappers.h"

#define FAILED_TRIES 5

int
lwan_openat(lwan_request_t *request,
            int dirfd, const char *pathname, int flags)
{
    int fd;
    int tries;

    for (tries = FAILED_TRIES; tries; tries--) {
        fd = openat(dirfd, pathname, flags);
        if (LIKELY(fd >= 0)) {
            coro_defer(request->coro, CORO_DEFER(close), (void *)(intptr_t)fd);
            return fd;
        }

        switch (errno) {
        case EMFILE:
        case ENFILE:
        case ENOMEM:
            coro_yield(request->coro, 1);
            break;
        default:
            return -errno;
        }
    }

    return -ENFILE;
}

ssize_t
lwan_writev(lwan_request_t *request, const struct iovec *iov, int iovcnt)
{
    ssize_t retval;
    int tries;

    for (tries = FAILED_TRIES; tries; tries--) {
        retval = writev(request->fd, iov, iovcnt);
        if (LIKELY(retval >= 0))
            return retval;

        switch (errno) {
        case EAGAIN:
        case EINTR:
            coro_yield(request->coro, 1);
            break;
        default:
            goto out;
        }
    }

out:
    coro_yield(request->coro, 0);
    return -1;
}

ssize_t
lwan_write(lwan_request_t *request, const void *buf, size_t count)
{
    ssize_t retval;
    int tries;

    for (tries = FAILED_TRIES; tries; tries--) {
        retval = write(request->fd, buf, count);
        if (LIKELY(retval >= 0))
            return retval;

        switch (errno) {
        case EAGAIN:
        case EINTR:
            coro_yield(request->coro, 1);
            break;
        default:
            goto out;
        }
    }

out:
    coro_yield(request->coro, 0);
    return -1;
}

ssize_t
lwan_send(lwan_request_t *request, const void *buf, size_t count, int flags)
{
    ssize_t retval;
    int tries;

    for (tries = FAILED_TRIES; tries; tries--) {
        retval = send(request->fd, buf, count, flags);
        if (LIKELY(retval >= 0))
            return retval;

        switch (errno) {
        case EAGAIN:
        case EINTR:
            coro_yield(request->coro, 1);
            break;
        default:
            goto out;
        }
    }

out:
    coro_yield(request->coro, 0);
    return -1;
}
