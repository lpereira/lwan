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

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sendfile.h>

#include "lwan.h"
#include "lwan-io-wrappers.h"

static const int MAX_FAILED_TRIES = 5;

int
lwan_openat(lwan_request_t *request,
            int dirfd, const char *pathname, int flags)
{
    for (int tries = MAX_FAILED_TRIES; tries; tries--) {
        int fd = openat(dirfd, pathname, flags);
        if (LIKELY(fd >= 0)) {
            coro_defer(request->conn->coro, CORO_DEFER(close), (void *)(intptr_t)fd);
            return fd;
        }

        switch (errno) {
        case EWOULDBLOCK:
            request->conn->flags |= CONN_FLIP_FLAGS;
            /* Fallthrough */
        case EMFILE:
        case ENFILE:
        case EINTR:
        case ENOMEM:
            coro_yield(request->conn->coro, CONN_CORO_MAY_RESUME);
            break;
        default:
            return -errno;
        }
    }

    return -ENFILE;
}

ssize_t
lwan_writev(lwan_request_t *request, struct iovec *iov, int iov_count)
{
    ssize_t total_written = 0;
    int curr_iov = 0;

    for (int tries = MAX_FAILED_TRIES; tries;) {
        ssize_t written = writev(request->fd, iov + curr_iov, iov_count - curr_iov);
        if (UNLIKELY(written < 0)) {
            /* FIXME: Consider short writes as another try as well? */
            tries--;

            switch (errno) {
            case EAGAIN:
                request->conn->flags |= CONN_FLIP_FLAGS;
                /* Fallthrough */
            case EINTR:
                goto try_again;
            default:
                goto out;
            }
        }

        total_written += written;

        while (curr_iov < iov_count && written >= (ssize_t)iov[curr_iov].iov_len) {
            written -= (ssize_t)iov[curr_iov].iov_len;
            curr_iov++;
        }

        if (curr_iov == iov_count)
            return total_written;

        iov[curr_iov].iov_base = (char *)iov[curr_iov].iov_base + written;
        iov[curr_iov].iov_len -= (size_t)written;

try_again:
        coro_yield(request->conn->coro, CONN_CORO_MAY_RESUME);
    }

out:
    coro_yield(request->conn->coro, CONN_CORO_ABORT);
    __builtin_unreachable();
}

ssize_t
lwan_write(lwan_request_t *request, const void *buf, size_t count)
{
    ssize_t total_written = 0;

    for (int tries = MAX_FAILED_TRIES; tries;) {
        ssize_t written = write(request->fd, buf, count);
        if (UNLIKELY(written < 0)) {
            tries--;

            switch (errno) {
            case EAGAIN:
                request->conn->flags |= CONN_FLIP_FLAGS;
                /* Fallthrough */
            case EINTR:
                goto try_again;
            default:
                goto out;
            }
        }

        total_written += written;
        if ((size_t)total_written == count)
            return total_written;
        if ((size_t)total_written < count)
            buf = (char *)buf + written;

try_again:
        coro_yield(request->conn->coro, CONN_CORO_MAY_RESUME);
    }

out:
    coro_yield(request->conn->coro, CONN_CORO_ABORT);
    __builtin_unreachable();
}

ssize_t
lwan_send(lwan_request_t *request, const void *buf, size_t count, int flags)
{
    ssize_t total_sent = 0;

    for (int tries = MAX_FAILED_TRIES; tries;) {
        ssize_t written = send(request->fd, buf, count, flags);
        if (UNLIKELY(written < 0)) {
            tries--;

            switch (errno) {
            case EAGAIN:
                request->conn->flags |= CONN_FLIP_FLAGS;
                /* Fallthrough */
            case EINTR:
                goto try_again;
            default:
                goto out;
            }
        }

        total_sent += written;
        if ((size_t)total_sent == count)
            return total_sent;
        if ((size_t)total_sent < count)
            buf = (char *)buf + written;

try_again:
        coro_yield(request->conn->coro, CONN_CORO_MAY_RESUME);
    }

out:
    coro_yield(request->conn->coro, CONN_CORO_ABORT);
    __builtin_unreachable();
}

#if defined(__linux__)
void
lwan_sendfile(lwan_request_t *request, int in_fd, off_t offset, size_t count,
    const char *header, size_t header_len)
{
    size_t to_be_written = count;

    lwan_send(request, header, header_len, MSG_MORE);

    do {
        ssize_t written = sendfile(request->fd, in_fd, &offset, to_be_written);
        if (written < 0) {
            switch (errno) {
            case EAGAIN:
                request->conn->flags |= CONN_FLIP_FLAGS;
                /* Fallthrough */
            case EINTR:
                coro_yield(request->conn->coro, CONN_CORO_MAY_RESUME);
                continue;

            default:
                coro_yield(request->conn->coro, CONN_CORO_ABORT);
                __builtin_unreachable();
            }
        }

        to_be_written -= (size_t)written;

        coro_yield(request->conn->coro, CONN_CORO_MAY_RESUME);
    } while (to_be_written > 0);
}
#elif defined(__FreeBSD__) || defined(__APPLE__)
void
lwan_sendfile(lwan_request_t *request, int in_fd, off_t offset, size_t count,
    const char *header, size_t header_len)
{
    struct sf_hdtr headers = {
        .headers = (struct iovec[]) {
            {
                .iov_base = (void *)header,
                .iov_len = header_len
            }
        },
        .hdr_cnt = 1
    };
    size_t total_written = 0;
    off_t sbytes = (off_t)count;

    do {
        int r;

#ifdef __APPLE__
        r = sendfile(in_fd, request->fd, offset, &sbytes, &headers, 0);
#else
        r = sendfile(in_fd, request->fd, offset, count, &headers, &sbytes, SF_MNOWAIT);
#endif

        if (UNLIKELY(r < 0)) {
            switch (errno) {
            case EAGAIN:
                request->conn->flags |= CONN_FLIP_FLAGS;
                /* Fallthrough */
            case EBUSY:
            case EINTR:
                coro_yield(request->conn->coro, CONN_CORO_MAY_RESUME);
                continue;

            default:
                coro_yield(request->conn->coro, CONN_CORO_ABORT);
                __builtin_unreachable();
            }
        }

        total_written += (size_t)sbytes;

        coro_yield(request->conn->coro, CONN_CORO_MAY_RESUME);
    } while (total_written < count);
}
#else
#error No sendfile() implementation for this platform
#endif
