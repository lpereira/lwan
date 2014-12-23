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
#include <sys/sendfile.h>

#include "lwan.h"
#include "lwan-io-wrappers.h"

static const int max_failed_tries = 5;
static const size_t buffer_size = 1400;

int
lwan_openat(lwan_request_t *request,
            int dirfd, const char *pathname, int flags)
{
    for (int tries = max_failed_tries; tries; tries--) {
        int fd = openat(dirfd, pathname, flags);
        if (LIKELY(fd >= 0)) {
            coro_defer(request->conn->coro, CORO_DEFER(close), (void *)(intptr_t)fd);
            return fd;
        }

        switch (errno) {
        case EINTR:
        case EMFILE:
        case ENFILE:
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

    for (int tries = max_failed_tries; tries;) {
        ssize_t written = writev(request->fd, iov + curr_iov, iov_count - curr_iov);
        if (UNLIKELY(written < 0)) {
            /* FIXME: Consider short writes as another try as well? */
            tries--;

            switch (errno) {
            case EAGAIN:
            case EINTR:
                goto try_again;
            default:
                goto out;
            }
        }

        total_written += written;

        while (written >= (ssize_t)iov[curr_iov].iov_len)
            written -= (ssize_t)iov[curr_iov++].iov_len;

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

    for (int tries = max_failed_tries; tries;) {
        ssize_t written = write(request->fd, buf, count);
        if (UNLIKELY(written < 0)) {
            tries--;

            switch (errno) {
            case EAGAIN:
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
    ssize_t retval;

    for (int tries = max_failed_tries; tries; tries--) {
        retval = send(request->fd, buf, count, flags);
        if (LIKELY(retval >= 0))
            return retval;

        switch (errno) {
        case EAGAIN:
        case EINTR:
            coro_yield(request->conn->coro, CONN_CORO_MAY_RESUME);
            break;
        default:
            goto out;
        }
    }

out:
    coro_yield(request->conn->coro, CONN_CORO_ABORT);
    __builtin_unreachable();
}

static ALWAYS_INLINE ssize_t
sendfile_read_write(coro_t *coro, int in_fd, int out_fd, off_t offset, size_t count)
{
    /* FIXME: Use lwan_{read,write}() here */
    ssize_t total_bytes_written = 0;
    /* This buffer is allocated on the heap in order to minimize stack usage
     * inside the coroutine */
    char *buffer = coro_malloc(coro, buffer_size);

    if (offset && lseek(in_fd, offset, SEEK_SET) < 0) {
        lwan_status_perror("lseek");
        return -1;
    }

    while (count > 0) {
        ssize_t read_bytes = read(in_fd, buffer, buffer_size);
        if (read_bytes < 0) {
            coro_yield(coro, CONN_CORO_ABORT);
            __builtin_unreachable();
        }

        ssize_t bytes_written = write(out_fd, buffer, (size_t)read_bytes);
        if (bytes_written < 0) {
            coro_yield(coro, CONN_CORO_ABORT);
            __builtin_unreachable();
        }

        total_bytes_written += bytes_written;
        count -= (size_t)bytes_written;
        coro_yield(coro, CONN_CORO_MAY_RESUME);
    }

    return total_bytes_written;
}

static ALWAYS_INLINE ssize_t
sendfile_linux_sendfile(coro_t *coro, int in_fd, int out_fd, off_t offset, size_t count)
{
    size_t total_written = 0;
    size_t to_be_written = count;

    do {
        ssize_t written = sendfile(out_fd, in_fd, &offset, to_be_written);
        if (written < 0) {
            switch (errno) {
            case EAGAIN:
            case EINTR:
                coro_yield(coro, CONN_CORO_MAY_RESUME);
                continue;

            default:
                coro_yield(coro, CONN_CORO_ABORT);
                __builtin_unreachable();
            }
        }

        total_written += (size_t)written;
        to_be_written -= (size_t)written;

        coro_yield(coro, CONN_CORO_MAY_RESUME);
    } while (to_be_written > 0);

    return (ssize_t)total_written;
}

ssize_t
lwan_sendfile(lwan_request_t *request, int in_fd, off_t offset, size_t count)
{
    if (count > buffer_size * 5) {
        if (UNLIKELY(posix_fadvise(in_fd, offset, (off_t)count,
                                            POSIX_FADV_SEQUENTIAL) < 0))
            lwan_status_perror("posix_fadvise");
    }

    ssize_t written_bytes = sendfile_linux_sendfile(
			request->conn->coro, in_fd, request->fd, offset, count);

    if (UNLIKELY(written_bytes < 0)) {
        switch (errno) {
        case ENOSYS:
        case EINVAL:
            return sendfile_read_write(request->conn->coro, in_fd, request->fd, offset, count);
        }
    }
    return written_bytes;
}
