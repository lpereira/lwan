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

#ifdef __linux__
#include <sys/sendfile.h>
#endif /* __linux__ */

#include "lwan.h"
#include "lwan-io-wrappers.h"

static const int const max_failed_tries = 5;
static const size_t const buffer_size = 1400;

int
lwan_openat(lwan_request_t *request,
            int dirfd, const char *pathname, int flags)
{
    int fd;
    int tries;

    for (tries = max_failed_tries; tries; tries--) {
        fd = openat(dirfd, pathname, flags);
        if (LIKELY(fd >= 0)) {
            coro_defer(request->coro, CORO_DEFER(close), (void *)(intptr_t)fd);
            return fd;
        }

        switch (errno) {
        case EMFILE:
        case ENFILE:
        case ENOMEM:
            coro_yield(request->coro, REQUEST_CORO_MAY_RESUME);
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

    for (tries = max_failed_tries; tries; tries--) {
        retval = writev(request->fd, iov, iovcnt);
        if (LIKELY(retval >= 0))
            return retval;

        switch (errno) {
        case EAGAIN:
        case EINTR:
            coro_yield(request->coro, REQUEST_CORO_MAY_RESUME);
            break;
        default:
            goto out;
        }
    }

out:
    coro_yield(request->coro, REQUEST_CORO_ABORT);
    ASSERT_NOT_REACHED_RETURN(-1);
}

ssize_t
lwan_write(lwan_request_t *request, const void *buf, size_t count)
{
    ssize_t retval;
    int tries;

    for (tries = max_failed_tries; tries; tries--) {
        retval = write(request->fd, buf, count);
        if (LIKELY(retval >= 0))
            return retval;

        switch (errno) {
        case EAGAIN:
        case EINTR:
            coro_yield(request->coro, REQUEST_CORO_MAY_RESUME);
            break;
        default:
            goto out;
        }
    }

out:
    coro_yield(request->coro, REQUEST_CORO_ABORT);
    ASSERT_NOT_REACHED_RETURN(-1);
}

ssize_t
lwan_send(lwan_request_t *request, const void *buf, size_t count, int flags)
{
    ssize_t retval;
    int tries;

    for (tries = max_failed_tries; tries; tries--) {
        retval = send(request->fd, buf, count, flags);
        if (LIKELY(retval >= 0))
            return retval;

        switch (errno) {
        case EAGAIN:
        case EINTR:
            coro_yield(request->coro, REQUEST_CORO_MAY_RESUME);
            break;
        default:
            goto out;
        }
    }

out:
    coro_yield(request->coro, REQUEST_CORO_ABORT);
    ASSERT_NOT_REACHED_RETURN(-1);
}

static ALWAYS_INLINE ssize_t
_sendfile_read_write(coro_t *coro, int in_fd, int out_fd, off_t offset, size_t count)
{
    /* FIXME: Use lwan_{read,write}() here */
    size_t total_bytes_written = 0;
    /* This buffer is allocated on the heap in order to minimize stack usage
     * inside the coroutine */
    char *buffer = coro_malloc(coro, buffer_size);

    if (offset && lseek(in_fd, offset, SEEK_SET) < 0) {
        lwan_status_perror("lseek");
        return -1;
    }

    while (total_bytes_written < count) {
        ssize_t read_bytes = read(in_fd, buffer, buffer_size);
        if (read_bytes < 0) {
            coro_yield(coro, REQUEST_CORO_ABORT);
            ASSERT_NOT_REACHED_RETURN(-1);
        }

        ssize_t bytes_written = write(out_fd, buffer, read_bytes);
        if (bytes_written < 0) {
            coro_yield(coro, REQUEST_CORO_ABORT);
            ASSERT_NOT_REACHED_RETURN(-1);
        }

        total_bytes_written += bytes_written;
        coro_yield(coro, REQUEST_CORO_MAY_RESUME);
    }

    return total_bytes_written;
}

#ifdef __linux__
static ALWAYS_INLINE ssize_t
_sendfile_linux_sendfile(coro_t *coro, int in_fd, int out_fd, off_t offset, size_t count)
{
    size_t total_written = 0;
    ssize_t written;

    ssize_t to_be_written = count - total_written;
    do {
        written = sendfile(out_fd, in_fd, &offset, to_be_written);
        if (written < 0) {
            switch (errno) {
            case EAGAIN:
            case EINTR:
                coro_yield(coro, REQUEST_CORO_MAY_RESUME);

                /* Try sending less stuff next time */
                if (LIKELY(to_be_written > (ssize_t)buffer_size))
                    to_be_written >>= 1;
                continue;

            default:
                coro_yield(coro, REQUEST_CORO_ABORT);
                ASSERT_NOT_REACHED_RETURN(-1);
            }
        }

        total_written += written;
        to_be_written = count - total_written;

        coro_yield(coro, REQUEST_CORO_MAY_RESUME);
    } while (count > total_written);

    return total_written;
}
#endif

ssize_t
lwan_sendfile(lwan_request_t *request, int in_fd, off_t offset, size_t count)
{
    if (count > buffer_size * 5) {
        if (UNLIKELY(posix_fadvise(in_fd, offset, count,
                                            POSIX_FADV_SEQUENTIAL) < 0))
            lwan_status_perror("posix_fadvise");
    }

#ifdef __linux__
    ssize_t written_bytes = -1;
    written_bytes = _sendfile_linux_sendfile(request->coro, in_fd, request->fd, offset, count);

    if (UNLIKELY(written_bytes < 0)) {
        switch (errno) {
        case ENOSYS:
        case EINVAL:
#endif
            return _sendfile_read_write(request->coro, in_fd, request->fd, offset, count);

#ifdef __linux__
        }
    }
    return written_bytes;
#endif
}
