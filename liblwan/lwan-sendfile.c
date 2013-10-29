/*
 * lwan - simple web server
 * Copyright (c) 2012 Leandro A. F. Pereira <leandro@hardinfo.org>
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
#include <stdlib.h>

#ifdef __linux__
#include <sys/sendfile.h>
#endif /* __linux__ */

#include "lwan.h"
#include "lwan-sendfile.h"

static const size_t const buffer_size = 1400;

static ALWAYS_INLINE ssize_t
_sendfile_read_write(coro_t *coro, int in_fd, int out_fd, off_t offset, size_t count)
{
    size_t total_bytes_written = 0;
    /* This buffer is allocated on the heap in order to minimize stack usage
     * inside the coroutine */
    char *buffer = malloc(buffer_size);

    if (offset && lseek(in_fd, offset, SEEK_SET) < 0) {
        lwan_status_perror("lseek");
        goto error;
    }

    while (total_bytes_written < count) {
        ssize_t read_bytes = read(in_fd, buffer, buffer_size);
        if (read_bytes < 0) {
            lwan_status_perror("read");
            goto error;
        }

        ssize_t bytes_written = write(out_fd, buffer, read_bytes);
        if (bytes_written < 0) {
            lwan_status_perror("write");
            goto error;
        }

        total_bytes_written += bytes_written;
        coro_yield(coro, 1);
    }

    free(buffer);
    return total_bytes_written;

error:
    free(buffer);
    return -1;
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
            if (UNLIKELY(errno != EAGAIN))
                return -1;
            coro_yield(coro, 1);

            /* Try sending less stuff next time */
            if (LIKELY(to_be_written > (ssize_t)buffer_size))
                to_be_written >>= 1;
        } else
            to_be_written = count - (total_written += written);
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
