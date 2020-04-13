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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "lwan-io-wrappers.h"
#include "lwan-private.h"

static const int MAX_FAILED_TRIES = 5;

ssize_t
lwan_writev(struct lwan_request *request, struct iovec *iov, size_t iov_count)
{
    ssize_t total_written = 0;
    size_t curr_iov = 0;
    int flags = 0;

    if (request->conn->flags & CONN_CORK)
        flags |= MSG_MORE;

    for (int tries = MAX_FAILED_TRIES; tries;) {
        struct msghdr hdr = {
            .msg_iov = iov + curr_iov,
            .msg_iovlen = iov_count - curr_iov,
        };
        ssize_t written = sendmsg(request->fd, &hdr, flags);
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

        while (curr_iov < iov_count &&
               written >= (ssize_t)iov[curr_iov].iov_len) {
            written -= (ssize_t)iov[curr_iov].iov_len;
            curr_iov++;
        }

        if (curr_iov == iov_count)
            return total_written;

        iov[curr_iov].iov_base = (char *)iov[curr_iov].iov_base + written;
        iov[curr_iov].iov_len -= (size_t)written;

    try_again:
        coro_yield(request->conn->coro, CONN_CORO_WANT_WRITE);
    }

out:
    coro_yield(request->conn->coro, CONN_CORO_ABORT);
    __builtin_unreachable();
}

ssize_t
lwan_readv(struct lwan_request *request, struct iovec *iov, int iov_count)
{
    ssize_t total_bytes_read = 0;
    int curr_iov = 0;

    for (int tries = MAX_FAILED_TRIES; tries;) {
        ssize_t bytes_read =
            readv(request->fd, iov + curr_iov, iov_count - curr_iov);
        if (UNLIKELY(bytes_read < 0)) {
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

        total_bytes_read += bytes_read;

        while (curr_iov < iov_count &&
               bytes_read >= (ssize_t)iov[curr_iov].iov_len) {
            bytes_read -= (ssize_t)iov[curr_iov].iov_len;
            curr_iov++;
        }

        if (curr_iov == iov_count)
            return total_bytes_read;

        iov[curr_iov].iov_base = (char *)iov[curr_iov].iov_base + bytes_read;
        iov[curr_iov].iov_len -= (size_t)bytes_read;

    try_again:
        coro_yield(request->conn->coro, CONN_CORO_WANT_READ);
    }

out:
    coro_yield(request->conn->coro, CONN_CORO_ABORT);
    __builtin_unreachable();
}

ssize_t lwan_send(struct lwan_request *request,
                  const void *buf,
                  size_t count,
                  int flags)
{
    ssize_t total_sent = 0;

    if (request->conn->flags & CONN_CORK)
        flags |= MSG_MORE;

    for (int tries = MAX_FAILED_TRIES; tries;) {
        ssize_t written = send(request->fd, buf, count, flags);
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

        total_sent += written;
        if ((size_t)total_sent == count)
            return total_sent;
        if ((size_t)total_sent < count)
            buf = (char *)buf + written;

    try_again:
        coro_yield(request->conn->coro, CONN_CORO_WANT_WRITE);
    }

out:
    coro_yield(request->conn->coro, CONN_CORO_ABORT);
    __builtin_unreachable();
}

ssize_t
lwan_recv(struct lwan_request *request, void *buf, size_t count, int flags)
{
    ssize_t total_recv = 0;

    for (int tries = MAX_FAILED_TRIES; tries;) {
        ssize_t recvd = recv(request->fd, buf, count, flags);
        if (UNLIKELY(recvd < 0)) {
            tries--;

            switch (errno) {
            case EAGAIN:
            case EINTR:
                goto try_again;
            default:
                goto out;
            }
        }

        total_recv += recvd;
        if ((size_t)total_recv == count)
            return total_recv;
        if ((size_t)total_recv < count)
            buf = (char *)buf + recvd;

    try_again:
        coro_yield(request->conn->coro, CONN_CORO_WANT_READ);
    }

out:
    coro_yield(request->conn->coro, CONN_CORO_ABORT);
    __builtin_unreachable();
}

#if defined(__linux__)
static inline size_t min_size(size_t a, size_t b) { return (a > b) ? b : a; }

void lwan_sendfile(struct lwan_request *request,
                   int in_fd,
                   off_t offset,
                   size_t count,
                   const char *header,
                   size_t header_len)
{
    size_t chunk_size = min_size(count, 1 << 17);
    size_t to_be_written = count;

    lwan_send(request, header, header_len, MSG_MORE);

    while (true) {
        ssize_t written = sendfile(request->fd, in_fd, &offset, chunk_size);
        if (written < 0) {
            switch (errno) {
            case EAGAIN:
            case EINTR:
                goto try_again;
            default:
                coro_yield(request->conn->coro, CONN_CORO_ABORT);
                __builtin_unreachable();
            }
        }

        to_be_written -= (size_t)written;
        if (!to_be_written)
            break;

        chunk_size = min_size(to_be_written, 1 << 19);
        lwan_readahead_queue(in_fd, offset, chunk_size);

    try_again:
        coro_yield(request->conn->coro, CONN_CORO_WANT_WRITE);
    }
}
#elif defined(__FreeBSD__) || defined(__APPLE__)
void lwan_sendfile(struct lwan_request *request,
                   int in_fd,
                   off_t offset,
                   size_t count,
                   const char *header,
                   size_t header_len)
{
    struct sf_hdtr headers = {.headers =
                                  (struct iovec[]){{.iov_base = (void *)header,
                                                    .iov_len = header_len}},
                              .hdr_cnt = 1};
    size_t total_written = 0;
    off_t sbytes = (off_t)count;

    do {
        int r;

#ifdef __APPLE__
        r = sendfile(in_fd, request->fd, offset, &sbytes, &headers, 0);
#else
        r = sendfile(in_fd, request->fd, offset, count, &headers, &sbytes,
                     SF_MNOWAIT);
#endif

        if (UNLIKELY(r < 0)) {
            switch (errno) {
            case EAGAIN:
            case EBUSY:
            case EINTR:
                goto try_again;
            default:
                coro_yield(request->conn->coro, CONN_CORO_ABORT);
                __builtin_unreachable();
            }
        }

        total_written += (size_t)sbytes;

    try_again:
        coro_yield(request->conn->coro, CONN_CORO_WANT_WRITE);
    } while (total_written < count);
}
#else
static inline size_t min_size(size_t a, size_t b) { return (a > b) ? b : a; }

static size_t try_pread_file(struct lwan_request *request,
                             int fd,
                             void *buffer,
                             size_t len,
                             off_t offset)
{
    size_t total_read = 0;

    for (int tries = MAX_FAILED_TRIES; tries;) {
        ssize_t r = pread(fd, buffer, len, offset);

        if (UNLIKELY(r < 0)) {
            tries--;

            switch (errno) {
            case EAGAIN:
            case EINTR:
                goto try_again;
            default:
                goto out;
            }
        }

        total_read += (size_t)r;
        offset += r;
        if (total_read == len || r == 0)
            return total_read;

    try_again:
        /* fd is a file; just re-read */
        (void)0;
    }

out:
    coro_yield(request->conn->coro, CONN_CORO_ABORT);
    __builtin_unreachable();
}

void lwan_sendfile(struct lwan_request *request,
                   int in_fd,
                   off_t offset,
                   size_t count,
                   const char *header,
                   size_t header_len)
{
    unsigned char buffer[512];

    lwan_send(request, header, header_len, MSG_MORE);

    while (count) {
        size_t bytes_read = try_pread_file(request, in_fd, buffer,
            min_size(count, sizeof(buffer)), offset);
        lwan_send(request, buffer, bytes_read, 0);
        count -= bytes_read;
        offset += bytes_read;
    }
}
#endif
