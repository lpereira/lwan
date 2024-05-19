/*
 * lwan - web server
 * Copyright (c) 2013 L. A. F. Pereira <l@tia.mat.br>
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

ssize_t lwan_writev_fd(struct lwan_request *request,
                       int fd,
                       struct iovec *iov,
                       int iov_count)
{
    ssize_t total_written = 0;
    int curr_iov = 0;
    int flags = (request->conn->flags & CONN_CORK) ? MSG_MORE : 0;

    for (int tries = MAX_FAILED_TRIES; tries;) {
        const int remaining_len = (int)(iov_count - curr_iov);
        ssize_t written;

        if (remaining_len == 1) {
            const struct iovec *vec = &iov[curr_iov];
            return lwan_send_fd(request, fd, vec->iov_base, vec->iov_len,
                                flags);
        }

        struct msghdr hdr = {
            .msg_iov = iov + curr_iov,
            .msg_iovlen = (size_t)remaining_len,
        };
        written = sendmsg(fd, &hdr, flags);

        if (UNLIKELY(written < 0)) {
            /* FIXME: Consider short writes as another try as well? */
            tries--;

            switch (errno) {
            case EAGAIN:
            case EINTR:
                break;
            default:
                return -errno;
            }
        } else {
            total_written += written;

            while (curr_iov < iov_count &&
                   written >= (ssize_t)iov[curr_iov].iov_len) {
                written -= (ssize_t)iov[curr_iov].iov_len;
                curr_iov++;
            }

            iov[curr_iov].iov_base = (char *)iov[curr_iov].iov_base + written;
            iov[curr_iov].iov_len -= (size_t)written;

            if (curr_iov == iov_count && iov[curr_iov].iov_len == 0)
                return total_written;
        }

        lwan_request_await_read(request, fd);
    }

    return -ETIMEDOUT;
}

ssize_t lwan_readv_fd(struct lwan_request *request,
                      int fd,
                      struct iovec *iov,
                      int iov_count)
{
    ssize_t total_bytes_read = 0;
    int curr_iov = 0;

    for (int tries = MAX_FAILED_TRIES; tries;) {
        ssize_t bytes_read = readv(fd, iov + curr_iov, iov_count - curr_iov);
        if (UNLIKELY(bytes_read < 0)) {
            /* FIXME: Consider short reads as another try as well? */
            tries--;

            switch (errno) {
            case EAGAIN:
            case EINTR:
                break;
            default:
                return -errno;
            }
        } else {
            total_bytes_read += bytes_read;

            while (curr_iov < iov_count &&
                   bytes_read >= (ssize_t)iov[curr_iov].iov_len) {
                bytes_read -= (ssize_t)iov[curr_iov].iov_len;
                curr_iov++;
            }

            iov[curr_iov].iov_base =
                (char *)iov[curr_iov].iov_base + bytes_read;
            iov[curr_iov].iov_len -= (size_t)bytes_read;

            if (curr_iov == iov_count && iov[curr_iov].iov_len == 0)
                return total_bytes_read;
        }

        lwan_request_await_read(request, fd);
    }

    return -ETIMEDOUT;
}

ssize_t lwan_send_fd(struct lwan_request *request,
                     int fd,
                     const void *buf,
                     size_t count,
                     int flags)
{
    size_t to_send = count;

    if (request->conn->flags & CONN_CORK)
        flags |= MSG_MORE;

    for (int tries = MAX_FAILED_TRIES; tries;) {
        ssize_t written = send(fd, buf, to_send, flags);
        if (UNLIKELY(written < 0)) {
            tries--;

            switch (errno) {
            case EAGAIN:
            case EINTR:
                break;
            default:
                return -errno;
            }
        } else {
            to_send -= (size_t)written;
            if (!to_send)
                return count;
            buf = (char *)buf + written;
        }

        lwan_request_await_write(request, fd);
    }

    return -ETIMEDOUT;
}

ssize_t
lwan_recv_fd(struct lwan_request *request, int fd, void *buf, size_t count, int flags)
{
    size_t to_recv = count;

    for (int tries = MAX_FAILED_TRIES; tries;) {
        ssize_t recvd = recv(fd, buf, to_recv, flags);
        if (UNLIKELY(recvd < 0)) {
            tries--;

            switch (errno) {
            case EINTR:
            case EAGAIN:
                if (flags & MSG_DONTWAIT)
                    return count - to_recv;
                break;
            default:
                return -errno;
            }
        } else {
            to_recv -= (size_t)recvd;
            if (!to_recv)
                return count;
            buf = (char *)buf + recvd;
        }

        lwan_request_await_read(request, fd);
    }

    return -ETIMEDOUT;
}

#if defined(__linux__)
int lwan_sendfile_fd(struct lwan_request *request,
                     int out_fd,
                     int in_fd,
                     off_t offset,
                     size_t count,
                     const char *header,
                     size_t header_len)
{
    /* Clamp each chunk to 2^21 bytes[1] to balance throughput and
     * scalability.  This used to be capped to 2^14 bytes, as that's the
     * maximum TLS record size[2], but was found to be hurtful for
     * performance[2], so use the same default value that Nginx uses.
     *
     * First chunk is clamped to 2^21 - header_len, because the header is
     * sent using MSG_MORE.  Subsequent chunks are sized 2^21 bytes.  (Do
     * this regardless of this connection being TLS or not for simplicity.)
     *
     * [1] https://www.kernel.org/doc/html/v5.12/networking/tls.html#sending-tls-application-data
     * [2] https://github.com/lpereira/lwan/issues/334
     */
    size_t chunk_size = LWAN_MIN(count, (1ul << 21) - header_len);
    size_t to_be_written = count;
    ssize_t r;

    assert(header_len < (1ul << 21));

    r = lwan_send_fd(request, out_fd, header, header_len, MSG_MORE);
    if (r < 0)
        return (int)r;

    while (true) {
        ssize_t written = sendfile(out_fd, in_fd, &offset, chunk_size);
        if (UNLIKELY(written < 0)) {
            switch (errno) {
            case EAGAIN:
            case EINTR:
                break;
            default:
                return -errno;
            }
        } else {
            to_be_written -= (size_t)written;
            if (!to_be_written)
                return 0;

            chunk_size = LWAN_MIN(to_be_written, 1ul << 21);
            lwan_readahead_queue(in_fd, offset, chunk_size);
        }

        lwan_request_await_write(request, out_fd);
    }
}
#elif defined(__FreeBSD__) || defined(__APPLE__)
int lwan_sendfile(struct lwan_request *request,
                  int out_fd,
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
    off_t sbytes = (off_t)count;

    if (!count) {
        /* FreeBSD's sendfile() won't send the headers when count is 0. Why? */
        return lwan_writev_fd(request, out_fd, headers.headers,
                              headers.hdr_cnt);
    }

    while (true) {
        int r;

#ifdef __APPLE__
        r = sendfile(in_fd, out_fd, offset, &sbytes, &headers, 0);
#else
        r = sendfile(in_fd, out_fd, offset, count, &headers, &sbytes,
                     SF_MNOWAIT);
#endif
        if (UNLIKELY(r < 0)) {
            switch (errno) {
            case EAGAIN:
            case EBUSY:
            case EINTR:
                break;
            default:
                return -errno;
            }
        } else {
            count -= (size_t)sbytes;
            if (!count)
                return 0;
        }

        lwan_request_await_write(request, out_fd);
    }
}
#else
static ssize_t try_pread_file(struct lwan_request *request,
                              int fd,
                              void *buffer,
                              size_t len,
                              off_t offset)
{
    size_t total_read = 0;

    for (int tries = MAX_FAILED_TRIES; tries;) {
        ssize_t r = pread(fd, buffer, len, offset);

        if (r == 0) {
            return total_read;
        }
        if (UNLIKELY(r < 0)) {
            tries--;

            switch (errno) {
            case EAGAIN:
            case EINTR:
                /* fd is a file, re-read -- but give other coros some time */
                coro_yield(request->conn->coro, CONN_CORO_YIELD);
                continue;
            default:
                return -errno;
            }
        }

        total_read += (size_t)r;
        if (total_read == len) {
            return total_read;
        }

        offset += r;
    }

    return -ETIMEDOUT;
}

int lwan_sendfile_fd(struct lwan_request *request,
                     int out_fd,
                     int in_fd,
                     off_t offset,
                     size_t count,
                     const char *header,
                     size_t header_len)
{
    unsigned char buffer[512];
    ssize_t r;

    r = lwan_send_fd(request, out_fd, header, header_len, MSG_MORE);
    if (UNLIKELY(r < 0)) {
        return (int)r;
    }

    while (count) {
        r = try_pread_file(request, in_fd, buffer,
                           LWAN_MIN(count, sizeof(buffer)), offset);
        if (UNLIKELY(r <= 0))
            return (int)r;

        size_t bytes_read = (size_t)r;
        r = lwan_send_fd(request, out_fd, buffer, bytes_read,
                         bytes_read < sizeof(buffer) ? 0 : MSG_MORE);
        if (UNLIKELY(r < 0))
            return (int)r;

        count -= bytes_read;
        offset += bytes_read;
    }

    return 0;
}
#endif
