/*
 * lwan - web server
 * Copyright (c) 2019 L. A. F. Pereira <l@tia.mat.br>
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

#define _GNU_SOURCE
#include <assert.h>
#include <endian.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>

#if defined(__x86_64__)
#include <immintrin.h>
#endif

#include "lwan-io-wrappers.h"
#include "lwan-private.h"

enum ws_opcode {
    WS_OPCODE_CONTINUATION = 0,
    WS_OPCODE_TEXT = 1,
    WS_OPCODE_BINARY = 2,
    WS_OPCODE_CLOSE = 8,
    WS_OPCODE_PING = 9,
    WS_OPCODE_PONG = 10,

    WS_OPCODE_RSVD_1 = 3,
    WS_OPCODE_RSVD_2 = 4,
    WS_OPCODE_RSVD_3 = 5,
    WS_OPCODE_RSVD_4 = 6,
    WS_OPCODE_RSVD_5 = 7,

    WS_OPCODE_RSVD_CONTROL_1 = 11,
    WS_OPCODE_RSVD_CONTROL_2 = 12,
    WS_OPCODE_RSVD_CONTROL_3 = 13,
    WS_OPCODE_RSVD_CONTROL_4 = 14,
    WS_OPCODE_RSVD_CONTROL_5 = 15,

    WS_OPCODE_INVALID = 16,
};

#define WS_MASKED 0x80

static ALWAYS_INLINE bool
write_websocket_frame_full(struct lwan_request *request,
                           unsigned char header_byte,
                           char *msg,
                           size_t len,
                           bool use_coro)
{
    uint8_t frame[10] = {header_byte};
    size_t frame_len;

    if (len <= 125) {
        frame[1] = (uint8_t)len;
        frame_len = 2;
    } else if (len <= 65535) {
        frame[1] = 0x7e;
        memcpy(frame + 2, &(uint16_t){htons((uint16_t)len)}, sizeof(uint16_t));
        frame_len = 4;
    } else {
        frame[1] = 0x7f;
        memcpy(frame + 2, &(uint64_t){htobe64((uint64_t)len)},
               sizeof(uint64_t));
        frame_len = 10;
    }

    struct iovec vec[] = {
        {.iov_base = frame, .iov_len = frame_len},
        {.iov_base = msg, .iov_len = len},
    };

    if (LIKELY(use_coro)) {
        lwan_writev(request, vec, N_ELEMENTS(vec));
        return true;
    }

    size_t total_written = 0;
    int curr_iov = 0;
    for (int try = 0; try < 10; try++) {
        ssize_t written = writev(request->fd, &vec[curr_iov],
                                 (int)N_ELEMENTS(vec) - curr_iov);
        if (written < 0) {
            if (errno == EAGAIN || errno == EINTR)
                continue;
            return false;
        }

        total_written += (size_t)written;
        while (curr_iov < (int)N_ELEMENTS(vec) &&
               written >= (ssize_t)vec[curr_iov].iov_len) {
            written -= (ssize_t)vec[curr_iov].iov_len;
            curr_iov++;
        }
        if (curr_iov == (int)N_ELEMENTS(vec))
            return true;

        vec[curr_iov].iov_base = (char *)vec[curr_iov].iov_base + written;
        vec[curr_iov].iov_len -= (size_t)written;
    }

    return false;
}

static bool write_websocket_frame(struct lwan_request *request,
                                  unsigned char header_byte,
                                  char *msg,
                                  size_t len)
{
    return write_websocket_frame_full(request, header_byte, msg, len, true);
}

static inline void lwan_response_websocket_write(struct lwan_request *request, unsigned char op)
{
    size_t len = lwan_strbuf_get_length(request->response.buffer);
    char *msg = lwan_strbuf_get_buffer(request->response.buffer);
    unsigned char header = WS_MASKED | op;

    if (!(request->conn->flags & CONN_IS_WEBSOCKET))
        return;

    write_websocket_frame(request, header, msg, len);
    lwan_strbuf_reset(request->response.buffer);
}

void lwan_response_websocket_write_text(struct lwan_request *request)
{
    lwan_response_websocket_write(request, WS_OPCODE_TEXT);
}

void lwan_response_websocket_write_binary(struct lwan_request *request)
{
    lwan_response_websocket_write(request, WS_OPCODE_BINARY);
}

static size_t get_frame_length(struct lwan_request *request, uint16_t header)
{
    uint64_t len;

    switch (header & 0x7f) {
    case 0x7e:
        lwan_recv(request, &len, 2, 0);
        len = (uint64_t)ntohs((uint16_t)len);

        if (len < 0x7e) {
            lwan_status_warning("Can't use 16-bit encoding for frame length of %zu",
                                len);
            coro_yield(request->conn->coro, CONN_CORO_ABORT);
            __builtin_unreachable();
        }

        return (size_t)len;
    case 0x7f:
        lwan_recv(request, &len, 8, 0);
        len = be64toh(len);

        if (UNLIKELY(len > SSIZE_MAX)) {
            lwan_status_warning("Frame length of %zu won't fit a ssize_t",
                                len);
            coro_yield(request->conn->coro, CONN_CORO_ABORT);
            __builtin_unreachable();
        }
        if (UNLIKELY(len <= 0xffff)) {
            lwan_status_warning("Can't use 64-bit encoding for frame length of %zu",
                                len);
            coro_yield(request->conn->coro, CONN_CORO_ABORT);
            __builtin_unreachable();
        }

        return (size_t)len;
    default:
        return (size_t)(header & 0x7f);
    }
}

static void unmask(char *msg, size_t msg_len, char mask[static 4])
{
    uint32_t mask32;

    /* TODO: handle alignment of `msg` to use (at least) NT loads
     *       as we're rewriting msg anyway.  (NT writes aren't that
     *       useful as the unmasked value will be used right after.) */

#if defined(__AVX2__)
    if (msg_len >= 32) {
        const __m256i mask256 =
            _mm256_castps_si256(_mm256_broadcast_ss((const float *)mask));
        do {
            const __m256i v = _mm256_lddqu_si256((const __m256i *)msg);
            _mm256_storeu_si256((__m256i *)msg, _mm256_xor_si256(v, mask256));
            msg += 32;
            msg_len -= 32;
        } while (msg_len >= 32);

        if (msg_len >= 16) {
            const __m128i mask128 = _mm256_extracti128_si256(mask256, 0);
            const __m128i v = _mm_lddqu_si128((const __m128i *)msg);
            _mm_storeu_si128((__m128i *)msg, _mm_xor_si128(v, mask128));
            msg += 16;
            msg_len -= 16;
        }

        mask32 = (uint32_t)_mm256_extract_epi32(mask256, 0);
    } else {
        mask32 = string_as_uint32(mask);
    }
#elif defined(__SSE3__)
    if (msg_len >= 16) {
        const __m128i mask128 =
            _mm_castps_si128(_mm_load_ps1((const float *)mask));

        do {
            const __m128i v = _mm_lddqu_si128((const __m128i *)msg);
            _mm_storeu_si128((__m128i *)msg, _mm_xor_si128(v, mask128));
            msg += 16;
            msg_len -= 16;
        } while (msg_len >= 16);

        mask32 = _mm_extract_epi32(mask128, 0);
    } else {
        mask32 = string_as_uint32(mask);
    }
#else
    mask32 = string_as_uint32(mask);
#endif

#if __SIZEOF_POINTER__ == 8
    if (msg_len >= 8) {
        const uint64_t mask64 = (uint64_t)mask32 << 32 | (uint64_t)mask32;

        do {
            uint64_t v = string_as_uint64(msg);
            v ^= mask64;
            msg = mempcpy(msg, &v, sizeof(v));
            msg_len -= 8;
        } while (msg_len >= 8);
    }
#endif

    if (msg_len >= 4) {
        do {
            uint32_t v = string_as_uint32(msg);
            v ^= mask32;
            msg = mempcpy(msg, &v, sizeof(v));
            msg_len -= 4;
        } while (msg_len >= 4);
    }

    switch (msg_len) {
    case 3:
        msg[2] ^= mask[2]; /* fallthrough */
    case 2:
        msg[1] ^= mask[1]; /* fallthrough */
    case 1:
        msg[0] ^= mask[0];
        break;
    default:
        __builtin_unreachable();
    }
}

static void
ping_pong(struct lwan_request *request, uint16_t header, enum ws_opcode opcode)
{
    const size_t len = header & 0x7f;
    char msg[128];
    char mask[4];

    assert(header & WS_MASKED);
    assert(opcode == WS_OPCODE_PING || opcode == WS_OPCODE_PONG);

    if (UNLIKELY(len > 125)) {
        lwan_status_debug("Received %s frame with length %zu."
                          "Max is 125. Aborting connection.",
                          opcode == WS_OPCODE_PING ? "PING" : "PONG", len);
        coro_yield(request->conn->coro, CONN_CORO_ABORT);
        __builtin_unreachable();
    }

    struct iovec vec[] = {
        {.iov_base = mask, .iov_len = sizeof(mask)},
        {.iov_base = msg, .iov_len = len},
    };

    if (opcode == WS_OPCODE_PING) {
        lwan_readv(request, vec, N_ELEMENTS(vec));
        unmask(msg, len, mask);
        write_websocket_frame(request, WS_MASKED | WS_OPCODE_PONG, msg, len);
    } else {
        /* From MDN: "You might also get a pong without ever sending a ping;
         * ignore this if it happens." */

        /* FIXME: should we care about the contents of PONG packets? */
        /* FIXME: should we have a lwan_recvmsg() too that takes an iovec? */
        const size_t total_len = vec[0].iov_len + vec[1].iov_len;
        if (LIKELY(total_len < sizeof(msg))) {
            lwan_recv(request, msg, total_len, MSG_TRUNC);
        } else {
            lwan_recv(request, vec[0].iov_base, vec[0].iov_len, MSG_TRUNC);
            lwan_recv(request, vec[1].iov_base, vec[1].iov_len, MSG_TRUNC);
        }
    }
}

bool lwan_send_websocket_ping_for_tq(struct lwan_connection *conn)
{
    uint32_t mask32 = (uint32_t)lwan_random_uint64();
    char mask[sizeof(mask32)];
    struct timespec payload;

    memcpy(mask, &mask32, sizeof(mask32));

    if (UNLIKELY(clock_gettime(monotonic_clock_id, &payload) < 0))
        return false;

    unmask((char *)&payload, sizeof(payload), mask);

    /* use_coro is set to false here because this function is called outside
     * a connection coroutine and the I/O wrappers might yield, which of course
     * wouldn't work */
    struct lwan_request req = {
        .conn = conn,
        .fd = lwan_connection_get_fd(conn->thread->lwan, conn),
    };
    return write_websocket_frame_full(&req, WS_MASKED | WS_OPCODE_PING,
                                      (char *)&payload, sizeof(payload), false);
}

int lwan_response_websocket_read_hint(struct lwan_request *request, size_t size_hint)
{
    enum ws_opcode opcode = WS_OPCODE_INVALID;
    enum ws_opcode last_opcode;
    uint16_t header;
    bool continuation = false;

    if (!(request->conn->flags & CONN_IS_WEBSOCKET))
        return ENOTCONN;

    lwan_strbuf_reset_trim(request->response.buffer, size_hint);

next_frame:
    last_opcode = opcode;

    if (!lwan_recv(request, &header, sizeof(header), continuation ? 0 : MSG_DONTWAIT))
        return EAGAIN;
    header = htons(header);
    continuation = false;

    if (UNLIKELY(header & 0x7000)) {
        lwan_status_debug("RSV1...RSV3 has non-zero value %d, aborting", header & 0x7000);
        /* No extensions are supported yet, so fail connection per RFC6455. */
        coro_yield(request->conn->coro, CONN_CORO_ABORT);
        __builtin_unreachable();
    }
    if (UNLIKELY(!(header & WS_MASKED))) {
        lwan_status_debug("Client sent an unmasked WebSockets frame, aborting");
        coro_yield(request->conn->coro, CONN_CORO_ABORT);
        __builtin_unreachable();
    }

    opcode = (header & 0x0f00) >> 8;
    switch (opcode) {
    case WS_OPCODE_CONTINUATION:
        if (UNLIKELY(last_opcode > WS_OPCODE_BINARY)) {
            /* Continuation frames are only available for opcodes [0..2] */
            coro_yield(request->conn->coro, CONN_CORO_ABORT);
            __builtin_unreachable();
        }

        continuation = true;
        break;

    case WS_OPCODE_TEXT:
    case WS_OPCODE_BINARY:
        break;

    case WS_OPCODE_CLOSE:
        request->conn->flags &= ~CONN_IS_WEBSOCKET;
        break;

    case WS_OPCODE_PONG:
    case WS_OPCODE_PING:
        ping_pong(request, header, opcode);
        goto next_frame;

    case WS_OPCODE_RSVD_1 ... WS_OPCODE_RSVD_5:
    case WS_OPCODE_RSVD_CONTROL_1 ... WS_OPCODE_RSVD_CONTROL_5:
    case WS_OPCODE_INVALID:
        /* RFC6455: ...the receiving endpoint MUST _Fail the WebSocket Connection_ */
        coro_yield(request->conn->coro, CONN_CORO_ABORT);
        __builtin_unreachable();
    }

    size_t frame_len = get_frame_length(request, header);
    char *msg = lwan_strbuf_extend_unsafe(request->response.buffer, frame_len);
    if (UNLIKELY(!msg)) {
        coro_yield(request->conn->coro, CONN_CORO_ABORT);
        __builtin_unreachable();
    }

    char mask[4];
    struct iovec vec[] = {
        {.iov_base = mask, .iov_len = sizeof(mask)},
        {.iov_base = msg, .iov_len = frame_len},
    };
    lwan_readv(request, vec, N_ELEMENTS(vec));
    unmask(msg, frame_len, mask);

    if (continuation && !(header & 0x8000))
        goto next_frame;

    return (request->conn->flags & CONN_IS_WEBSOCKET) ? 0 : ECONNRESET;
}

inline int lwan_response_websocket_read(struct lwan_request *request)
{
    /* Ensure that a rogue client won't keep increasing the memory usage in an
     * uncontrolled manner by curbing the backing store to 1KB at most by default.
     * If an application expects messages to be larger than 1024 bytes on average,
     * they can call lwan_response_websocket_read_hint() directly with a larger
     * value to avoid malloc chatter (things should still work, but will be
     * slightly more inefficient). */
    return lwan_response_websocket_read_hint(request, 1024);
}
