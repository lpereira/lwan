/*
 * lwan - simple web server
 * Copyright (c) 2019 Leandro A. F. Pereira <leandro@hardinfo.org>
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
#include <endian.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>

#if defined(__x86_64__)
#include <emmintrin.h>
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
};

static void write_websocket_frame(struct lwan_request *request,
                                  unsigned char header_byte,
                                  char *msg,
                                  size_t len)
{
    uint8_t frame[9];
    size_t frame_len;

    if (len <= 125) {
        frame[0] = (uint8_t)len;
        frame_len = 1;
    } else if (len <= 65535) {
        frame[0] = 0x7e;
        memcpy(frame + 1, &(uint16_t){htons((uint16_t)len)}, sizeof(uint16_t));
        frame_len = 3;
    } else {
        frame[0] = 0x7f;
        memcpy(frame + 1, &(uint64_t){htobe64((uint64_t)len)},
               sizeof(uint64_t));
        frame_len = 9;
    }

    struct iovec vec[] = {
        {.iov_base = &header_byte, .iov_len = 1},
        {.iov_base = frame, .iov_len = frame_len},
        {.iov_base = msg, .iov_len = len},
    };

    lwan_writev(request, vec, N_ELEMENTS(vec));
}

void lwan_response_websocket_write(struct lwan_request *request)
{
    size_t len = lwan_strbuf_get_length(request->response.buffer);
    char *msg = lwan_strbuf_get_buffer(request->response.buffer);
    /* FIXME: does it make a difference if we use WS_OPCODE_TEXT or
     * WS_OPCODE_BINARY? */
    unsigned char header = 0x80 | WS_OPCODE_TEXT;

    if (!(request->conn->flags & CONN_IS_WEBSOCKET))
        return;

    write_websocket_frame(request, header, msg, len);
    lwan_strbuf_reset(request->response.buffer);
}

static void send_websocket_pong(struct lwan_request *request, size_t len)
{
    char temp[128];

    if (UNLIKELY(len > 125)) {
        lwan_status_debug("Received PING opcode with length %zu."
                          "Max is 125. Aborting connection.",
                          len);
        coro_yield(request->conn->coro, CONN_CORO_ABORT);
        __builtin_unreachable();
    }

    lwan_recv(request, temp, len, 0);
    write_websocket_frame(request, WS_OPCODE_PONG, temp, len);
}

static uint64_t get_frame_length(struct lwan_request *request, uint16_t header)
{
    uint64_t len;

    switch (header & 0x7f) {
    case 0x7e:
        lwan_recv(request, &len, 2, 0);
        return (uint64_t)ntohs((uint16_t)len);
    case 0x7f:
        lwan_recv(request, &len, 8, 0);
        return (uint64_t)be64toh(len);
    default:
        return (uint64_t)(header & 0x7f);
    }
}

static void discard_frame(struct lwan_request *request, uint16_t header)
{
    uint64_t len = get_frame_length(request, header);

    for (char buffer[128]; len;)
        len -= (size_t)lwan_recv(request, buffer, sizeof(buffer), 0);
}

static void unmask(char *msg, uint64_t msg_len, char mask[static 4])
{
    const uint32_t mask32 = string_as_uint32(mask);
    char *msg_end = msg + msg_len;

    if (sizeof(void *) == 8) {
        const uint64_t mask64 = (uint64_t)mask32 << 32 | mask32;

#if defined(__x86_64__)
        if (msg_end - msg >= 16) {
            const __m128i mask128 =
                _mm_setr_epi64((__m64)mask64, (__m64)mask64);

            do {
                __m128i v = _mm_loadu_si128((__m128i *)msg);
                _mm_storeu_si128((__m128i *)msg, _mm_xor_si128(v, mask128));
                msg += 16;
            } while (msg_end - msg >= 16);
        }
#endif

        if (msg_end - msg >= 8) {
            uint64_t v = string_as_uint64(msg);
            v ^= mask64;
            msg = mempcpy(msg, &v, sizeof(v));
        }
    }

    while (msg_end - msg >= 4) {
        uint32_t v = string_as_uint32(msg);
        v ^= mask32;
        msg = mempcpy(msg, &v, sizeof(v));
    }

    switch (msg_end - msg) {
    case 3:
        msg[2] ^= mask[2]; /* fallthrough */
    case 2:
        msg[1] ^= mask[1]; /* fallthrough */
    case 1:
        msg[0] ^= mask[0];
    }
}

int lwan_response_websocket_read(struct lwan_request *request)
{
    uint16_t header;
    uint64_t frame_len;
    bool continuation = false;

    if (!(request->conn->flags & CONN_IS_WEBSOCKET))
        return ENOTCONN;

    lwan_strbuf_reset(request->response.buffer);

next_frame:
    if (!lwan_recv(request, &header, sizeof(header), continuation ? 0 : MSG_DONTWAIT))
        return EAGAIN;
    header = htons(header);

    if (UNLIKELY(header & 0x7000)) {
        lwan_status_debug("RSV1...RSV3 has non-zero value %d, aborting", header & 0x7000);
        /* No extensions are supported yet, so fail connection per RFC6455. */
        coro_yield(request->conn->coro, CONN_CORO_ABORT);
        __builtin_unreachable();
    }
    if (UNLIKELY(!(header & 0x80))) {
        lwan_status_debug("Client sent an unmasked WebSockets frame, aborting");
        coro_yield(request->conn->coro, CONN_CORO_ABORT);
        __builtin_unreachable();
    }

    switch ((enum ws_opcode)((header & 0x0f00) >> 8)) {
    case WS_OPCODE_CONTINUATION:
        continuation = true;
        break;

    case WS_OPCODE_TEXT:
    case WS_OPCODE_BINARY:
        break;

    case WS_OPCODE_CLOSE:
        request->conn->flags &= ~CONN_IS_WEBSOCKET;
        break;

    case WS_OPCODE_PING:
        send_websocket_pong(request, header & 0x7f);
        goto next_frame;

    case WS_OPCODE_PONG:
        lwan_status_debug("Received unsolicited PONG frame, discarding frame");
        discard_frame(request, header);
        goto next_frame;

    case WS_OPCODE_RSVD_1 ... WS_OPCODE_RSVD_5:
        lwan_status_debug("Received reserved non-control frame opcode: 0x%x, aborting",
            (header & 0x0f00) >> 8);
        /* RFC6455: ...the receiving endpoint MUST _Fail the WebSocket Connection_ */
        coro_yield(request->conn->coro, CONN_CORO_ABORT);
        __builtin_unreachable();

    case WS_OPCODE_RSVD_CONTROL_1 ... WS_OPCODE_RSVD_CONTROL_5:
        lwan_status_debug("Received reserved control frame opcode: 0x%x, aborting",
            (header & 0x0f00) >> 8);
        /* RFC6455: ...the receiving endpoint MUST _Fail the WebSocket Connection_ */
        coro_yield(request->conn->coro, CONN_CORO_ABORT);
        __builtin_unreachable();
    }

    size_t cur_buf_len = lwan_strbuf_get_length(request->response.buffer);

    frame_len = get_frame_length(request, header);
    if (UNLIKELY(!lwan_strbuf_grow_by(request->response.buffer, frame_len))) {
        coro_yield(request->conn->coro, CONN_CORO_ABORT);
        __builtin_unreachable();
    }
    /* FIXME: API to update used size, too, not just capacity!   Also, this can't
     * overflow if adding frame_len, as this is checked by grow_by() already. */
    request->response.buffer->used += frame_len;

    char *msg = lwan_strbuf_get_buffer(request->response.buffer) + cur_buf_len;
    char mask[4];
    struct iovec vec[] = {
        {.iov_base = mask, .iov_len = sizeof(mask)},
        {.iov_base = msg, .iov_len = frame_len},
    };
    lwan_readv(request, vec, N_ELEMENTS(vec));
    unmask(msg, frame_len, mask);

    if (continuation && !(header & 0x8000)) {
        continuation = false;
        goto next_frame;
    }

    return (request->conn->flags & CONN_IS_WEBSOCKET) ? 0 : ECONNRESET;
}
