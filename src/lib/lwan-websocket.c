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

#include <endian.h>

#include "lwan-private.h"
#include "lwan-io-wrappers.h"

enum ws_opcode {
    WS_OPCODE_CONTINUATION = 0,
    WS_OPCODE_TEXT = 1,
    WS_OPCODE_BINARY = 2,
    WS_OPCODE_CLOSE = 8,
    WS_OPCODE_PING = 9,
    WS_OPCODE_PONG = 10,
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
    size_t generation;
    char *temp;

    if (UNLIKELY(len > 125)) {
        lwan_status_debug("Received PING opcode with length %zu."
                          "Max is 125. Aborting connection.",
                          len);
        goto abort;
    }

    generation = coro_deferred_get_generation(request->conn->coro);

    temp = coro_malloc(request->conn->coro, len);
    if (UNLIKELY(!temp))
        goto abort;

    lwan_recv(request, temp, len, 0);
    write_websocket_frame(request, WS_OPCODE_PONG, temp, len);

    coro_deferred_run(request->conn->coro, generation);

    return;

abort:
    coro_yield(request->conn->coro, CONN_CORO_ABORT);
    __builtin_unreachable();
}

bool lwan_response_websocket_read(struct lwan_request *request)
{
    uint16_t header;
    uint64_t len_frame;
    char *msg;
    bool continuation = false;
    bool fin;

    if (!(request->conn->flags & CONN_IS_WEBSOCKET))
        return false;

    lwan_strbuf_reset(request->response.buffer);

next_frame:
    lwan_recv(request, &header, sizeof(header), 0);

    fin = (header & 0x8000);

    switch ((enum ws_opcode)((header & 0xf00) >> 8)) {
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
        /* FIXME: handling PING packets here doesn't seem ideal; they won't be
         * handled, for instance, if the user never receives data from the
         * websocket. */
        send_websocket_pong(request, header & 0x7f);
        goto next_frame;
    default:
        lwan_status_debug(
            "Received unexpected WebSockets opcode: 0x%x, ignoring",
            (header & 0xf00) >> 8);
        goto next_frame;
    }

    switch (header & 0x7f) {
    default:
        len_frame = (uint64_t)(header & 0x7f);
        break;
    case 0x7e:
        lwan_recv(request, &len_frame, 2, 0);
        len_frame = (uint64_t)ntohs((uint16_t)len_frame);
        break;
    case 0x7f:
        lwan_recv(request, &len_frame, 8, 0);
        len_frame = be64toh(len_frame);
        break;
    }

    size_t cur_len = lwan_strbuf_get_length(request->response.buffer);

    if (UNLIKELY(!lwan_strbuf_grow_by(request->response.buffer, len_frame))) {
        coro_yield(request->conn->coro, CONN_CORO_ABORT);
        __builtin_unreachable();
    }

    msg = lwan_strbuf_get_buffer(request->response.buffer) + cur_len;

    if (LIKELY(header & 0x80)) {
        /* Payload is masked; should always be true on Client->Server comms but
         * don't assume this is always the case. */
        union {
            char as_char[4];
            uint32_t as_int;
        } masks;
        struct iovec vec[] = {
            {.iov_base = masks.as_char, .iov_len = sizeof(masks.as_char)},
            {.iov_base = msg, .iov_len = len_frame},
        };

        lwan_readv(request, vec, N_ELEMENTS(vec));

        if (masks.as_int != 0x00000000) {
            for (uint64_t i = 0; i < len_frame; i++)
                msg[i] ^= masks.as_char[i % sizeof(masks)];
        }
    } else {
        lwan_recv(request, msg, len_frame, 0);
    }

    if (continuation && !fin) {
        coro_yield(request->conn->coro, CONN_CORO_WANT_READ);
        continuation = false;

        goto next_frame;
    }

    return request->conn->flags & CONN_IS_WEBSOCKET;
}
