/*
 * lwan - web server
 * Copyright (c) 2018 L. A. F. Pereira <l@tia.mat.br>
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

#include <errno.h>
#include <stdlib.h>

#include "lwan.h"
#include "lwan-pubsub.h"

#include "websocket-sample.h"

static struct lwan_pubsub_topic *chat;

/* This is a write-only sample of the API: it just sends random integers
 * over a WebSockets connection. */
LWAN_HANDLER_ROUTE(ws_write, "/ws-write")
{
    enum lwan_http_status status = lwan_request_websocket_upgrade(request);

    if (status != HTTP_SWITCHING_PROTOCOLS)
        return status;

    while (true) {
        lwan_strbuf_printf(response->buffer, "Some random integer: %d", rand());
        lwan_response_websocket_write_text(request);
        lwan_request_sleep(request, 1000);
    }

    __builtin_unreachable();
}

static void free_strbuf(void *data)
{
    lwan_strbuf_free((struct lwan_strbuf *)data);
}

/* This is a slightly more featured echo server that tells how many seconds
 * passed since the last message has been received, and keeps sending it back
 * again and again. */
LWAN_HANDLER_ROUTE(ws_read, "/ws-read")
{
    enum lwan_http_status status = lwan_request_websocket_upgrade(request);
    struct lwan_strbuf *last_msg_recv;
    int seconds_since_last_msg = 0;

    if (status != HTTP_SWITCHING_PROTOCOLS)
        return status;

    last_msg_recv = lwan_strbuf_new();
    if (!last_msg_recv)
        return HTTP_INTERNAL_ERROR;
    coro_defer(request->conn->coro, free_strbuf, last_msg_recv);

    while (true) {
        switch (lwan_response_websocket_read(request)) {
        case ENOTCONN:   /* read() called before connection is websocket */
        case ECONNRESET: /* Client closed the connection */
            goto out;

        case EAGAIN: /* Nothing is available */
            lwan_strbuf_printf(response->buffer,
                               "Last message was received %d seconds ago: %.*s",
                               seconds_since_last_msg,
                               (int)lwan_strbuf_get_length(last_msg_recv),
                               lwan_strbuf_get_buffer(last_msg_recv));
            lwan_response_websocket_write_text(request);

            lwan_request_sleep(request, 1000);
            seconds_since_last_msg++;
            break;

        case 0: /* We got something! Copy it to echo it back */
            lwan_strbuf_set(last_msg_recv,
                            lwan_strbuf_get_buffer(response->buffer),
                            lwan_strbuf_get_length(response->buffer));

            seconds_since_last_msg = 0;

            break;
        }
    }

out:
    /* We abort the coroutine here because there's not much we can do at this
     * point as this isn't a HTTP connection anymore.  */
    coro_yield(request->conn->coro, CONN_CORO_ABORT);
    __builtin_unreachable();
}

static void unsub_chat(void *data1, void *data2)
{
    lwan_pubsub_unsubscribe((struct lwan_pubsub_topic *)data1,
                            (struct lwan_pubsub_subscriber *)data2);
}

static void pub_depart_message(void *data1, void *data2)
{
    char buffer[128];
    int r;

    r = snprintf(buffer, sizeof(buffer), "*** User%d has departed the chat!\n",
                 (int)(intptr_t)data2);
    if (r < 0 || (size_t)r >= sizeof(buffer))
        return;

    lwan_pubsub_publish((struct lwan_pubsub_topic *)data1, buffer, (size_t)r);
}

LWAN_HANDLER_ROUTE(ws_chat, "/ws-chat")
{
    struct lwan_pubsub_subscriber *sub;
    struct lwan_pubsub_msg *msg;
    enum lwan_http_status status;
    static int total_user_count;
    int user_id;

    sub = lwan_pubsub_subscribe(chat);
    if (!sub)
        return HTTP_INTERNAL_ERROR;
    coro_defer2(request->conn->coro, unsub_chat, chat, sub);

    status = lwan_request_websocket_upgrade(request);
    if (status != HTTP_SWITCHING_PROTOCOLS)
        return status;

    user_id = ATOMIC_INC(total_user_count);

    lwan_strbuf_printf(response->buffer, "*** Welcome to the chat, User%d!\n",
                       user_id);
    lwan_response_websocket_write_text(request);

    coro_defer2(request->conn->coro, pub_depart_message, chat,
                (void *)(intptr_t)user_id);
    lwan_pubsub_publishf(chat, "*** User%d has joined the chat!\n", user_id);

    const int websocket_fd = request->fd;
    const int sub_fd = lwan_pubsub_get_notification_fd(sub);
    while (true) {
        int resumed_fd =
            lwan_request_awaitv_any(request, websocket_fd, CONN_CORO_WANT_READ,
                                    sub_fd, CONN_CORO_WANT_READ, -1);

        if (resumed_fd == sub_fd) {
            while ((msg = lwan_pubsub_consume(sub))) {
                const struct lwan_value *value = lwan_pubsub_msg_value(msg);

                lwan_strbuf_set(response->buffer, value->value, value->len);

                /* Mark as done before writing: websocket_write() can abort the
                 * coroutine and we want to drop the reference before this
                 * happens. */
                lwan_pubsub_msg_done(msg);

                lwan_response_websocket_write_text(request);
            }
        } else if (resumed_fd == websocket_fd) {
            switch (lwan_response_websocket_read(request)) {
            case ENOTCONN:   /* read() called before connection is websocket */
            case ECONNRESET: /* Client closed the connection */
                goto out;

            case 0: /* We got something! Copy it to echo it back */
                lwan_pubsub_publishf(
                    chat, "User%d: %.*s\n", user_id,
                    (int)lwan_strbuf_get_length(response->buffer),
                    lwan_strbuf_get_buffer(response->buffer));
            }
        } else if (resumed_fd < 0) {
            lwan_status_error("error from fd %d", -resumed_fd);
            goto out;
        } else {
            lwan_status_warning("not awaiting on fd %d, ignoring", resumed_fd);
        }
    }

out:
    /* We abort the coroutine here because there's not much we can do at this
     * point as this isn't a HTTP connection anymore.  */
    coro_yield(request->conn->coro, CONN_CORO_ABORT);
    __builtin_unreachable();
}

LWAN_HANDLER_ROUTE(index, "/")
{
    request->response.mime_type = "text/html";
    lwan_strbuf_set_static(response->buffer,
                           index_html_value.value,
                           index_html_value.len);

    return HTTP_OK;
}

int main(void)
{
    chat = lwan_pubsub_new_topic();

    lwan_main();

    lwan_pubsub_free_topic(chat);

    return 0;
}
