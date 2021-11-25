/*
 * lwan - simple web server
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

static struct lwan_pubsub_topic *chat;

/* This is a write-only sample of the API: it just sends random integers
 * over a WebSockets connection. */
LWAN_HANDLER(ws_write)
{
    enum lwan_http_status status = lwan_request_websocket_upgrade(request);

    if (status != HTTP_SWITCHING_PROTOCOLS)
        return status;

    while (true) {
        lwan_strbuf_printf(response->buffer, "Some random integer: %d", rand());
        lwan_response_websocket_write(request);
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
LWAN_HANDLER(ws_read)
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
            lwan_response_websocket_write(request);

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

LWAN_HANDLER(ws_chat)
{
    struct lwan_pubsub_subscriber *sub;
    struct lwan_pubsub_msg *msg;
    enum lwan_http_status status;
    static int total_user_count;
    int user_id;
    uint64_t sleep_time = 1000;

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
    lwan_response_websocket_write(request);

    coro_defer2(request->conn->coro, pub_depart_message, chat,
                (void *)(intptr_t)user_id);
    lwan_pubsub_publishf(chat, "*** User%d has joined the chat!\n", user_id);

    while (true) {
        switch (lwan_response_websocket_read(request)) {
        case ENOTCONN:   /* read() called before connection is websocket */
        case ECONNRESET: /* Client closed the connection */
            goto out;

        case EAGAIN: /* Nothing is available from other clients */
            while ((msg = lwan_pubsub_consume(sub))) {
                const struct lwan_value *value = lwan_pubsub_msg_value(msg);

                lwan_strbuf_set(response->buffer, value->value, value->len);

                /* Mark as done before writing: websocket_write() can abort the
                 * coroutine and we want to drop the reference before this
                 * happens. */
                lwan_pubsub_msg_done(msg);

                lwan_response_websocket_write(request);
                sleep_time = 500;
            }

            lwan_request_sleep(request, sleep_time);

            /* We're receiving a lot of messages, wait up to 1s (500ms in the loop
             * above, and 500ms in the increment below). Otherwise, wait 500ms every
             * time we return from lwan_request_sleep() until we reach 8s.  This way,
             * if a chat is pretty busy, we'll have a lag of at least 1s -- which is
             * probably fine; if it's not busy, we can sleep a bit more and conserve
             * some resources. */
            if (sleep_time <= 8000)
                sleep_time += 500;
            break;

        case 0: /* We got something! Copy it to echo it back */
            lwan_pubsub_publishf(chat, "User%d: %.*s\n", user_id,
                                 (int)lwan_strbuf_get_length(response->buffer),
                                 lwan_strbuf_get_buffer(response->buffer));
            break;
        }
    }

out:
    /* We abort the coroutine here because there's not much we can do at this
     * point as this isn't a HTTP connection anymore.  */
    coro_yield(request->conn->coro, CONN_CORO_ABORT);
    __builtin_unreachable();
}

LWAN_HANDLER(index)
{
    static const char message[] =
        "<html>\n"
        "    <head>\n"
        "        <script type=\"text/javascript\">\n"
        "            write_sock = new WebSocket(\"ws://localhost:8080/ws-write\")\n"
        "            write_sock.onmessage = function (event) {\n"
        "              document.getElementById(\"write-output\").innerText = event.data;\n"
        "            }\n"
        "            write_sock.onerror = function(event) {\n"
        "              document.getElementById(\"write-output\").innerText = \"Disconnected\";\n"
        "              document.getElementById(\"write-output\").style.background = \"red\";\n"
        "            }\n"
        "            write_sock.onopen = function(event) {\n"
        "              document.getElementById(\"write-output\").style.background = \"blue\";\n"
        "            }\n"
        "            read_sock = new WebSocket(\"ws://localhost:8080/ws-read\")\n"
        "            read_sock.onmessage = function (event) {\n"
        "              document.getElementById(\"read-output\").innerText = event.data;\n"
        "            }\n"
        "            read_sock.onopen = function(event) {\n"
        "              document.getElementById(\"read-button\").disabled = false;\n"
        "              document.getElementById(\"read-input\").disabled = false;\n"
        "              document.getElementById(\"read-output\").style.background = \"blue\";\n"
        "              document.getElementById(\"read-output\").innerText = \"\";\n"
        "            }\n"
        "            read_sock.onerror = function(event) {\n"
        "              document.getElementById(\"read-button\").disabled = true;\n"
        "              document.getElementById(\"read-input\").disabled = true;\n"
        "              document.getElementById(\"read-output\").innerText = \"Disconnected\";\n"
        "              document.getElementById(\"read-output\").style.background = \"red\";\n"
        "            }\n"
        "            send_to_read_sock = function() {\n"
        "              read_sock.send(document.getElementById(\"read-input\").value);\n"
        "            }\n"
        "            chat_sock = new WebSocket(\"ws://localhost:8080/ws-chat\")\n"
        "            chat_sock.onopen = function(event) {\n"
        "              document.getElementById(\"chat-button\").disabled = false;\n"
        "              document.getElementById(\"chat-input\").disabled = false;\n"
        "              document.getElementById(\"chat-textarea\").style.background = \"blue\";\n"
        "              document.getElementById(\"chat-input\").innerText = \"\";\n"
        "            }\n"
        "            chat_sock.onerror = function(event) {\n"
        "              document.getElementById(\"chat-button\").disabled = true;\n"
        "              document.getElementById(\"chat-input\").disabled = true;\n"
        "              document.getElementById(\"chat-input\").innerText = \"Disconnected\";\n"
        "              document.getElementById(\"chat-textarea\").style.background = \"red\";\n"
        "            }\n"
        "            chat_sock.onmessage = function (event) {\n"
        "              document.getElementById(\"chat-textarea\").value += event.data;\n"
        "            }\n"
        "            send_chat_msg = function() {\n"
        "              chat_sock.send(document.getElementById(\"chat-input\").value);\n"
        "              document.getElementById(\"chat-input\").value = \"\";\n"
        "            }\n"
        "        </script>\n"
        "    </head>\n"
        "    <body>\n"
        "       <h1>Lwan WebSocket demo!</h1>\n"
        "       <h2>Send-only sample: server is writing this continuously:</h2>\n"
        "       <p><div id=\"write-output\" style=\"background: red; color: yellow\">Disconnected</div></p>\n"
        "       <h2>Echo server sample:</h2>\n"
        "       <p><input id=\"read-input\" disabled><button disabled id=\"read-button\" onclick=\"send_to_read_sock()\">Send</button></p>\n"
        "       <p>Server said this: <div id=\"read-output\" style=\"background: red; color: yellow\">Disconnected</div></p>\n"
        "       <h3>Chat sample:</h3>\n"
        "       Send message: <input id=\"chat-input\" disabled><button disabled id=\"chat-button\" onclick=\"send_chat_msg()\">Send</button></p>\n"
        "       <textarea id=\"chat-textarea\" rows=\"20\" cols=\"120\" style=\"color: yellow; background-color: red\"></textarea>\n"
        "    </body>\n"
        "</html>";

    request->response.mime_type = "text/html";
    lwan_strbuf_set_static(response->buffer, message, sizeof(message) - 1);

    return HTTP_OK;
}

int main(void)
{
    const struct lwan_url_map default_map[] = {
        {.prefix = "/ws-write", .handler = LWAN_HANDLER_REF(ws_write)},
        {.prefix = "/ws-read", .handler = LWAN_HANDLER_REF(ws_read)},
        {.prefix = "/ws-chat", .handler = LWAN_HANDLER_REF(ws_chat)},
        {.prefix = "/", .handler = LWAN_HANDLER_REF(index)},
        {},
    };
    struct lwan l;

    lwan_init(&l);

    chat = lwan_pubsub_new_topic();

    lwan_set_url_map(&l, default_map);
    lwan_main_loop(&l);

    lwan_shutdown(&l);
    lwan_pubsub_free_topic(chat);

    return 0;
}
