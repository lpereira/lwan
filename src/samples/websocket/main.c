/*
 * lwan - simple web server
 * Copyright (c) 2018 Leandro A. F. Pereira <leandro@hardinfo.org>
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
        "        </script>\n"
        "    </head>\n"
        "    <body>\n"
        "       <h1>Lwan WebSocket demo!</h1>\n"
        "       <h2>Send-only sample: server is writing this continuously:</h2>\n"
        "       <p><div id=\"write-output\" style=\"background: red; color: yellow\">Disconnected</div></p>\n"
        "       <h2>Echo server sample:</h2>\n"
        "       <p><input id=\"read-input\" disabled><button disabled id=\"read-button\" onclick=\"send_to_read_sock()\">Send</button></p>\n"
        "       <p>Server said this: <div id=\"read-output\" style=\"background: red; color: yellow\">Disconnected</div></p>\n"
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
        {.prefix = "/", .handler = LWAN_HANDLER_REF(index)},
        {},
    };
    struct lwan l;

    lwan_init(&l);

    lwan_set_url_map(&l, default_map);
    lwan_main_loop(&l);

    lwan_shutdown(&l);

    return 0;
}
