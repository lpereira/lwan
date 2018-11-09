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

#include <stdlib.h>

#include "lwan.h"

LWAN_HANDLER(ws)
{
    enum lwan_http_status status = lwan_request_websocket_upgrade(request);

    if (status != HTTP_SWITCHING_PROTOCOLS)
        return status;

    while (true) {
        lwan_strbuf_printf(response->buffer, "Some random integer: %d", rand());
        lwan_response_websocket_write(request);
        lwan_request_sleep(request, 1000);
    }

    return HTTP_OK;
}

LWAN_HANDLER(index)
{
    static const char message[] = "<html>\n"
        "    <head>\n"
        "        <script type=\"text/javascript\">\n"
        "            sock=new WebSocket(\"ws://localhost:8080/ws\")\n"
        "            sock.onmessage = function (event) {\n"
        "              document.getElementById(\"output\").innerText = event.data;\n"
        "            }\n"
        "        </script>\n"
        "    </head>\n"
        "    <body>\n"
        "       <div id=\"output\"></div>\n"
        "    </body>\n"
        "</html>";

    request->response.mime_type = "text/html";
    lwan_strbuf_set_static(response->buffer, message, sizeof(message) - 1);

    return HTTP_OK;
}

int main(void)
{
    const struct lwan_url_map default_map[] = {
        {.prefix = "/ws", .handler = LWAN_HANDLER_REF(ws)},
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
