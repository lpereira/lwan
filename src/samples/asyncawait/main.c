/*
 * lwan - simple web server
 * Copyright (c) 2020 L. A. F. Pereira <l@tia.mat.br>
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

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

#include "lwan.h"

static void close_socket(void *data) { close((int)(intptr_t)data); }

LWAN_HANDLER(asyncawait)
{
    int fd;
    struct sockaddr_in addr;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return HTTP_INTERNAL_ERROR;

    coro_defer(request->conn->coro, close_socket, (void *)(intptr_t)fd);

    addr = (struct sockaddr_in){.sin_family = AF_INET,
                                .sin_addr.s_addr = inet_addr("127.0.0.1"),
                                .sin_port = htons(6969)};
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        return HTTP_UNAVAILABLE;

    while (true) {
        char buffer[128];
        ssize_t r = lwan_request_async_read(request, fd, buffer, sizeof(buffer));

        lwan_strbuf_set_static(response->buffer, buffer, (size_t)r);
        lwan_response_send_chunk(request);
    }

    return HTTP_OK;
}

int main(void)
{
    const struct lwan_url_map default_map[] = {
        {.prefix = "/", .handler = LWAN_HANDLER_REF(asyncawait)},
        {},
    };
    struct lwan l;

    lwan_init(&l);

    lwan_set_url_map(&l, default_map);
    lwan_main_loop(&l);

    lwan_shutdown(&l);

    return 0;
}
