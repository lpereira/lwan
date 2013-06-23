/*
 * lwan - simple web server
 * Copyright (c) 2012, 2013 Leandro A. F. Pereira <leandro@hardinfo.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include "lwan.h"

#define SET_SOCKET_OPTION(_domain,_option,_param,_size) \
    do { \
        if (setsockopt(fd, (_domain), (_option), (_param), (_size)) < 0) { \
            lwan_status_perror("setsockopt"); \
            goto handle_error; \
        } \
    } while(0)

#ifndef TCP_FASTOPEN
#define TCP_FASTOPEN 23
#endif

void
lwan_socket_init(lwan_t *l)
{
    struct sockaddr_in sin;
    int fd;

    lwan_status_debug("Initializing sockets");

    fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        lwan_status_perror("socket");
        exit(-1);
    }

    SET_SOCKET_OPTION(SOL_SOCKET, SO_REUSEADDR, (int[]){ 1 }, sizeof(int));
    SET_SOCKET_OPTION(SOL_SOCKET, SO_LINGER,
        ((struct linger[]){{ .l_onoff = 1, .l_linger = 1 }}), sizeof(struct linger));

    /* This might fail if running on an old kernel, so don't use the macro */
    if (UNLIKELY(setsockopt(fd, SOL_TCP, TCP_FASTOPEN,
                                            (int[]){ 5 }, sizeof(int)) < 0))
        lwan_status_warning("TCP_FASTOPEN not supported by kernel");

    memset(&sin, 0, sizeof(sin));
    sin.sin_port = htons(l->config.port);
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_family = AF_INET;

    if (bind(fd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        lwan_status_perror("bind");
        goto handle_error;
    }

    if (listen(fd, l->thread.count * l->thread.max_fd) < 0) {
        lwan_status_perror("listen");
        goto handle_error;
    }

    l->main_socket = fd;

    lwan_status_info("Listening on http://0.0.0.0:%d", l->config.port);
    return;

handle_error:
    close(fd);
    exit(-1);
}

#undef SET_SOCKET_OPTION

void
lwan_socket_shutdown(lwan_t *l)
{
    lwan_status_debug("Shutting down sockets");
    if (shutdown(l->main_socket, SHUT_RDWR) < 0) {
        lwan_status_perror("shutdown");
        close(l->main_socket);
        exit(-4);
    }
    close(l->main_socket);
}
