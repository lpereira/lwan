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
#include <netdb.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "lwan.h"
#include "sd-daemon.h"
#include "int-to-str.h"


static int
_get_backlog_size(void)
{
#ifdef SOMAXCONN
    int backlog = SOMAXCONN;
#else
    int backlog = 128;
#endif
    FILE *somaxconn;

    somaxconn = fopen("/proc/sys/net/core/somaxconn", "r");
    if (somaxconn) {
        int tmp;
        if (fscanf(somaxconn, "%d", &tmp) == 1)
            backlog = tmp;
        fclose(somaxconn);
    }

    return backlog;
}

static uint16_t
_get_listening_port(int fd)
{
    struct sockaddr_in sin;
    socklen_t len = sizeof(sin);

    if (getsockname(fd, (struct sockaddr *)&sin, &len) < 0)
        lwan_status_critical_perror("getsockname");

    return ntohs(sin.sin_port);
}

static int
_setup_socket_from_systemd(lwan_t *l)
{
    int fd = SD_LISTEN_FDS_START;

    if (!sd_is_socket_inet(fd, AF_INET, SOCK_STREAM, 1, 0))
        lwan_status_critical("Passed file descriptor is not a "
            "listening TCP socket");

    l->config.port = _get_listening_port(fd);

    return fd;
}

#define SET_SOCKET_OPTION(_domain,_option,_param,_size) \
    do { \
        if (setsockopt(fd, (_domain), (_option), (_param), (_size)) < 0) \
            lwan_status_critical_perror("setsockopt"); \
    } while(0)

#define SET_SOCKET_OPTION_MAY_FAIL(_domain,_option,_param,_size) \
    do { \
        if (setsockopt(fd, (_domain), (_option), (_param), (_size)) < 0) \
            lwan_status_warning("%s not supported by the kernel", \
                #_option); \
    } while(0)

#ifndef SO_REUSEPORT
#define SO_REUSEPORT 15
#endif

static int
_setup_socket_normally(lwan_t *l)
{
    char port_buf[INT_TO_STR_BUFFER_SIZE];
    size_t port_len;
    struct addrinfo *addrs, *a;
    struct addrinfo hints = {
        .ai_family = l->config.ipv6 ? AF_INET6 : AF_INET,
        .ai_socktype = SOCK_STREAM,
        .ai_flags = AI_PASSIVE
    };
    int fd;

    char *port = uint_to_string(l->config.port, port_buf, &port_len);
    int ret = getaddrinfo(NULL, port, &hints, &addrs);
    if (ret)
        lwan_status_critical("getaddrinfo: %s\n", gai_strerror(ret));

    /* Try each address until we bind one successfully. */
    for (a = addrs; a; a = a->ai_next) {
        fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
        if (fd < 0)
            continue;
        SET_SOCKET_OPTION(SOL_SOCKET, SO_REUSEADDR, (int[]){ 1 }, sizeof(int));
        if (l->config.reuse_port)
            SET_SOCKET_OPTION_MAY_FAIL(SOL_SOCKET, SO_REUSEPORT,
                                                    (int[]){ 1 }, sizeof(int));
        if (bind(fd, a->ai_addr, a->ai_addrlen) == 0)
            break;
        close(fd);
    }
    if (!a)
        lwan_status_critical("Could not bind socket");

    if (listen(fd, _get_backlog_size()) < 0)
        lwan_status_critical_perror("listen");

    char host_buf[NI_MAXHOST], serv_buf[NI_MAXSERV];
    ret = getnameinfo(a->ai_addr, a->ai_addrlen, host_buf, sizeof(host_buf),
                      serv_buf, sizeof(serv_buf), NI_NUMERICSERV);
    if (ret)
        lwan_status_critical("getnameinfo: %s\n", gai_strerror(ret));

    if (a->ai_family == AF_INET6)
        lwan_status_info("Listening on http://[%s]:%s", host_buf, serv_buf);
    else
        lwan_status_info("Listening on http://%s:%s", host_buf, serv_buf);

    freeaddrinfo(addrs);
    return fd;
}

#ifndef TCP_FASTOPEN
#define TCP_FASTOPEN 23
#endif

void
lwan_socket_init(lwan_t *l)
{
    int fd, n;

    lwan_status_debug("Initializing sockets");

    n = sd_listen_fds(1);
    if (n > 1) {
        lwan_status_critical("Too many file descriptors received");
    } else if (n == 1) {
        fd = _setup_socket_from_systemd(l);
    } else {
        fd = _setup_socket_normally(l);
    }

    SET_SOCKET_OPTION(SOL_SOCKET, SO_LINGER,
        ((struct linger[]){{ .l_onoff = 1, .l_linger = 1 }}), sizeof(struct linger));

    SET_SOCKET_OPTION_MAY_FAIL(SOL_TCP, TCP_FASTOPEN,
                                            (int[]){ 5 }, sizeof(int));
    SET_SOCKET_OPTION_MAY_FAIL(SOL_TCP, TCP_QUICKACK,
                                            (int[]){ 0 }, sizeof(int));

    l->main_socket = fd;
}

#undef SET_SOCKET_OPTION
#undef SET_SOCKET_OPTION_MAY_FAIL

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
