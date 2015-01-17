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

#define _GNU_SOURCE
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
get_backlog_size(void)
{
#ifdef SOMAXCONN
    int backlog = SOMAXCONN;
#else
    int backlog = 128;
#endif
    FILE *somaxconn;

    somaxconn = fopen("/proc/sys/net/core/somaxconn", "re");
    if (somaxconn) {
        int tmp;
        if (fscanf(somaxconn, "%d", &tmp) == 1)
            backlog = tmp;
        fclose(somaxconn);
    }

    return backlog;
}

static int
setup_socket_from_systemd(void)
{
    int fd = SD_LISTEN_FDS_START;

    if (!sd_is_socket_inet(fd, AF_UNSPEC, SOCK_STREAM, 1, 0))
        lwan_status_critical("Passed file descriptor is not a "
            "listening TCP socket");

    int flags = fcntl(fd, F_GETFD);
    if (flags < 0)
        lwan_status_critical_perror("Could not obtain socket flags");
    if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0)
        lwan_status_critical_perror("Could not set socket flags");

    return fd;
}

static sa_family_t
parse_listener_ipv4(char *listener, char **node, char **port)
{
    char *colon = strrchr(listener, ':');
    if (!colon) {
        *port = "8080";
        if (!strchr(listener, '.')) {
            /* 8080 */
            *node = "0.0.0.0";
        } else {
            /* 127.0.0.1 */
            *node = listener;
        }
    } else {
        /*
         * 127.0.0.1:8080
         * localhost:8080
         */
        *colon = '\0';
        *node = listener;
        *port = colon + 1;

        if (!strcmp(*node, "*")) {
            /* *:8080 */
            *node = "0.0.0.0";
        }
    }

    return AF_INET;
}

static sa_family_t
parse_listener_ipv6(char *listener, char **node, char **port)
{
    char *last_colon = strrchr(listener, ':');
    if (!last_colon)
        return AF_UNSPEC;

    if (*(last_colon - 1) == ']') {
        /* [::]:8080 */
        *(last_colon - 1) = '\0';
        *node = listener + 1;
        *port = last_colon + 1;
    } else {
        /* [::1] */
        listener[strlen(listener) - 1] = '\0';
        *node = listener + 1;
        *port = "8080";
    }

    return AF_INET6;
}

static sa_family_t
parse_listener(char *listener, char **node, char **port)
{
    if (*listener == '[')
        return parse_listener_ipv6(listener, node, port);
    return parse_listener_ipv4(listener, node, port);
}

static int
listen_addrinfo(int fd, const struct addrinfo *addr)
{
    if (listen(fd, get_backlog_size()) < 0)
        lwan_status_critical_perror("listen");

    char host_buf[NI_MAXHOST], serv_buf[NI_MAXSERV];
    int ret = getnameinfo(addr->ai_addr, addr->ai_addrlen, host_buf, sizeof(host_buf),
                      serv_buf, sizeof(serv_buf), NI_NUMERICHOST | NI_NUMERICSERV);
    if (ret)
        lwan_status_critical("getnameinfo: %s", gai_strerror(ret));

    if (addr->ai_family == AF_INET6)
        lwan_status_info("Listening on http://[%s]:%s", host_buf, serv_buf);
    else
        lwan_status_info("Listening on http://%s:%s", host_buf, serv_buf);

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
bind_and_listen_addrinfos(struct addrinfo *addrs, bool reuse_port)
{
    const struct addrinfo *addr;

    /* Try each address until we bind one successfully. */
    for (addr = addrs; addr; addr = addr->ai_next) {
        int fd = socket(addr->ai_family,
            addr->ai_socktype | SOCK_CLOEXEC, addr->ai_protocol);
        if (fd < 0)
            continue;

        SET_SOCKET_OPTION(SOL_SOCKET, SO_REUSEADDR, (int[]){ 1 }, sizeof(int));
        SET_SOCKET_OPTION_MAY_FAIL(SOL_SOCKET, SO_REUSEPORT,
                                                (int[]){ reuse_port }, sizeof(int));

        if (!bind(fd, addr->ai_addr, addr->ai_addrlen))
            return listen_addrinfo(fd, addr);

        close(fd);
    }

    lwan_status_critical("Could not bind socket");
}

static int
setup_socket_normally(lwan_t *l)
{
    char *node, *port;
    char *listener = strdupa(l->config.listener);
    sa_family_t family = parse_listener(listener, &node, &port);
    if (family == AF_UNSPEC)
        lwan_status_critical("Could not parse listener: %s", l->config.listener);

    struct addrinfo *addrs;
    struct addrinfo hints = {
        .ai_family = family,
        .ai_socktype = SOCK_STREAM,
        .ai_flags = AI_PASSIVE
    };

    int ret = getaddrinfo(node, port, &hints, &addrs);
    if (ret)
        lwan_status_critical("getaddrinfo: %s", gai_strerror(ret));

    int fd = bind_and_listen_addrinfos(addrs, l->config.reuse_port);
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
        fd = setup_socket_from_systemd();
    } else {
        fd = setup_socket_normally(l);
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
