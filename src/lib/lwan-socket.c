/*
 * lwan - web server
 * Copyright (c) 2012, 2013 L. A. F. Pereira <l@tia.mat.br>
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
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "lwan-private.h"

#include "int-to-str.h"
#include "sd-daemon.h"

#ifdef __linux__

static bool reno_supported;
static void init_reno_supported(void)
{
    FILE *allowed;

    reno_supported = false;

    allowed = fopen("/proc/sys/net/ipv4/tcp_allowed_congestion_control", "re");
    if (!allowed)
        return;

    char line[4096];
    if (fgets(line, sizeof(line), allowed)) {
        if (strstr(line, "reno"))
            reno_supported = true;
    }
    fclose(allowed);
}

static bool is_reno_supported(void)
{
    static pthread_once_t reno_supported_once = PTHREAD_ONCE_INIT;
    pthread_once(&reno_supported_once, init_reno_supported);
    return reno_supported;
}
#endif

static int backlog_size;
static void init_backlog_size(void)
{
#ifdef __linux__
    FILE *somaxconn;

    somaxconn = fopen("/proc/sys/net/core/somaxconn", "re");
    if (somaxconn) {
        int tmp;
        if (fscanf(somaxconn, "%d", &tmp) == 1)
            backlog_size = tmp;
        fclose(somaxconn);
    }
#endif

    if (!backlog_size)
        backlog_size = SOMAXCONN;
}

static int get_backlog_size(void)
{
    static pthread_once_t backlog_size_once = PTHREAD_ONCE_INIT;
    pthread_once(&backlog_size_once, init_backlog_size);
    return backlog_size;
}

static int set_socket_flags(int fd)
{
    int flags = fcntl(fd, F_GETFD);
    if (flags < 0)
        lwan_status_critical_perror("Could not obtain socket flags");
    if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0)
        lwan_status_critical_perror("Could not set socket flags");

    flags = fcntl(fd, F_GETFL);
    if (flags < 0)
        lwan_status_critical_perror("Could not obtain socket flags");
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
        lwan_status_critical_perror("Could not set socket flags");

    return fd;
}

static sa_family_t parse_listener_ipv4(char *listener, char **node, char **port)
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

        if (streq(*node, "*")) {
            /* *:8080 */
            *node = "0.0.0.0";

            return AF_UNSPEC; /* IPv4 or IPv6 */
        }
    }

    return AF_INET;
}

static sa_family_t parse_listener_ipv6(char *listener, char **node, char **port)
{
    char *last_colon = strrchr(listener, ':');
    if (!last_colon)
        return AF_MAX;

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

sa_family_t lwan_socket_parse_address(char *listener, char **node, char **port)
{
    if (*listener == '[')
        return parse_listener_ipv6(listener, node, port);

    return parse_listener_ipv4(listener, node, port);
}

static sa_family_t parse_listener(char *listener, char **node, char **port)
{
    if (streq(listener, "systemd")) {
        lwan_status_critical(
            "Listener configured to use systemd socket activation, "
            "but started outside systemd.");
        return AF_MAX;
    }

    return lwan_socket_parse_address(listener, node, port);
}

static int listen_addrinfo(int fd,
                           const struct addrinfo *addr,
                           bool print_listening_msg,
                           bool is_https)
{
    if (listen(fd, get_backlog_size()) < 0)
        lwan_status_critical_perror("listen");

    if (print_listening_msg) {
        const char *s_if_https = is_https ? "s" : "";
        char host_buf[NI_MAXHOST], serv_buf[NI_MAXSERV];
        int ret = getnameinfo(addr->ai_addr, addr->ai_addrlen, host_buf,
                              sizeof(host_buf), serv_buf, sizeof(serv_buf),
                              NI_NUMERICHOST | NI_NUMERICSERV);
        if (ret)
            lwan_status_critical("getnameinfo: %s", gai_strerror(ret));

        if (addr->ai_family == AF_INET6)
            lwan_status_info("Listening on http%s://[%s]:%s", s_if_https,
                             host_buf, serv_buf);
        else
            lwan_status_info("Listening on http%s://%s:%s", s_if_https,
                             host_buf, serv_buf);
    }

    return set_socket_flags(fd);
}

#define SET_SOCKET_OPTION(_domain, _option, _param)                            \
    do {                                                                       \
        const socklen_t _param_size_ = (socklen_t)sizeof(*(_param));           \
        if (setsockopt(fd, (_domain), (_option), (_param), _param_size_) < 0)  \
            lwan_status_critical_perror("setsockopt");                         \
    } while (0)

#define SET_SOCKET_OPTION_MAY_FAIL(_domain, _option, _param)                   \
    do {                                                                       \
        const socklen_t _param_size_ = (socklen_t)sizeof(*(_param));           \
        if (setsockopt(fd, (_domain), (_option), (_param), _param_size_) < 0)  \
            lwan_status_perror("%s not supported by the kernel", #_option);    \
    } while (0)

static int bind_and_listen_addrinfos(const struct addrinfo *addrs,
                                     bool print_listening_msg,
                                     bool is_https)
{
    const struct addrinfo *addr;

    /* Try each address until we bind one successfully. */
    for (addr = addrs; addr; addr = addr->ai_next) {
        int fd = socket(addr->ai_family,
                        addr->ai_socktype,
                        addr->ai_protocol);
        if (fd < 0)
            continue;

        SET_SOCKET_OPTION(SOL_SOCKET, SO_REUSEADDR, (int[]){1});
#ifdef SO_REUSEPORT
        SET_SOCKET_OPTION(SOL_SOCKET, SO_REUSEPORT, (int[]){1});
#else
        lwan_status_critical("SO_REUSEPORT not supported by the OS");
#endif

        if (!bind(fd, addr->ai_addr, addr->ai_addrlen))
            return listen_addrinfo(fd, addr, print_listening_msg, is_https);

        close(fd);
    }

    lwan_status_critical("Could not bind socket");
}

static int setup_socket_normally(const struct lwan *l,
                                 bool print_listening_msg,
                                 bool is_https,
                                 const char *listener_from_config)
{
    char *node, *port;
    char *listener = strdupa(listener_from_config);
    sa_family_t family = parse_listener(listener, &node, &port);

    if (family == AF_MAX) {
        lwan_status_critical("Could not parse listener: %s",
                             l->config.listener);
    }

    struct addrinfo *addrs;
    struct addrinfo hints = {.ai_family = family,
                             .ai_socktype = SOCK_STREAM,
                             .ai_flags = AI_PASSIVE};

    int ret = getaddrinfo(node, port, &hints, &addrs);
    if (ret)
        lwan_status_critical("getaddrinfo: %s", gai_strerror(ret));

    int fd = bind_and_listen_addrinfos(addrs, print_listening_msg, is_https);
    freeaddrinfo(addrs);
    return fd;
}

static int set_socket_options(const struct lwan *l, int fd)
{
    SET_SOCKET_OPTION(SOL_SOCKET, SO_LINGER,
                      (&(struct linger){.l_onoff = 1, .l_linger = 1}));

#ifdef __linux__

#ifndef TCP_FASTOPEN
#define TCP_FASTOPEN 23
#endif

    SET_SOCKET_OPTION_MAY_FAIL(SOL_SOCKET, SO_REUSEADDR, (int[]){1});
    SET_SOCKET_OPTION_MAY_FAIL(SOL_TCP, TCP_FASTOPEN, (int[]){5});
    SET_SOCKET_OPTION_MAY_FAIL(SOL_TCP, TCP_QUICKACK, (int[]){0});
    SET_SOCKET_OPTION_MAY_FAIL(SOL_TCP, TCP_DEFER_ACCEPT,
                               (int[]){(int)l->config.keep_alive_timeout});

    if (is_reno_supported())
        setsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, "reno", 4);
#endif

    return fd;
}

static int from_systemd_socket(const struct lwan *l, int fd)
{
    if (!sd_is_socket_inet(fd, AF_UNSPEC, SOCK_STREAM, 1, 0)) {
        lwan_status_critical("Passed file descriptor is not a "
                             "listening TCP socket");
    }

    return set_socket_options(l, set_socket_flags(fd));
}

int lwan_create_listen_socket(const struct lwan *l,
                              bool print_listening_msg,
                              bool is_https)
{
    const char *listener = is_https ? l->config.tls_listener
                                    : l->config.listener;

    if (!strncmp(listener, "systemd:", sizeof("systemd:") - 1)) {
        char **names = NULL;
        int n = sd_listen_fds_with_names(false, &names);
        int fd = -1;

        if (n < 0) {
            errno = -n;
            lwan_status_perror(
                "Could not parse socket activation data from systemd");
            return n;
        }

        listener += sizeof("systemd:") - 1;

        for (int i = 0; i < n; i++) {
            if (!strcmp(names[i], listener)) {
                fd = SD_LISTEN_FDS_START + i;
                break;
            }
        }

        strv_free(names);

        if (fd < 0) {
            lwan_status_critical(
                "No socket named `%s' has been passed from systemd", listener);
        }

        return from_systemd_socket(l, fd);
    }

    if (streq(listener, "systemd")) {
        int n = sd_listen_fds(false);

        if (n < 0) {
            errno = -n;
            lwan_status_perror("Could not obtain sockets passed from systemd");
            return n;
        }

        if (n != 1) {
            lwan_status_critical(
                "%d listeners passed from systemd. Must specify listeners with "
                "systemd:listener-name syntax",
                n);
        }

        return from_systemd_socket(l, SD_LISTEN_FDS_START);
    }

    int fd = setup_socket_normally(l, print_listening_msg, is_https, listener);
    return set_socket_options(l, fd);
}

#undef SET_SOCKET_OPTION
#undef SET_SOCKET_OPTION_MAY_FAIL
