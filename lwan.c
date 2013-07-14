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
#include <fcntl.h>
#include <setjmp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "lwan.h"

static jmp_buf cleanup_jmp_buf;

void
lwan_init(lwan_t *l)
{
    int max_threads = sysconf(_SC_NPROCESSORS_ONLN);
    struct rlimit r;

    lwan_status_init(l);
    lwan_status_debug("Initializing lwan web server");

    l->thread.count = max_threads > 0 ? max_threads : 2;

    if (getrlimit(RLIMIT_NOFILE, &r) < 0)
        lwan_status_critical_perror("getrlimit");

    if (r.rlim_max == RLIM_INFINITY)
        r.rlim_cur *= 8;
    else if (r.rlim_cur < r.rlim_max)
        r.rlim_cur = r.rlim_max;
    if (setrlimit(RLIMIT_NOFILE, &r) < 0)
        lwan_status_critical_perror("setrlimit");

    l->requests = calloc(r.rlim_cur, sizeof(lwan_request_t));
    l->thread.max_fd = r.rlim_cur / l->thread.count;
    lwan_status_info("Using %d threads, maximum %d sockets per thread",
        l->thread.count, l->thread.max_fd);

    for (--r.rlim_cur; r.rlim_cur; --r.rlim_cur) {
        l->requests[r.rlim_cur].response.buffer = strbuf_new();
        l->requests[r.rlim_cur].lwan = l;
    }

    srand(time(NULL));
    signal(SIGPIPE, SIG_IGN);
    close(STDIN_FILENO);

    lwan_socket_init(l);
    lwan_thread_init(l);
    lwan_job_thread_init();
    lwan_response_init();
}

static void
_url_map_free(lwan_t *l)
{
    if (!l->url_map)
        return;

    lwan_trie_destroy(l->url_map_trie);
    lwan_url_map_t *url_map = l->url_map;
    for (; url_map->prefix; url_map++) {
        lwan_handler_t *handler = url_map->handler;

        if (handler && handler->shutdown)
            handler->shutdown(url_map->data);
    }
}

void
lwan_shutdown(lwan_t *l)
{
    lwan_status_info("Shutting down");

    lwan_job_thread_shutdown();
    lwan_thread_shutdown(l);
    lwan_socket_shutdown(l);

    lwan_status_debug("Shutting down URL handlers");
    _url_map_free(l);

    lwan_response_shutdown();
    lwan_status_shutdown(l);

    int i;
    for (i = l->thread.max_fd * l->thread.count - 1; i >= 0; --i)
        strbuf_free(l->requests[i].response.buffer);

    free(l->requests);
}

void
lwan_set_url_map(lwan_t *l, lwan_url_map_t *url_map)
{
    _url_map_free(l);

    l->url_map = url_map;
    l->url_map_trie = lwan_trie_new();
    if (!l->url_map_trie)
        lwan_status_critical_perror("lwan_trie_new");

    for (; url_map->prefix; url_map++) {
        lwan_handler_t *handler = url_map->handler;

        url_map->prefix_len = strlen(url_map->prefix);
        lwan_trie_add(l->url_map_trie, url_map->prefix, url_map);

        if (!handler || !handler->init) {
            url_map->flags = HANDLER_PARSE_MASK;
            continue;
        }
        url_map->data = handler->init(url_map->args);
        url_map->callback = handler->handle;
        url_map->flags = handler->flags;
    }
}

static ALWAYS_INLINE void
_push_request_fd(lwan_t *l, int fd, struct sockaddr_in *addr, socklen_t addr_size)
{
    static int counter = 0;
    unsigned thread = counter++ % l->thread.count;
    int epoll_fd = l->thread.threads[thread].epoll_fd;
    struct epoll_event event = {
        .events = EPOLLIN | EPOLLRDHUP | EPOLLERR | EPOLLET,
        .data.fd = fd
    };

    memcpy(&l->requests[fd].remote_address, addr, addr_size);
    l->requests[fd].thread = &l->thread.threads[thread];

    if (UNLIKELY(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event) < 0))
        lwan_status_critical_perror("epoll_ctl");
}

static void
_signal_handler(int signal_number)
{
    lwan_status_info("Signal %d (%s) received",
                                signal_number, strsignal(signal_number));
    longjmp(cleanup_jmp_buf, 1);
}

void
lwan_main_loop(lwan_t *l)
{
    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0)
        lwan_status_critical_perror("epoll_create1");

    if (setjmp(cleanup_jmp_buf))
        goto end;

    signal(SIGINT, _signal_handler);

    struct epoll_event events[128];
    struct epoll_event socket_ev = {
        .events = EPOLLIN,
        .data.u32 = 0
    };
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, l->main_socket, &socket_ev) < 0)
        lwan_status_critical_perror("epoll_ctl");

    lwan_status_info("Ready to serve");

    for (;;) {
        int n_fds = epoll_wait(epoll_fd, events, N_ELEMENTS(events), -1);
        for (; n_fds > 0; --n_fds) {
            struct sockaddr_in addr;
            int child_fd;
            socklen_t addr_size = sizeof(struct sockaddr_in);

            child_fd = accept4(l->main_socket, (struct sockaddr *)&addr,
                               &addr_size, SOCK_NONBLOCK);
            if (UNLIKELY(child_fd < 0)) {
                lwan_status_perror("accept");
                continue;
            }

            _push_request_fd(l, child_fd, &addr, addr_size);
        }
    }

end:
    close(epoll_fd);
}
