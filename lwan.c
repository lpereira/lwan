/*
 * lwan - simple web server
 * Copyright (c) 2012 Leandro A. F. Pereira <leandro@hardinfo.org>
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
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "lwan.h"

static jmp_buf cleanup_jmp_buf;
static lwan_key_value_t empty_query_string_kv[] = {
    { .key = NULL, .value = NULL }
};

const char *
lwan_determine_mime_type_for_file_name(char *file_name)
{
    char *last_dot = strrchr(file_name, '.');
    if (UNLIKELY(!last_dot))
        goto fallback;

    STRING_SWITCH_L(last_dot) {
    case EXT_CSS: return "text/css";
    case EXT_HTM: return "text/html";
    case EXT_JPG: return "image/jpeg";
    case EXT_JS:  return "application/javascript";
    case EXT_PNG: return "image/png";
    case EXT_TXT: return "text/plain";
    }

fallback:
    return "application/octet-stream";
}

const char *
lwan_http_status_as_string(lwan_http_status_t status)
{
    switch (status) {
    case HTTP_OK: return "OK";
    case HTTP_NOT_MODIFIED: return "Not modified";
    case HTTP_BAD_REQUEST: return "Bad request";
    case HTTP_NOT_FOUND: return "Not found";
    case HTTP_FORBIDDEN: return "Forbidden";
    case HTTP_NOT_ALLOWED: return "Not allowed";
    case HTTP_TOO_LARGE: return "Request too large";
    case HTTP_INTERNAL_ERROR: return "Internal server error";
    }
    return "Invalid";
}

const char *
lwan_http_status_as_descriptive_string(lwan_http_status_t status)
{
    switch (status) {
    case HTTP_OK: return "Success!";
    case HTTP_NOT_MODIFIED: return "The content has not changed since previous request.";
    case HTTP_BAD_REQUEST: return "The client has issued a bad request.";
    case HTTP_NOT_FOUND: return "The requested resource could not be found on this server.";
    case HTTP_FORBIDDEN: return "Access to this resource has been denied.";
    case HTTP_NOT_ALLOWED: return "The requested method is not allowed by this server.";
    case HTTP_TOO_LARGE: return "The request entity is too large.";
    case HTTP_INTERNAL_ERROR: return "The server encountered an internal error that couldn't be recovered from.";
    }
    return "Invalid";
}

#define SET_SOCKET_OPTION(_domain,_option,_param,_size) \
    do { \
        if (setsockopt(fd, (_domain), (_option), (_param), (_size)) < 0) { \
            perror("setsockopt"); \
            goto handle_error; \
        } \
    } while(0)

static void
_socket_init(lwan_t *l)
{
    struct sockaddr_in sin;
    int fd;

    fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        perror("socket");
        exit(-1);
    }

    SET_SOCKET_OPTION(SOL_SOCKET, SO_REUSEADDR, (int[]){ 1 }, sizeof(int));
    if (l->config.enable_linger)
        SET_SOCKET_OPTION(SOL_SOCKET, SO_LINGER,
            ((struct linger[]){{ .l_onoff = 1, .l_linger = 1 }}), sizeof(struct linger));

    memset(&sin, 0, sizeof(sin));
    sin.sin_port = htons(l->config.port);
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_family = AF_INET;

    if (bind(fd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("bind");
        goto handle_error;
    }

    if (listen(fd, l->thread.count * l->thread.max_fd) < 0) {
        perror("listen");
        goto handle_error;
    }

    l->main_socket = fd;
    return;

handle_error:
    close(fd);
    exit(-1);
}

#undef SET_SOCKET_OPTION

static void
_socket_shutdown(lwan_t *l)
{
    if (shutdown(l->main_socket, SHUT_RDWR) < 0) {
        perror("shutdown");
        close(l->main_socket);
        exit(-4);
    }
    close(l->main_socket);
}


ALWAYS_INLINE void
_reset_request(lwan_request_t *request)
{
    strbuf_t *response_buffer = request->response.buffer;
    lwan_t *lwan = request->lwan;
    coro_t *coro = request->coro;
    int fd = request->fd;

    if (request->query_string_kv.base != empty_query_string_kv)
        free(request->query_string_kv.base);

    memset(request, 0, sizeof(*request));

    request->fd = fd;
    request->lwan = lwan;
    request->coro = coro;
    request->response.buffer = response_buffer;
    request->query_string_kv.base = empty_query_string_kv;
    strbuf_reset(request->response.buffer);
}

static int
_process_request_coro(coro_t *coro)
{
    lwan_request_t *request = coro_get_data(coro);

    _reset_request(request);
    lwan_process_request(request);

    return 0;
}

static ALWAYS_INLINE void
_handle_hangup(int epoll_fd, struct epoll_event *event, lwan_request_t *request)
{
    if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, event->data.fd, event) < 0)
        perror("epoll_ctl");
    request->flags.alive = false;
    close(event->data.fd);
}

static ALWAYS_INLINE void
_cleanup_coro(lwan_request_t *request)
{
    if (!request->coro || request->flags.should_resume_coro)
        return;
    /* FIXME: Reuse coro? */
    coro_free(request->coro);
    request->coro = NULL;
}

static ALWAYS_INLINE void
_spawn_coro_if_needed(lwan_request_t *request, coro_switcher_t *switcher)
{
    if (request->coro)
        return;
    request->coro = coro_new(switcher, _process_request_coro, request);
    request->flags.should_resume_coro = true;
    request->flags.write_events = false;
}

static ALWAYS_INLINE void
_resume_coro_if_needed(lwan_request_t *request, int epoll_fd)
{
    if (!request->flags.should_resume_coro || UNLIKELY(!request->coro))
        return;

    request->flags.should_resume_coro = coro_resume(request->coro);
    if (request->flags.should_resume_coro == request->flags.write_events)
        return;

    static const int const events_by_write_flag[] = {
        EPOLLOUT | EPOLLRDHUP | EPOLLERR,
        EPOLLIN | EPOLLRDHUP | EPOLLERR | EPOLLET
    };
    struct epoll_event event = {
        .events = events_by_write_flag[request->flags.write_events],
        .data.fd = request->fd
    };

    if (UNLIKELY(epoll_ctl(epoll_fd, EPOLL_CTL_MOD, request->fd, &event) < 0))
        perror("epoll_ctl");

    request->flags.write_events ^= 1;
}

static void *
_thread(void *data)
{
    lwan_thread_t *t = data;
    struct epoll_event *events = calloc(t->lwan->thread.max_fd, sizeof(*events));
    int *death_queue = calloc(1, t->lwan->thread.max_fd * sizeof(int));
    int epoll_fd = t->epoll_fd, n_fds, i;
    unsigned int death_time = 0;
    lwan_request_t *requests = t->lwan->requests;
    int death_queue_last = 0, death_queue_first = 0, death_queue_population = 0;
    coro_switcher_t switcher;

    for (;;) {
        switch (n_fds = epoll_wait(epoll_fd, events, t->lwan->thread.max_fd,
                                            death_queue_population ? 1000 : -1)) {
        case -1:
            switch (errno) {
            case EBADF:
            case EINVAL:
                goto epoll_fd_closed;
            case EINTR:
                perror("epoll_wait");
            }
            continue;
        case 0: /* timeout: shutdown waiting sockets */
            death_time++;

            while (death_queue_population) {
                lwan_request_t *request = &requests[death_queue[death_queue_first]];

                if (request->time_to_die <= death_time) {
                    /* One request just died, advance the queue. */
                    ++death_queue_first;
                    --death_queue_population;
                    death_queue_first %= t->lwan->thread.max_fd;

                    if (request->coro) {
                        coro_free(request->coro);
                        request->coro = NULL;
                    }

                    /* A request might have died from a hangup event */
                    if (!request->flags.alive)
                        continue;

                    request->flags.alive = false;
                    if (request->flags.is_keep_alive)
                        close(request->fd);
                } else {
                    /* Next time. Next time. */
                    break;
                }
            }
            break;
        default: /* activity in some of this poller's file descriptor */
            for (i = 0; i < n_fds; ++i) {
                lwan_request_t *request = &requests[events[i].data.fd];

                request->fd = events[i].data.fd;

                if (UNLIKELY(events[i].events & (EPOLLRDHUP | EPOLLHUP))) {
                    _handle_hangup(epoll_fd, &events[i], request);
                    continue;
                }

                _cleanup_coro(request);
                _spawn_coro_if_needed(request, &switcher);
                _resume_coro_if_needed(request, epoll_fd);

                /*
                 * If the response handler is a coroutine, consider the request as a
                 * keep-alive one.
                 */
                if (LIKELY(request->flags.is_keep_alive || request->flags.should_resume_coro)) {
                    /*
                     * Update the time to die. This might overflow in ~136 years,
                     * so plan ahead.
                     */
                    request->time_to_die = death_time + t->lwan->config.keep_alive_timeout;

                    /*
                     * The connection hasn't been added to the keep-alive
                     * list-to-kill. Do it now and mark it as alive so that
                     * we know what to do whenever there's activity on its
                     * socket again. Or not. Mwahahaha.
                     */
                    if (!request->flags.alive) {
                        death_queue[death_queue_last++] = events[i].data.fd;
                        ++death_queue_population;
                        death_queue_last %= t->lwan->thread.max_fd;
                        request->flags.alive = true;
                    }
                } else {
                    /*
                     * Either the request has a Connection: Close header, or its
                     * associated coroutine shouldn't be resumed.
                     */
                    coro_free(request->coro);
                    request->coro = NULL;
                    request->flags.alive = false;
                    request->flags.should_resume_coro = false;
                    close(events[i].data.fd);
                }
            }
        }
    }

epoll_fd_closed:
    free(death_queue);
    free(events);

    return NULL;
}

static void
_create_thread(lwan_t *l, int thread_n)
{
    pthread_attr_t attr;
    lwan_thread_t *thread = &l->thread.threads[thread_n];

    thread->lwan = l;
    if ((thread->epoll_fd = epoll_create1(0)) < 0) {
        perror("epoll_create");
        exit(-1);
    }

    if (pthread_attr_init(&attr)) {
        perror("pthread_attr_init");
        exit(-1);
    }

    if (pthread_attr_setscope(&attr, PTHREAD_SCOPE_SYSTEM)) {
        perror("pthread_attr_setscope");
        exit(-1);
    }

    if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE)) {
        perror("pthread_attr_setdetachstate");
        exit(-1);
    }

    if (pthread_create(&thread->id, &attr, _thread, thread)) {
        perror("pthread_create");
        pthread_attr_destroy(&attr);
        exit(-1);
    }

    if (l->config.enable_thread_affinity) {
        cpu_set_t cpuset;

        CPU_ZERO(&cpuset);
        CPU_SET(thread_n, &cpuset);
        if (pthread_setaffinity_np(thread->id, sizeof(cpu_set_t), &cpuset)) {
            perror("pthread_setaffinity_np");
            exit(-1);
        }
    }

    if (pthread_attr_destroy(&attr)) {
        perror("pthread_attr_destroy");
        exit(-1);
    }
}

static void
_thread_init(lwan_t *l)
{
    int i;

    l->thread.threads = malloc(sizeof(lwan_thread_t) * l->thread.count);

    for (i = l->thread.count - 1; i >= 0; i--)
        _create_thread(l, i);
}

static void
_thread_shutdown(lwan_t *l)
{
    int i;

    /*
     * Closing epoll_fd makes the thread gracefully finish; it might
     * take a while to notice this if keep-alive timeout is high.
     * Thread shutdown is performed in separate loops so that we
     * don't wait one thread to join when there are others to be
     * finalized.
     */
    for (i = l->thread.count - 1; i >= 0; i--)
        close(l->thread.threads[i].epoll_fd);
    for (i = l->thread.count - 1; i >= 0; i--)
#ifdef __linux__
        pthread_tryjoin_np(l->thread.threads[i].id, NULL);
#else
        pthread_join(l->thread.threads[i].id, NULL);
#endif /* __linux__ */

    free(l->thread.threads);
}

void
lwan_init(lwan_t *l)
{
    int max_threads = sysconf(_SC_NPROCESSORS_ONLN);
    struct rlimit r;

    l->thread.count = max_threads > 0 ? max_threads : 2;

    if (getrlimit(RLIMIT_NOFILE, &r) < 0) {
        perror("getrlimit");
        exit(-1);
    }
    if (r.rlim_max == RLIM_INFINITY)
        r.rlim_cur *= 8;
    else if (r.rlim_cur < r.rlim_max)
        r.rlim_cur = r.rlim_max;
    if (setrlimit(RLIMIT_NOFILE, &r) < 0) {
        perror("setrlimit");
        exit(-1);
    }

    l->requests = calloc(r.rlim_cur, sizeof(lwan_request_t));
    l->thread.max_fd = r.rlim_cur / l->thread.count;
    printf("Using %d threads, maximum %d sockets per thread.\n",
        l->thread.count, l->thread.max_fd);

    for (--r.rlim_cur; r.rlim_cur; --r.rlim_cur) {
        l->requests[r.rlim_cur].response.buffer = strbuf_new();
        l->requests[r.rlim_cur].lwan = l;
    }

    srand(time(NULL));
    signal(SIGPIPE, SIG_IGN);
    close(STDIN_FILENO);

    _socket_init(l);
    _thread_init(l);
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
    _thread_shutdown(l);
    _socket_shutdown(l);
    _url_map_free(l);

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
    if (!l->url_map_trie) {
        perror("lwan_trie_new");
        exit(-1);
    }

    for (; url_map->prefix; url_map++) {
        lwan_handler_t *handler = url_map->handler;

        url_map->prefix_len = strlen(url_map->prefix);
        lwan_trie_add(l->url_map_trie, url_map->prefix, url_map);

        if (!handler || !handler->init)
            continue;
        url_map->data = handler->init(url_map->args);
        url_map->callback = handler->handle;
    }
}

static ALWAYS_INLINE int
_schedule_request(lwan_t *l)
{
#if defined(USE_LORENTZ_WATERWHEEL_SCHEDULER) && USE_LORENTZ_WATERWHEEL_SCHEDULER==1
    static unsigned int counter = 0;
    return ((rand() & 15) > 7 ? ++counter : --counter) % l->thread.count;
#else
    static int counter = 0;
    return counter++ % l->thread.count;
#endif
}

static ALWAYS_INLINE void
_push_request_fd(lwan_t *l, int fd)
{
    int epoll_fd = l->thread.threads[_schedule_request(l)].epoll_fd;
    struct epoll_event event = {
        .events = EPOLLIN | EPOLLRDHUP | EPOLLERR | EPOLLET,
        .data.fd = fd
    };

    if (UNLIKELY(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event) < 0)) {
        perror("epoll_ctl");
        exit(-1);
    }
}

static void
_cleanup(int signal_number)
{
    printf("Signal %d received.\n", signal_number);
    longjmp(cleanup_jmp_buf, 1);
}

void
lwan_main_loop(lwan_t *l)
{
    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        perror("epoll_create1");
        return;
    }

    if (setjmp(cleanup_jmp_buf))
        goto end;

    signal(SIGINT, _cleanup);

    struct epoll_event events[128];
    struct epoll_event ev = {
        .events = EPOLLIN,
    };

    if (fcntl(l->main_socket, F_SETFL, O_NONBLOCK) < 0) {
        perror("fcntl: main socket");
        exit(-1);
    }
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, l->main_socket, &ev) < 0) {
        perror("epoll_ctl");
        exit(-1);
    }

    for (;;) {
        int n_fds;
        for (n_fds = epoll_wait(epoll_fd, events, N_ELEMENTS(events), -1);
                n_fds > 0;
                --n_fds) {
            int child_fd = accept4(l->main_socket, NULL, NULL, SOCK_NONBLOCK);
            if (UNLIKELY(child_fd < 0)) {
                perror("accept");
                continue;
            }

            _push_request_fd(l, child_fd);
        }
    }

end:
    close(epoll_fd);
}
