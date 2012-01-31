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
#include <netinet/in.h>
#include <netinet/tcp.h>
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
#include "lwan-hello-world.h"
#include "lwan-serve-files.h"

#define REQUEST_SUPPORTS_KEEP_ALIVE(r) ((r)->http_version == HTTP_1_1)

static const char* const _http_versions[] = {
    [HTTP_1_0] = "1.0",
    [HTTP_1_1] = "1.1"
};
static const char* const _http_connection_policy[] = {
    [HTTP_1_0] = "Close",
    [HTTP_1_1] = "Keep-Alive"
};

static lwan_url_map_t default_map[] = {
    { .prefix = "/hello", .callback = hello_world, .data = NULL },
    { .prefix = "/", .callback = serve_files, .data = "./files_root" },
    { .prefix = NULL },
};

static jmp_buf cleanup_jmp_buf;

void
lwan_request_set_corked(lwan_request_t *request, bool setting)
{
    if (setsockopt(request->fd, IPPROTO_TCP, TCP_CORK,
                        (int[]){ setting }, sizeof(int)) < 0)
        perror("setsockopt");
}

const char *
lwan_determine_mime_type_for_file_name(char *file_name)
{
    char *last_dot = strrchr(file_name, '.');
    if (!last_dot)
        goto fallback;

    STRING_SWITCH(last_dot) {
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
    case HTTP_BAD_REQUEST: return "Bad request";
    case HTTP_NOT_FOUND: return "Not found";
    case HTTP_FORBIDDEN: return "Forbidden";
    case HTTP_NOT_ALLOWED: return "Not allowed";
    case HTTP_INTERNAL_ERROR: return "Internal server error";
    }
    return "Invalid";
}

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

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (int[]){ 1 }, sizeof(int)) < 0) {
        perror("setsockopt");
        goto handle_error;
    }

    memset(&sin, 0, sizeof(sin));
    sin.sin_port = htons(l->config.port);
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_family = AF_INET;

    if (bind(fd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("bind");
        goto handle_error;
    }

    if (listen(fd, (3 * (l->thread.count * l->thread.max_fd)) / 2) < 0) {
        perror("listen");
        goto handle_error;
    }

    l->main_socket = fd;
    return;

handle_error:
    close(fd);
    exit(-1);
}

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

static inline __attribute__((always_inline)) char *
_identify_http_method(lwan_request_t *request, char *buffer)
{
    STRING_SWITCH(buffer) {
    case HTTP_STR_GET:
        request->method = HTTP_GET;
        return buffer + 4;
    case HTTP_STR_HEAD:
        request->method = HTTP_HEAD;
        return buffer + 5;
    }
    return NULL;
}

static inline  __attribute__((always_inline)) char *
_identify_http_path(lwan_request_t *request, char *buffer)
{
    /* FIXME
     * - query string
     * - fragment
     */
    char *end_of_line = strchr(buffer, '\r');
    if (!end_of_line)
        return NULL;
    *end_of_line = '\0';

    char *space = end_of_line - sizeof("HTTP/X.X");
    if (*(space + 1) != 'H') /* assume HTTP/X.Y */
        return NULL;
    *space = '\0';

    if (*(space + 6) >= '1')
        request->http_version = *(space + 8) == '0' ? HTTP_1_0 : HTTP_1_1;
    else
        return NULL;

    request->url = buffer;
    request->url_len = space - buffer;

    return end_of_line + 1;
}

static inline  __attribute__((always_inline)) char *
_identify_http_header_end(lwan_request_t *request __attribute__((unused)), char *buffer)
{
    char *end_of_header = strstr(buffer, "\r\n\r\n");
    return end_of_header ? end_of_header + 4 : NULL;
}

static inline  __attribute__((always_inline)) lwan_url_map_t *
_find_url_map_for_request(lwan_t *l, lwan_request_t *request)
{
    lwan_url_map_t *url_map;

    /* FIXME
     * - bsearch if url_map is too large
     * - regex maybe? this might hurt performance
     */
    for (url_map = l->url_map; url_map->prefix; url_map++) {
        if (!strncmp(request->url, url_map->prefix, url_map->prefix_len))
            return url_map;
    }

    return NULL;
}

static bool
_process_request(lwan_t *l, lwan_request_t *request)
{
    lwan_url_map_t *url_map;
    char buffer[8192], *p_buffer;

    switch (read(request->fd, buffer, sizeof(buffer))) {
    case 0:
        return false;
    case -1:
        perror("read");
        return false;
    }

    p_buffer = _identify_http_method(request, buffer);
    if (!p_buffer) {
        if (*buffer == '\r' || *buffer == '\n')
            return lwan_default_response(l, request, HTTP_BAD_REQUEST);
        return lwan_default_response(l, request, HTTP_NOT_ALLOWED);
    }

    p_buffer = _identify_http_path(request, p_buffer);
    if (!p_buffer)
        return lwan_default_response(l, request, HTTP_BAD_REQUEST);

    if (REQUEST_SUPPORTS_KEEP_ALIVE(request)) {
        p_buffer = _identify_http_header_end(request, p_buffer);
        if (!p_buffer)
            return lwan_default_response(l, request, HTTP_BAD_REQUEST);
    }

    if ((url_map = _find_url_map_for_request(l, request))) {
        request->url += url_map->prefix_len;
        return lwan_response(l, request, url_map->callback(request, url_map->data));
    }

    return lwan_default_response(l, request, HTTP_NOT_FOUND);
}

static void *
_thread(void *data)
{
    lwan_thread_t *t = data;
    struct epoll_event events[t->lwan->thread.max_fd];
    int epoll_fd = t->epoll_fd, nfds, n;
    int *fds = calloc(1, t->lwan->thread.max_fd * sizeof(int));
    int fd_wrptr, fd_rdptr;

    for (fd_wrptr = fd_rdptr = 0; ; ) {
        switch (nfds = epoll_wait(epoll_fd, events, N_ELEMENTS(events),
                            t->lwan->config.keep_alive_timeout)) {
        case -1:
            if (errno == EBADF || errno == EINVAL)
                goto epoll_fd_closed;
            if (errno != EINTR)
                perror("epoll_wait");
            continue;
        case 0: /* timeout: shutdown waiting sockets */
            while (fd_wrptr != fd_rdptr) {
                close(fds[fd_rdptr++]);
                fd_rdptr %= t->lwan->thread.max_fd;
            }
            break;
        default: /* activity in some of this poller's file descriptor */
            for (n = 0; n < nfds; ++n) {
                lwan_request_t request = {.fd = events[n].data.fd};

                if (_process_request(t->lwan, &request)) {
                    if (REQUEST_SUPPORTS_KEEP_ALIVE(&request)) {
                        fds[fd_wrptr++] = events[n].data.fd;
                        fd_wrptr %= t->lwan->thread.max_fd;
                        continue;
                    }
                }
                close(events[n].data.fd);
            }
        }
    }

epoll_fd_closed:
    free(fds);

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
        pthread_join(l->thread.threads[i].id, NULL);

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

    l->thread.max_fd = r.rlim_cur / l->thread.count;
    printf("Using %d threads, maximum %d sockets per thread.\n",
        l->thread.count, l->thread.max_fd);

    signal(SIGPIPE, SIG_IGN);
    _socket_init(l);
    _thread_init(l);
}

void
lwan_shutdown(lwan_t *l)
{
    _thread_shutdown(l);
    _socket_shutdown(l);
}

void
lwan_set_url_map(lwan_t *l, lwan_url_map_t *url_map)
{
    for (l->url_map = url_map; url_map->prefix; url_map++)
        url_map->prefix_len = strlen(url_map->prefix);
}

void
lwan_request_set_response(lwan_request_t *request, lwan_response_t *response)
{
    request->response = response;
}

bool
lwan_response_header(lwan_t *l, lwan_request_t *request, lwan_http_status_t status)
{
    char headers[512];
    int len;

    len = snprintf(headers, sizeof(headers),
                   "HTTP/%s %d %s\r\n"
                   "Content-Length: %d\r\n"
                   "Content-Type: %s\r\n"
                   "Connection: %s\r\n"
                   "\r\n",
                   _http_versions[request->http_version],
                   status,
                   lwan_http_status_as_string(status),
                   request->response->content_length,
                   request->response->mime_type,
                   _http_connection_policy[request->http_version]);
    if (len < 0) {
        lwan_default_response(l, request, HTTP_INTERNAL_ERROR);
        return false;
    }

    if (write(request->fd, headers, len) < 0) {
        perror("write header");
        return false;
    }

    return true;
}

bool
lwan_response(lwan_t *l, lwan_request_t *request, lwan_http_status_t status)
{
    if (!request->response) {
        lwan_default_response(l, request, status);
        return false;
    }

    if (request->response->stream_content.callback) {
        lwan_http_status_t callback_status;

        callback_status = request->response->stream_content.callback(l, request,
                    request->response->stream_content.data);
        if (callback_status == HTTP_OK)
            return true;

        lwan_default_response(l, request, callback_status);
        return false;
    }

    if (!lwan_response_header(l, request, status))
        return false;

    if (request->method == HTTP_HEAD)
        return true;

    if (write(request->fd,
               request->response->content,
               request->response->content_length) < 0) {
        perror("write response");
        return false;
    }

    return true;
}

bool
lwan_default_response(lwan_t *l, lwan_request_t *request, lwan_http_status_t status)
{
    char output[256];
    int len = snprintf(output, sizeof(output), "HTTP Status %d (%s)",
                            status, lwan_http_status_as_string(status));
    if (len < 0) {
        perror("snprintf");
        exit(-1);
    }

    lwan_request_set_response(request, (lwan_response_t[]) {{
        .mime_type = "text/plain",
        .content = output,
        .content_length = len,
    }});

    return lwan_response(l, request, status);
}

static void
_push_request_fd(lwan_t *l, int fd)
{
    static int current_thread = 0;
    int epoll_fd = l->thread.threads[current_thread % l->thread.count].epoll_fd;
    struct epoll_event event = {
        .events = EPOLLIN | EPOLLET,
        .data.fd = fd
    };

    fcntl(fd, F_SETFL, O_RDWR | O_NONBLOCK);
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event) < 0) {
        perror("epoll_ctl");
        exit(-1);
    }

    current_thread++;
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
    if (setjmp(cleanup_jmp_buf))
        return;

    signal(SIGINT, _cleanup);

    for (;;) {
        int child_fd = accept(l->main_socket, NULL, NULL);
        if (child_fd < 0) {
            perror("accept");
            close(child_fd);
            continue;
        }

        _push_request_fd(l, child_fd);
    }
}

int
main(void)
{
    lwan_t l = {
        .config = {
            .port = 8080,
            .keep_alive_timeout = 5000,
            .enable_thread_affinity = false,
        }
    };

    lwan_init(&l);
    lwan_set_url_map(&l, default_map);
    lwan_main_loop(&l);
    lwan_shutdown(&l);

    return 0;
}
