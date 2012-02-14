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
#include <ctype.h>
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
#include "int-to-str.h"

static const char* const _http_versions[] = {
    [HTTP_1_0] = "1.0",
    [HTTP_1_1] = "1.1"
};
static const char* const _http_connection_type[] = {
    "Close",
    "Keep-Alive"
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
    if (UNLIKELY(setsockopt(request->fd, IPPROTO_TCP, TCP_CORK,
                        (int[]){ setting }, sizeof(int)) < 0))
        perror("setsockopt");
}

const char *
lwan_determine_mime_type_for_file_name(char *file_name)
{
    char *last_dot = strrchr(file_name, '.');
    if (UNLIKELY(!last_dot))
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
    case HTTP_TOO_LARGE: return "Request too large";
    case HTTP_INTERNAL_ERROR: return "Internal server error";
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
        SET_SOCKET_OPTION(SOL_SOCKET, SO_LINGER, ((int[]){ 1, 1 }), 2*sizeof(int));
    if (l->config.enable_tcp_defer_accept)
        SET_SOCKET_OPTION(SOL_TCP, TCP_DEFER_ACCEPT, (int[]){ 1 }, sizeof(int));

    memset(&sin, 0, sizeof(sin));
    sin.sin_port = htons(l->config.port);
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_family = AF_INET;

    if (bind(fd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("bind");
        goto handle_error;
    }

    if (listen(fd, 128 * 1024) < 0) {
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

static ALWAYS_INLINE char *
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

static ALWAYS_INLINE char *
_identify_http_path(lwan_request_t *request, char *buffer, size_t limit)
{
    /* FIXME
     * - query string
     * - fragment
     */
    char *end_of_line = memchr(buffer, '\r', limit);
    if (!end_of_line)
        return NULL;
    *end_of_line = '\0';

    char *space = end_of_line - sizeof("HTTP/X.X");
    if (UNLIKELY(*(space + 1) != 'H')) /* assume HTTP/X.Y */
        return NULL;
    *space = '\0';

    if (LIKELY(*(space + 6) == '1'))
        request->http_version = *(space + 8) == '0' ? HTTP_1_0 : HTTP_1_1;
    else
        return NULL;

    request->url = buffer;
    request->url_len = space - buffer;

    if (UNLIKELY(*request->url != '/'))
        return NULL;

    return end_of_line + 1;
}

#define MATCH_HEADER(hdr) \
  do { \
        char *end; \
        p += sizeof(hdr) - 1; \
        if (UNLIKELY(*p++ != ':'))	/* not the header we're looking for */ \
          goto did_not_match; \
        if (UNLIKELY(*p++ != ' '))	/* not the header we're looking for */ \
          goto did_not_match; \
        if (LIKELY(end = strchr(p, '\r'))) {      /* couldn't find line end */ \
          *end = '\0'; \
          value = p; \
          p = end + 1; \
          if (UNLIKELY(*p != '\n')) \
            goto did_not_match; \
        } else \
          goto did_not_match; \
  } while (0)

#define CASE_HEADER(hdr_const,hdr_name) case hdr_const: MATCH_HEADER(hdr_name);

ALWAYS_INLINE static char *
_parse_headers(lwan_request_t *request, char *buffer)
{
    char *p;

    for (p = buffer; p && *p; buffer = ++p) {
        char *value;

        STRING_SWITCH(p) {
        CASE_HEADER(HTTP_HDR_CONNECTION, "Connection")
            request->header.connection = (*value | 0x20);
            break;
        CASE_HEADER(HTTP_HDR_HOST, "Host")
            /* Virtual hosts are not supported yet; ignore */
            break;
        CASE_HEADER(HTTP_HDR_IF_MODIFIED_SINCE, "If-Modified-Since")
            /* Ignore */
            break;
        CASE_HEADER(HTTP_HDR_RANGE, "Range")
            /* Ignore */
            break;
        CASE_HEADER(HTTP_HDR_REFERER, "Referer")
            /* Ignore */
            break;
        CASE_HEADER(HTTP_HDR_COOKIE, "Cookie")
            /* Ignore */
            break;
        }
did_not_match:
        p = strchr(p, '\n');
    }

    return buffer;
}

#undef CASE_HEADER
#undef MATCH_HEADER

ALWAYS_INLINE static char *
_ignore_leading_whitespace(char *buffer)
{
    while (*buffer && memchr(" \t\r\n", *buffer, 4))
        buffer++;
    return buffer;
}

ALWAYS_INLINE static void
_compute_flags(lwan_request_t *request)
{
    if (request->http_version == HTTP_1_1)
        request->flags.is_keep_alive = (request->header.connection != 'c');
    else
        request->flags.is_keep_alive = (request->header.connection == 'k');
}

static bool
_process_request(lwan_t *l, lwan_request_t *request)
{
    lwan_url_map_t *url_map;
    char buffer[6 * 1024], *p_buffer;
    size_t bytes_read;

    switch (bytes_read = read(request->fd, buffer, sizeof(buffer))) {
    case 0:
        return false;
    case -1:
        perror("read");
        return false;
    case sizeof(buffer):
        return lwan_default_response(l, request, HTTP_TOO_LARGE);
    }

    buffer[bytes_read] = '\0';

    p_buffer = _ignore_leading_whitespace(buffer);
    if (!*p_buffer)
        return lwan_default_response(l, request, HTTP_BAD_REQUEST);

    p_buffer = _identify_http_method(request, p_buffer);
    if (UNLIKELY(!p_buffer))
        return lwan_default_response(l, request, HTTP_NOT_ALLOWED);

    p_buffer = _identify_http_path(request, p_buffer, bytes_read);
    if (UNLIKELY(!p_buffer))
        return lwan_default_response(l, request, HTTP_BAD_REQUEST);

    p_buffer = _parse_headers(request, p_buffer);
    if (UNLIKELY(!p_buffer))
        return lwan_default_response(l, request, HTTP_BAD_REQUEST);

    _compute_flags(request);

    if ((url_map = lwan_trie_lookup_prefix(l->url_map_trie, request->url))) {
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
                    if (request.flags.is_keep_alive) {
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
    if (r.rlim_max == RLIM_INFINITY)
        r.rlim_cur *= 8;
    else if (r.rlim_cur < r.rlim_max)
        r.rlim_cur = r.rlim_max;
    if (setrlimit(RLIMIT_NOFILE, &r) < 0) {
        perror("setrlimit");
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
    lwan_trie_destroy(l->url_map_trie);
    _thread_shutdown(l);
    _socket_shutdown(l);
}

void
lwan_set_url_map(lwan_t *l, lwan_url_map_t *url_map)
{
    lwan_trie_destroy(l->url_map_trie);

    l->url_map_trie = lwan_trie_new();
    if (!l->url_map_trie) {
        perror("lwan_trie_new");
        exit(-1);
    }

    for (; url_map->prefix; url_map++) {
        url_map->prefix_len = strlen(url_map->prefix);
        lwan_trie_add(l->url_map_trie, url_map->prefix, url_map);
    }
}

void
lwan_request_set_response(lwan_request_t *request, lwan_response_t *response)
{
    request->response = response;
}

#define APPEND_STRING_LEN(const_str_,len_) \
    memcpy(p_headers, (const_str_), (len_)); \
    p_headers += (len_)
#define APPEND_INT8(value_) \
    APPEND_CHAR(decimal_digits[((value_) / 100) % 10]); \
    APPEND_CHAR(decimal_digits[((value_) / 10) % 10]); \
    APPEND_CHAR(decimal_digits[(value_) % 10])
#define APPEND_INT(value_) \
    len = int_to_string((value_), buffer); \
    APPEND_STRING_LEN(buffer, len)
#define APPEND_CHAR(value_) \
    *p_headers++ = (value_)
#define APPEND_CONSTANT(const_str_) \
    APPEND_STRING_LEN((const_str_), sizeof(const_str_) - 1)

bool
lwan_response_header(lwan_t *l __attribute__((unused)), lwan_request_t *request, lwan_http_status_t status)
{
    char headers[512], *p_headers;
    char buffer[32];
    int32_t len;

    p_headers = headers;

    APPEND_CONSTANT("HTTP/");
    APPEND_STRING_LEN(_http_versions[request->http_version], 3);
    APPEND_CHAR(' ');
    APPEND_INT8(status);
    APPEND_CHAR(' ');
    APPEND_STRING_LEN(lwan_http_status_as_string(status), 2);
    APPEND_CONSTANT("\r\nContent-Length: ");
    APPEND_INT(request->response->content_length);
    APPEND_CONSTANT("\r\nContent-Type: ");
    APPEND_STRING_LEN(request->response->mime_type, strlen(request->response->mime_type));
    APPEND_CONSTANT("\r\nConnection: ");
    APPEND_STRING_LEN(_http_connection_type[request->flags.is_keep_alive],
        (request->flags.is_keep_alive ? sizeof("Keep-Alive") : sizeof("Close")) - 1);
    APPEND_CONSTANT("\r\n\r\n\0");

    if (UNLIKELY(write(request->fd, headers, strlen(headers)) < 0)) {
        perror("write header");
        return false;
    }

    return true;
}

#undef APPEND_STRING_LEN
#undef APPEND_CONSTANT
#undef APPEND_CHAR
#undef APPEND_INT

bool
lwan_response(lwan_t *l, lwan_request_t *request, lwan_http_status_t status)
{
    if (UNLIKELY(!request->response)) {
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

    if (UNLIKELY(!lwan_response_header(l, request, status)))
        return false;

    if (request->method == HTTP_HEAD)
        return true;

    if (UNLIKELY(write(request->fd,
                       request->response->content,
                       request->response->content_length) < 0)) {
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
    if (UNLIKELY(len < 0)) {
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

static ALWAYS_INLINE void
_push_request_fd(lwan_t *l, int fd)
{
    static int current_thread = 0;
    int epoll_fd = l->thread.threads[current_thread++ % l->thread.count].epoll_fd;
    struct epoll_event event = {
        .events = EPOLLIN | EPOLLET,
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
    if (setjmp(cleanup_jmp_buf))
        return;

    signal(SIGINT, _cleanup);

    int epoll_fd = epoll_create1(0);
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

    close(epoll_fd);
}

int
main(void)
{
    lwan_t l = {
        .config = {
            .port = 8080,
            .keep_alive_timeout = 5000,
            .enable_thread_affinity = false,
            .enable_tcp_defer_accept = true,
            .enable_linger = false
        }
    };

    lwan_init(&l);
    lwan_set_url_map(&l, default_map);
    lwan_main_loop(&l);
    lwan_shutdown(&l);

    return 0;
}
