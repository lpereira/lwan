#define _GNU_SOURCE
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "lwan.h"

lwan_http_status_t hello_world(lwan_request_t *request, void *data __attribute__((unused)))
{
    static lwan_response_t response = {
        .mime_type = "text/plain",
        .content = "Hello, world!",
        .content_length = sizeof("Hello, world!") - 1
    };

    lwan_request_set_response(request, &response);
    return HTTP_OK;
}

static lwan_url_map_t default_map[] = {
    { .prefix = "/", .callback = hello_world, .data = NULL },
    { .prefix = NULL },
};

static void
_lwan_socket_init(lwan_t *l)
{
    struct sockaddr_in sin;
    int fd;

    fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        perror("socket");
        exit(-1);
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char[]){ 1 }, sizeof(char*)) < 0) {
        perror("setsockopt");
        goto handle_error;
    }

    memset(&sin, 0, sizeof(sin));
    sin.sin_port = htons(l->port);
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_family = AF_INET;

    if (bind(fd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("bind");
        goto handle_error;
    }

    if (listen(fd, 10) < 0) {
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
_lwan_socket_shutdown(lwan_t *l)
{
    if (shutdown(l->main_socket, SHUT_RDWR) < 0) {
        perror("shutdown");
        close(l->main_socket);
        exit(-4);
    }
    close(l->main_socket);
}

static void *
_lwan_thread(void *data)
{
    lwan_thread_t *t = data;
    struct epoll_event events[10];
    int epoll_fd = t->epoll_fd;

    for (;;) {
        int nfds = epoll_wait(epoll_fd, events, sizeof(events) / sizeof(events[0]), -1);
        if (nfds < 0) {
            perror("epoll_wait");
            continue;
        }

        int n;
        for (n = 0; n < nfds; ++n) {
            if (lwan_process_request_from_socket(t->lwan, events[n].data.fd)) {
                if (shutdown(events[n].data.fd, SHUT_RDWR) < 0)
                    perror("shutdown");
            }
            close(events[n].data.fd);
        }
    }

    return NULL;
}

static void
_lwan_create_thread(lwan_t *l, int thread_n)
{
    pthread_attr_t attr;
    cpu_set_t cpuset;
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

    if (pthread_create(&thread->id, &attr, _lwan_thread, thread)) {
        perror("pthread_create");
        pthread_attr_destroy(&attr);
        exit(-1);
    }

    CPU_ZERO(&cpuset);
    CPU_SET(thread_n, &cpuset);
    if (pthread_setaffinity_np(thread->id, sizeof(cpu_set_t), &cpuset)) {
        perror("pthread_setaffinity_np");
        exit(-1);
    }

    if (pthread_attr_destroy(&attr)) {
        perror("pthread_attr_destroy");
        exit(-1);
    }
}

static void
_lwan_thread_init(lwan_t *l)
{
    int i;

    l->thread.threads = malloc(sizeof(lwan_thread_t) * l->thread.count);

    for (i = l->thread.count - 1; i >= 0; i--)
        _lwan_create_thread(l, i);
}

static void
_lwan_destroy_thread(lwan_t *l, int thread_n)
{
    pthread_cancel(l->thread.threads[thread_n].id);
}

static void
_lwan_thread_shutdown(lwan_t *l)
{
    int i;

    for (i = l->thread.count - 1; i >= 0; i--)
        _lwan_destroy_thread(l, i);
    free(l->thread.threads);
}

void
lwan_init(lwan_t *l)
{
    _lwan_socket_init(l);
    _lwan_thread_init(l);
    signal(SIGPIPE, SIG_IGN);
}

void
lwan_shutdown(lwan_t *l)
{
    _lwan_thread_shutdown(l);
    _lwan_socket_shutdown(l);
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
lwan_response(lwan_t *l, lwan_request_t *request, lwan_http_status_t status)
{
    char headers[512];
    int len;

    len = snprintf(headers, sizeof(headers),
                   "HTTP/1.1 %d\r\n"
                   "Content-Length: %d\r\n"
                   "Content-Type: %s\r\n"
                   "Connection: close\r\n"
                   "\r\n",
                   status,
                   request->response->content_length,
                   request->response->mime_type);
    if (len < 0) {
        lwan_default_response(l, request, HTTP_INTERNAL_ERROR);
        return false;
    }

    if (write(request->fd, headers, len) < 0) {
        perror("write header");
        return false;
    }

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
    char output[32];
    int len = snprintf(output, sizeof(output), "Error %d", status);

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

static char *
_identify_http_method(lwan_request_t *request, char *buffer)
{
    if (!strncmp(buffer, "GET ", 4)) {
        request->method = HTTP_GET;
        return buffer + 4;
    }
    if (!strncmp(buffer, "POST ", 5)) {
        request->method = HTTP_POST;
        return buffer + 5;
    }
    return NULL;
}

static char *
_identify_http_path(lwan_request_t *request, char *buffer)
{
    /* FIXME
     * - query string
     */
    char *end_of_line = strchr(buffer, '\r');
    if (!end_of_line)
        return NULL;
    *end_of_line = '\0';

    char *space = end_of_line - sizeof("HTTP/X.X");
    if (*(space + 1) != 'H')
        return NULL;
    *space = '\0';

    request->url = buffer;
    request->url_len = space - buffer;

    return end_of_line + 1;
}

static lwan_url_map_t *
_find_callback_for_request(lwan_t *l, lwan_request_t *request)
{
    lwan_url_map_t *url_map;

    /* FIXME
     * - bsearch if url_map is too large
     * - regex maybe? this might hurt performance
     */
    for (url_map = l->url_map; url_map->prefix; url_map++) {
        if (request->url_len > url_map->prefix_len)
            continue;

        if (!strncmp(request->url, url_map->prefix, url_map->prefix_len))
            return url_map;
    }

    return NULL;
}

bool
lwan_process_request_from_socket(lwan_t *l, int fd)
{
    lwan_url_map_t *url_map;
    lwan_request_t request;
    char buffer[128], *p_buffer;
    int n_read;

    memset(&request, 0, sizeof(request));
    request.fd = fd;

    n_read = read(fd, buffer, sizeof(buffer));
    if (n_read < 0) {
        perror("read");
        return false;
    }

    p_buffer = _identify_http_method(&request, buffer);
    if (!p_buffer)
        return lwan_default_response(l, &request, HTTP_NOT_ALLOWED);

    p_buffer = _identify_http_path(&request, p_buffer);
    if (!p_buffer)
        return lwan_default_response(l, &request, HTTP_BAD_REQUEST);

    if ((url_map = _find_callback_for_request(l, &request)))
        return lwan_response(l, &request, url_map->callback(&request, url_map->data));

    return lwan_default_response(l, &request, HTTP_NOT_FOUND);
}

void
lwan_push_request_fd(lwan_t *l, int fd)
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

void
lwan_main_loop(lwan_t *l)
{
    for (;;) {
        int child_fd = accept(l->main_socket, NULL, NULL);
        if (child_fd < 0) {
            perror("accept");
            close(child_fd);
            continue;
        }

        lwan_push_request_fd(l, child_fd);
    }
}

int
main(void)
{
    lwan_t l = {
        .port = 8080,
        .thread = {
            .count = 4
        }
    };

    lwan_init(&l);
    lwan_set_url_map(&l, default_map);
    lwan_main_loop(&l);
    lwan_shutdown(&l);

    return 0;
}
