#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
    lwan_t *l = data;

    for (;;) {
        int fd = lwan_request_queue_pop_fd(l);
        if (fd < 0)
            continue;

        if (lwan_process_request_from_socket(l, fd)) {
            if (shutdown(fd, SHUT_RDWR) < 0)
                perror("shutdown");
        }

        close(fd);
    }

    return NULL;
}

static void
_lwan_create_thread(lwan_t *l, int thread_n)
{
    pthread_attr_t attr;
    cpu_set_t cpuset;

    if (pthread_attr_init(&attr)) {
        perror("pthread_attr_init");
        exit(-1);
    }

    if (pthread_create(&l->thread.ids[thread_n], &attr, _lwan_thread, l)) {
        perror("pthread_create");
        pthread_attr_destroy(&attr);
        exit(-1);
    }

    CPU_ZERO(&cpuset);
    CPU_SET(thread_n, &cpuset);
    if (pthread_setaffinity_np(l->thread.ids[thread_n], sizeof(cpu_set_t), &cpuset)) {
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
    int pipe_fd[2];

    l->thread.ids = malloc(sizeof(pthread_t) * l->thread.count);

    if (pipe(pipe_fd) < 0) {
        perror("pipe");
        exit(-1);
    }

    l->thread.sockets[0] = pipe_fd[0];
    l->thread.sockets[1] = pipe_fd[1];

    for (i = l->thread.count - 1; i >= 0; i--)
        _lwan_create_thread(l, i);
}

static void
_lwan_destroy_thread(lwan_t *l, int thread_n)
{
    pthread_cancel(l->thread.ids[thread_n]);
}

static void
_lwan_thread_shutdown(lwan_t *l)
{
    int i;

    for (i = l->thread.count - 1; i >= 0; i--)
        _lwan_destroy_thread(l, i);

    close(l->thread.sockets[0]);
    close(l->thread.sockets[1]);
    free(l->thread.ids);
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

    lwan_response_t response = {
        .mime_type = "text/plain",
        .content = output,
        .content_length = len,
    };

    request->response = &response;
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

    char *space = strrchr(buffer, ' ');
    if (!space)
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
lwan_request_queue_push_fd(lwan_t *l, int fd)
{
    if (write(l->thread.sockets[1], &fd, sizeof(fd)) < 0)
        perror("write");
}

int
lwan_request_queue_pop_fd(lwan_t *l)
{
    int fd;
    if (read(l->thread.sockets[0], &fd, sizeof(fd)) < 0) {
        perror("read");
        return -1;
    }
    return fd;
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

        lwan_request_queue_push_fd(l, child_fd);
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
