#include <arpa/inet.h>
#include <netinet/in.h>
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

void
lwan_init(lwan_t *l)
{
    _lwan_socket_init(l);
}

void
lwan_shutdown(lwan_t *l)
{
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

void
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
        return;
    }
    
    if (write(request->fd, headers, len) < 0) {
        perror("write");
        exit(-1);
    }
    
    if (write(request->fd,
              request->response->content,
              request->response->content_length) < 0) {
        perror("write");
        exit(-1);
    }
}

void
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
    lwan_response(l, request, status);
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
_find_callback(lwan_t *l, lwan_request_t *request)
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

void
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
        return;
    }
    
    p_buffer = _identify_http_method(&request, buffer);
    if (!p_buffer) {
        lwan_default_response(l, &request, HTTP_NOT_ALLOWED);
        return;
    }
    
    p_buffer = _identify_http_path(&request, p_buffer);
    if (!p_buffer) {
        lwan_default_response(l, &request, HTTP_BAD_REQUEST);
        return;
    }
    
    if ((url_map = _find_callback(l, &request))) {
        lwan_response(l, &request, url_map->callback(&request, url_map->data));
        return;
    }
    
    lwan_default_response(l, &request, HTTP_NOT_FOUND);
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
        
        lwan_process_request_from_socket(l, child_fd);
        
        if (shutdown(child_fd, SHUT_RDWR) < 0) {
            perror("shutdown");
            close(child_fd);
            continue;
        }

        close(child_fd);
    }
}

int
main(void)
{
    lwan_t l = {
        .port = 8080,
    };
    
    lwan_init(&l);
    lwan_set_url_map(&l, default_map);
    lwan_main_loop(&l);    
    lwan_shutdown(&l);

    return 0;
}
