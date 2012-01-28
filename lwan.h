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

#ifndef _LWAN_H__
#define _LWAN_H_

#include <pthread.h>
#include <stdbool.h>

#define N_ELEMENTS(array) (sizeof(array) / sizeof(array[0]))

typedef struct lwan_thread_t_		lwan_thread_t;
typedef struct lwan_request_t_		lwan_request_t;
typedef struct lwan_response_t_		lwan_response_t;
typedef struct lwan_url_map_t_		lwan_url_map_t;
typedef struct lwan_t_			lwan_t;
typedef struct lwan_thread_t_		lwan_thread_t;

typedef enum {
    HTTP_OK = 200,
    HTTP_BAD_REQUEST = 400,
    HTTP_NOT_FOUND = 404,
    HTTP_FORBIDDEN = 403,
    HTTP_NOT_ALLOWED = 405,
    HTTP_INTERNAL_ERROR = 500,
} lwan_http_status_t;

typedef enum {
    HTTP_GET = 0,
    HTTP_HEAD
} lwan_http_method_t;

typedef enum {
    HTTP_1_0 = 0,
    HTTP_1_1
} lwan_http_version_t;

struct lwan_response_t_ {
    char *content;
    char *mime_type;
    int content_length;
};

struct lwan_request_t_ {
    lwan_http_method_t method;
    lwan_http_version_t http_version;
    lwan_response_t *response;
    char *url;
    int url_len;
    int fd;
};

struct lwan_url_map_t_ {
    const char *prefix;
    int prefix_len;
    lwan_http_status_t (*callback)(lwan_request_t *request, void *data);
    void *data;
};

struct lwan_thread_t_ {
    lwan_t *lwan;
    int epoll_fd;
    pthread_t id;
};

struct lwan_t_ {
    lwan_url_map_t *url_map;
    int main_socket;

    struct {
        int port;
        int keep_alive_timeout;
        bool enable_thread_affinity;
    } config;

    struct {
        int count;
        int max_fd;
        lwan_thread_t *threads;
    } thread;
};

void lwan_init(lwan_t *l);
void lwan_set_url_map(lwan_t *l, lwan_url_map_t *url_map);
void lwan_main_loop(lwan_t *l);
void lwan_request_set_response(lwan_request_t *request, lwan_response_t *response);
bool lwan_response(lwan_t *l, lwan_request_t *request, lwan_http_status_t status);
bool lwan_default_response(lwan_t *l, lwan_request_t *request, lwan_http_status_t status);
const char *lwan_http_status_as_string(lwan_http_status_t status);
void lwan_shutdown(lwan_t *l);

#endif /* _LWAN_H_ */
