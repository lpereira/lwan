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

#ifndef __LWAN_H__
#define __LWAN_H__

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

#include "lwan-trie.h"

#define N_ELEMENTS(array) (sizeof(array) / sizeof(array[0]))

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#  define MULTICHAR_CONSTANT(a,b,c,d) ((int32_t)((a) | (b) << 8 | (c) << 16 | (d) << 24))
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#  define MULTICHAR_CONSTANT(d,c,b,a) ((int32_t)((a) | (b) << 8 | (c) << 16 | (d) << 24))
#elif __BYTE_ORDER__ == __ORDER_PDP_ENDIAN__
#  error A PDP? Seriously?
#endif

#define STRING_SWITCH(s) switch (*((int32_t *)(s)))

#define ALWAYS_INLINE inline __attribute__((always_inline))

#define LIKELY_IS(x,y)	__builtin_expect((x), (y))
#define LIKELY(x)	LIKELY_IS(!!(x), 1)
#define UNLIKELY(x)	LIKELY_IS((x), 0)

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
    HTTP_TOO_LARGE = 413,
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

enum {
    EXT_JPG = MULTICHAR_CONSTANT('.','j','p','g'),
    EXT_PNG = MULTICHAR_CONSTANT('.','p','n','g'),
    EXT_HTM = MULTICHAR_CONSTANT('.','h','t','m'),
    EXT_CSS = MULTICHAR_CONSTANT('.','c','s','s'),
    EXT_TXT = MULTICHAR_CONSTANT('.','t','x','t'),
    EXT_JS  = MULTICHAR_CONSTANT('.','j','s',0),
} lwan_mime_ext_t;

enum {
    HTTP_STR_GET  = MULTICHAR_CONSTANT('G','E','T',' '),
    HTTP_STR_HEAD = MULTICHAR_CONSTANT('H','E','A','D'),
} lwan_http_method_str_t;

enum {
    HTTP_HDR_CONNECTION        = MULTICHAR_CONSTANT('C','o','n','n'),
    HTTP_HDR_HOST              = MULTICHAR_CONSTANT('H','o','s','t'),
    HTTP_HDR_COOKIE            = MULTICHAR_CONSTANT('C','o','o','k'),
    HTTP_HDR_RANGE             = MULTICHAR_CONSTANT('R','a','n','g'),
    HTTP_HDR_REFERER           = MULTICHAR_CONSTANT('R','e','f','e'),
    HTTP_HDR_IF_MODIFIED_SINCE = MULTICHAR_CONSTANT('I','f','-','m')
} lwan_http_header_str_t;

struct lwan_response_t_ {
    char *content;
    char *mime_type;
    int content_length;

    struct {
        lwan_http_status_t (*callback)(lwan_t *lwan, lwan_request_t *request, void *data);
        void *data;
    } stream_content;
};

struct lwan_request_t_ {
    lwan_http_method_t method;
    lwan_http_version_t http_version;
    lwan_response_t *response;
    char *url;
    int url_len;
    int fd;

    struct {
        char connection;
    } header;

    struct {
        bool is_keep_alive;
    } flags;
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
    lwan_trie_t *url_map_trie;
    int main_socket;

    struct {
        int port;
        int keep_alive_timeout;
        unsigned char enable_thread_affinity : 1,
                      enable_tcp_defer_accept : 1,
                      enable_linger : 1;
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
bool lwan_response_header(lwan_t *l, lwan_request_t *request, lwan_http_status_t status);
bool lwan_default_response(lwan_t *l, lwan_request_t *request, lwan_http_status_t status);
const char *lwan_http_status_as_string(lwan_http_status_t status);
const char *lwan_determine_mime_type_for_file_name(char *file_name);
void lwan_request_set_corked(lwan_request_t *request, bool setting);
void lwan_shutdown(lwan_t *l);

#endif /* __LWAN_H__ */
