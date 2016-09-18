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

#pragma once

#if defined (__cplusplus)
extern "C" {
#endif

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <netinet/in.h>

#include "hash.h"
#include "lwan-config.h"
#include "lwan-coro.h"
#include "lwan-status.h"
#include "lwan-trie.h"
#include "strbuf.h"

#define DEFAULT_BUFFER_SIZE 4096
#define DEFAULT_HEADERS_SIZE 512

#define N_ELEMENTS(array) (sizeof(array) / sizeof(array[0]))

#ifdef DISABLE_INLINE_FUNCTIONS
#  define ALWAYS_INLINE
#else
#  define ALWAYS_INLINE inline __attribute__((always_inline))
#endif

#ifdef DISABLE_BRANCH_PREDICTION
#  define LIKELY_IS(x,y) (x)
#else
#  define LIKELY_IS(x,y)	__builtin_expect((x), (y))
#endif

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#  define MULTICHAR_CONSTANT(a,b,c,d) ((int32_t)((a) | (b) << 8 | (c) << 16 | (d) << 24))
#  define MULTICHAR_CONSTANT_SMALL(a,b) ((int16_t)((a) | (b) << 8))
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#  define MULTICHAR_CONSTANT(d,c,b,a) ((int32_t)((a) | (b) << 8 | (c) << 16 | (d) << 24))
#  define MULTICHAR_CONSTANT_SMALL(b,a) ((int16_t)((a) | (b) << 8))
#elif __BYTE_ORDER__ == __ORDER_PDP_ENDIAN__
#  error A PDP? Seriously?
#endif

#define MULTICHAR_CONSTANT_L(a,b,c,d) (MULTICHAR_CONSTANT(a,b,c,d) | 0x20202020)
#define MULTICHAR_CONSTANT_SMALL_L(a,b) (MULTICHAR_CONSTANT_SMALL(a,b) | 0x2020)

static ALWAYS_INLINE int32_t string_as_int32(const char *s)
{
    int32_t i;
    memcpy(&i, s, sizeof(int32_t));
    return i;
}

static ALWAYS_INLINE int16_t string_as_int16(const char *s)
{
    int16_t i;
    memcpy(&i, s, sizeof(int16_t));
    return i;
}

#define STRING_SWITCH(s) switch (string_as_int32(s))
#define STRING_SWITCH_L(s) switch (string_as_int32(s) | 0x20202020)

#define STRING_SWITCH_SMALL(s) switch (string_as_int16(s))
#define STRING_SWITCH_SMALL_L(s) switch (string_as_int16(s) | 0x2020)

#define LIKELY(x)	LIKELY_IS(!!(x), 1)
#define UNLIKELY(x)	LIKELY_IS((x), 0)

#define ATOMIC_READ(V)		(*(volatile typeof(V) *)&(V))
#define ATOMIC_AAF(P, V) 	(__sync_add_and_fetch((P), (V)))
#define ATOMIC_INC(V)		ATOMIC_AAF(&(V), 1)
#define ATOMIC_DEC(V)		ATOMIC_AAF(&(V), -1)
#define ATOMIC_BITWISE(P, O, V) (__sync_##O##_and_fetch((P), (V)))

#if defined (__cplusplus)
#define ENFORCE_STATIC_BUFFER_LENGTH
#else
#define ENFORCE_STATIC_BUFFER_LENGTH	static
#endif

typedef struct lwan_t_			lwan_t;
typedef struct lwan_module_t_		lwan_module_t;
typedef struct lwan_key_value_t_	lwan_key_value_t;
typedef struct lwan_request_t_		lwan_request_t;
typedef struct lwan_response_t_		lwan_response_t;
typedef struct lwan_thread_t_		lwan_thread_t;
typedef struct lwan_url_map_t_		lwan_url_map_t;
typedef struct lwan_value_t_		lwan_value_t;
typedef struct lwan_config_t_		lwan_config_t;
typedef struct lwan_proxy_t_		lwan_proxy_t;
typedef struct lwan_connection_t_	lwan_connection_t;

typedef enum {
    HTTP_OK = 200,
    HTTP_PARTIAL_CONTENT = 206,
    HTTP_MOVED_PERMANENTLY = 301,
    HTTP_NOT_MODIFIED = 304,
    HTTP_BAD_REQUEST = 400,
    HTTP_NOT_AUTHORIZED = 401,
    HTTP_FORBIDDEN = 403,
    HTTP_NOT_FOUND = 404,
    HTTP_NOT_ALLOWED = 405,
    HTTP_TIMEOUT = 408,
    HTTP_TOO_LARGE = 413,
    HTTP_RANGE_UNSATISFIABLE = 416,
    HTTP_I_AM_A_TEAPOT = 418,
    HTTP_INTERNAL_ERROR = 500,
    HTTP_NOT_IMPLEMENTED = 501,
    HTTP_UNAVAILABLE = 503,
} lwan_http_status_t;

typedef enum {
    HANDLER_PARSE_QUERY_STRING = 1<<0,
    HANDLER_PARSE_IF_MODIFIED_SINCE = 1<<1,
    HANDLER_PARSE_RANGE = 1<<2,
    HANDLER_PARSE_ACCEPT_ENCODING = 1<<3,
    HANDLER_PARSE_POST_DATA = 1<<4,
    HANDLER_MUST_AUTHORIZE = 1<<5,
    HANDLER_REMOVE_LEADING_SLASH = 1<<6,
    HANDLER_CAN_REWRITE_URL = 1<<7,
    HANDLER_PARSE_COOKIES = 1<<8,
    HANDLER_DATA_IS_HASH_TABLE = 1<<9,

    HANDLER_PARSE_MASK = 1<<0 | 1<<1 | 1<<2 | 1<<3 | 1<<4 | 1<<8
} lwan_handler_flags_t;

typedef enum {
    REQUEST_ALL_FLAGS          = -1,
    REQUEST_METHOD_GET         = 1<<0,
    REQUEST_METHOD_HEAD        = 1<<1,
    REQUEST_METHOD_POST        = 1<<2,
    REQUEST_ACCEPT_DEFLATE     = 1<<3,
    REQUEST_ACCEPT_GZIP        = 1<<4,
    REQUEST_IS_HTTP_1_0        = 1<<5,
    RESPONSE_SENT_HEADERS      = 1<<6,
    RESPONSE_CHUNKED_ENCODING  = 1<<7,
    RESPONSE_NO_CONTENT_LENGTH = 1<<8,
    RESPONSE_URL_REWRITTEN     = 1<<9,
    REQUEST_ALLOW_PROXY_REQS   = 1<<10,
    REQUEST_PROXIED            = 1<<11
} lwan_request_flags_t;

typedef enum {
    CONN_MASK               = -1,
    CONN_KEEP_ALIVE         = 1<<0,
    CONN_IS_ALIVE           = 1<<1,
    CONN_SHOULD_RESUME_CORO = 1<<2,
    CONN_WRITE_EVENTS       = 1<<3,
    CONN_MUST_READ          = 1<<4,
} lwan_connection_flags_t;

typedef enum {
    CONN_CORO_ABORT = -1,
    CONN_CORO_MAY_RESUME = 0,
    CONN_CORO_FINISHED = 1
} lwan_connection_coro_yield_t;

struct lwan_key_value_t_ {
    char *key;
    char *value;
};

struct lwan_response_t_ {
    strbuf_t *buffer;
    const char *mime_type;
    size_t content_length;
    lwan_key_value_t *headers;

    struct {
        lwan_http_status_t (*callback)(lwan_request_t *request, void *data);
        void *data;
        void *priv;
    } stream;
};

struct lwan_value_t_ {
    char *value;
    size_t len;
};

struct lwan_connection_t_ {
    /* This structure is exactly 32-bytes on x86-64. If it is changed,
     * make sure the scheduler (lwan.c) is updated as well. */
    lwan_connection_flags_t flags;
    unsigned int time_to_die;
    coro_t *coro;
    lwan_thread_t *thread;
    int prev, next; /* for death queue */
};

struct lwan_proxy_t_ {
    union {
        struct sockaddr_in ipv4;
        struct sockaddr_in6 ipv6;
    } from, to;
};

struct lwan_request_t_ {
    lwan_request_flags_t flags;
    int fd;
    lwan_value_t url;
    lwan_value_t original_url;
    lwan_connection_t *conn;
    lwan_proxy_t *proxy;

    struct {
        lwan_key_value_t *base;
        size_t len;
    } query_params, post_data, cookies;
    struct {
        time_t if_modified_since;
        struct {
          off_t from;
          off_t to;
        } range;
        lwan_value_t *body;
        lwan_value_t *content_type;
    } header;
    lwan_response_t response;
};

struct lwan_module_t_ {
    void *(*init)(const char *prefix, void *args);
    void *(*init_from_hash)(const char *prefix, const struct hash *hash);
    void (*shutdown)(void *data);
    bool (*parse_conf)(void *data, config_t *config);
    lwan_http_status_t (*handle)(lwan_request_t *request, lwan_response_t *response, void *data);
    lwan_handler_flags_t flags;
};

struct lwan_url_map_t_ {
    lwan_http_status_t (*handler)(lwan_request_t *request, lwan_response_t *response, void *data);
    void *data;

    const char *prefix;
    size_t prefix_len;
    lwan_handler_flags_t flags;

    const lwan_module_t *module;
    void *args;

    struct {
        char *realm;
        char *password_file;
    } authorization;
};

struct lwan_thread_t_ {
    lwan_t *lwan;
    struct {
        char date[30];
        char expires[30];
        time_t last;
    } date;

    int epoll_fd;
    int pipe_fd[2];
    pthread_t self;
    void *barrier;
};

struct lwan_config_t_ {
    char *listener;
    char *error_template;
    char *config_file_path;
    size_t max_post_data_size;
    unsigned short keep_alive_timeout;
    unsigned int expires;
    short unsigned int n_threads;
    bool quiet;
    bool reuse_port;
    bool proxy_protocol;
};

struct lwan_t_ {
    lwan_trie_t url_map_trie;
    lwan_connection_t *conns;

    struct {
        lwan_thread_t *threads;
        unsigned int max_fd;
        unsigned short count;
    } thread;

    struct hash *module_registry;
    lwan_config_t config;
    int main_socket;
};

void lwan_set_url_map(lwan_t *l, const lwan_url_map_t *map);
void lwan_main_loop(lwan_t *l);

void lwan_response(lwan_request_t *request, lwan_http_status_t status);
void lwan_default_response(lwan_request_t *request, lwan_http_status_t status);
size_t lwan_prepare_response_header(lwan_request_t *request, lwan_http_status_t status, char header_buffer[], size_t header_buffer_size)
    __attribute__((warn_unused_result));

const char *lwan_request_get_post_param(lwan_request_t *request, const char *key)
    __attribute__((warn_unused_result));
const char *lwan_request_get_query_param(lwan_request_t *request, const char *key)
    __attribute__((warn_unused_result));
const char * lwan_request_get_cookie(lwan_request_t *request, const char *key)
    __attribute__((warn_unused_result));

bool lwan_response_set_chunked(lwan_request_t *request, lwan_http_status_t status);
void lwan_response_send_chunk(lwan_request_t *request);

bool lwan_response_set_event_stream(lwan_request_t *request, lwan_http_status_t status);
void lwan_response_send_event(lwan_request_t *request, const char *event);

const char *lwan_http_status_as_string(lwan_http_status_t status)
    __attribute__((pure)) __attribute__((warn_unused_result));
const char *lwan_http_status_as_string_with_code(lwan_http_status_t status)
    __attribute__((pure)) __attribute__((warn_unused_result));
const char *lwan_http_status_as_descriptive_string(lwan_http_status_t status)
    __attribute__((pure)) __attribute__((warn_unused_result));
const char *lwan_determine_mime_type_for_file_name(const char *file_name)
    __attribute__((pure)) __attribute__((warn_unused_result));

void lwan_init(lwan_t *l);
void lwan_init_with_config(lwan_t *l, const lwan_config_t *config);
void lwan_shutdown(lwan_t *l);

const lwan_config_t *lwan_get_default_config(void);

int lwan_connection_get_fd(const lwan_t *lwan, const lwan_connection_t *conn)
    __attribute__((pure)) __attribute__((warn_unused_result));


const char *lwan_request_get_remote_address(lwan_request_t *request,
            char buffer[ENFORCE_STATIC_BUFFER_LENGTH INET6_ADDRSTRLEN])
    __attribute__((warn_unused_result));

void lwan_format_rfc_time(time_t t, char buffer[ENFORCE_STATIC_BUFFER_LENGTH 30]);

#if defined (__cplusplus)
}
#endif
