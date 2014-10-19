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
#include <netinet/in.h>

#include "lwan-coro.h"
#include "lwan-trie.h"
#include "lwan-status.h"
#include "strbuf.h"
#include "hash.h"

#define DEFAULT_BUFFER_SIZE 4096
#define DEFAULT_HEADERS_SIZE 512

#undef static_assert
#define static_assert(expr, msg)	_Static_assert((expr), msg)

#define ASSERT_NOT_REACHED()  assert(!"Not reached")
#define ASSERT_NOT_REACHED_RETURN(...) \
    do { \
        ASSERT_NOT_REACHED(); \
        return (__VA_ARGS__); \
    } while(0)

#define N_ELEMENTS(array) (sizeof(array) / sizeof(array[0]))

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#  define MULTICHAR_CONSTANT(a,b,c,d) ((int32_t)((a) | (b) << 8 | (c) << 16 | (d) << 24))
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#  define MULTICHAR_CONSTANT(d,c,b,a) ((int32_t)((a) | (b) << 8 | (c) << 16 | (d) << 24))
#elif __BYTE_ORDER__ == __ORDER_PDP_ENDIAN__
#  error A PDP? Seriously?
#endif

#define MULTICHAR_CONSTANT_L(a,b,c,d) (MULTICHAR_CONSTANT(a,b,c,d) | 0x20202020)

#define STRING_SWITCH(s) switch (*((int32_t *)(s)))
#define STRING_SWITCH_L(s) switch (*((int32_t *)(s)) | 0x20202020)

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

#define LIKELY(x)	LIKELY_IS(!!(x), 1)
#define UNLIKELY(x)	LIKELY_IS((x), 0)

#define ATOMIC_READ(V)		(*(volatile typeof(V) *)&(V))
#define ATOMIC_AAF(P, V) 	(__sync_add_and_fetch((P), (V)))
#define ATOMIC_INC(V)		ATOMIC_AAF(&(V), 1)
#define ATOMIC_DEC(V)		ATOMIC_AAF(&(V), -1)
#define ATOMIC_BITWISE(P, O, V) (__sync_##O##_and_fetch((P), (V)))

typedef struct lwan_t_			lwan_t;
typedef struct lwan_module_t_		lwan_module_t;
typedef struct lwan_key_value_t_	lwan_key_value_t;
typedef struct lwan_request_t_		lwan_request_t;
typedef struct lwan_response_t_		lwan_response_t;
typedef struct lwan_thread_t_		lwan_thread_t;
typedef struct lwan_url_map_t_		lwan_url_map_t;
typedef struct lwan_value_t_		lwan_value_t;
typedef struct lwan_config_t_		lwan_config_t;
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
    HTTP_INTERNAL_ERROR = 500,
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

    HANDLER_PARSE_MASK = 1<<0 | 1<<1 | 1<<2 | 1<<3 | 1<<4
} lwan_handler_flags_t;

typedef enum {
    REQUEST_ACCEPT_DEFLATE     = 1<<0,
    REQUEST_IS_HTTP_1_0        = 1<<1,
    REQUEST_METHOD_GET         = 1<<2,
    REQUEST_METHOD_HEAD        = 1<<3,
    REQUEST_METHOD_POST        = 1<<4,
    RESPONSE_SENT_HEADERS      = 1<<5,
    RESPONSE_CHUNKED_ENCODING  = 1<<6,
    RESPONSE_NO_CONTENT_LENGTH = 1<<7
} lwan_request_flags_t;

typedef enum {
    CONN_MASK               = -1,
    CONN_KEEP_ALIVE         = 1<<0,
    CONN_IS_ALIVE           = 1<<1,
    CONN_SHOULD_RESUME_CORO = 1<<2,
    CONN_WRITE_EVENTS       = 1<<3
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

struct lwan_request_t_ {
    lwan_request_flags_t flags;
    int fd;
    lwan_value_t url;
    lwan_value_t original_url;
    lwan_connection_t *conn;

    struct {
        lwan_key_value_t *base;
        size_t len;
    } query_params, post_data;
    struct {
        time_t if_modified_since;
        struct {
          off_t from;
          off_t to;
        } range;
    } header;
    lwan_response_t response;
};

struct lwan_module_t_ {
    const char *name;
    void *(*init)(void *args);
    void *(*init_from_hash)(const struct hash *hash);
    void (*shutdown)(void *data);
    lwan_http_status_t (*handle)(lwan_request_t *request, lwan_response_t *response, void *data);
    lwan_handler_flags_t flags;
};

struct lwan_url_map_t_ {
    lwan_http_status_t (*handler)(lwan_request_t *request, lwan_response_t *response, void *data);
    void *data;

    char *prefix;
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
    short id;

    pthread_t self;
    int epoll_fd;
    int socketpair[2];
};

struct lwan_config_t_ {
    char *listener;
    unsigned short keep_alive_timeout;
    bool quiet;
    bool reuse_port;
    unsigned int expires;
};

struct lwan_t_ {
    lwan_trie_t *url_map_trie;
    lwan_connection_t *conns;
    int main_socket;

    lwan_config_t config;

    struct {
        short count;
        unsigned max_fd;
        lwan_thread_t *threads;
    } thread;

    struct hash *module_registry;
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
const char *lwan_request_get_remote_address(lwan_request_t *request, char buffer[static INET6_ADDRSTRLEN])
    __attribute__((warn_unused_result));
void lwan_process_request(lwan_t *l, lwan_request_t *request);

bool lwan_response_set_chunked(lwan_request_t *request, lwan_http_status_t status);
void lwan_response_send_chunk(lwan_request_t *request);

bool lwan_response_set_event_stream(lwan_request_t *request, lwan_http_status_t status);
void lwan_response_send_event(lwan_request_t *request, const char *event);

void lwan_format_rfc_time(time_t t, char buffer[static 30]);

const char *lwan_http_status_as_string(lwan_http_status_t status)
    __attribute__((pure)) __attribute__((warn_unused_result));
const char *lwan_http_status_as_string_with_code(lwan_http_status_t status)
    __attribute__((pure)) __attribute__((warn_unused_result));
const char *lwan_http_status_as_descriptive_string(lwan_http_status_t status)
    __attribute__((pure)) __attribute__((warn_unused_result));
const char *lwan_determine_mime_type_for_file_name(const char *file_name)
    __attribute__((pure)) __attribute__((warn_unused_result));

void lwan_init(lwan_t *l);
void lwan_shutdown(lwan_t *l);

int lwan_connection_get_fd(lwan_connection_t *conn)
    __attribute__((pure)) __attribute__((warn_unused_result));

#endif /* __LWAN_H__ */
