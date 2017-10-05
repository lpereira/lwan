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
#include "lwan-array.h"
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
#  define MULTICHAR_CONSTANT(a,b,c,d) \
    ((int32_t)((a) | (b) << 8 | (c) << 16 | (d) << 24))
#  define MULTICHAR_CONSTANT_SMALL(a,b) \
    ((int16_t)((a) | (b) << 8))
#  define MULTICHAR_CONSTANT_LARGE(a,b,c,d,e,f,g,h) \
    ((int64_t)MULTICHAR_CONSTANT(a,b,c,d) | (int64_t)MULTICHAR_CONSTANT(e,f,g,h)<<32)
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#  define MULTICHAR_CONSTANT(d,c,b,a) \
    ((int32_t)((a) | (b) << 8 | (c) << 16 | (d) << 24))
#  define MULTICHAR_CONSTANT_SMALL(b,a) \
    ((int16_t)((a) | (b) << 8))
#  define MULTICHAR_CONSTANT_LARGE(a,b,c,d,e,f,g,h) \
    ((int64_t)MULTICHAR_CONSTANT(a,b,c,d)<<32 | (int64_t)MULTICHAR_CONSTANT(e,f,g,h))
#elif __BYTE_ORDER__ == __ORDER_PDP_ENDIAN__
#  error A PDP? Seriously?
#endif

#define MULTICHAR_CONSTANT_L(a,b,c,d) \
    (MULTICHAR_CONSTANT(a,b,c,d) | 0x20202020)
#define MULTICHAR_CONSTANT_SMALL_L(a,b) \
    (MULTICHAR_CONSTANT_SMALL(a,b) | 0x2020)
#define MULTICHAR_CONSTANT_LARGE_L(a,b,c,d,e,f,g,h) \
    (MULTICHAR_CONSTANT_LARGE(a,b,c,d,e,f,g,h) | 0x2020202020202020)

static ALWAYS_INLINE int64_t string_as_int64(const char *s)
{
    int64_t i;
    memcpy(&i, s, sizeof(int64_t));
    return i;
}

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

#define STRING_SWITCH_LARGE(s) switch (string_as_int64(s))
#define STRING_SWITCH_LARGE_L(s) switch (string_as_int64(s) | 0x2020202020202020)

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

enum lwan_http_status {
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
    HTTP_CLIENT_TOO_HIGH = 420,
    HTTP_INTERNAL_ERROR = 500,
    HTTP_NOT_IMPLEMENTED = 501,
    HTTP_UNAVAILABLE = 503,
    HTTP_SERVER_TOO_HIGH = 520,
};

enum lwan_handler_flags {
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
};

enum lwan_request_flags {
    REQUEST_ALL_FLAGS          = -1,

    REQUEST_METHOD_MASK        = 1<<0 | 1<<1 | 1<<2,
    REQUEST_METHOD_GET         = 1<<0,
    REQUEST_METHOD_POST        = 1<<1,
    REQUEST_METHOD_HEAD        = 1<<0 | 1<<1,
    REQUEST_METHOD_OPTIONS     = 1<<2,
    REQUEST_METHOD_DELETE      = 1<<2 | 1<<0,

    REQUEST_ACCEPT_DEFLATE     = 1<<3,
    REQUEST_ACCEPT_GZIP        = 1<<4,
    REQUEST_IS_HTTP_1_0        = 1<<5,
    REQUEST_ALLOW_PROXY_REQS   = 1<<6,
    REQUEST_PROXIED            = 1<<7,
    REQUEST_ALLOW_CORS         = 1<<8,

    RESPONSE_SENT_HEADERS      = 1<<9,
    RESPONSE_CHUNKED_ENCODING  = 1<<10,
    RESPONSE_NO_CONTENT_LENGTH = 1<<11,
    RESPONSE_URL_REWRITTEN     = 1<<12,
};

enum lwan_connection_flags {
    CONN_MASK               = -1,
    CONN_KEEP_ALIVE         = 1<<0,
    CONN_IS_ALIVE           = 1<<1,
    CONN_SHOULD_RESUME_CORO = 1<<2,
    CONN_WRITE_EVENTS       = 1<<3,
    CONN_MUST_READ          = 1<<4,
};

enum lwan_connection_coro_yield {
    CONN_CORO_ABORT = -1,
    CONN_CORO_MAY_RESUME = 0,
    CONN_CORO_FINISHED = 1
};

struct lwan_key_value {
    char *key;
    char *value;
};

struct lwan_request;
struct lwan_response {
    struct strbuf *buffer;
    const char *mime_type;
    size_t content_length;
    struct lwan_key_value *headers;

    struct {
        enum lwan_http_status (*callback)(struct lwan_request *request, void *data);
        void *data;
        void *priv;
    } stream;
};

struct lwan_value {
    char *value;
    size_t len;
};

struct lwan_connection {
    /* This structure is exactly 32-bytes on x86-64. If it is changed,
     * make sure the scheduler (lwan.c) is updated as well. */
    enum lwan_connection_flags flags;
    unsigned int time_to_die;
    struct coro *coro;
    struct lwan_thread *thread;
    int prev, next; /* for death queue */
};

struct lwan_proxy {
    union {
        struct sockaddr_in ipv4;
        struct sockaddr_in6 ipv6;
    } from, to;
};

DEFINE_ARRAY_TYPE(lwan_key_value_array, struct lwan_key_value)

struct lwan_request {
    enum lwan_request_flags flags;
    int fd;
    struct lwan_value url;
    struct lwan_value original_url;
    struct lwan_connection *conn;
    struct lwan_proxy *proxy;

    struct lwan_key_value_array query_params, post_data, cookies;

    struct {
        time_t if_modified_since;
        struct {
          off_t from;
          off_t to;
        } range;
        struct lwan_value *body;
        struct lwan_value *content_type;
    } header;
    struct lwan_response response;
};

struct lwan_module {
    void *(*init)(const char *prefix, void *args);
    void *(*init_from_hash)(const char *prefix, const struct hash *hash);
    void (*shutdown)(void *data);
    bool (*parse_conf)(void *data, struct config *config);
    enum lwan_http_status (*handle)(struct lwan_request *request, struct lwan_response *response, void *data);
    enum lwan_handler_flags flags;
};

struct lwan_url_map {
    enum lwan_http_status (*handler)(struct lwan_request *request, struct lwan_response *response, void *data);
    void *data;

    const char *prefix;
    size_t prefix_len;
    enum lwan_handler_flags flags;

    const struct lwan_module *module;
    void *args;

    struct {
        char *realm;
        char *password_file;
    } authorization;
};

struct lwan_thread {
    struct lwan *lwan;
    struct {
        char date[30];
        char expires[30];
        time_t last;
    } date;

    int epoll_fd;
    int pipe_fd[2];
    pthread_t self;
};

struct lwan_config {
    char *listener;
    char *error_template;
    char *config_file_path;
    size_t max_post_data_size;
    unsigned short keep_alive_timeout;
    unsigned int expires;
    unsigned short n_threads;
    bool quiet;
    bool reuse_port;
    bool proxy_protocol;
    bool allow_cors;
    bool allow_post_temp_file;
};

struct lwan {
    struct lwan_trie url_map_trie;
    struct lwan_connection *conns;

    struct {
        pthread_barrier_t barrier;
        struct lwan_thread *threads;
        unsigned int max_fd;
        unsigned short count;
    } thread;

    struct hash *module_registry;
    struct lwan_config config;
    int main_socket;
};

void lwan_set_url_map(struct lwan *l, const struct lwan_url_map *map);
void lwan_main_loop(struct lwan *l);

void lwan_response(struct lwan_request *request, enum lwan_http_status status);
void lwan_default_response(struct lwan_request *request, enum lwan_http_status status);
size_t lwan_prepare_response_header(struct lwan_request *request, enum lwan_http_status status, char header_buffer[], size_t header_buffer_size)
    __attribute__((warn_unused_result));

const char *lwan_request_get_post_param(struct lwan_request *request, const char *key)
    __attribute__((warn_unused_result));
const char *lwan_request_get_query_param(struct lwan_request *request, const char *key)
    __attribute__((warn_unused_result));
const char * lwan_request_get_cookie(struct lwan_request *request, const char *key)
    __attribute__((warn_unused_result));

bool lwan_response_set_chunked(struct lwan_request *request, enum lwan_http_status status);
void lwan_response_send_chunk(struct lwan_request *request);

bool lwan_response_set_event_stream(struct lwan_request *request, enum lwan_http_status status);
void lwan_response_send_event(struct lwan_request *request, const char *event);

const char *lwan_http_status_as_string(enum lwan_http_status status)
    __attribute__((pure)) __attribute__((warn_unused_result));
const char *lwan_http_status_as_string_with_code(enum lwan_http_status status)
    __attribute__((pure)) __attribute__((warn_unused_result));
const char *lwan_http_status_as_descriptive_string(enum lwan_http_status status)
    __attribute__((pure)) __attribute__((warn_unused_result));
const char *lwan_determine_mime_type_for_file_name(const char *file_name)
    __attribute__((pure)) __attribute__((warn_unused_result));

void lwan_init(struct lwan *l);
void lwan_init_with_config(struct lwan *l, const struct lwan_config *config);
void lwan_shutdown(struct lwan *l);

const struct lwan_config *lwan_get_default_config(void);

int lwan_connection_get_fd(const struct lwan *lwan, const struct lwan_connection *conn)
    __attribute__((pure)) __attribute__((warn_unused_result));

const char *lwan_request_get_remote_address(struct lwan_request *request,
            char buffer[ENFORCE_STATIC_BUFFER_LENGTH INET6_ADDRSTRLEN])
    __attribute__((warn_unused_result));

int lwan_format_rfc_time(const time_t in, char out[ENFORCE_STATIC_BUFFER_LENGTH 30]);
int lwan_parse_rfc_time(const char in[ENFORCE_STATIC_BUFFER_LENGTH 30], time_t *out);

static inline enum lwan_request_flags
lwan_request_get_method(const struct lwan_request *request)
{
    return (enum lwan_request_flags)(request->flags & REQUEST_METHOD_MASK);
}

#if defined (__cplusplus)
}
#endif
