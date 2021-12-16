/*
 * lwan - simple web server
 * Copyright (c) 2012 L. A. F. Pereira <l@tia.mat.br>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#pragma once

#if defined(__cplusplus)
extern "C" {
#endif

#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "hash.h"
#include "timeout.h"
#include "lwan-array.h"
#include "lwan-config.h"
#include "lwan-coro.h"
#include "lwan-status.h"
#include "lwan-strbuf.h"
#include "lwan-trie.h"

#if defined(__cplusplus)
#define ZERO_IF_IS_ARRAY(array) 0
#else
/* This macro expands to 0 if its parameter is an array, and generates a
 * compilation error otherwise.  This is used by the N_ELEMENTS() macro to catch
 * invalid usages of this macro (e.g. when using arrays decayed to pointers in
 * function parameters). */
#define ZERO_IF_IS_ARRAY(array)                                                \
    (!sizeof(char[1 - 2 * __builtin_types_compatible_p(                        \
                              __typeof__(array), __typeof__(&(array)[0]))]))
#endif

#define N_ELEMENTS(array)                                                      \
    (ZERO_IF_IS_ARRAY(array) | sizeof(array) / sizeof(array[0]))


#ifdef __APPLE__
#define LWAN_SECTION_NAME(name_) "__DATA," #name_
#else
#define LWAN_SECTION_NAME(name_) #name_
#endif

#define LWAN_MODULE_REF(name_) lwan_module_info_##name_.module
#define LWAN_MODULE_FORWARD_DECL(name_)                                        \
    extern const struct lwan_module_info lwan_module_info_##name_;
#define LWAN_REGISTER_MODULE(name_, module_)                                   \
    const struct lwan_module_info                                              \
        __attribute__((used, section(LWAN_SECTION_NAME(lwan_module))))         \
            lwan_module_info_##name_ = {.name = #name_, .module = module_}

#define LWAN_HANDLER_REF(name_) lwan_handler_##name_
#define LWAN_HANDLER(name_)                                                    \
    static enum lwan_http_status lwan_handler_##name_(                         \
        struct lwan_request *, struct lwan_response *, void *);                \
    static const struct lwan_handler_info                                      \
        __attribute__((used, section(LWAN_SECTION_NAME(lwan_handler))))        \
            lwan_handler_info_##name_ = {.name = #name_,                       \
                                         .handler = lwan_handler_##name_};     \
    static enum lwan_http_status lwan_handler_##name_(                         \
        struct lwan_request *request __attribute__((unused)),                  \
        struct lwan_response *response __attribute__((unused)),                \
        void *data __attribute__((unused)))

#define ALWAYS_INLINE inline __attribute__((always_inline))

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define STR4_INT(a, b, c, d) ((uint32_t)((a) | (b) << 8 | (c) << 16 | (d) << 24))
#define STR2_INT(a, b) ((uint16_t)((a) | (b) << 8))
#define STR8_INT(a, b, c, d, e, f, g, h)                                       \
    ((uint64_t)STR4_INT(a, b, c, d) | (uint64_t)STR4_INT(e, f, g, h) << 32)
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define STR4_INT(d, c, b, a) ((uint32_t)((a) | (b) << 8 | (c) << 16 | (d) << 24))
#define STR2_INT(b, a) ((uint16_t)((a) | (b) << 8))
#define STR8_INT(a, b, c, d, e, f, g, h)                                       \
    ((uint64_t)STR4_INT(a, b, c, d) << 32 | (uint64_t)STR4_INT(e, f, g, h))
#elif __BYTE_ORDER__ == __ORDER_PDP_ENDIAN__
#error A PDP? Seriously?
#endif

static ALWAYS_INLINE uint16_t string_as_uint16(const char *s)
{
    uint16_t u;

    memcpy(&u, s, sizeof(u));

    return u;
}

static ALWAYS_INLINE uint32_t string_as_uint32(const char *s)
{
    uint32_t u;

    memcpy(&u, s, sizeof(u));

    return u;
}

static ALWAYS_INLINE uint64_t string_as_uint64(const char *s)
{
    uint64_t u;

    memcpy(&u, s, sizeof(u));

    return u;
}

#define LOWER2(s) ((s) | (uint16_t)0x2020)
#define LOWER4(s) ((s) | (uint32_t)0x20202020)
#define LOWER8(s) ((s) | (uint64_t)0x2020202020202020)

#define STR2_INT_L(a, b) LOWER2(STR2_INT(a, b))
#define STR4_INT_L(a, b, c, d) LOWER4(STR4_INT(a, b, c, d))
#define STR8_INT_L(a, b, c, d, e, f, g, h) LOWER8(STR8_INT(a, b, c, d, e, f, g, h))

#define STRING_SWITCH_SMALL(s) switch (string_as_uint16(s))
#define STRING_SWITCH_SMALL_L(s) switch (LOWER2(string_as_uint16(s)))
#define STRING_SWITCH(s) switch (string_as_uint32(s))
#define STRING_SWITCH_L(s) switch (LOWER4(string_as_uint32(s)))
#define STRING_SWITCH_LARGE(s) switch (string_as_uint64(s))
#define STRING_SWITCH_LARGE_L(s) switch (LOWER8(string_as_uint64(s)))

#define LIKELY_IS(x, y) __builtin_expect((x), (y))
#define LIKELY(x) LIKELY_IS(!!(x), 1)
#define UNLIKELY(x) LIKELY_IS((x), 0)

#define ATOMIC_READ(V) (*(volatile typeof(V) *)&(V))
#define ATOMIC_OP(P, O, V) (__sync_##O##_and_fetch((P), (V)))
#define ATOMIC_AAF(P, V) ATOMIC_OP((P), add, (V))
#define ATOMIC_SAF(P, V) ATOMIC_OP((P), sub, (V))
#define ATOMIC_INC(V) ATOMIC_AAF(&(V), 1)
#define ATOMIC_DEC(V) ATOMIC_SAF(&(V), 1)

#if defined(__cplusplus)
#define LWAN_ARRAY_PARAM(length) [length]
#else
#define LWAN_ARRAY_PARAM(length) [static length]
#endif

#define FOR_EACH_HTTP_STATUS(X)                                                                                                             \
    X(SWITCHING_PROTOCOLS, 101, "Switching protocols", "Protocol is switching over from HTTP")                                              \
    X(OK, 200, "OK", "Success")                                                                                                             \
    X(PARTIAL_CONTENT, 206, "Partial content", "Delivering part of requested resource")                                                     \
    X(MOVED_PERMANENTLY, 301, "Moved permanently", "This content has moved to another place")                                               \
    X(NOT_MODIFIED, 304, "Not modified", "The content has not changed since previous request")                                              \
    X(TEMPORARY_REDIRECT, 307, "Temporary Redirect", "This content can be temporarily found at a different location")                       \
    X(BAD_REQUEST, 400, "Bad request", "The client has issued a bad request")                                                               \
    X(NOT_AUTHORIZED, 401, "Not authorized", "Client has no authorization to access this resource")                                         \
    X(FORBIDDEN, 403, "Forbidden", "Access to this resource has been denied")                                                               \
    X(NOT_FOUND, 404, "Not found", "The requested resource could not be found on this server")                                              \
    X(NOT_ALLOWED, 405, "Not allowed", "The requested method is not allowed by this server")                                                \
    X(TIMEOUT, 408, "Request timeout", "Client did not produce a request within expected timeframe")                                        \
    X(TOO_LARGE, 413, "Request too large", "The request entity is too large")                                                               \
    X(RANGE_UNSATISFIABLE, 416, "Requested range unsatisfiable", "The server can't supply the requested portion of the requested resource") \
    X(I_AM_A_TEAPOT, 418, "I'm a teapot", "Client requested to brew coffee but device is a teapot")                                         \
    X(CLIENT_TOO_HIGH, 420, "Client too high", "Client is too high to make a request")                                                      \
    X(INTERNAL_ERROR, 500, "Internal server error", "The server encountered an internal error that couldn't be recovered from")             \
    X(NOT_IMPLEMENTED, 501, "Not implemented", "Server lacks the ability to fulfil the request")                                            \
    X(UNAVAILABLE, 503, "Service unavailable", "The server is either overloaded or down for maintenance")                                   \
    X(SERVER_TOO_HIGH, 520, "Server too high", "The server is too high to answer the request")

#define GENERATE_ENUM_ITEM(id, code, short, long) HTTP_ ## id = code,
enum lwan_http_status {
    HTTP_CLASS__INFORMATIONAL = 100,
    HTTP_CLASS__SUCCESS = 200,
    HTTP_CLASS__REDIRECT = 300,
    HTTP_CLASS__CLIENT_ERROR = 400,
    HTTP_CLASS__SERVER_ERROR = 500,

    FOR_EACH_HTTP_STATUS(GENERATE_ENUM_ITEM)
};
#undef GENERATE_ENUM_ITEM

enum lwan_handler_flags {
    HANDLER_EXPECTS_BODY_DATA = 1 << 0,
    HANDLER_MUST_AUTHORIZE = 1 << 1,
    HANDLER_CAN_REWRITE_URL = 1 << 2,
    HANDLER_DATA_IS_HASH_TABLE = 1 << 3,

    HANDLER_PARSE_MASK = HANDLER_EXPECTS_BODY_DATA,
};

/* 1<<0 set: response has body; see has_response_body() in lwan-response.c */
/* 1<<3 set: request has body; see request_has_body() in lwan-request.c */
#define FOR_EACH_REQUEST_METHOD(X)                                             \
    X(GET, get, (1 << 0), STR4_INT('G', 'E', 'T', ' '))                        \
    X(POST, post, (1 << 3 | 1 << 1 | 1 << 0), STR4_INT('P', 'O', 'S', 'T'))    \
    X(HEAD, head, (1 << 1), STR4_INT('H', 'E', 'A', 'D'))                      \
    X(OPTIONS, options, (1 << 2), STR4_INT('O', 'P', 'T', 'I'))                \
    X(DELETE, delete, (1 << 1 | 1 << 2), STR4_INT('D', 'E', 'L', 'E'))         \
    X(PUT, put, (1 << 3 | 1 << 2 | 1 << 0), STR4_INT('P', 'U', 'T', ' '))

#define SELECT_MASK(upper, lower, mask, constant) mask |
#define GENERATE_ENUM_ITEM(upper, lower, mask, constant) REQUEST_METHOD_##upper = mask,

enum lwan_request_flags {
    REQUEST_ALL_FLAGS = -1,

    REQUEST_METHOD_MASK = FOR_EACH_REQUEST_METHOD(SELECT_MASK) 0,
    FOR_EACH_REQUEST_METHOD(GENERATE_ENUM_ITEM)

    REQUEST_ACCEPT_DEFLATE = 1 << 4,
    REQUEST_ACCEPT_GZIP = 1 << 5,
    REQUEST_ACCEPT_BROTLI = 1 << 6,
    REQUEST_ACCEPT_ZSTD = 1 << 7,
    REQUEST_ACCEPT_MASK = 1 << 4 | 1 << 5 | 1 << 6 | 1 << 7,

    REQUEST_IS_HTTP_1_0 = 1 << 8,
    REQUEST_ALLOW_PROXY_REQS = 1 << 9,
    REQUEST_PROXIED = 1 << 10,
    REQUEST_ALLOW_CORS = 1 << 11,

    RESPONSE_SENT_HEADERS = 1 << 12,
    RESPONSE_CHUNKED_ENCODING = 1 << 13,
    RESPONSE_NO_CONTENT_LENGTH = 1 << 14,
    RESPONSE_NO_EXPIRES = 1 << 15,
    RESPONSE_URL_REWRITTEN = 1 << 16,

    RESPONSE_STREAM = 1 << 17,

    REQUEST_PARSED_QUERY_STRING = 1 << 18,
    REQUEST_PARSED_IF_MODIFIED_SINCE = 1 << 19,
    REQUEST_PARSED_RANGE = 1 << 20,
    REQUEST_PARSED_FORM_DATA = 1 << 21,
    REQUEST_PARSED_COOKIES = 1 << 22,
    REQUEST_PARSED_ACCEPT_ENCODING = 1 << 23,

    RESPONSE_INCLUDE_REQUEST_ID = 1 << 24,

    REQUEST_HAS_QUERY_STRING = 1 << 25,
};

#undef SELECT_MASK
#undef GENERATE_ENUM_ITEM

enum lwan_connection_flags {
    CONN_MASK = -1,

    /* These flags have smaller numbers so that the table to convert
     * them to epoll events is smaller.  See conn_flags_to_epoll_events(). */
    CONN_EVENTS_READ = 1 << 0,
    CONN_EVENTS_WRITE = 1 << 1,
    CONN_EVENTS_READ_WRITE = CONN_EVENTS_READ | CONN_EVENTS_WRITE,
    CONN_EVENTS_MASK = 1 << 0 | 1 << 1,

    CONN_IS_KEEP_ALIVE = 1 << 2,
    CONN_IS_UPGRADE = 1 << 3,
    CONN_IS_WEBSOCKET = 1 << 4,

    /* This is only used to determine if timeout_del() is necessary when
     * the connection coro ends. */
    CONN_SUSPENDED = 1 << 5,
    CONN_HAS_REMOVE_SLEEP_DEFER = 1 << 6,

    CONN_CORK = 1 << 7,

    /* Set only on file descriptors being watched by async/await to determine
     * which epoll operation to use when suspending/resuming (ADD/MOD). Reset
     * whenever associated client connection is closed. */
    CONN_ASYNC_AWAIT = 1 << 8,

    CONN_SENT_CONNECTION_HEADER = 1 << 9,

    /* Both are used to know if an epoll event pertains to a listener rather
     * than a client.  */
    CONN_LISTENER_HTTP = 1 << 10,
    CONN_LISTENER_HTTPS = 1 << 11,

    /* Set on file descriptors accepted by listeners with the
     * CONN_LISTENER_HTTPS flag, and unset right after the handshake has been
     * completed (when CONN_TLS is then set.) */
    CONN_NEEDS_TLS_SETUP = 1 << 12,

    /* Used mostly for the Lua and Rewrite modules */
    CONN_TLS = 1 << 14,
};

enum lwan_connection_coro_yield {
    CONN_CORO_ABORT,

    CONN_CORO_YIELD,

    CONN_CORO_WANT_READ,
    CONN_CORO_WANT_WRITE,
    CONN_CORO_WANT_READ_WRITE,

    CONN_CORO_SUSPEND,
    CONN_CORO_RESUME,

    /* Group async stuff together to make it easier to check if a connection
     * coroutine is yielding because of async reasons. */
    CONN_CORO_ASYNC_AWAIT_READ,
    CONN_CORO_ASYNC_AWAIT_WRITE,
    CONN_CORO_ASYNC_AWAIT_READ_WRITE,

    CONN_CORO_MAX,

    CONN_CORO_ASYNC = CONN_CORO_ASYNC_AWAIT_READ,
};

struct lwan_key_value {
    char *key;
    char *value;
};

struct lwan_request;

struct lwan_response {
    struct lwan_strbuf *buffer;
    const char *mime_type;

    union {
        struct {
            const struct lwan_key_value *headers;
        };

        struct {
            enum lwan_http_status (*callback)(struct lwan_request *request,
                                              void *data);
            void *data;
        } stream;
    };
};

struct lwan_value {
    char *value;
    size_t len;
};

struct lwan_connection {
    /* This structure is exactly 32-bytes on x86-64. If it is changed,
     * make sure the scheduler (lwan-thread.c) is updated as well. */
    enum lwan_connection_flags flags;
    unsigned int time_to_expire;
    struct coro *coro;
    struct lwan_thread *thread;
    int prev, next; /* for timeout queue */
};

struct lwan_proxy {
    union {
        struct sockaddr_in ipv4;
        struct sockaddr_in6 ipv6;
    } from, to;
};

DEFINE_ARRAY_TYPE(lwan_key_value_array, struct lwan_key_value)

struct lwan_request_parser_helper;

struct lwan_request {
    enum lwan_request_flags flags;
    int fd;
    struct lwan_connection *conn;
    const struct lwan_value *const global_response_headers;

    struct lwan_request_parser_helper *helper;

    struct lwan_value url;
    struct lwan_value original_url;
    struct lwan_response response;

    struct lwan_proxy *proxy;
    struct timeout timeout;
};

struct lwan_module {
    enum lwan_http_status (*handle_request)(struct lwan_request *request,
                                            struct lwan_response *response,
                                            void *instance);

    void *(*create)(const char *prefix, void *args);
    void *(*create_from_hash)(const char *prefix, const struct hash *hash);
    void (*destroy)(void *instance);

    bool (*parse_conf)(void *instance, struct config *config);

    enum lwan_handler_flags flags;
};

struct lwan_module_info {
    const char *name;
    const struct lwan_module *module;
};

struct lwan_handler_info {
    const char *name;
    enum lwan_http_status (*handler)(struct lwan_request *request,
                                     struct lwan_response *response,
                                     void *data);
};

struct lwan_url_map {
    enum lwan_http_status (*handler)(struct lwan_request *request,
                                     struct lwan_response *response,
                                     void *data);
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
    } date;
    int epoll_fd;
    struct timeouts *wheel;
    int listen_fd;
    int tls_listen_fd;
    unsigned int cpu;
    pthread_t self;
};

struct lwan_straitjacket {
    const char *user_name;
    const char *chroot_path;
    bool drop_capabilities;
};

struct lwan_config {
    /* Field will be overridden during initialization. */
    enum lwan_request_flags request_flags;
    struct lwan_key_value *global_headers;

    char *listener;
    char *tls_listener;
    char *error_template;
    char *config_file_path;

    struct {
        char *cert;
        char *key;
    } ssl;

    size_t max_post_data_size;
    size_t max_put_data_size;

    unsigned int keep_alive_timeout;
    unsigned int expires;
    unsigned int n_threads;

    bool quiet;
    bool proxy_protocol;
    bool allow_cors;
    bool allow_post_temp_file;
    bool allow_put_temp_file;
};

struct lwan {
    struct lwan_trie url_map_trie;
    struct lwan_connection *conns;
    struct lwan_value headers;

#if defined(HAVE_MBEDTLS)
    struct lwan_tls_context *tls;
#endif

    struct {
        struct lwan_thread *threads;

        unsigned int max_fd;
        unsigned int count;
        pthread_barrier_t barrier;
    } thread;

    struct lwan_config config;

    unsigned int online_cpus;
    unsigned int available_cpus;
};

void lwan_set_url_map(struct lwan *l, const struct lwan_url_map *map);
void lwan_main_loop(struct lwan *l);

size_t lwan_prepare_response_header(struct lwan_request *request,
                                    enum lwan_http_status status,
                                    char header_buffer[],
                                    size_t header_buffer_size)
    __attribute__((warn_unused_result));

const char *lwan_request_get_post_param(struct lwan_request *request,
                                        const char *key)
    __attribute__((warn_unused_result, pure));
const char *lwan_request_get_query_param(struct lwan_request *request,
                                         const char *key)
    __attribute__((warn_unused_result, pure));
const char *lwan_request_get_cookie(struct lwan_request *request,
                                    const char *key)
    __attribute__((warn_unused_result, pure));
const char *lwan_request_get_header(struct lwan_request *request,
                                    const char *header)
    __attribute__((warn_unused_result));

void lwan_request_sleep(struct lwan_request *request, uint64_t ms);

bool lwan_response_set_chunked(struct lwan_request *request,
                               enum lwan_http_status status);
void lwan_response_send_chunk(struct lwan_request *request);

bool lwan_response_set_event_stream(struct lwan_request *request,
                                    enum lwan_http_status status);
void lwan_response_send_event(struct lwan_request *request, const char *event);

const char *lwan_determine_mime_type_for_file_name(const char *file_name)
    __attribute__((pure)) __attribute__((warn_unused_result));

void lwan_init(struct lwan *l);
void lwan_init_with_config(struct lwan *l, const struct lwan_config *config);
void lwan_shutdown(struct lwan *l);

const struct lwan_config *lwan_get_default_config(void);

const char *
lwan_request_get_remote_address(struct lwan_request *request,
                                char buffer LWAN_ARRAY_PARAM(INET6_ADDRSTRLEN))
    __attribute__((warn_unused_result));


static inline enum lwan_request_flags
lwan_request_get_method(const struct lwan_request *request)
{
    return (enum lwan_request_flags)(request->flags & REQUEST_METHOD_MASK);
}
const char *lwan_request_get_method_str(const struct lwan_request *request);

int lwan_request_get_range(struct lwan_request *request,
                           off_t *from,
                           off_t *to);
int lwan_request_get_if_modified_since(struct lwan_request *request,
                                       time_t *value);
const struct lwan_value *
lwan_request_get_request_body(struct lwan_request *request);
const struct lwan_value *
lwan_request_get_content_type(struct lwan_request *request);
const struct lwan_key_value_array *
lwan_request_get_cookies(struct lwan_request *request);
const struct lwan_key_value_array *
lwan_request_get_query_params(struct lwan_request *request);
const struct lwan_key_value_array *
lwan_request_get_post_params(struct lwan_request *request);
enum lwan_request_flags
lwan_request_get_accept_encoding(struct lwan_request *request);

enum lwan_http_status
lwan_request_websocket_upgrade(struct lwan_request *request);
void lwan_response_websocket_write(struct lwan_request *request);
int lwan_response_websocket_read(struct lwan_request *request);
int lwan_response_websocket_read_hint(struct lwan_request *request, size_t size_hint);

void lwan_request_await_read(struct lwan_request *r, int fd);
void lwan_request_await_write(struct lwan_request *r, int fd);
void lwan_request_await_read_write(struct lwan_request *r, int fd);
ssize_t lwan_request_async_read(struct lwan_request *r, int fd, void *buf, size_t len);
ssize_t lwan_request_async_write(struct lwan_request *r, int fd, const void *buf, size_t len);

#if defined(__cplusplus)
}
#endif
