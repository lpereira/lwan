/*
 * lwan - web server
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#pragma once

#include <stdlib.h>
#include <limits.h>

#include "lwan.h"

#define N_HEADER_START 64
#define DEFAULT_BUFFER_SIZE 4096
#define DEFAULT_HEADERS_SIZE 4096

#define LWAN_LAZY_GLOBAL(type_, name_)                                         \
    static type_ lazy_global_##name_;                                          \
    static type_ new_lazy_global_##name_(void);                                \
    __attribute__((cold)) static void initialize_lazy_global_##name_(void)     \
    {                                                                          \
        lazy_global_##name_ = new_lazy_global_##name_();                       \
    }                                                                          \
    static type_ name_(void)                                                   \
    {                                                                          \
        static pthread_once_t once = PTHREAD_ONCE_INIT;                        \
        pthread_once(&once, initialize_lazy_global_##name_);                   \
        return lazy_global_##name_;                                            \
    }                                                                          \
    __attribute__((                                                            \
        cold,                                                                  \
        always_inline)) static inline type_ new_lazy_global_##name_(void)

#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
/* Workaround for:
 * https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=15216 */
#define LWAN_LAZY_THREAD_LOCAL(type_, name_) static inline type_ name_(void)
#else
#define LWAN_LAZY_THREAD_LOCAL(type_, name_)                                   \
    static type_ new_lazy_thread_local_##name_(void);                          \
    static type_ name_(void)                                                   \
    {                                                                          \
        static __thread type_ val;                                             \
        static __thread bool initialized;                                      \
        if (UNLIKELY(!initialized)) {                                          \
            val = new_lazy_thread_local_##name_();                             \
            initialized = true;                                                \
        }                                                                      \
        return val;                                                            \
    }                                                                          \
    __attribute__((cold,                                                       \
                   noinline)) static type_ new_lazy_thread_local_##name_(void)
#endif

struct lwan_constructor_callback_info {
    void (*func)(struct lwan *);
    int prio;
};

#define LWAN_CONSTRUCTOR(name_, prio_)                                         \
    __attribute__((no_sanitize_address)) static void lwan_constructor_##name_( \
        struct lwan *l __attribute__((unused)));                               \
    static const struct lwan_constructor_callback_info __attribute__((         \
        used, section(LWAN_SECTION_NAME(                                       \
                  lwan_constructor)))) lwan_constructor_info_##name_ = {       \
        .func = lwan_constructor_##name_,                                      \
        .prio = (prio_),                                                       \
    };                                                                         \
    static ALWAYS_INLINE void lwan_constructor_##name_(                        \
        struct lwan *l __attribute__((unused)))

struct lwan_request_parser_helper {
    struct lwan_value *buffer; /* The whole request buffer */
    char *next_request;        /* For pipelined requests */

    struct lwan_value accept_encoding; /* Accept-Encoding: */

    struct lwan_value query_string; /* Stuff after ? and before # */

    struct lwan_value body_data;      /* Request body for POST and PUT */
    struct lwan_value content_type;   /* Content-Type: for POST and PUT */
    struct lwan_value content_length; /* Content-Length: */

    struct lwan_value connection; /* Connection: */

    struct lwan_value host; /* Host: */

    struct lwan_key_value_array cookies, query_params, post_params;

    char **header_start;   /* Headers: n: start, n+1: end */
    size_t n_header_start; /* len(header_start) */

    struct { /* If-Modified-Since: */
        struct lwan_value raw;
        time_t parsed;
    } if_modified_since;

    struct { /* Range: */
        struct lwan_value raw;
        off_t from, to;
    } range;

    uint64_t request_id; /* Request ID for debugging purposes */

    time_t error_when_time;   /* Time to abort request read */
    int error_when_n_packets; /* Max. number of packets */
    int urls_rewritten;       /* Times URLs have been rewritten */
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

#define LWAN_CONCAT(a_, b_) a_ ## b_
#define LWAN_TMP_ID_DETAIL(n_) LWAN_CONCAT(lwan_tmp_id, n_)
#define LWAN_TMP_ID LWAN_TMP_ID_DETAIL(__COUNTER__)

#define LWAN_MIN_MAX_DETAIL(a_, b_, name_a_, name_b_, op_)                     \
    ({                                                                         \
        const __typeof__((a_) + 0) name_a_ = (a_);                             \
        const __typeof__((b_) + 0) name_b_ = (b_);                             \
        name_a_ op_ name_b_ ? name_b_ : name_a_;                               \
    })

#define LWAN_MIN(a_, b_) LWAN_MIN_MAX_DETAIL(a_, b_, LWAN_TMP_ID, LWAN_TMP_ID, >)

#define LWAN_MAX(a_, b_) LWAN_MIN_MAX_DETAIL(a_, b_, LWAN_TMP_ID, LWAN_TMP_ID, <)

void lwan_set_thread_name(const char *name);

void lwan_response_init(struct lwan *l);
void lwan_response_shutdown(struct lwan *l);

int lwan_create_listen_socket(const struct lwan *l,
                              bool print_listening_msg,
                              bool is_https);

void lwan_thread_init(struct lwan *l);
void lwan_thread_shutdown(struct lwan *l);

void lwan_status_init(struct lwan *l);
void lwan_status_shutdown(struct lwan *l);

void lwan_job_thread_init(void);
void lwan_job_thread_main_loop(void);
void lwan_job_thread_shutdown(void);
void lwan_job_add(bool (*cb)(void *data), void *data);
void lwan_job_del(bool (*cb)(void *data), void *data);

void lwan_tables_init(void);
void lwan_tables_shutdown(void);

void lwan_readahead_init(void);
void lwan_readahead_shutdown(void);
void lwan_readahead_queue(int fd, off_t off, size_t size);
void lwan_madvise_queue(void *addr, size_t size);

char *lwan_strbuf_extend_unsafe(struct lwan_strbuf *s, size_t by);
bool lwan_strbuf_has_grow_buffer_failed_flag(const struct lwan_strbuf *s);

void lwan_process_request(struct lwan *l, struct lwan_request *request);
size_t lwan_prepare_response_header_full(struct lwan_request *request,
     enum lwan_http_status status, char headers[],
     size_t headers_buf_size, const struct lwan_key_value *additional_headers);

void lwan_response(struct lwan_request *request, enum lwan_http_status status);
void lwan_default_response(struct lwan_request *request,
                           enum lwan_http_status status);
void lwan_fill_default_response(struct lwan_strbuf *buffer,
                                enum lwan_http_status status);


const char *lwan_get_config_path(char *path_buf, size_t path_buf_len);

uint8_t lwan_char_isspace(char ch) __attribute__((pure));
uint8_t lwan_char_isxdigit(char ch) __attribute__((pure));
uint8_t lwan_char_isdigit(char ch) __attribute__((pure));
uint8_t lwan_char_isalpha(char ch) __attribute__((pure));
uint8_t lwan_char_isalnum(char ch) __attribute__((pure));
uint8_t lwan_char_iscgiheader(char ch) __attribute__((pure));

static ALWAYS_INLINE __attribute__((pure)) size_t lwan_nextpow2(size_t number)
{
#if defined(LWAN_HAVE_BUILTIN_CLZLL)
    static const int size_bits = (int)sizeof(number) * CHAR_BIT;

    if (sizeof(size_t) == sizeof(unsigned int)) {
        return (size_t)1 << (size_bits - __builtin_clz((unsigned int)number));
    } else if (sizeof(size_t) == sizeof(unsigned long)) {
        return (size_t)1 << (size_bits - __builtin_clzl((unsigned long)number));
    } else if (sizeof(size_t) == sizeof(unsigned long long)) {
        return (size_t)1 << (size_bits - __builtin_clzll((unsigned long long)number));
    } else {
        (void)size_bits;
    }
#endif

    number--;
    number |= number >> 1;
    number |= number >> 2;
    number |= number >> 4;
    number |= number >> 8;
    number |= number >> 16;
#if __SIZE_WIDTH__ == 64
    number |= number >> 32;
#endif

    return number + 1;
}

#if defined(LWAN_HAVE_MBEDTLS)
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ssl.h>

struct lwan_tls_context {
    mbedtls_ssl_config config;
    mbedtls_x509_crt server_cert;
    mbedtls_pk_context server_key;

    mbedtls_entropy_context entropy;

    mbedtls_ctr_drbg_context ctr_drbg;
};
#endif

#ifdef LWAN_HAVE_LUA
#include <lua.h>

lua_State *lwan_lua_create_state(const char *script_file, const char *script);
void lwan_lua_state_push_request(lua_State *L, struct lwan_request *request);
const char *lwan_lua_state_last_error(lua_State *L);
#endif

/* This macro is used as an attempt to convince the compiler that it should
 * never elide an expression -- for instance, when writing fuzz-test or
 * micro-benchmarks. */
#define LWAN_NO_DISCARD(...)                                                   \
    do {                                                                       \
        __typeof__(__VA_ARGS__) no_discard_ = __VA_ARGS__;                     \
        __asm__ __volatile__("" ::"g"(no_discard_) : "memory");                \
    } while (0)

static inline void lwan_always_bzero(void *ptr, size_t len)
{
    LWAN_NO_DISCARD(memset(ptr, 0, len));
}

#ifdef __APPLE__
#define SECTION_START(name_) __start_##name_[] __asm("section$start$__DATA$" #name_)
#define SECTION_END(name_)   __stop_##name_[] __asm("section$end$__DATA$" #name_)
#else
#define SECTION_START(name_) __start_##name_[]
#define SECTION_END(name_) __stop_##name_[]
#endif

#define SECTION_START_SYMBOL(section_name_, iter_)                             \
    ({                                                                         \
        extern const typeof(*iter_) SECTION_START(section_name_);              \
        __start_##section_name_;                                               \
    })

#define SECTION_STOP_SYMBOL(section_name_, iter_)                              \
    ({                                                                         \
        extern const typeof(*iter_) SECTION_END(section_name_);                \
        __stop_##section_name_;                                                \
    })

#define LWAN_SECTION_FOREACH(section_name_, iter_)                             \
    for (iter_ = SECTION_START_SYMBOL(section_name_, iter_);                   \
         iter_ < SECTION_STOP_SYMBOL(section_name_, iter_); (iter_)++)

extern clockid_t monotonic_clock_id;

static inline void *
lwan_aligned_alloc(size_t n, size_t alignment)
{
    void *ret;

    assert((alignment & (alignment - 1)) == 0);
    assert((alignment % (sizeof(void *))) == 0);

    n = (n + alignment - 1) & ~(alignment - 1);
    if (UNLIKELY(posix_memalign(&ret, alignment, n)))
        return NULL;

    return ret;
}

static ALWAYS_INLINE int lwan_calculate_n_packets(size_t total)
{
    /* 740 = 1480 (a common MTU) / 2, so that Lwan'll optimistically error out
     * after ~2x number of expected packets to fully read the request body.*/
    return LWAN_MAX(5, (int)(total / 740));
}

long int lwan_getentropy(void *buffer, size_t buffer_len, int flags);
uint64_t lwan_random_uint64();

const char *lwan_http_status_as_string(enum lwan_http_status status)
    __attribute__((const)) __attribute__((warn_unused_result));
const char *lwan_http_status_as_string_with_code(enum lwan_http_status status)
    __attribute__((const)) __attribute__((warn_unused_result));
const char *lwan_http_status_as_descriptive_string(enum lwan_http_status status)
    __attribute__((const)) __attribute__((warn_unused_result));

static ALWAYS_INLINE __attribute__((pure, warn_unused_result)) int
lwan_connection_get_fd(const struct lwan *lwan,
                       const struct lwan_connection *conn)
{
    return (int)(intptr_t)(conn - lwan->conns);
}

int lwan_format_rfc_time(const time_t in, char out LWAN_ARRAY_PARAM(30));
int lwan_parse_rfc_time(const char in LWAN_ARRAY_PARAM(30), time_t *out);

void lwan_straitjacket_enforce_from_config(struct config *c);

uint64_t lwan_request_get_id(struct lwan_request *request);

ssize_t lwan_find_headers(char **header_start, struct lwan_value *buffer,
                          char **next_request);

sa_family_t lwan_socket_parse_address(char *listener, char **node, char **port);

void lwan_request_foreach_header_for_cgi(struct lwan_request *request,
                                         void (*cb)(const char *header_name,
                                                    size_t header_len,
                                                    const char *value,
                                                    size_t value_len,
                                                    void *user_data),
                                         void *user_data);

bool lwan_send_websocket_ping_for_tq(struct lwan_connection *conn);
