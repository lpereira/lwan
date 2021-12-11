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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#pragma once

#include <stdlib.h>
#include <limits.h>

#include "lwan.h"

struct lwan_request_parser_helper {
    struct lwan_value *buffer;		/* The whole request buffer */
    char *next_request;			/* For pipelined requests */

    char **header_start;		/* Headers: n: start, n+1: end */
    size_t n_header_start;		/* len(header_start) */

    struct lwan_value accept_encoding;	/* Accept-Encoding: */

    struct lwan_value query_string;	/* Stuff after ? and before # */

    struct lwan_value body_data; /* Request body for POST and PUT */
    struct lwan_value content_type;	/* Content-Type: for POST and PUT */
    struct lwan_value content_length;	/* Content-Length: */

    struct lwan_value connection;	/* Connection: */

    struct lwan_key_value_array cookies, query_params, post_params;

    struct { /* If-Modified-Since: */
        struct lwan_value raw;
        time_t parsed;
    } if_modified_since;

    struct { /* Range: */
        struct lwan_value raw;
        off_t from, to;
    } range;

    uint64_t request_id;		/* Request ID for debugging purposes */

    time_t error_when_time;		/* Time to abort request read */
    int error_when_n_packets;		/* Max. number of packets */
    int urls_rewritten;			/* Times URLs have been rewritten */
};

#define DEFAULT_BUFFER_SIZE 4096
#define DEFAULT_HEADERS_SIZE 512

#define N_HEADER_START 64

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

int lwan_socket_get_backlog_size(void);

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

void lwan_process_request(struct lwan *l, struct lwan_request *request);
size_t lwan_prepare_response_header_full(struct lwan_request *request,
     enum lwan_http_status status, char headers[],
     size_t headers_buf_size, const struct lwan_key_value *additional_headers);

void lwan_response(struct lwan_request *request, enum lwan_http_status status);
void lwan_default_response(struct lwan_request *request,
                           enum lwan_http_status status);
void lwan_fill_default_response(struct lwan_strbuf *buffer,
                                enum lwan_http_status status);

void lwan_straitjacket_enforce_from_config(struct config *c);

const char *lwan_get_config_path(char *path_buf, size_t path_buf_len);

uint8_t lwan_char_isspace(char ch) __attribute__((pure));
uint8_t lwan_char_isxdigit(char ch) __attribute__((pure));
uint8_t lwan_char_isdigit(char ch) __attribute__((pure));

static ALWAYS_INLINE __attribute__((pure)) size_t lwan_nextpow2(size_t number)
{
#if defined(HAVE_BUILTIN_CLZLL)
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

#if defined(HAVE_MBEDTLS)
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

#ifdef HAVE_LUA
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

int lwan_connection_get_fd(const struct lwan *lwan,
                           const struct lwan_connection *conn)
    __attribute__((pure)) __attribute__((warn_unused_result));

int lwan_format_rfc_time(const time_t in, char out LWAN_ARRAY_PARAM(30));
int lwan_parse_rfc_time(const char in LWAN_ARRAY_PARAM(30), time_t *out);

void lwan_straitjacket_enforce(const struct lwan_straitjacket *sj);

uint64_t lwan_request_get_id(struct lwan_request *request);

