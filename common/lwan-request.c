/*
 * lwan - simple web server
 * Copyright (c) 2012-2014 Leandro A. F. Pereira <leandro@hardinfo.org>
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

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "lwan.h"
#include "lwan-config.h"
#include "lwan-http-authorize.h"

typedef enum {
    FINALIZER_DONE,
    FINALIZER_TRY_AGAIN,
    FINALIZER_YIELD_TRY_AGAIN,
    FINALIZER_ERROR_TOO_LARGE
} lwan_read_finalizer_t;

typedef struct lwan_request_parse_t_	lwan_request_parse_t;

struct lwan_request_parse_t_ {
    lwan_value_t buffer;
    lwan_value_t query_string;
    lwan_value_t if_modified_since;
    lwan_value_t range;
    lwan_value_t accept_encoding;
    lwan_value_t fragment;
    lwan_value_t content_length;
    lwan_value_t post_data;
    lwan_value_t content_type;
    lwan_value_t authorization;
    char connection;
};

static char decode_hex_digit(char ch) __attribute__((pure));
static bool is_hex_digit(char ch) __attribute__((pure));
static unsigned long has_zero_byte(unsigned long n) __attribute__((pure));
static unsigned long is_space(char ch) __attribute__((pure));
static char *ignore_leading_whitespace(char *buffer) __attribute__((pure));

static ALWAYS_INLINE char *
identify_http_method(lwan_request_t *request, char *buffer)
{
    enum {
        HTTP_STR_GET  = MULTICHAR_CONSTANT('G','E','T',' '),
        HTTP_STR_HEAD = MULTICHAR_CONSTANT('H','E','A','D'),
        HTTP_STR_POST = MULTICHAR_CONSTANT('P','O','S','T')
    };

    STRING_SWITCH(buffer) {
    case HTTP_STR_GET:
        request->flags |= REQUEST_METHOD_GET;
        return buffer + 4;
    case HTTP_STR_HEAD:
        request->flags |= REQUEST_METHOD_HEAD;
        return buffer + 5;
    case HTTP_STR_POST:
        request->flags |= REQUEST_METHOD_POST;
        return buffer + 5;
    }
    return NULL;
}

static ALWAYS_INLINE char
decode_hex_digit(char ch)
{
    return (char)((ch <= '9') ? ch - '0' : (ch & 7) + 9);
}

static ALWAYS_INLINE bool
is_hex_digit(char ch)
{
    return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F');
}

static size_t
url_decode(char *str)
{
    if (UNLIKELY(!str))
        return 0;

    char *ch, *decoded;
    for (decoded = ch = str; *ch; ch++) {
        if (*ch == '%' && LIKELY(is_hex_digit(ch[1]) && is_hex_digit(ch[2]))) {
            char tmp = (char)(decode_hex_digit(ch[1]) << 4 | decode_hex_digit(ch[2]));
            if (UNLIKELY(!tmp))
                return 0;
            *decoded++ = tmp;
            ch += 2;
        } else if (*ch == '+') {
            *decoded++ = ' ';
        } else {
            *decoded++ = *ch;
        }
    }

    *decoded = '\0';
    return (size_t)(decoded - str);
}

static int
key_value_compare_qsort_key(const void *a, const void *b)
{
    return strcmp(((lwan_key_value_t *)a)->key, ((lwan_key_value_t *)b)->key);
}

#define DECODE_AND_ADD() \
    do { \
        if (LIKELY(url_decode(key))) { \
            kvs[values].key = key; \
            if (LIKELY(url_decode(value))) \
                kvs[values].value = value; \
            else \
                kvs[values].value = ""; \
            ++values; \
            if (UNLIKELY(values >= N_ELEMENTS(kvs))) \
                goto oom; \
        } \
    } while(0)

static void
parse_urlencoded_keyvalues(lwan_request_t *request,
    lwan_value_t *helper_value, lwan_key_value_t **base, size_t *len)
{
    if (!helper_value->value)
        return;

    char *key = helper_value->value;
    char *value = NULL;
    size_t values = 0;
    lwan_key_value_t kvs[256];

    for (char *ch = key; *ch; ch++) {
        switch (*ch) {
        case '=':
            *ch = '\0';
            value = ch + 1;
            break;
        case '&':
        case ';':
            *ch = '\0';
            DECODE_AND_ADD();
            key = ch + 1;
            value = NULL;
        }
    }

    DECODE_AND_ADD();
oom:
    kvs[values].key = kvs[values].value = NULL;

    lwan_key_value_t *kv = coro_malloc(request->conn->coro,
                                    (1 + values) * sizeof(lwan_key_value_t));
    if (LIKELY(kv)) {
        qsort(kvs, values, sizeof(lwan_key_value_t), key_value_compare_qsort_key);
        *base = memcpy(kv, kvs, (1 + values) * sizeof(lwan_key_value_t));
        *len = values;
    }
}

#undef DECODE_AND_ADD

static void
parse_query_string(lwan_request_t *request, lwan_request_parse_t *helper)
{
    parse_urlencoded_keyvalues(request, &helper->query_string,
            &request->query_params.base, &request->query_params.len);
}

static void
parse_post_data(lwan_request_t *request, lwan_request_parse_t *helper)
{
    static const char content_type[] = "application/x-www-form-urlencoded";

    if (helper->content_type.len != sizeof(content_type) - 1)
        return;
    if (UNLIKELY(strcmp(helper->content_type.value, content_type)))
        return;

    parse_urlencoded_keyvalues(request, &helper->post_data,
            &request->post_data.base, &request->post_data.len);
}

static char *
identify_http_path(lwan_request_t *request, char *buffer,
            lwan_request_parse_t *helper)
{
    static const size_t minimal_request_line_len = sizeof("/ HTTP/1.0") - 1;

    char *end_of_line = memchr(buffer, '\r',
                            (helper->buffer.len - (size_t)(buffer - helper->buffer.value)));
    if (UNLIKELY(!end_of_line))
        return NULL;
    if (UNLIKELY((size_t)(end_of_line - buffer) < minimal_request_line_len))
        return NULL;
    *end_of_line = '\0';

    char *space = end_of_line - sizeof("HTTP/X.X");
    if (UNLIKELY(*(space + 1) != 'H')) /* assume HTTP/X.Y */
        return NULL;
    *space = '\0';

    if (UNLIKELY(*(space + 6) != '1'))
        return NULL;

    if (*(space + 8) == '0')
        request->flags |= REQUEST_IS_HTTP_1_0;

    if (UNLIKELY(*buffer != '/'))
        return NULL;

    request->url.value = buffer;
    request->url.len = (size_t)(space - buffer);

    /* Most of the time, fragments are small -- so search backwards */
    char *fragment = memrchr(buffer, '#', request->url.len);
    if (fragment) {
        *fragment = '\0';
        helper->fragment.value = fragment + 1;
        helper->fragment.len = (size_t)(space - fragment - 1);
        request->url.len -= helper->fragment.len + 1;
    }

    /* Most of the time, query string values are larger than the URL, so
       search from the beginning */
    char *query_string = memchr(buffer, '?', request->url.len);
    if (query_string) {
        *query_string = '\0';
        helper->query_string.value = query_string + 1;
        helper->query_string.len = (size_t)((fragment ? fragment : space) - query_string - 1);
        request->url.len -= helper->query_string.len + 1;
    }

    request->original_url.value = buffer;
    request->original_url.len = request->url.len;

    return end_of_line + 1;
}

#define MATCH_HEADER(hdr) \
  do { \
        char *end; \
        p += sizeof(hdr) - 1; \
        if (p >= buffer_end)            /* reached the end of header blocks */ \
          goto end; \
        if (UNLIKELY(*p++ != ':'))	/* not the header we're looking for */ \
          goto did_not_match; \
        if (UNLIKELY(*p++ != ' '))	/* not the header we're looking for */ \
          goto did_not_match; \
        if (LIKELY(end = strchr(p, '\r'))) { \
          *end = '\0'; \
          value = p; \
          p = end + 1; \
          length = (size_t)(end - value); \
          if (UNLIKELY(*p != '\n')) \
            goto did_not_match; \
        } else goto did_not_match;      /* couldn't find line end */ \
  } while (0)

#define CASE_HEADER(hdr_const,hdr_name) \
    case hdr_const: MATCH_HEADER(hdr_name);

static char *
parse_headers(lwan_request_parse_t *helper, char *buffer, char *buffer_end)
{
    enum {
        HTTP_HDR_CONNECTION        = MULTICHAR_CONSTANT_L('C','o','n','n'),
        HTTP_HDR_RANGE             = MULTICHAR_CONSTANT_L('R','a','n','g'),
        HTTP_HDR_IF_MODIFIED_SINCE = MULTICHAR_CONSTANT_L('I','f','-','M'),
        HTTP_HDR_ACCEPT            = MULTICHAR_CONSTANT_L('A','c','c','e'),
        HTTP_HDR_CONTENT           = MULTICHAR_CONSTANT_L('C','o','n','t'),
        HTTP_HDR_ENCODING          = MULTICHAR_CONSTANT_L('-','E','n','c'),
        HTTP_HDR_LENGTH            = MULTICHAR_CONSTANT_L('-','L','e','n'),
        HTTP_HDR_TYPE              = MULTICHAR_CONSTANT_L('-','T','y','p'),
        HTTP_HDR_AUTHORIZATION     = MULTICHAR_CONSTANT_L('A','u','t','h'),
    };

    if (UNLIKELY(!buffer))
        return NULL;

    for (char *p = buffer; *p; buffer = ++p) {
        char *value;
        size_t length;

retry:
        if ((p + sizeof(int32_t)) >= buffer_end)
            break;

        STRING_SWITCH_L(p) {
        CASE_HEADER(HTTP_HDR_CONNECTION, "Connection")
            helper->connection = (*value | 0x20);
            break;
        CASE_HEADER(HTTP_HDR_IF_MODIFIED_SINCE, "If-Modified-Since")
            helper->if_modified_since.value = value;
            helper->if_modified_since.len = length;
            break;
        CASE_HEADER(HTTP_HDR_RANGE, "Range")
            helper->range.value = value;
            helper->range.len = length;
            break;
        CASE_HEADER(HTTP_HDR_AUTHORIZATION, "Authorization")
            helper->authorization.value = value;
            helper->authorization.len = length;
            break;
        CASE_HEADER(HTTP_HDR_ENCODING, "-Encoding")
            helper->accept_encoding.value = value;
            helper->accept_encoding.len = length;
            break;
        CASE_HEADER(HTTP_HDR_TYPE, "-Type")
            helper->content_type.value = value;
            helper->content_type.len = length;
            break;
        CASE_HEADER(HTTP_HDR_LENGTH, "-Length")
            helper->content_length.value = value;
            helper->content_length.len = length;
            break;
        case HTTP_HDR_CONTENT:
            p += sizeof("Content") - 1;
            goto retry;
        case HTTP_HDR_ACCEPT:
            p += sizeof("Accept") - 1;
            goto retry;
        }
did_not_match:
        p = memchr(p, '\n', (size_t)(buffer_end - p));
        if (!p)
            break;
    }

end:
    return buffer;
}

#undef CASE_HEADER
#undef MATCH_HEADER

static void
parse_if_modified_since(lwan_request_t *request, lwan_request_parse_t *helper)
{
    if (UNLIKELY(!helper->if_modified_since.len))
        return;

    struct tm t;
    char *processed = strptime(helper->if_modified_since.value,
                "%a, %d %b %Y %H:%M:%S GMT", &t);

    if (UNLIKELY(!processed))
        return;
    if (UNLIKELY(*processed))
        return;

    request->header.if_modified_since = timegm(&t);
}

static void
parse_range(lwan_request_t *request, lwan_request_parse_t *helper)
{
    if (UNLIKELY(helper->range.len <= (sizeof("bytes=") - 1)))
        return;

    char *range = helper->range.value;
    if (UNLIKELY(strncmp(range, "bytes=", sizeof("bytes=") - 1)))
        return;

    range += sizeof("bytes=") - 1;
    off_t from, to;

    if (sscanf(range, "%"PRIu64"-%"PRIu64, &from, &to) == 2) {
        request->header.range.from = from;
        request->header.range.to = to;
    } else if (sscanf(range, "-%"PRIu64, &to) == 1) {
        request->header.range.from = 0;
        request->header.range.to = to;
    } else if (sscanf(range, "%"PRIu64"-", &from) == 1) {
        request->header.range.from = from;
        request->header.range.to = -1;
    } else {
        request->header.range.from = -1;
        request->header.range.to = -1;
    }
}

static void
parse_accept_encoding(lwan_request_t *request, lwan_request_parse_t *helper)
{
    if (!helper->accept_encoding.len)
        return;

    enum {
        ENCODING_DEFL1 = MULTICHAR_CONSTANT('d','e','f','l'),
        ENCODING_DEFL2 = MULTICHAR_CONSTANT(' ','d','e','f')
    };

    for (char *p = helper->accept_encoding.value; p && *p; p++) {
        STRING_SWITCH(p) {
        case ENCODING_DEFL1:
        case ENCODING_DEFL2:
            request->flags |= REQUEST_ACCEPT_DEFLATE;
            return;
        }

        if (!(p = strchr(p, ',')))
            break;
    }
}

static ALWAYS_INLINE unsigned long
has_zero_byte(unsigned long n)
{
    return ((n - 0x01010101UL) & ~n) & 0x80808080UL;
}

static ALWAYS_INLINE unsigned long
is_space(char ch)
{
    return has_zero_byte((0x1010101UL * (unsigned long)ch) ^ 0x090a0d20UL);
}

static ALWAYS_INLINE char *
ignore_leading_whitespace(char *buffer)
{
    while (*buffer && is_space(*buffer))
        buffer++;
    return buffer;
}

static ALWAYS_INLINE void
compute_keep_alive_flag(lwan_request_t *request, lwan_request_parse_t *helper)
{
    bool is_keep_alive;
    if (request->flags & REQUEST_IS_HTTP_1_0)
        is_keep_alive = (helper->connection == 'k');
    else
        is_keep_alive = (helper->connection != 'c');
    if (is_keep_alive)
        request->conn->flags |= CONN_KEEP_ALIVE;
    else
        request->conn->flags &= ~CONN_KEEP_ALIVE;
}

static lwan_http_status_t read_from_request_socket(lwan_request_t *request,
    lwan_value_t *buffer, const size_t buffer_size,
    lwan_read_finalizer_t (*finalizer)(size_t total_read, size_t buffer_size, lwan_value_t *buffer))
{
    ssize_t n;
    size_t total_read = 0;
    int packets_remaining = 16;

    for (; packets_remaining > 0; packets_remaining--) {
        n = read(request->fd, buffer->value + total_read,
                    (size_t)(buffer_size - total_read));
        /* Client has shutdown orderly, nothing else to do; kill coro */
        if (UNLIKELY(n == 0)) {
            coro_yield(request->conn->coro, CONN_CORO_ABORT);
            __builtin_unreachable();
        }

        if (UNLIKELY(n < 0)) {
            switch (errno) {
            case EAGAIN:
            case EINTR:
yield_and_read_again:
                /* Toggle write events so the scheduler thinks we're in a
                 * "can read" state (and thus resumable). */
                request->conn->flags ^= CONN_WRITE_EVENTS;
                /* Yield 1 so the scheduler doesn't kill the coroutine. */
                coro_yield(request->conn->coro, CONN_CORO_MAY_RESUME);
                /* Put the WRITE_EVENTS flag back on. */
                request->conn->flags ^= CONN_WRITE_EVENTS;
                /* We can probably read again, so try it */
                continue;
            }

            /* Unexpected error before reading anything */
            if (UNLIKELY(!total_read))
                return HTTP_BAD_REQUEST;

            /* Unexpected error, kill coro */
            coro_yield(request->conn->coro, CONN_CORO_ABORT);
            __builtin_unreachable();
        }

        total_read += (size_t)n;
        buffer->value[total_read] = '\0';

        switch (finalizer(total_read, buffer_size, buffer)) {
        case FINALIZER_DONE:
            buffer->len = (size_t)total_read;
            return HTTP_OK;
        case FINALIZER_TRY_AGAIN:
            continue;
        case FINALIZER_YIELD_TRY_AGAIN:
            goto yield_and_read_again;
        case FINALIZER_ERROR_TOO_LARGE:
            return HTTP_TOO_LARGE;
        }
    }

    /*
     * packets_remaining reached zero: return a timeout error to avoid clients
     * being intentionally slow and hogging the server.
     *
     * FIXME: What should be the best approach? Error with 408, or give some more
     * time by fiddling with the connection's time to die?
     */
    return HTTP_TIMEOUT;
}

static lwan_read_finalizer_t read_request_finalizer(size_t total_read,
    size_t buffer_size, lwan_value_t *buffer)
{
    if (UNLIKELY(total_read < 4))
        return FINALIZER_YIELD_TRY_AGAIN;

    if (UNLIKELY(total_read == buffer_size))
        return FINALIZER_ERROR_TOO_LARGE;

    if (LIKELY(!memcmp(buffer->value + total_read - 4, "\r\n\r\n", 4)))
        return FINALIZER_DONE;

    char *post_data_separator = strrchr(buffer->value, '\n');
    if (post_data_separator) {
        if (LIKELY(!memcmp(post_data_separator - 3, "\r\n\r", 3)))
            return FINALIZER_DONE;
    }

    return FINALIZER_TRY_AGAIN;
}

static ALWAYS_INLINE lwan_http_status_t
read_request(lwan_request_t *request, lwan_request_parse_t *helper)
{
    return read_from_request_socket(request, &helper->buffer,
                        DEFAULT_BUFFER_SIZE, read_request_finalizer);
}

static lwan_read_finalizer_t
read_post_data_finalizer(size_t total_read, size_t buffer_size,
    lwan_value_t *buffer __attribute__((unused)))
{
    if (LIKELY(total_read == buffer_size))
        return FINALIZER_DONE;
    return FINALIZER_YIELD_TRY_AGAIN;
}

static lwan_http_status_t
read_post_data(lwan_request_t *request, lwan_request_parse_t *helper, char
            *buffer)
{
    long parsed_length;

    if (!helper->content_length.value)
        return HTTP_BAD_REQUEST;
    parsed_length = parse_long(helper->content_length.value, DEFAULT_BUFFER_SIZE);
    if (UNLIKELY(parsed_length > DEFAULT_BUFFER_SIZE))
        return HTTP_TOO_LARGE;
    if (UNLIKELY(parsed_length < 0))
        return HTTP_BAD_REQUEST;

    size_t post_data_size = (size_t)parsed_length;
    size_t curr_post_data_len =
                    (helper->buffer.len - (size_t)(buffer - helper->buffer.value));
    if (curr_post_data_len == post_data_size) {
        helper->post_data.value = buffer;
        helper->post_data.len = (size_t)post_data_size;

        return HTTP_OK;
    }

    helper->post_data.value = coro_malloc(request->conn->coro, (size_t)post_data_size);
    if (!helper->post_data.value)
        return HTTP_INTERNAL_ERROR;

    memcpy(helper->post_data.value, buffer, (size_t)curr_post_data_len);
    helper->post_data.len = (size_t)curr_post_data_len;
    helper->post_data.value += curr_post_data_len;

    lwan_http_status_t status = read_from_request_socket(request,
                        &helper->post_data,
                        post_data_size - curr_post_data_len,
                        read_post_data_finalizer);
    if (status != HTTP_OK)
        return status;

    helper->post_data.value -= curr_post_data_len;
    return HTTP_OK;
}

static lwan_http_status_t
parse_http_request(lwan_request_t *request, lwan_request_parse_t *helper)
{
    char *buffer;

    buffer = ignore_leading_whitespace(helper->buffer.value);
    if (UNLIKELY(!*buffer))
        return HTTP_BAD_REQUEST;

    buffer = identify_http_method(request, buffer);
    if (UNLIKELY(!buffer))
        return HTTP_NOT_ALLOWED;

    buffer = identify_http_path(request, buffer, helper);
    if (UNLIKELY(!buffer))
        return HTTP_BAD_REQUEST;

    buffer = parse_headers(helper, buffer, helper->buffer.value + helper->buffer.len);
    if (UNLIKELY(!buffer))
        return HTTP_BAD_REQUEST;

    size_t decoded_len = url_decode(request->url.value);
    if (UNLIKELY(!decoded_len))
        return HTTP_BAD_REQUEST;
    request->original_url.len = request->url.len = decoded_len;

    compute_keep_alive_flag(request, helper);

    if (request->flags & REQUEST_METHOD_POST) {
        lwan_http_status_t status = read_post_data(request, helper, buffer);
        if (UNLIKELY(status != HTTP_OK))
            return status;
    }

    return HTTP_OK;
}

static lwan_http_status_t
prepare_for_response(lwan_url_map_t *url_map,
                      lwan_request_t *request,
                      lwan_request_parse_t *helper)
{
    if (url_map->flags & HANDLER_PARSE_QUERY_STRING)
        parse_query_string(request, helper);

    if (url_map->flags & HANDLER_PARSE_IF_MODIFIED_SINCE)
        parse_if_modified_since(request, helper);

    if (url_map->flags & HANDLER_PARSE_RANGE)
        parse_range(request, helper);

    if (url_map->flags & HANDLER_PARSE_ACCEPT_ENCODING)
        parse_accept_encoding(request, helper);

    if (request->flags & REQUEST_METHOD_POST) {
        if (url_map->flags & HANDLER_PARSE_POST_DATA)
            parse_post_data(request, helper);
        else
            return HTTP_NOT_ALLOWED;
    }

    if (url_map->flags & HANDLER_MUST_AUTHORIZE) {
        if (!lwan_http_authorize(request,
                        &helper->authorization,
                        url_map->authorization.realm,
                        url_map->authorization.password_file))
            return HTTP_NOT_AUTHORIZED;
    }

    if (url_map->flags & HANDLER_REMOVE_LEADING_SLASH) {
        while (*request->url.value == '/' && request->url.len > 0) {
            ++request->url.value;
            --request->url.len;
        }
    }

    return HTTP_OK;
}

void
lwan_process_request(lwan_t *l, lwan_request_t *request)
{
    lwan_http_status_t status;
    lwan_url_map_t *url_map;
    char buffer[DEFAULT_BUFFER_SIZE];
    lwan_request_parse_t helper = {
        .buffer = {
            .value = buffer,
            .len = 0
        }
    };

    status = read_request(request, &helper);
    if (UNLIKELY(status != HTTP_OK)) {
        /* If status is anything but a bad request at this point, give up. */
        if (status != HTTP_BAD_REQUEST)
            lwan_default_response(request, status);

        return;
    }

    status = parse_http_request(request, &helper);
    if (UNLIKELY(status != HTTP_OK)) {
        lwan_default_response(request, status);
        return;
    }

    url_map = lwan_trie_lookup_prefix(l->url_map_trie, request->url.value);
    if (UNLIKELY(!url_map)) {
        lwan_default_response(request, HTTP_NOT_FOUND);
        return;
    }

    request->url.value += url_map->prefix_len;
    request->url.len -= url_map->prefix_len;

    status = prepare_for_response(url_map, request, &helper);
    if (UNLIKELY(status != HTTP_OK)) {
        lwan_default_response(request, status);
        return;
    }

    status = url_map->handler(request, &request->response, url_map->data);
    lwan_response(request, status);
}

static const char *
value_array_bsearch(lwan_key_value_t *base, const size_t len, const char *key)
{
    if (UNLIKELY(!len))
        return NULL;

    size_t lower_bound = 0;
    size_t upper_bound = len;
    size_t key_len = strlen(key);

    while (lower_bound < upper_bound) {
        /* lower_bound + upper_bound will never overflow */
        size_t idx = (lower_bound + upper_bound) / 2;
        lwan_key_value_t *ptr = base + idx;
        int cmp = strncmp(key, ptr->key, key_len);
        if (LIKELY(!cmp))
            return ptr->value;
        if (cmp > 0)
            lower_bound = idx + 1;
        else
            upper_bound = idx;
    }

    return NULL;
}

ALWAYS_INLINE const char *
lwan_request_get_query_param(lwan_request_t *request, const char *key)
{
    return value_array_bsearch(request->query_params.base,
                                            request->query_params.len, key);
}

ALWAYS_INLINE const char *
lwan_request_get_post_param(lwan_request_t *request, const char *key)
{
    return value_array_bsearch(request->post_data.base,
                                            request->post_data.len, key);
}

ALWAYS_INLINE int
lwan_connection_get_fd(lwan_connection_t *conn)
{
    return (int)(ptrdiff_t)(conn - conn->thread->lwan->conns);
}

const char *
lwan_request_get_remote_address(lwan_request_t *request,
            char buffer[static INET6_ADDRSTRLEN])
{
    struct sockaddr_storage sock_addr = { 0 };
    socklen_t sock_len = sizeof(struct sockaddr_storage);
    if (UNLIKELY(getpeername(request->fd, (struct sockaddr *)&sock_addr, &sock_len) < 0))
        return NULL;

    if (sock_addr.ss_family == AF_INET)
        return inet_ntop(AF_INET, &((struct sockaddr_in *)&sock_addr)->sin_addr,
                         buffer, INET6_ADDRSTRLEN);
    return inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&sock_addr)->sin6_addr,
                     buffer, INET6_ADDRSTRLEN);
}
