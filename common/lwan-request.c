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

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "lwan.h"

enum {
    HTTP_STR_GET  = MULTICHAR_CONSTANT('G','E','T',' '),
    HTTP_STR_HEAD = MULTICHAR_CONSTANT('H','E','A','D'),
} lwan_http_method_str_t;

enum {
    HTTP_HDR_CONNECTION        = MULTICHAR_CONSTANT_L('C','o','n','n'),
    HTTP_HDR_RANGE             = MULTICHAR_CONSTANT_L('R','a','n','g'),
    HTTP_HDR_IF_MODIFIED_SINCE = MULTICHAR_CONSTANT_L('I','f','-','M'),
    HTTP_HDR_ACCEPT            = MULTICHAR_CONSTANT_L('A','c','c','e'),
    HTTP_HDR_ENCODING          = MULTICHAR_CONSTANT_L('-','E','n','c')
} lwan_http_header_str_t;

typedef struct lwan_request_parse_t_	lwan_request_parse_t;

struct lwan_request_parse_t_ {
    lwan_value_t buffer;
    lwan_value_t query_string;
    lwan_value_t if_modified_since;
    lwan_value_t range;
    lwan_value_t accept_encoding;
    lwan_value_t fragment;
    char connection;
};

static char _decode_hex_digit(char ch) __attribute__((pure));
static bool _is_hex_digit(char ch) __attribute__((pure));
static unsigned long _has_zero_byte(unsigned long n) __attribute__((pure));
static unsigned long _is_space(char ch) __attribute__((pure));
static char *_ignore_leading_whitespace(char *buffer) __attribute__((pure));

static ALWAYS_INLINE char *
_identify_http_method(lwan_request_t *request, char *buffer)
{
    STRING_SWITCH(buffer) {
    case HTTP_STR_GET:
        request->flags |= REQUEST_METHOD_GET;
        return buffer + 4;
    case HTTP_STR_HEAD:
        request->flags |= REQUEST_METHOD_HEAD;
        return buffer + 5;
    }
    return NULL;
}

static ALWAYS_INLINE char
_decode_hex_digit(char ch)
{
    return (ch <= '9') ? ch - '0' : (ch & 7) + 9;
}

static ALWAYS_INLINE bool
_is_hex_digit(char ch)
{
    return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F');
}

static size_t
_url_decode(char *str)
{
    if (UNLIKELY(!str))
        return 0;

    char *ch, *decoded;
    for (decoded = ch = str; *ch; ch++) {
        if (*ch == '%' && LIKELY(_is_hex_digit(ch[1]) && _is_hex_digit(ch[2]))) {
            char tmp = _decode_hex_digit(ch[1]) << 4 | _decode_hex_digit(ch[2]);
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
    return decoded - str;
}

static int
_key_value_compare_qsort_key(const void *a, const void *b)
{
    return strcmp(((lwan_key_value_t *)a)->key, ((lwan_key_value_t *)b)->key);
}

#define DECODE_AND_ADD() \
    do { \
        if (LIKELY(_url_decode(key))) { \
            qs[values].key = key; \
            if (LIKELY(_url_decode(value))) \
                qs[values].value = value; \
            else \
                qs[values].value = ""; \
            ++values; \
            if (UNLIKELY(values >= N_ELEMENTS(qs))) \
                goto oom; \
        } \
    } while(0)

static void
_parse_query_string(lwan_request_t *request, lwan_request_parse_t *helper)
{
    if (!helper->query_string.value)
        return;

    char *key = helper->query_string.value;
    char *value = NULL;
    char *ch;
    size_t values = 0;
    lwan_key_value_t qs[256];

    for (ch = helper->query_string.value; *ch; ch++) {
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
    qs[values].key = qs[values].value = NULL;

    lwan_key_value_t *kv = malloc((1 + values) * sizeof(lwan_key_value_t));
    if (LIKELY(kv)) {
        qsort(qs, values, sizeof(lwan_key_value_t), _key_value_compare_qsort_key);
        request->query_params.base = memcpy(kv, qs, (1 + values) * sizeof(lwan_key_value_t));
        request->query_params.len = values;
    }
}

#undef DECODE_AND_ADD

static ALWAYS_INLINE char *
_identify_http_path(lwan_request_t *request, char *buffer,
            lwan_request_parse_t *helper)
{
    char *end_of_line = memchr(buffer, '\r', helper->buffer.len - (buffer - helper->buffer.value));
    if (!end_of_line)
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
    request->url.len = space - buffer;

    /* Most of the time, fragments are small -- so search backwards */
    char *fragment = memrchr(buffer, '#', request->url.len);
    if (fragment) {
        *fragment = '\0';
        helper->fragment.value = fragment + 1;
        helper->fragment.len = space - fragment - 1;
        request->url.len -= helper->fragment.len + 1;
    }

    /* Most of the time, query string values are larger than the URL, so
       search from the beginning */
    char *query_string = memchr(buffer, '?', request->url.len);
    if (query_string) {
        *query_string = '\0';
        helper->query_string.value = query_string + 1;
        helper->query_string.len = (fragment ? fragment : space) - query_string - 1;
        request->url.len -= helper->query_string.len + 1;
    }

    request->original_url.value = buffer;
    request->original_url.len = space - buffer;

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
          length = end - value - 1; \
          if (UNLIKELY(*p != '\n')) \
            goto did_not_match; \
        } else goto did_not_match;      /* couldn't find line end */ \
  } while (0)

#define CASE_HEADER(hdr_const,hdr_name) \
    case hdr_const: MATCH_HEADER(hdr_name);

static ALWAYS_INLINE char *
_parse_headers(lwan_request_parse_t *helper, char *buffer, char *buffer_end)
{
    char *p;

    if (UNLIKELY(!buffer))
        return NULL;

    for (p = buffer; *p; buffer = ++p) {
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
        CASE_HEADER(HTTP_HDR_ENCODING, "-Encoding")
            helper->accept_encoding.value = value;
            helper->accept_encoding.len = length;
            break;
        case HTTP_HDR_ACCEPT:
            p += sizeof("Accept") - 1;
            goto retry;
        }
did_not_match:
        p = memchr(p, '\n', buffer_end - p);
        if (UNLIKELY(!p))
            return NULL;
    }

end:
    return buffer;
}

#undef CASE_HEADER
#undef MATCH_HEADER

static ALWAYS_INLINE void
_parse_if_modified_since(lwan_request_t *request, lwan_request_parse_t *helper)
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

static ALWAYS_INLINE void
_parse_range(lwan_request_t *request, lwan_request_parse_t *helper)
{
    if (helper->range.len <= (sizeof("bytes=") - 1))
        return;

    char *range = helper->range.value;
    if (UNLIKELY(strncmp(range, "bytes=", sizeof("bytes=") - 1)))
        return;

    range += sizeof("bytes=") - 1;
    off_t from, to;

    if (sscanf(range, "%lu-%lu", &from, &to) == 2) {
        request->header.range.from = from;
        request->header.range.to = to;
    } else if (sscanf(range, "-%lu", &to) == 1) {
        request->header.range.from = 0;
        request->header.range.to = to;
    } else if (sscanf(range, "%lu-", &from) == 1) {
        request->header.range.from = from;
        request->header.range.to = -1;
    } else {
        request->header.range.from = -1;
        request->header.range.to = -1;
    }
}

static ALWAYS_INLINE void
_parse_accept_encoding(lwan_request_t *request, lwan_request_parse_t *helper)
{
    char *p;

    if (!helper->accept_encoding.len)
        return;

    enum {
        ENCODING_DEFL1 = MULTICHAR_CONSTANT('d','e','f','l'),
        ENCODING_DEFL2 = MULTICHAR_CONSTANT(' ','d','e','f')
    };

    for (p = helper->accept_encoding.value; p && *p; p++) {
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
_has_zero_byte(unsigned long n)
{
    return ((n - 0x01010101UL) & ~n) & 0x80808080UL;
}

static ALWAYS_INLINE unsigned long
_is_space(char ch)
{
    return _has_zero_byte((0x1010101 * ch) ^ 0x090a0d20);
}

static ALWAYS_INLINE char *
_ignore_leading_whitespace(char *buffer)
{
    while (*buffer && _is_space(*buffer))
        buffer++;
    return buffer;
}

static ALWAYS_INLINE void
_compute_keep_alive_flag(lwan_request_t *request, lwan_request_parse_t *helper)
{
    bool is_keep_alive;
    if (!(request->flags & REQUEST_IS_HTTP_1_0))
        is_keep_alive = (helper->connection != 'c');
    else
        is_keep_alive = (helper->connection == 'k');
    if (is_keep_alive)
        request->conn->flags |= CONN_REQUEST_IS_KEEP_ALIVE;
    else
        request->conn->flags &= ~CONN_REQUEST_IS_KEEP_ALIVE;
}

static ALWAYS_INLINE lwan_http_status_t
_parse_http_request(lwan_request_t *request, lwan_request_parse_t *helper)
{
    char *buffer;

    buffer = _ignore_leading_whitespace(helper->buffer.value);
    if (UNLIKELY(!*buffer))
        return HTTP_BAD_REQUEST;

    buffer = _identify_http_method(request, buffer);
    if (UNLIKELY(!buffer))
        return HTTP_NOT_ALLOWED;

    buffer = _identify_http_path(request, buffer, helper);
    if (UNLIKELY(!buffer))
        return HTTP_BAD_REQUEST;

    buffer = _parse_headers(helper, buffer, helper->buffer.value + helper->buffer.len);
    if (UNLIKELY(!buffer))
        return HTTP_BAD_REQUEST;

    size_t decoded_len = _url_decode(request->url.value);
    if (UNLIKELY(!decoded_len))
        return HTTP_BAD_REQUEST;
    request->original_url.len = request->url.len = decoded_len;

    _compute_keep_alive_flag(request, helper);

    return HTTP_OK;
}

static ALWAYS_INLINE lwan_http_status_t
_read_request(lwan_request_t *request, lwan_request_parse_t *helper)
{
    ssize_t n;
    ssize_t total_read = 0;

    do {
read_again:
        n = read(request->conn->fd, helper->buffer.value + total_read,
                    DEFAULT_BUFFER_SIZE - total_read);
        /* Client has shutdown orderly, nothing else to do; kill coro */
        if (UNLIKELY(n == 0)) {
            coro_yield(request->conn->coro, CONN_CORO_ABORT);
            ASSERT_NOT_REACHED();
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
                goto read_again;
            }

            if (!total_read) /* Unexpected error before reading anything */
                return HTTP_BAD_REQUEST;

            /* Unexpected error, kill coro */
            coro_yield(request->conn->coro, CONN_CORO_ABORT);
            ASSERT_NOT_REACHED();
        }

        total_read += n;
        if (UNLIKELY(total_read < 4)) /* Need space for \r\n\r\n at least */
            goto yield_and_read_again;
        if (UNLIKELY(total_read == DEFAULT_BUFFER_SIZE))
            return HTTP_TOO_LARGE;

        helper->buffer.value[total_read] = '\0';
    } while (memcmp(helper->buffer.value + total_read - 4, "\r\n\r\n", 4));

    helper->buffer.len = total_read;
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

    status = _read_request(request, &helper);
    if (UNLIKELY(status != HTTP_OK)) {
        /* If status is anything but a bad request at this point, give up. */
        if (status != HTTP_BAD_REQUEST)
            lwan_default_response(request, status);

        return;
    }

    status = _parse_http_request(request, &helper);
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

    if (url_map->flags & HANDLER_PARSE_QUERY_STRING)
        _parse_query_string(request, &helper);
    if (url_map->flags & HANDLER_PARSE_IF_MODIFIED_SINCE)
        _parse_if_modified_since(request, &helper);
    if (url_map->flags & HANDLER_PARSE_RANGE)
        _parse_range(request, &helper);
    if (url_map->flags & HANDLER_PARSE_ACCEPT_ENCODING)
        _parse_accept_encoding(request, &helper);

    status = url_map->callback(request, &request->response, url_map->data);
    lwan_response(request, status);
}

const char *
lwan_request_get_query_param(lwan_request_t *request, const char *key)
{
    if (UNLIKELY(!request->query_params.len))
        return NULL;

    size_t lower_bound = 0;
    size_t upper_bound = request->query_params.len;
    size_t key_len = strlen(key);
    lwan_key_value_t *base = request->query_params.base;

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

const char *
lwan_request_get_remote_address(lwan_request_t *request,
            char *buffer)
{
    /* The definition of inet_ntoa() in the standard is not thread-safe. The
     * glibc version uses a static buffer stored in the TLS to make do, but
     * in the end, inet_ntoa() is actually a call to snprintf().  Call it
     * ourselves, using a user-supplied buffer.  This should be a tiny wee
     * little bit faster.  */
    unsigned char *octets = (unsigned char *) &request->conn->remote_address;
    if (UNLIKELY(snprintf(buffer, INET_ADDRSTRLEN, "%d.%d.%d.%d",
                octets[0], octets[1], octets[2], octets[3]) < 0))
        return NULL;
    return buffer;
}
