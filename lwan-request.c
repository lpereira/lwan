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
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "lwan.h"
#include "int-to-str.h"

static char _decode_hex_digit(char ch) __attribute__((pure));
static bool _is_hex_digit(char ch) __attribute__((pure));
static unsigned long _has_zero_byte(unsigned long n) __attribute__((pure));
static unsigned long _is_space(char ch) __attribute__((pure));
static char *_ignore_leading_whitespace(char *buffer) __attribute__((pure));

static const char* const _http_versions[] = {
    [HTTP_1_0] = "1.0",
    [HTTP_1_1] = "1.1"
};

static ALWAYS_INLINE char *
_identify_http_method(lwan_request_t *request, char *buffer)
{
    STRING_SWITCH(buffer) {
    case HTTP_STR_GET:
        request->method = HTTP_GET;
        return buffer + 4;
    case HTTP_STR_HEAD:
        request->method = HTTP_HEAD;
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
    if (!str)
        return 0;

    char *ch, *decoded;
    for (decoded = ch = str; *ch; ch++) {
        if (*ch == '%' && LIKELY(_is_hex_digit(ch[1]) && _is_hex_digit(ch[2]))) {
            *decoded++ = _decode_hex_digit(ch[1]) << 4 | _decode_hex_digit(ch[2]);
            ch += 2;
        } else if (*ch == '+')
            *decoded++ = ' ';
        else
            *decoded++ = *ch;
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
_parse_query_string(lwan_request_t *request)
{
    if (!request->query_string.value)
        return;

    char *key = request->query_string.value;
    char *value = NULL;
    char *ch;
    size_t values = 0;
    lwan_key_value_t qs[256];

    for (ch = request->query_string.value; *ch; ch++) {
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
        request->query_string_kv.base = memcpy(kv, qs, (1 + values) * sizeof(lwan_key_value_t));
        request->query_string_kv.len = values;
    }
}

#undef DECODE_AND_ADD

static ALWAYS_INLINE char *
_identify_http_path(lwan_request_t *request, char *buffer, size_t limit)
{
    char *end_of_line = memchr(buffer, '\r', limit);
    if (!end_of_line)
        return NULL;
    *end_of_line = '\0';

    char *space = end_of_line - sizeof("HTTP/X.X");
    if (UNLIKELY(*(space + 1) != 'H')) /* assume HTTP/X.Y */
        return NULL;
    *space = '\0';

    if (LIKELY(*(space + 6) == '1'))
        request->http_version = *(space + 8) == '0' ? HTTP_1_0 : HTTP_1_1;
    else
        return NULL;

    if (UNLIKELY(*buffer != '/'))
        return NULL;

    request->url.value = buffer;
    request->url.len = space - buffer;

    /* Most of the time, fragments are small -- so search backwards */
    char *fragment = memrchr(buffer, '#', request->url.len);
    if (fragment) {
        *fragment = '\0';
        request->fragment.value = fragment + 1;
        request->fragment.len = space - fragment - 1;
        request->url.len -= request->fragment.len + 1;
    }

    /* Most of the time, query string values are larger than the URL, so
       search from the beginning */
    char *query_string = memchr(buffer, '?', request->url.len);
    if (query_string) {
        *query_string = '\0';
        request->query_string.value = query_string + 1;
        request->query_string.len = (fragment ? fragment : space) - query_string - 1;
        request->url.len -= request->query_string.len + 1;
    }

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
_parse_headers(lwan_request_t *request, char *buffer, char *buffer_end)
{
    char *p;

    for (p = buffer; p && *p; buffer = ++p) {
        char *value;
        size_t length;

retry:
        if ((p + sizeof(int32_t)) >= buffer_end)
            break;

        STRING_SWITCH_L(p) {
        CASE_HEADER(HTTP_HDR_CONNECTION, "Connection")
            request->header.connection = (*value | 0x20);
            break;
        CASE_HEADER(HTTP_HDR_HOST, "Host")
            /* Virtual hosts are not supported yet; ignore */
            break;
        CASE_HEADER(HTTP_HDR_IF_MODIFIED_SINCE, "If-Modified-Since")
            request->if_modified_since.value = value;
            request->if_modified_since.len = length;
            break;
        CASE_HEADER(HTTP_HDR_RANGE, "Range")
            request->range.value = value;
            request->range.len = length;
            break;
        CASE_HEADER(HTTP_HDR_REFERER, "Referer")
            /* Ignore */
            break;
        CASE_HEADER(HTTP_HDR_COOKIE, "Cookie")
            /* Ignore */
            break;
        CASE_HEADER(HTTP_HDR_ENCODING, "-Encoding")
            request->accept_encoding.value = value;
            request->accept_encoding.len = length;
            break;
        case HTTP_HDR_ACCEPT:
            p += sizeof("Accept") - 1;
            goto retry;
        }
did_not_match:
        p = memchr(p, '\n', buffer_end - p);
    }

end:
    return buffer;
}

#undef CASE_HEADER
#undef MATCH_HEADER

static ALWAYS_INLINE void
_parse_if_modified_since(lwan_request_t *request)
{
    if (UNLIKELY(!request->if_modified_since.len))
        return;

    struct tm t;
    char *processed = strptime(request->if_modified_since.value, "%a, %d %b %Y %H:%M:%S GMT", &t);

    if (UNLIKELY(!processed))
        return;
    if (UNLIKELY(*processed))
        return;

    request->header.if_modified_since = timegm(&t);
}

static ALWAYS_INLINE void
_parse_range(lwan_request_t *request)
{
    if (request->range.len <= (sizeof("bytes=") - 1))
        return;

    char *range = request->range.value;
    if (UNLIKELY(strncmp(range, "bytes=", sizeof("bytes=") - 1)))
        return;

    range += sizeof("bytes=") - 1;
    off_t from, to;

    if (sscanf(range, "%ld-%ld", &from, &to) == 2) {
        request->header.range.from = from;
        request->header.range.to = to;
    } else if (sscanf(range, "-%ld", &to) == 1) {
        request->header.range.from = 0;
        request->header.range.to = to;
    } else if (sscanf(range, "%ld-", &from) == 1) {
        request->header.range.from = from;
        request->header.range.to = -1;
    } else {
        request->header.range.from = -1;
        request->header.range.to = -1;
    }
}

static ALWAYS_INLINE void
_parse_accept_encoding(lwan_request_t *request)
{
    char *p;

    if (!request->accept_encoding.len)
        return;

    enum {
        ENCODING_DEFL1 = MULTICHAR_CONSTANT('d','e','f','l'),
        ENCODING_DEFL2 = MULTICHAR_CONSTANT(' ','d','e','f')
    };

    for (p = request->accept_encoding.value; p && *p;) {
        STRING_SWITCH(p) {
        case ENCODING_DEFL1:
        case ENCODING_DEFL2:
            request->header.accept_encoding.deflate = true;
            return;
        }

        if (!(p = strchr(p, ',')))
            break;

        p++;
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
_compute_flags(lwan_request_t *request)
{
    if (request->http_version == HTTP_1_1)
        request->flags.is_keep_alive = (request->header.connection != 'c');
    else
        request->flags.is_keep_alive = (request->header.connection == 'k');
}

bool
lwan_process_request(lwan_request_t *request)
{
    lwan_url_map_t *url_map;
    char *p_buffer;
    size_t bytes_read;

    switch (bytes_read = read(request->fd, request->buffer, sizeof(request->buffer))) {
    case 0:
        return false;
    case -1:
        perror("read");
        return false;
    case sizeof(request->buffer):
        return lwan_default_response(request, HTTP_TOO_LARGE);
    }

    request->buffer[bytes_read] = '\0';

    p_buffer = _ignore_leading_whitespace(request->buffer);
    if (UNLIKELY(!*p_buffer))
        return lwan_default_response(request, HTTP_BAD_REQUEST);

    p_buffer = _identify_http_method(request, p_buffer);
    if (UNLIKELY(!p_buffer))
        return lwan_default_response(request, HTTP_NOT_ALLOWED);

    p_buffer = _identify_http_path(request, p_buffer, bytes_read);
    if (UNLIKELY(!p_buffer))
        return lwan_default_response(request, HTTP_BAD_REQUEST);

    p_buffer = _parse_headers(request, p_buffer, request->buffer + bytes_read);
    if (UNLIKELY(!p_buffer))
        return lwan_default_response(request, HTTP_BAD_REQUEST);

    _compute_flags(request);

    if ((url_map = lwan_trie_lookup_prefix(request->lwan->url_map_trie, request->url.value))) {
        request->url.value += url_map->prefix_len;
        request->url.len -= url_map->prefix_len;

        if (url_map->flags & HANDLER_PARSE_QUERY_STRING)
            _parse_query_string(request);
        if (url_map->flags & HANDLER_PARSE_IF_MODIFIED_SINCE)
            _parse_if_modified_since(request);
        if (url_map->flags & HANDLER_PARSE_RANGE)
            _parse_range(request);
        if (url_map->flags & HANDLER_PARSE_ACCEPT_ENCODING)
            _parse_accept_encoding(request);

        return lwan_response(request, url_map->callback(request, &request->response, url_map->data));
    }

    return lwan_default_response(request, HTTP_NOT_FOUND);
}


#define RETURN_0_ON_OVERFLOW(len_) \
    if (UNLIKELY(p_headers + (len_) >= p_headers_end)) return 0

#define APPEND_STRING_LEN(const_str_,len_) \
    do { \
        RETURN_0_ON_OVERFLOW(len_); \
        p_headers = mempcpy(p_headers, (const_str_), (len_)); \
    } while(0)

#define APPEND_STRING(str_) \
    do { \
        len = strlen(str_); \
        RETURN_0_ON_OVERFLOW(len); \
        p_headers = mempcpy(p_headers, (str_), len); \
    } while(0)

#define APPEND_CHAR(value_) \
    do { \
        RETURN_0_ON_OVERFLOW(1); \
        *p_headers++ = (value_); \
    } while(0)

#define APPEND_CHAR_NOCHECK(value_) \
    *p_headers++ = (value_)

#define APPEND_INT8(value_) \
    do { \
        RETURN_0_ON_OVERFLOW(3); \
        APPEND_CHAR_NOCHECK(((value_) / 100) % 10 + '0'); \
        APPEND_CHAR_NOCHECK(((value_) / 10) % 10 + '0'); \
        APPEND_CHAR_NOCHECK((value_) % 10 + '0'); \
    } while(0)

#define APPEND_UINT(value_) \
    do { \
        char *tmp = uint_to_string((value_), buffer, &len); \
        RETURN_0_ON_OVERFLOW(len); \
        APPEND_STRING_LEN(tmp, len); \
    } while(0)

#define APPEND_CONSTANT(const_str_) \
    APPEND_STRING_LEN((const_str_), sizeof(const_str_) - 1)

ALWAYS_INLINE size_t
lwan_prepare_response_header(lwan_request_t *request, lwan_http_status_t status, char headers[], size_t headers_buf_size)
{
    char *p_headers;
    char *p_headers_end = headers + headers_buf_size;
    char buffer[32];
    size_t len;

    p_headers = headers;

    APPEND_CONSTANT("HTTP/");
    APPEND_STRING_LEN(_http_versions[request->http_version], 3);
    APPEND_CHAR(' ');
    APPEND_INT8(status);
    APPEND_CHAR(' ');
    APPEND_STRING(lwan_http_status_as_string(status));
    APPEND_CONSTANT("\r\nContent-Length: ");
    if (request->response.stream.callback)
        APPEND_UINT(request->response.content_length);
    else
        APPEND_UINT(strbuf_get_length(request->response.buffer));
    APPEND_CONSTANT("\r\nContent-Type: ");
    APPEND_STRING(request->response.mime_type);
    if (request->flags.is_keep_alive)
        APPEND_CONSTANT("\r\nConnection: keep-alive");
    else
        APPEND_CONSTANT("\r\nConnection: close");

    if (status < HTTP_BAD_REQUEST && request->response.headers) {
        lwan_key_value_t *header;

        for (header = request->response.headers; header->key; header++) {
            APPEND_CHAR('\r');
            APPEND_CHAR('\n');
            APPEND_STRING(header->key);
            APPEND_CHAR(':');
            APPEND_CHAR(' ');
            APPEND_STRING(header->value);
        }
    }
    APPEND_CONSTANT("\r\nServer: lwan\r\n\r\n\0");

    return p_headers - headers - 1;
}

#undef APPEND_STRING_LEN
#undef APPEND_STRING
#undef APPEND_CONSTANT
#undef APPEND_CHAR
#undef APPEND_INT

const char *
lwan_request_get_query_param(lwan_request_t *request, const char *key)
{
    if (UNLIKELY(!request->query_string_kv.len))
        return NULL;

    size_t lower_bound = 0;
    size_t upper_bound = request->query_string_kv.len;
    size_t key_len = strlen(key);
    lwan_key_value_t *base = request->query_string_kv.base;

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
