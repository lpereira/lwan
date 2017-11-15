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
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "lwan-private.h"

#include "lwan-config.h"
#include "lwan-http-authorize.h"

enum lwan_read_finalizer {
    FINALIZER_DONE,
    FINALIZER_TRY_AGAIN,
    FINALIZER_YIELD_TRY_AGAIN,
    FINALIZER_ERROR_TOO_LARGE,
    FINALIZER_ERROR_TIMEOUT
};

struct request_parser_helper {
    struct lwan_value *buffer;
    char *next_request;			/* For pipelined requests */
    struct lwan_value accept_encoding;
    struct lwan_value if_modified_since;
    struct lwan_value range;
    struct lwan_value cookie;

    struct lwan_value query_string;
    struct lwan_value fragment;
    struct lwan_value content_length;
    struct lwan_value authorization;

    struct lwan_value post_data;
    struct lwan_value content_type;

    time_t error_when_time;
    int error_when_n_packets;
    int urls_rewritten;
    char connection;
};

struct proxy_header_v2 {
    uint8_t sig[12];
    uint8_t cmd_ver;
    uint8_t fam;
    uint16_t len;
    union {
        struct {
            in_addr_t src_addr;
            in_addr_t dst_addr;
            uint16_t src_port;
            uint16_t dst_port;
        } ip4;
        struct {
            struct in6_addr src_addr;
            struct in6_addr dst_addr;
            uint16_t src_port;
            uint16_t dst_port;
        } ip6;
    } addr;
};

static char decode_hex_digit(char ch) __attribute__((pure));
static char *ignore_leading_whitespace(char *buffer) __attribute__((pure));


static bool
parse_ascii_port(char *port, unsigned short *out)
{
    unsigned long parsed;
    char *end_ptr;

    errno = 0;
    parsed = strtoul(port, &end_ptr, 10);

    if (UNLIKELY(errno != 0))
        return false;

    if (UNLIKELY(*end_ptr != '\0'))
        return false;

    if (UNLIKELY((unsigned long)(unsigned short)parsed != parsed))
        return false;

    *out = htons((unsigned short)parsed);
    return true;
}

static char *
strsep_char(char *strp, char delim)
{
    char *ptr;

    if (UNLIKELY(!strp))
        return NULL;

    ptr = strchr(strp, delim);
    if (UNLIKELY(!ptr))
        return NULL;

    *ptr = '\0';
    return ptr + 1;
}

static char *
parse_proxy_protocol_v1(struct lwan_request *request, char *buffer)
{
    static const size_t line_size = 108;
    char *end, *protocol, *src_addr, *dst_addr, *src_port, *dst_port;
    unsigned int size;
    struct lwan_proxy *const proxy = request->proxy;

    end = memchr(buffer, '\r', line_size);
    if (UNLIKELY(!end || end[1] != '\n'))
        return NULL;
    *end = '\0';
    size = (unsigned int) (end + 2 - buffer);

    protocol = buffer + sizeof("PROXY ") - 1;
    src_addr = strsep_char(protocol, ' ');
    dst_addr = strsep_char(src_addr, ' ');
    src_port = strsep_char(dst_addr, ' ');
    dst_port = strsep_char(src_port, ' ');

    if (UNLIKELY(!dst_port))
        return NULL;

    enum {
        TCP4 = MULTICHAR_CONSTANT('T', 'C', 'P', '4'),
        TCP6 = MULTICHAR_CONSTANT('T', 'C', 'P', '6'),
    };

    STRING_SWITCH(protocol) {
    case TCP4: {
        struct sockaddr_in *from = &proxy->from.ipv4;
        struct sockaddr_in *to = &proxy->to.ipv4;

        from->sin_family = to->sin_family = AF_INET;

        if (UNLIKELY(inet_pton(AF_INET, src_addr, &from->sin_addr) <= 0))
            return NULL;
        if (UNLIKELY(inet_pton(AF_INET, dst_addr, &to->sin_addr) <= 0))
            return NULL;
        if (UNLIKELY(!parse_ascii_port(src_port, &from->sin_port)))
            return NULL;
        if (UNLIKELY(!parse_ascii_port(dst_port, &to->sin_port)))
            return NULL;

        break;
    }
    case TCP6: {
        struct sockaddr_in6 *from = &proxy->from.ipv6;
        struct sockaddr_in6 *to = &proxy->to.ipv6;

        from->sin6_family = to->sin6_family = AF_INET6;

        if (UNLIKELY(inet_pton(AF_INET6, src_addr, &from->sin6_addr) <= 0))
            return NULL;
        if (UNLIKELY(inet_pton(AF_INET6, dst_addr, &to->sin6_addr) <= 0))
            return NULL;
        if (UNLIKELY(!parse_ascii_port(src_port, &from->sin6_port)))
            return NULL;
        if (UNLIKELY(!parse_ascii_port(dst_port, &to->sin6_port)))
            return NULL;

        break;
    }
    default:
        return NULL;
    }

    request->flags |= REQUEST_PROXIED;
    return buffer + size;
}

static char *
parse_proxy_protocol_v2(struct lwan_request *request, char *buffer)
{
    struct proxy_header_v2 *hdr = (struct proxy_header_v2*)buffer;
    const unsigned int proto_signature_length = 16;
    unsigned int size;
    struct lwan_proxy *const proxy = request->proxy;

    enum {
        LOCAL = 0x20,
        PROXY = 0x21,
        TCP4 = 0x11,
        TCP6 = 0x21
    };

    size = proto_signature_length + (unsigned int)ntohs(hdr->len);
    if (UNLIKELY(size > (unsigned int)sizeof(*hdr)))
        return NULL;

    if (hdr->cmd_ver == LOCAL) {
        struct sockaddr_in *from = &proxy->from.ipv4;
        struct sockaddr_in *to = &proxy->to.ipv4;

        from->sin_family = to->sin_family = AF_UNSPEC;
    } else if (hdr->cmd_ver == PROXY) {
        if (hdr->fam == TCP4) {
            struct sockaddr_in *from = &proxy->from.ipv4;
            struct sockaddr_in *to = &proxy->to.ipv4;

            to->sin_family = from->sin_family = AF_INET;

            from->sin_addr.s_addr = hdr->addr.ip4.src_addr;
            from->sin_port = hdr->addr.ip4.src_port;

            to->sin_addr.s_addr = hdr->addr.ip4.dst_addr;
            to->sin_port = hdr->addr.ip4.dst_port;
        } else if (hdr->fam == TCP6) {
            struct sockaddr_in6 *from = &proxy->from.ipv6;
            struct sockaddr_in6 *to = &proxy->to.ipv6;

            from->sin6_family = to->sin6_family = AF_INET6;

            from->sin6_addr = hdr->addr.ip6.src_addr;
            from->sin6_port = hdr->addr.ip6.src_port;

            to->sin6_addr = hdr->addr.ip6.dst_addr;
            to->sin6_port = hdr->addr.ip6.dst_port;
        } else {
            return NULL;
        }
    } else {
        return NULL;
    }

    request->flags |= REQUEST_PROXIED;
    return buffer + size;
}

static ALWAYS_INLINE char *
identify_http_method(struct lwan_request *request, char *buffer)
{
    enum {
        HTTP_STR_GET     = MULTICHAR_CONSTANT('G','E','T',' '),
        HTTP_STR_HEAD    = MULTICHAR_CONSTANT('H','E','A','D'),
        HTTP_STR_POST    = MULTICHAR_CONSTANT('P','O','S','T'),
        HTTP_STR_OPTIONS = MULTICHAR_CONSTANT('O','P','T','I'),
        HTTP_STR_DELETE  = MULTICHAR_CONSTANT('D','E','L','E'),
    };

    STRING_SWITCH(buffer) {
    case HTTP_STR_GET:
        request->flags |= REQUEST_METHOD_GET;
        return buffer + sizeof("GET ") - 1;
    case HTTP_STR_HEAD:
        request->flags |= REQUEST_METHOD_HEAD;
        return buffer + sizeof("HEAD ") - 1;
    case HTTP_STR_POST:
        request->flags |= REQUEST_METHOD_POST;
        return buffer + sizeof("POST ") - 1;
    case HTTP_STR_OPTIONS:
        request->flags |= REQUEST_METHOD_OPTIONS;
        return buffer + sizeof("OPTIONS ") - 1;
    case HTTP_STR_DELETE:
        request->flags |= REQUEST_METHOD_DELETE;
        return buffer + sizeof("DELETE ") - 1;
    }

    return NULL;
}

static ALWAYS_INLINE char
decode_hex_digit(char ch)
{
    return (char)((ch <= '9') ? ch - '0' : (ch & 7) + 9);
}

static size_t
url_decode(char *str)
{
    if (UNLIKELY(!str))
        return 0;

    char *ch, *decoded;
    for (decoded = ch = str; *ch; ch++) {
        if (*ch == '%' && LIKELY(lwan_char_isxdigit(ch[1]) && lwan_char_isxdigit(ch[2]))) {
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
key_value_compare(const void *a, const void *b)
{
    return strcmp(((struct lwan_key_value *)a)->key, ((struct lwan_key_value *)b)->key);
}

static void
parse_key_values(struct lwan_request *request,
    struct lwan_value *helper_value, struct lwan_key_value_array *array,
    size_t (*decode_value)(char *value), const char separator)
{
    struct lwan_key_value *kv;
    char *ptr = helper_value->value;

    if (!helper_value->len)
        return;

    lwan_key_value_array_init(array);
    /* Calling lwan_key_value_array_reset() twice is fine, so even if 'goto
     * error' is executed in this function, nothing bad should happen.  */
    coro_defer(request->conn->coro, CORO_DEFER(lwan_key_value_array_reset), array);

    do {
        char *key, *value;

        while (*ptr == ' ' || *ptr == separator)
            ptr++;
        if (UNLIKELY(*ptr == '\0'))
            goto error;

        key = ptr;
        ptr = strsep_char(key, separator);

        value = strsep_char(key, '=');
        if (UNLIKELY(!value))
            value = "";
        else if (UNLIKELY(!decode_value(value)))
            goto error;

        if (UNLIKELY(!decode_value(key)))
            goto error;

        kv = lwan_key_value_array_append(array);
        if (UNLIKELY(!kv))
            goto error;

        kv->key = key;
        kv->value = value;
    } while (ptr);

    kv = lwan_key_value_array_append(array);
    if (UNLIKELY(!kv))
        goto error;
    kv->key = kv->value = NULL;

    lwan_key_value_array_sort(array, key_value_compare);

    return;

error:
    lwan_key_value_array_reset(array);
}

static size_t
identity_decode(char *input __attribute__((unused)))
{
    return 1;
}

static void
parse_cookies(struct lwan_request *request, struct request_parser_helper *helper)
{
    parse_key_values(request, &helper->cookie, &request->cookies,
        identity_decode, ';');
}

static void
parse_query_string(struct lwan_request *request, struct request_parser_helper *helper)
{
    parse_key_values(request, &helper->query_string, &request->query_params,
        url_decode, '&');
}

static void
parse_post_data(struct lwan_request *request, struct request_parser_helper *helper)
{
    static const char content_type[] = "application/x-www-form-urlencoded";

    request->header.body = &helper->post_data;
    request->header.content_type = &helper->content_type;

    if (helper->content_type.len < sizeof(content_type) - 1)
        return;
    if (UNLIKELY(strncmp(helper->content_type.value, content_type, sizeof(content_type) - 1)))
        return;

    parse_key_values(request, &helper->post_data, &request->post_data,
        url_decode, '&');
}

static void
parse_fragment_and_query(struct lwan_request *request,
    struct request_parser_helper *helper, const char *space)
{
    /* Most of the time, fragments are small -- so search backwards */
    char *fragment = memrchr(request->url.value, '#', request->url.len);
    if (fragment) {
        *fragment = '\0';
        helper->fragment.value = fragment + 1;
        helper->fragment.len = (size_t)(space - fragment - 1);
        request->url.len -= helper->fragment.len + 1;
    }

    /* Most of the time, query string values are larger than the URL, so
       search from the beginning */
    char *query_string = memchr(request->url.value, '?', request->url.len);
    if (query_string) {
        *query_string = '\0';
        helper->query_string.value = query_string + 1;
        helper->query_string.len = (size_t)((fragment ? fragment : space) - query_string - 1);
        request->url.len -= helper->query_string.len + 1;
    }
}

static char *
identify_http_path(struct lwan_request *request, char *buffer,
            struct request_parser_helper *helper)
{
    static const size_t minimal_request_line_len = sizeof("/ HTTP/1.0") - 1;
    char *space, *end_of_line;
    enum {
        HTTP_VERSION_1_0 = MULTICHAR_CONSTANT_LARGE('H','T','T','P','/','1','.','0'),
        HTTP_VERSION_1_1 = MULTICHAR_CONSTANT_LARGE('H','T','T','P','/','1','.','1'),
    };

    if (UNLIKELY(*buffer != '/'))
        return NULL;

    end_of_line = memchr(buffer, '\r',
        (helper->buffer->len - (size_t)(buffer - helper->buffer->value)));
    if (UNLIKELY(!end_of_line))
        return NULL;
    if (UNLIKELY((size_t)(end_of_line - buffer) < minimal_request_line_len))
        return NULL;
    *end_of_line = '\0';

    space = end_of_line - sizeof("HTTP/X.X");

    request->url.value = buffer;
    request->url.len = (size_t)(space - buffer);
    parse_fragment_and_query(request, helper, space);
    request->original_url = request->url;

    *space++ = '\0';

    STRING_SWITCH_LARGE(space) {
    case HTTP_VERSION_1_0:
        request->flags |= REQUEST_IS_HTTP_1_0;
        /* fallthrough */
    case HTTP_VERSION_1_1:
        break;
    default:
        return NULL;
    }

    return end_of_line + 1;
}

#define MATCH_HEADER(hdr) \
  do { \
        p += sizeof(hdr) - 1; \
        if (UNLIKELY(p >= buffer_end)) /* reached the end of header blocks */ \
            return NULL; \
        \
        if (UNLIKELY(string_as_int16(p) != HTTP_HDR_COLON_SPACE)) \
            goto did_not_match; \
        p += 2; \
        \
        char *end = strchr(p, '\r'); \
        if (UNLIKELY(!end)) \
            goto did_not_match; \
        \
        *end = '\0'; \
        value = p; \
        length = (size_t)(end - value); \
        \
        p = end + 1; \
        if (UNLIKELY(*p != '\n')) \
            goto did_not_match; \
  } while (0)

#define CASE_HEADER(hdr_const,hdr_name) \
    case hdr_const: MATCH_HEADER(hdr_name);

static char *
parse_headers(struct request_parser_helper *helper, char *buffer, char *buffer_end)
{
    enum {
        HTTP_HDR_COLON_SPACE       = MULTICHAR_CONSTANT_SMALL(':', ' '),
        HTTP_HDR_REQUEST_END       = MULTICHAR_CONSTANT_SMALL('\r','\n'),
        HTTP_HDR_ENCODING          = MULTICHAR_CONSTANT_L('-','E','n','c'),
        HTTP_HDR_LENGTH            = MULTICHAR_CONSTANT_L('-','L','e','n'),
        HTTP_HDR_TYPE              = MULTICHAR_CONSTANT_L('-','T','y','p'),
        HTTP_HDR_ACCEPT            = MULTICHAR_CONSTANT_L('A','c','c','e'),
        HTTP_HDR_AUTHORIZATION     = MULTICHAR_CONSTANT_L('A','u','t','h'),
        HTTP_HDR_CONNECTION        = MULTICHAR_CONSTANT_L('C','o','n','n'),
        HTTP_HDR_CONTENT           = MULTICHAR_CONSTANT_L('C','o','n','t'),
        HTTP_HDR_COOKIE            = MULTICHAR_CONSTANT_L('C','o','o','k'),
        HTTP_HDR_IF_MODIFIED_SINCE = MULTICHAR_CONSTANT_L('I','f','-','M'),
        HTTP_HDR_RANGE             = MULTICHAR_CONSTANT_L('R','a','n','g')
    };

    for (char *p = buffer; *p; buffer = ++p) {
        char *value;
        size_t length;

        if ((p + sizeof(int32_t)) >= buffer_end)
            break;

        STRING_SWITCH_L(p) {
        case HTTP_HDR_ACCEPT:
            p += sizeof("Accept") - 1;

            STRING_SWITCH_L(p) {
            CASE_HEADER(HTTP_HDR_ENCODING, "-Encoding")
                helper->accept_encoding.value = value;
                helper->accept_encoding.len = length;
                break;
            }
            break;
        CASE_HEADER(HTTP_HDR_AUTHORIZATION, "Authorization")
            helper->authorization.value = value;
            helper->authorization.len = length;
            break;
        CASE_HEADER(HTTP_HDR_CONNECTION, "Connection")
            helper->connection = (*value | 0x20);
            break;
        case HTTP_HDR_CONTENT:
            p += sizeof("Content") - 1;

            STRING_SWITCH_L(p) {
            CASE_HEADER(HTTP_HDR_TYPE, "-Type")
                helper->content_type.value = value;
                helper->content_type.len = length;
                break;
            CASE_HEADER(HTTP_HDR_LENGTH, "-Length")
                helper->content_length.value = value;
                helper->content_length.len = length;
                break;
            }
            break;
        CASE_HEADER(HTTP_HDR_COOKIE, "Cookie")
            helper->cookie.value = value;
            helper->cookie.len = length;
            break;
        CASE_HEADER(HTTP_HDR_IF_MODIFIED_SINCE, "If-Modified-Since")
            helper->if_modified_since.value = value;
            helper->if_modified_since.len = length;
            break;
        CASE_HEADER(HTTP_HDR_RANGE, "Range")
            helper->range.value = value;
            helper->range.len = length;
            break;
        default:
            STRING_SWITCH_SMALL(p) {
            case HTTP_HDR_REQUEST_END:
                *p = '\0';
                helper->next_request = p + sizeof("\r\n") - 1;
                return p;
            }
        }
did_not_match:
        p = memchr(p, '\n', (size_t)(buffer_end - p));
        if (!p)
            break;
    }

    return buffer;
}

#undef CASE_HEADER
#undef MATCH_HEADER

static void
parse_if_modified_since(struct lwan_request *request, struct request_parser_helper *helper)
{
    time_t parsed;

    if (UNLIKELY(!helper->if_modified_since.len))
        return;

    if (UNLIKELY(lwan_parse_rfc_time(helper->if_modified_since.value, &parsed) < 0))
        return;

    request->header.if_modified_since = parsed;
}

static void
parse_range(struct lwan_request *request, struct request_parser_helper *helper)
{
    if (UNLIKELY(helper->range.len <= (sizeof("bytes=") - 1)))
        return;

    char *range = helper->range.value;
    if (UNLIKELY(strncmp(range, "bytes=", sizeof("bytes=") - 1)))
        return;

    range += sizeof("bytes=") - 1;
    off_t from, to;

    if (sscanf(range, "%"SCNu64"-%"SCNu64, &from, &to) == 2) {
        request->header.range.from = from;
        request->header.range.to = to;
    } else if (sscanf(range, "-%"SCNu64, &to) == 1) {
        request->header.range.from = 0;
        request->header.range.to = to;
    } else if (sscanf(range, "%"SCNu64"-", &from) == 1) {
        request->header.range.from = from;
        request->header.range.to = -1;
    } else {
        request->header.range.from = -1;
        request->header.range.to = -1;
    }
}

static void
parse_accept_encoding(struct lwan_request *request, struct request_parser_helper *helper)
{
    if (!helper->accept_encoding.len)
        return;

    enum {
        ENCODING_DEFL1 = MULTICHAR_CONSTANT('d','e','f','l'),
        ENCODING_DEFL2 = MULTICHAR_CONSTANT(' ','d','e','f'),
        ENCODING_GZIP1 = MULTICHAR_CONSTANT('g','z','i','p'),
        ENCODING_GZIP2 = MULTICHAR_CONSTANT(' ','g','z','i')
    };

    for (char *p = helper->accept_encoding.value; *p; p++) {
        STRING_SWITCH(p) {
        case ENCODING_DEFL1:
        case ENCODING_DEFL2:
            request->flags |= REQUEST_ACCEPT_DEFLATE;
            break;
        case ENCODING_GZIP1:
        case ENCODING_GZIP2:
            request->flags |= REQUEST_ACCEPT_GZIP;
            break;
        }

        if (!(p = strchr(p, ',')))
            break;
    }
}

static ALWAYS_INLINE char *
ignore_leading_whitespace(char *buffer)
{
    while (*buffer && lwan_char_isspace(*buffer))
        buffer++;
    return buffer;
}

static ALWAYS_INLINE void
compute_keep_alive_flag(struct lwan_request *request, struct request_parser_helper *helper)
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

static enum lwan_http_status read_from_request_socket(struct lwan_request *request,
    struct lwan_value *buffer, struct request_parser_helper *helper, const size_t buffer_size,
    enum lwan_read_finalizer (*finalizer)(size_t total_read, size_t buffer_size, struct request_parser_helper *helper, int n_packets))
{
    ssize_t n;
    size_t total_read = 0;
    int n_packets = 0;

    if (helper->next_request) {
        buffer->len -= (size_t)(helper->next_request - buffer->value);
        /* FIXME: This memmove() could be eventually removed if a better
         * stucture were used for the request buffer. */
        memmove(buffer->value, helper->next_request, buffer->len);
        total_read = buffer->len;
        goto try_to_finalize;
    }

    for (; ; n_packets++) {
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
                request->conn->flags |= CONN_MUST_READ;
                coro_yield(request->conn->coro, CONN_CORO_MAY_RESUME);
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
        buffer->len = (size_t)total_read;

try_to_finalize:
        switch (finalizer(total_read, buffer_size, helper, n_packets)) {
        case FINALIZER_DONE:
            request->conn->flags &= ~CONN_MUST_READ;
            buffer->value[buffer->len] = '\0';
            return HTTP_OK;
        case FINALIZER_TRY_AGAIN:
            continue;
        case FINALIZER_YIELD_TRY_AGAIN:
            goto yield_and_read_again;
        case FINALIZER_ERROR_TOO_LARGE:
            return HTTP_TOO_LARGE;
        case FINALIZER_ERROR_TIMEOUT:
            return HTTP_TIMEOUT;
        }
    }

    /* Shouldn't reach here. */
    coro_yield(request->conn->coro, CONN_CORO_ABORT);
    __builtin_unreachable();
    return HTTP_INTERNAL_ERROR;
}

static enum lwan_read_finalizer read_request_finalizer(size_t total_read,
    size_t buffer_size, struct request_parser_helper *helper, int n_packets)
{
    /* 16 packets should be enough to read a request (without the body, as
     * is the case for POST requests).  This yields a timeout error to avoid
     * clients being intentionally slow and hogging the server.  */
    if (UNLIKELY(n_packets > helper->error_when_n_packets))
        return FINALIZER_ERROR_TIMEOUT;

    if (UNLIKELY(total_read < 4))
        return FINALIZER_YIELD_TRY_AGAIN;

    if (UNLIKELY(total_read == buffer_size))
        return FINALIZER_ERROR_TOO_LARGE;

    if (LIKELY(helper->next_request)) {
        helper->next_request = NULL;
        return FINALIZER_DONE;
    }

    /* FIXME: Would saving the location of CRLFCRLF be useful? Maybe
     * parse_headers() could benefit from this information?  How would it
     * compare to helper->next_request?  */
    if (LIKELY(memmem(helper->buffer->value, helper->buffer->len, "\r\n\r\n", 4)))
        return FINALIZER_DONE;

    return FINALIZER_TRY_AGAIN;
}

static ALWAYS_INLINE enum lwan_http_status
read_request(struct lwan_request *request, struct request_parser_helper *helper)
{
    return read_from_request_socket(request, helper->buffer, helper,
                        DEFAULT_BUFFER_SIZE, read_request_finalizer);
}

static enum lwan_read_finalizer post_data_finalizer(size_t total_read,
    size_t buffer_size, struct request_parser_helper *helper, int n_packets)
{
    if (buffer_size == total_read)
        return FINALIZER_DONE;

    /* For POST requests, the body can be larger, and due to small MTUs on
     * most ethernet connections, responding with a timeout solely based on
     * number of packets doesn't work.  Use keepalive timeout instead.  */
    if (UNLIKELY(time(NULL) > helper->error_when_time))
        return FINALIZER_ERROR_TIMEOUT;

    /* In addition to time, also estimate the number of packets based on an
     * usual MTU value and the request body size.  */
    if (UNLIKELY(n_packets > helper->error_when_n_packets))
        return FINALIZER_ERROR_TIMEOUT;

    return FINALIZER_TRY_AGAIN;
}

static ALWAYS_INLINE int max(int a, int b)
{
    return (a > b) ? a : b;
}

static ALWAYS_INLINE int calculate_n_packets(size_t total)
{
    /* 740 = 1480 (a common MTU) / 2, so that Lwan'll optimistically error out
     * after ~2x number of expected packets to fully read the request body.*/
    return max(1, (int)(total / 740));
}

static const char *
get_abs_path_env(const char *var)
{
    const char *ret = secure_getenv(var);
    return (ret && *ret == '/') ? ret : NULL;
}

static const char *
get_temp_dir(void)
{
    struct stat st;
    const char *tmpdir;

    tmpdir = get_abs_path_env("TMPDIR");
    if (tmpdir)
        return tmpdir;

    tmpdir = get_abs_path_env("TMP");
    if (tmpdir)
        return tmpdir;

    tmpdir = get_abs_path_env("TEMP");
    if (tmpdir)
        return tmpdir;

    if (!stat("/tmp", &st) && S_ISDIR(st.st_mode))
        return "/tmp";

    if (!stat("/var/tmp", &st) && S_ISDIR(st.st_mode))
        return "/var/tmp";

    return NULL;
}

static int
create_temp_file(void)
{
    char template[PATH_MAX];
    const char *tmpdir;
    mode_t prev_mask;
    int ret;

    tmpdir = get_temp_dir();
    if (UNLIKELY(!tmpdir))
        return -ENOENT;

#if defined(O_TMPFILE)
    int fd = open(tmpdir, O_TMPFILE | O_RDWR | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
        S_IRUSR | S_IWUSR);
    if (LIKELY(fd >= 0))
        return fd;
#endif

    ret = snprintf(template, sizeof(template), "%s/lwanXXXXXX", tmpdir);
    if (UNLIKELY(ret < 0 || ret >= (int)sizeof(template)))
        return -EOVERFLOW;

    prev_mask = umask_for_tmpfile(S_IRUSR | S_IWUSR);
    ret = mkostemp(template, O_CLOEXEC);
    umask_for_tmpfile(prev_mask);

    if (LIKELY(ret >= 0))
        unlink(template);

    return ret;
}

struct file_backed_buffer {
    void *ptr;
    size_t size;
};

static void
free_post_buffer(void *data)
{
    struct file_backed_buffer *buf = data;

    munmap(buf->ptr, buf->size);
    free(buf);
}

static void*
alloc_post_buffer(struct coro *coro, size_t size, bool allow_file)
{
    struct file_backed_buffer *buf;
    void *ptr;
    int fd;

    if (LIKELY(size < 1<<20)) {
        ptr = coro_malloc(coro, size);

        if (LIKELY(ptr))
            return ptr;
    }

    if (UNLIKELY(!allow_file))
        return NULL;

    fd = create_temp_file();
    if (UNLIKELY(fd < 0))
        return NULL;

    if (UNLIKELY(ftruncate(fd, (off_t)size) < 0)) {
        close(fd);
        return NULL;
    }

    ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    close(fd);
    if (UNLIKELY(ptr == MAP_FAILED))
        return NULL;

    buf = coro_malloc_full(coro, sizeof(*buf), free_post_buffer);
    if (UNLIKELY(!buf)) {
        munmap(ptr, size);
        return NULL;
    }

    buf->ptr = ptr;
    buf->size = size;
    return ptr;
}

static enum lwan_http_status
read_post_data(struct lwan_request *request, struct request_parser_helper *helper)
{
    /* Holy indirection, Batman! */
    struct lwan_config *config = &request->conn->thread->lwan->config;
    const size_t max_post_data_size = config->max_post_data_size;
    char *new_buffer;
    long parsed_size;

    if (UNLIKELY(!helper->content_length.value))
        return HTTP_BAD_REQUEST;
    parsed_size = parse_long(helper->content_length.value, -1);
    if (UNLIKELY(parsed_size < 0))
        return HTTP_BAD_REQUEST;
    if (UNLIKELY(parsed_size >= (long)max_post_data_size))
        return HTTP_TOO_LARGE;

    size_t post_data_size = (size_t)parsed_size;
    size_t have;
    if (!helper->next_request) {
        have = 0;
    } else {
        char *buffer_end = helper->buffer->value + helper->buffer->len;
        have = (size_t)(ptrdiff_t)(buffer_end - helper->next_request);

        if (have >= post_data_size) {
            helper->post_data.value = helper->next_request;
            helper->post_data.len = post_data_size;
            helper->next_request += post_data_size;
            return HTTP_OK;
        }
    }

    new_buffer = alloc_post_buffer(request->conn->coro, post_data_size + 1,
        config->allow_post_temp_file);
    if (UNLIKELY(!new_buffer))
        return HTTP_INTERNAL_ERROR;

    helper->post_data.value = new_buffer;
    helper->post_data.len = post_data_size;
    if (have)
        new_buffer = mempcpy(new_buffer, helper->next_request, have);
    helper->next_request = NULL;

    helper->error_when_time = time(NULL) + config->keep_alive_timeout;
    helper->error_when_n_packets = calculate_n_packets(post_data_size);

    struct lwan_value buffer = { .value = new_buffer, .len = post_data_size - have };
    return read_from_request_socket(request, &buffer, helper, buffer.len,
        post_data_finalizer);
}

static char *
parse_proxy_protocol(struct lwan_request *request, char *buffer)
{
    enum {
        HTTP_PROXY_VER1 = MULTICHAR_CONSTANT('P','R','O','X'),
        HTTP_PROXY_VER2 = MULTICHAR_CONSTANT('\x0D','\x0A','\x0D','\x0A'),
    };

    STRING_SWITCH(buffer) {
    case HTTP_PROXY_VER1:
        return parse_proxy_protocol_v1(request, buffer);
    case HTTP_PROXY_VER2:
        return parse_proxy_protocol_v2(request, buffer);
    }

    return buffer;
}

static enum lwan_http_status
parse_http_request(struct lwan_request *request, struct request_parser_helper *helper)
{
    char *buffer = helper->buffer->value;

    if (request->flags & REQUEST_ALLOW_PROXY_REQS) {
        /* REQUEST_ALLOW_PROXY_REQS will be cleared in lwan_process_request() */

        buffer = parse_proxy_protocol(request, buffer);
        if (UNLIKELY(!buffer))
            return HTTP_BAD_REQUEST;
    }

    buffer = ignore_leading_whitespace(buffer);

    char *path = identify_http_method(request, buffer);
    if (UNLIKELY(!path))
        return HTTP_NOT_ALLOWED;

    buffer = identify_http_path(request, path, helper);
    if (UNLIKELY(!buffer))
        return HTTP_BAD_REQUEST;

    buffer = parse_headers(helper, buffer, helper->buffer->value + helper->buffer->len);
    if (UNLIKELY(!buffer))
        return HTTP_BAD_REQUEST;

    size_t decoded_len = url_decode(request->url.value);
    if (UNLIKELY(!decoded_len))
        return HTTP_BAD_REQUEST;
    request->original_url.len = request->url.len = decoded_len;

    compute_keep_alive_flag(request, helper);

    return HTTP_OK;
}

static enum lwan_http_status
prepare_for_response(struct lwan_url_map *url_map,
                      struct lwan_request *request,
                      struct request_parser_helper *helper)
{
    request->url.value += url_map->prefix_len;
    request->url.len -= url_map->prefix_len;

    if (url_map->flags & HANDLER_MUST_AUTHORIZE) {
        if (!lwan_http_authorize(request,
                        &helper->authorization,
                        url_map->authorization.realm,
                        url_map->authorization.password_file))
            return HTTP_NOT_AUTHORIZED;
    }

    if (url_map->flags & HANDLER_PARSE_QUERY_STRING)
        parse_query_string(request, helper);

    if (url_map->flags & HANDLER_PARSE_IF_MODIFIED_SINCE)
        parse_if_modified_since(request, helper);

    if (url_map->flags & HANDLER_PARSE_RANGE)
        parse_range(request, helper);

    if (url_map->flags & HANDLER_PARSE_ACCEPT_ENCODING)
        parse_accept_encoding(request, helper);

    if (url_map->flags & HANDLER_PARSE_COOKIES)
        parse_cookies(request, helper);

    if (url_map->flags & HANDLER_REMOVE_LEADING_SLASH) {
        while (*request->url.value == '/' && request->url.len > 0) {
            ++request->url.value;
            --request->url.len;
        }
    }

    if (lwan_request_get_method(request) == REQUEST_METHOD_POST) {
        enum lwan_http_status status;

        if (!(url_map->flags & HANDLER_PARSE_POST_DATA)) {
            /* FIXME: Discard POST data here? If a POST request is sent
             * to a handler that is not supposed to handle a POST request,
             * the next request in the pipeline will fail because the
             * body of the previous request will be used as the next
             * request itself. */
            return HTTP_NOT_ALLOWED;
        }

        status = read_post_data(request, helper);
        if (UNLIKELY(status != HTTP_OK))
            return status;

        parse_post_data(request, helper);
    }

    return HTTP_OK;
}

static bool
handle_rewrite(struct lwan_request *request, struct request_parser_helper *helper)
{
    request->flags &= ~RESPONSE_URL_REWRITTEN;

    parse_fragment_and_query(request, helper,
        request->url.value + request->url.len);

    helper->urls_rewritten++;
    if (UNLIKELY(helper->urls_rewritten > 4)) {
        lwan_default_response(request, HTTP_INTERNAL_ERROR);
        return false;
    }

    return true;
}

char *
lwan_process_request(struct lwan *l, struct lwan_request *request,
    struct lwan_value *buffer, char *next_request)
{
    enum lwan_http_status status;
    struct lwan_url_map *url_map;

    struct request_parser_helper helper = {
        .buffer = buffer,
        .next_request = next_request,
        .error_when_n_packets = calculate_n_packets(DEFAULT_BUFFER_SIZE)
    };

    status = read_request(request, &helper);
    if (UNLIKELY(status != HTTP_OK)) {
        /* This request was bad, but maybe there's a good one in the
         * pipeline.  */
        if (status == HTTP_BAD_REQUEST && helper.next_request)
            goto out;

        /* Response here can be: HTTP_TOO_LARGE, HTTP_BAD_REQUEST (without
         * next request), or HTTP_TIMEOUT.  Nothing to do, just abort the
         * coroutine.  */
        lwan_default_response(request, status);
        coro_yield(request->conn->coro, CONN_CORO_ABORT);
        __builtin_unreachable();
    }

    status = parse_http_request(request, &helper);
    if (UNLIKELY(status != HTTP_OK)) {
        lwan_default_response(request, status);
        goto out;
    }

lookup_again:
    url_map = lwan_trie_lookup_prefix(&l->url_map_trie, request->url.value);
    if (UNLIKELY(!url_map)) {
        lwan_default_response(request, HTTP_NOT_FOUND);
        goto out;
    }

    status = prepare_for_response(url_map, request, &helper);
    if (UNLIKELY(status != HTTP_OK)) {
        lwan_default_response(request, status);
        goto out;
    }

    status = url_map->handler(request, &request->response, url_map->data);
    if (UNLIKELY(url_map->flags & HANDLER_CAN_REWRITE_URL)) {
        if (request->flags & RESPONSE_URL_REWRITTEN) {
            if (LIKELY(handle_rewrite(request, &helper)))
                goto lookup_again;
            goto out;
        }
    }

    lwan_response(request, status);

out:
    return helper.next_request;
}

static inline void *
value_lookup(const struct lwan_key_value_array *array, const char *key)
{
    const struct lwan_array *la = (const struct lwan_array *)array;

    if (LIKELY(la->elements)) {
        struct lwan_key_value k = { .key = (char *)key };
        struct lwan_key_value *entry;

        entry = bsearch(&k, la->base, la->elements - 1, sizeof(k), key_value_compare);
        if (LIKELY(entry))
            return entry->value;
    }

    return NULL;
}

const char *
lwan_request_get_query_param(struct lwan_request *request, const char *key)
{
    return value_lookup(&request->query_params, key);
}

const char *
lwan_request_get_post_param(struct lwan_request *request, const char *key)
{
    return value_lookup(&request->post_data, key);
}

const char *
lwan_request_get_cookie(struct lwan_request *request, const char *key)
{
    return value_lookup(&request->cookies, key);
}

ALWAYS_INLINE int
lwan_connection_get_fd(const struct lwan *lwan, const struct lwan_connection *conn)
{
    return (int)(ptrdiff_t)(conn - lwan->conns);
}

const char *
lwan_request_get_remote_address(struct lwan_request *request,
            char buffer[static INET6_ADDRSTRLEN])
{
    struct sockaddr_storage non_proxied_addr = { .ss_family = AF_UNSPEC };
    struct sockaddr_storage *sock_addr;

    if (request->flags & REQUEST_PROXIED) {
        sock_addr = (struct sockaddr_storage *)&request->proxy->from;

        if (UNLIKELY(sock_addr->ss_family == AF_UNSPEC))
            return memcpy(buffer, "*unspecified*", sizeof("*unspecified*"));
    } else {
        socklen_t sock_len = sizeof(non_proxied_addr);

        sock_addr = &non_proxied_addr;

        if (UNLIKELY(getpeername(request->fd,
                                 (struct sockaddr *) sock_addr,
                                 &sock_len) < 0))
            return NULL;
    }

    if (sock_addr->ss_family == AF_INET)
        return inet_ntop(AF_INET,
                         &((struct sockaddr_in *) sock_addr)->sin_addr,
                         buffer, INET6_ADDRSTRLEN);

    return inet_ntop(AF_INET6,
                     &((struct sockaddr_in6 *) sock_addr)->sin6_addr,
                     buffer, INET6_ADDRSTRLEN);
}
