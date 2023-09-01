/*
 * lwan - web server
 * Copyright (c) 2012-2014 L. A. F. Pereira <l@tia.mat.br>
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
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <unistd.h>

#include "lwan-private.h"

#include "base64.h"
#include "list.h"
#include "lwan-config.h"
#include "lwan-http-authorize.h"
#include "lwan-io-wrappers.h"
#include "sha1.h"

#define HEADER_VALUE_SEPARATOR_LEN (sizeof(": ") - 1)
#define HEADER_TERMINATOR_LEN (sizeof("\r\n") - 1)
#define MIN_REQUEST_SIZE (sizeof("GET / HTTP/1.1\r\n\r\n") - 1)

enum lwan_read_finalizer {
    FINALIZER_DONE,
    FINALIZER_TRY_AGAIN,
    FINALIZER_TIMEOUT,
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
strsep_char(char *strp, const char *end, char delim)
{
    char *ptr;

    if (UNLIKELY(!strp))
        return NULL;

    if (UNLIKELY(strp > end))
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
    src_addr = strsep_char(protocol, end, ' ');
    dst_addr = strsep_char(src_addr, end, ' ');
    src_port = strsep_char(dst_addr, end, ' ');
    dst_port = strsep_char(src_port, end, ' ');

    if (UNLIKELY(!dst_port))
        return NULL;

    STRING_SWITCH(protocol) {
    case STR4_INT('T', 'C', 'P', '4'): {
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
    case STR4_INT('T', 'C', 'P', '6'): {
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

static char *parse_proxy_protocol_v2(struct lwan_request *request, char *buffer)
{
    struct proxy_header_v2 *hdr = (struct proxy_header_v2 *)buffer;
    struct lwan_request_parser_helper *helper = request->helper;
    const unsigned int proto_signature_length = 16;
    unsigned int size;
    struct lwan_proxy *const proxy = request->proxy;

    enum { LOCAL = 0x20, PROXY = 0x21, TCP4 = 0x11, TCP6 = 0x21 };

    size = proto_signature_length + (unsigned int)ntohs(hdr->len);
    if (UNLIKELY(size > (unsigned int)sizeof(*hdr)))
        return NULL;
    if (UNLIKELY(size >= helper->buffer->len))
        return NULL;

    if (LIKELY(hdr->cmd_ver == PROXY)) {
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
    } else if (hdr->cmd_ver == LOCAL) {
        struct sockaddr_in *from = &proxy->from.ipv4;
        struct sockaddr_in *to = &proxy->to.ipv4;

        from->sin_family = to->sin_family = AF_UNSPEC;
    } else {
        return NULL;
    }

    request->flags |= REQUEST_PROXIED;
    return buffer + size;
}

#if !defined(LWAN_HAVE_BUILTIN_EXPECT_PROBABILITY)
#define __builtin_expect_with_probability(value1, value2, probability) \
    __builtin_expect(value1, value2)
#endif

static ALWAYS_INLINE char *identify_http_method(struct lwan_request *request,
                                                char *buffer)
{
    const uint32_t first_four = string_as_uint32(buffer);

#define GENERATE_IF(upper, lower, mask, constant, probability)                 \
    if (__builtin_expect_with_probability(first_four == (constant), 1,         \
                                          probability)) {                      \
        request->flags |= (mask);                                              \
        return buffer + sizeof(#upper);                                        \
    }

    FOR_EACH_REQUEST_METHOD(GENERATE_IF)

#undef GENERATE_IF

    return NULL;
}

__attribute__((nonnull(1))) static ssize_t url_decode(char *str)
{
    static const unsigned char tbl1[256] = {
        [0 ... 255] = 255, ['0'] = 0 << 4,  ['1'] = 1 << 4,  ['2'] = 2 << 4,
        ['3'] = 3 << 4,    ['4'] = 4 << 4,  ['5'] = 5 << 4,  ['6'] = 6 << 4,
        ['7'] = 7 << 4,    ['8'] = 8 << 4,  ['9'] = 9 << 4,  ['a'] = 10 << 4,
        ['b'] = 11 << 4,   ['c'] = 12 << 4, ['d'] = 13 << 4, ['e'] = 14 << 4,
        ['f'] = 15 << 4,   ['A'] = 10 << 4, ['B'] = 11 << 4, ['C'] = 12 << 4,
        ['D'] = 13 << 4,   ['E'] = 14 << 4, ['F'] = 15 << 4,
    };
    static const char tbl2[256] = {
        [0 ... 255] = -1, ['0'] = 0,  ['1'] = 1,  ['2'] = 2,  ['3'] = 3,
        ['4'] = 4,        ['5'] = 5,  ['6'] = 6,  ['7'] = 7,  ['8'] = 8,
        ['9'] = 9,        ['a'] = 10, ['b'] = 11, ['c'] = 12, ['d'] = 13,
        ['e'] = 14,       ['f'] = 15, ['A'] = 10, ['B'] = 11, ['C'] = 12,
        ['D'] = 13,       ['E'] = 14, ['F'] = 15,
    };
    const char *inptr = str;
    char *outptr = str;

    for (char *p = strpbrk(inptr, "+%"); p; p = strpbrk(inptr, "+%")) {
        const ptrdiff_t diff = p - inptr;
        if (diff)
            outptr = mempmove(outptr, inptr, (size_t)diff);

        if (*p == '+') {
            *outptr++ = ' ';
            inptr = p + 1;
            continue;
        }

        const char first = (char)tbl1[(unsigned char)p[1]];
        const char second = tbl2[(unsigned char)p[2]];
        const char decoded = first | second;
        if (UNLIKELY(decoded <= 0)) {
            /* This shouldn't happen in normal circumstances, but if %00 is
             * found in the encoded string, bail here. */
            if (decoded == '\0')
                return -1;

            /* OR-ing both lookups will yield a negative number if either
             * encoded character is not a valid hex digit; check it here so
             * that other valid-but-negative bytes (e.g.  0xff) are still
             * written to outptr. */
            if (first == -1) {
                /* tbl1 is shifted so a valid nibble might be negative;
                 * check for all the bits here instead.  */
                return -1;
            }
            if (second < 0) {
                /* tbl2 isn't shifted so we can check for the sign bit only. */
                return -1;
            }
        }

        *outptr++ = decoded;
        inptr = p + 3;
    }

    if (inptr > outptr) {
        outptr = stpcpy(outptr, inptr);
        return (ssize_t)(outptr - str);
    }

    return (ssize_t)strlen(str);
}

static int key_value_compare(const void *a, const void *b)
{
    return strcmp(((const struct lwan_key_value *)a)->key,
                  ((const struct lwan_key_value *)b)->key);
}

static void
reset_key_value_array(void *data)
{
    struct lwan_key_value_array *array = data;

    lwan_key_value_array_reset(array);
}

static void parse_key_values(struct lwan_request *request,
                             struct lwan_value *helper_value,
                             struct lwan_key_value_array *array,
                             ssize_t (*decode_value)(char *value),
                             const char separator)
{
    struct lwan_key_value *kv;
    char *ptr = helper_value->value;
    const char *end = helper_value->value + helper_value->len;
    coro_deferred reset_defer;

    if (!helper_value->len)
        return;

    lwan_key_value_array_init(array);
    reset_defer = coro_defer(request->conn->coro, reset_key_value_array, array);

    do {
        char *key, *value;

        while (*ptr == ' ' || *ptr == separator)
            ptr++;
        if (UNLIKELY(*ptr == '\0'))
            break;

        key = ptr;
        ptr = strsep_char(key, end, separator);

        value = strsep_char(key, end, '=');
        if (UNLIKELY(!value)) {
            value = "";
        } else if (UNLIKELY(decode_value(value) < 0)) {
            /* Disallow values that failed decoding, but allow empty values */
            goto error;
        }

        if (UNLIKELY(decode_value(key) <= 0)) {
            /* Disallow keys that failed decoding, or empty keys */
            goto error;
        }

        kv = lwan_key_value_array_append(array);
        if (UNLIKELY(!kv))
            goto error;

        kv->key = key;
        kv->value = value;
    } while (ptr);

    lwan_key_value_array_sort(array, key_value_compare);

    return;

error:
    coro_defer_fire_and_disarm(request->conn->coro, reset_defer);
}

static ssize_t
identity_decode(char *input __attribute__((unused)))
{
    return 1;
}

static void parse_cookies(struct lwan_request *request)
{
    const char *cookies = lwan_request_get_header(request, "Cookie");

    if (!cookies)
        return;

    struct lwan_value header = {.value = (char *)cookies,
                                .len = strlen(cookies)};
    parse_key_values(request, &header, &request->helper->cookies,
                     identity_decode, ';');
}

static void parse_query_string(struct lwan_request *request)
{
    struct lwan_request_parser_helper *helper = request->helper;

    parse_key_values(request, &helper->query_string, &helper->query_params,
                     url_decode, '&');
}

static void parse_form_data(struct lwan_request *request)
{
    struct lwan_request_parser_helper *helper = request->helper;
    static const char content_type[] = "application/x-www-form-urlencoded";

    if (helper->content_type.len < sizeof(content_type) - 1)
        return;
    if (UNLIKELY(strncmp(helper->content_type.value, content_type,
                         sizeof(content_type) - 1)))
        return;

    parse_key_values(request, &helper->body_data, &helper->post_params,
                     url_decode, '&');
}

static void find_query_string(struct lwan_request *request, const char *space)
{
    struct lwan_request_parser_helper *helper = request->helper;

    char *query_string = memchr(request->url.value, '?', request->url.len);
    if (query_string) {
        *query_string = '\0';
        helper->query_string.value = query_string + 1;
        helper->query_string.len = (size_t)(space - query_string - 1);
        request->url.len -= helper->query_string.len + 1;
        request->flags |= REQUEST_HAS_QUERY_STRING;
    }
}

static char *
identify_http_path(struct lwan_request *request, char *buffer)
{
    struct lwan_request_parser_helper *helper = request->helper;
    static const size_t minimal_request_line_len = sizeof("/ HTTP/1.0") - 1;
    char *space, *end_of_line;
    ptrdiff_t end_len;

    if (UNLIKELY(*buffer != '/'))
        return NULL;

    end_len = buffer - helper->buffer->value;
    if (UNLIKELY((size_t)end_len >= helper->buffer->len))
        return NULL;

    end_of_line = memchr(buffer, '\r', helper->buffer->len - (size_t)end_len);
    if (UNLIKELY(!end_of_line))
        return NULL;
    if (UNLIKELY((size_t)(end_of_line - buffer) < minimal_request_line_len))
        return NULL;
    *end_of_line = '\0';

    space = end_of_line - sizeof("HTTP/X.X");

    request->url.value = buffer;
    request->url.len = (size_t)(space - buffer);
    find_query_string(request, space);
    request->original_url = request->url;

    *space++ = '\0';

    STRING_SWITCH_LARGE(space) {
    case STR8_INT('H','T','T','P','/','1','.','0'):
        request->flags |= REQUEST_IS_HTTP_1_0;
        break;
    case STR8_INT('H','T','T','P','/','1','.','1'):
        break;
    default:
        return NULL;
    }

    return end_of_line + 1;
}

__attribute__((noinline)) static void set_header_value(
    struct lwan_value *header, char *end, char *p, size_t header_len)
{
    p += header_len;

    if (LIKELY(string_as_uint16(p) == STR2_INT(':', ' '))) {
        *end = '\0';
        char *value = p + sizeof(": ") - 1;

        header->value = value;
        header->len = (size_t)(end - value);
    }
}

#define HEADER_LENGTH(hdr)                                                     \
    ({                                                                         \
        if (UNLIKELY(end - sizeof(hdr) + 1 < p))                               \
            continue;                                                          \
        sizeof(hdr) - 1;                                                       \
    })

#define SET_HEADER_VALUE(dest, hdr)                                            \
    do {                                                                       \
        const size_t header_len = HEADER_LENGTH(hdr);                          \
        set_header_value(&(helper->dest), end, p, header_len);                 \
    } while (0)

static ALWAYS_INLINE ssize_t find_headers(char **header_start,
                                          struct lwan_value *request_buffer,
                                          char **next_request)
{
    char *buffer = request_buffer->value;
    char *buffer_end = buffer + request_buffer->len;
    ssize_t n_headers = 0;
    char *next_header;

    for (char *next_chr = buffer + 1;;) {
        next_header = memchr(next_chr, '\r', (size_t)(buffer_end - next_chr));

        if (UNLIKELY(!next_header))
            return -1;

        if (next_chr == next_header) {
            if (buffer_end - next_chr >= (ptrdiff_t)HEADER_TERMINATOR_LEN) {
                STRING_SWITCH_SMALL (next_header) {
                case STR2_INT('\r', '\n'):
                    *next_request = next_header + HEADER_TERMINATOR_LEN;
                }
            }
            goto out;
        }

        /* Is there at least a space for a minimal (H)eader and a (V)alue? */
        if (LIKELY(next_header - next_chr >= (ptrdiff_t)(sizeof("H: V") - 1))) {
            header_start[n_headers++] = next_chr;

            if (UNLIKELY(n_headers >= N_HEADER_START - 1))
                return -1;
        } else {
            /* Better to abort early if there's no space. */
            return -1;
        }

        next_chr = next_header + HEADER_TERMINATOR_LEN;
        if (UNLIKELY(next_chr >= buffer_end))
            return -1;
    }

out:
    header_start[n_headers] = next_header;
    return n_headers;
}

static bool parse_headers(struct lwan_request_parser_helper *helper,
                          char *buffer)
{
    char **header_start = helper->header_start;
    ssize_t n_headers = 0;

    /* FIXME: is there a better way to do this? */
    struct lwan_value header_start_buffer = {
        .value = buffer,
        .len = helper->buffer->len - (size_t)(buffer - helper->buffer->value)
    };
    n_headers = find_headers(header_start, &header_start_buffer,
                             &helper->next_request);
    if (UNLIKELY(n_headers < 0))
        return false;

    for (ssize_t i = 0; i < n_headers; i++) {
        char *p = header_start[i];
        char *end = header_start[i + 1] - HEADER_TERMINATOR_LEN;

        STRING_SWITCH_L (p) {
        case STR4_INT_L('A', 'c', 'c', 'e'):
            p += HEADER_LENGTH("Accept");

            STRING_SWITCH_L (p) {
            case STR4_INT_L('-', 'E', 'n', 'c'):
                SET_HEADER_VALUE(accept_encoding, "-Encoding");
                break;
            }
            break;
        case STR4_INT_L('C', 'o', 'n', 'n'):
            SET_HEADER_VALUE(connection, "Connection");
            break;
        case STR4_INT_L('C', 'o', 'n', 't'):
            p += HEADER_LENGTH("Content");

            STRING_SWITCH_L (p) {
            case STR4_INT_L('-', 'T', 'y', 'p'):
                SET_HEADER_VALUE(content_type, "-Type");
                break;
            case STR4_INT_L('-', 'L', 'e', 'n'):
                SET_HEADER_VALUE(content_length, "-Length");
                break;
            }
            break;
        case STR4_INT_L('I', 'f', '-', 'M'):
            SET_HEADER_VALUE(if_modified_since.raw, "If-Modified-Since");
            break;
        case STR4_INT_L('H', 'o', 's', 't'):
            SET_HEADER_VALUE(host, "Host");
            break;
        case STR4_INT_L('R', 'a', 'n', 'g'):
            SET_HEADER_VALUE(range.raw, "Range");
            break;
        }
    }

    helper->n_header_start = (size_t)n_headers;
    return true;
}
#undef HEADER_LENGTH
#undef SET_HEADER_VALUE

ssize_t lwan_find_headers(char **header_start, struct lwan_value *buffer,
                          char **next_request)
{
    return find_headers(header_start, buffer, next_request);
}

static void parse_if_modified_since(struct lwan_request_parser_helper *helper)
{
    static const size_t header_len =
        sizeof("Wed, 17 Apr 2019 13:59:27 GMT") - 1;
    time_t parsed;

    if (UNLIKELY(helper->if_modified_since.raw.len != header_len))
        return;

    if (UNLIKELY(lwan_parse_rfc_time(helper->if_modified_since.raw.value,
                                     &parsed) < 0))
        return;

    helper->if_modified_since.parsed = parsed;
}

static bool
parse_off_without_sign(const char *ptr, char **end, off_t *off)
{
    unsigned long long val;

    static_assert(sizeof(val) >= sizeof(off_t),
                  "off_t fits in a long long");

    errno = 0;

    val = strtoull(ptr, end, 10);
    if (UNLIKELY(val == 0 && *end == ptr))
        return false;
    if (UNLIKELY(errno != 0))
        return false;
    if (UNLIKELY(val > OFF_MAX))
        return false;

    *off = (off_t)val;
    return true;
}

static void
parse_range(struct lwan_request_parser_helper *helper)
{
    if (UNLIKELY(helper->range.raw.len <= (sizeof("bytes=") - 1)))
        return;

    char *range = helper->range.raw.value;
    if (UNLIKELY(strncmp(range, "bytes=", sizeof("bytes=") - 1)))
        return;

    range += sizeof("bytes=") - 1;

    off_t from, to;
    char *end;

    if (*range == '-') {
        from = 0;

        if (!parse_off_without_sign(range + 1, &end, &to))
            goto invalid_range;
        if (*end != '\0')
            goto invalid_range;
    } else if (lwan_char_isdigit(*range)) {
        if (!parse_off_without_sign(range, &end, &from))
            goto invalid_range;
        if (*end != '-')
            goto invalid_range;

        range = end + 1;
        if (*range == '\0') {
            to = -1;
        } else {
            if (!parse_off_without_sign(range, &end, &to))
                goto invalid_range;
            if (*end != '\0')
                goto invalid_range;
        }
    } else {
invalid_range:
        to = from = -1;
    }

    helper->range.from = from;
    helper->range.to = to;
}

static void
parse_accept_encoding(struct lwan_request *request)
{
    struct lwan_request_parser_helper *helper = request->helper;

    if (!helper->accept_encoding.len)
        return;

    for (const char *p = helper->accept_encoding.value; *p; p++) {
        STRING_SWITCH(p) {
        case STR4_INT('d','e','f','l'):
        case STR4_INT(' ','d','e','f'):
            request->flags |= REQUEST_ACCEPT_DEFLATE;
            break;
        case STR4_INT('g','z','i','p'):
        case STR4_INT(' ','g','z','i'):
            request->flags |= REQUEST_ACCEPT_GZIP;
            break;
#if defined(LWAN_HAVE_ZSTD)
        case STR4_INT('z','s','t','d'):
        case STR4_INT(' ','z','s','t'):
            request->flags |= REQUEST_ACCEPT_ZSTD;
            break;
#endif
#if defined(LWAN_HAVE_BROTLI)
        default:
            while (lwan_char_isspace(*p))
                p++;

            STRING_SWITCH_SMALL(p) {
            case STR2_INT('b', 'r'):
                request->flags |= REQUEST_ACCEPT_BROTLI;
                break;
            }
#endif
        }

        if (!(p = strchr(p, ',')))
            break;
    }
}

static ALWAYS_INLINE char *
ignore_leading_whitespace(char *buffer)
{
    while (lwan_char_isspace(*buffer))
        buffer++;
    return buffer;
}

static ALWAYS_INLINE void parse_connection_header(struct lwan_request *request)
{
    struct lwan_request_parser_helper *helper = request->helper;
    bool has_keep_alive = false;
    bool has_close = false;

    if (!helper->connection.len)
        goto out;

    for (const char *p = helper->connection.value; *p; p++) {
        STRING_SWITCH_L(p) {
        case STR4_INT_L('k','e','e','p'):
        case STR4_INT_L(' ', 'k','e','e'):
            has_keep_alive = true;
            break;
        case STR4_INT_L('c','l','o','s'):
        case STR4_INT_L(' ', 'c','l','o'):
            has_close = true;
            break;
        case STR4_INT_L('u','p','g','r'):
        case STR4_INT_L(' ', 'u','p','g'):
            request->conn->flags |= CONN_IS_UPGRADE;
            break;
        }

        if (!(p = strchr(p, ',')))
            break;
    }

out:
    if (LIKELY(!(request->flags & REQUEST_IS_HTTP_1_0)))
        has_keep_alive = !has_close;

    if (has_keep_alive) {
        request->conn->flags |= CONN_IS_KEEP_ALIVE;
    } else {
        request->conn->flags &=
            ~(CONN_IS_KEEP_ALIVE | CONN_SENT_CONNECTION_HEADER);
    }
}

#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
static void save_to_corpus_for_fuzzing(struct lwan_value buffer)
{
    struct lwan_value buffer_copy;
    char corpus_name[PATH_MAX];
    const char *crlfcrlf;
    int fd;

    if (!(crlfcrlf = memmem(buffer.value, buffer.len, "\r\n\r\n", 4)))
        return;
    buffer.len = (size_t)(crlfcrlf - buffer.value + 4);

try_another_file_name:
    buffer_copy = buffer;

    snprintf(corpus_name, sizeof(corpus_name), "corpus-request-%d", rand());

    fd = open(corpus_name, O_WRONLY | O_CLOEXEC | O_CREAT | O_EXCL, 0644);
    if (fd < 0)
        goto try_another_file_name;

    while (buffer_copy.len) {
        ssize_t r = write(fd, buffer_copy.value, buffer_copy.len);

        if (r < 0) {
            if (errno == EAGAIN || errno == EINTR)
                continue;

            close(fd);
            unlink(corpus_name);
            goto try_another_file_name;
        }

        buffer_copy.value += r;
        buffer_copy.len -= r;
    }

    close(fd);
    lwan_status_debug("Request saved to %s", corpus_name);
}
#endif

static enum lwan_http_status
client_read(struct lwan_request *request,
            struct lwan_value *buffer,
            const size_t want_to_read,
            enum lwan_read_finalizer (*finalizer)(const struct lwan_value *buffer,
                                                  size_t want_to_read,
                                                  const struct lwan_request *request,
                                                  int n_packets))
{
    struct lwan_request_parser_helper *helper = request->helper;
    int n_packets = 0;

    if (helper->next_request) {
        const size_t next_request_len = (size_t)(helper->next_request - buffer->value);
        size_t new_len;

        if (__builtin_sub_overflow(buffer->len, next_request_len, &new_len)) {
            helper->next_request = NULL;
        } else if (new_len) {
            /* FIXME: This memmove() could be eventually removed if a better
             * stucture (maybe a ringbuffer, reading with readv(), and each
             * pointer is coro_strdup() if they wrap around?) were used for
             * the request buffer.  */
            buffer->len = new_len;
            memmove(buffer->value, helper->next_request, new_len);
            goto try_to_finalize;
        }
    }

    for (buffer->len = 0;; n_packets++) {
        size_t to_read = (size_t)(want_to_read - buffer->len);

        if (UNLIKELY(to_read == 0))
            return HTTP_TOO_LARGE;

        ssize_t n = recv(request->fd, buffer->value + buffer->len, to_read, 0);
        if (UNLIKELY(n <= 0)) {
            if (n < 0) {
                switch (errno) {
                case EINTR:
                case EAGAIN:
yield_and_read_again:
                    coro_yield(request->conn->coro, CONN_CORO_WANT_READ);
                    continue;
                }

                /* Unexpected error before reading anything */
                if (UNLIKELY(!buffer->len))
                    return HTTP_BAD_REQUEST;
            }

            /* Client shut down orderly (n = 0), or unrecoverable error (n < 0);
             * shut down coro. */
            break;
        }

        buffer->len += (size_t)n;

try_to_finalize:
        switch (finalizer(buffer, want_to_read, request, n_packets)) {
        case FINALIZER_DONE:
            buffer->value[buffer->len] = '\0';
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
            save_to_corpus_for_fuzzing(*buffer);
#endif
            return HTTP_OK;

        case FINALIZER_TRY_AGAIN:
            goto yield_and_read_again;

        case FINALIZER_TIMEOUT:
            return HTTP_TIMEOUT;
        }
    }

    coro_yield(request->conn->coro, CONN_CORO_ABORT);
    __builtin_unreachable();
    return HTTP_INTERNAL_ERROR;
}

static enum lwan_read_finalizer
read_request_finalizer_from_helper(const struct lwan_value *buffer,
                                   struct lwan_request_parser_helper *helper,
                                   int n_packets,
                                   bool allow_proxy_reqs)
{
    static const size_t min_proxied_request_size =
        MIN_REQUEST_SIZE + sizeof(struct proxy_header_v2);

    if (LIKELY(buffer->len >= MIN_REQUEST_SIZE)) {
        STRING_SWITCH (buffer->value + buffer->len - 4) {
        case STR4_INT('\r', '\n', '\r', '\n'):
            return FINALIZER_DONE;
        }
    }

    char *crlfcrlf = memmem(buffer->value, buffer->len, "\r\n\r\n", 4);
    if (LIKELY(crlfcrlf)) {
        if (LIKELY(helper->next_request)) {
            helper->next_request = NULL;
            return FINALIZER_DONE;
        }

        const size_t crlfcrlf_to_base = (size_t)(crlfcrlf - buffer->value);
        if (crlfcrlf_to_base >= MIN_REQUEST_SIZE - 4)
            return FINALIZER_DONE;

        if (buffer->len > min_proxied_request_size && allow_proxy_reqs) {
            /* FIXME: Checking for PROXYv2 protocol header here is a layering
             * violation. */
            STRING_SWITCH_LARGE (crlfcrlf + 4) {
            case STR8_INT(0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a):
                return FINALIZER_DONE;
            }
        }
    }

    /* Yield a timeout error to avoid clients being intentionally slow and
     * hogging the server.  (Clients can't only connect and do nothing, they
     * need to send data, otherwise the timeout queue timer will kick in and
     * close the connection.  Limit the number of packets to avoid them sending
     * just a byte at a time.) See lwan_calculate_n_packets() to see how this is
     * calculated. */
    if (UNLIKELY(n_packets > helper->error_when_n_packets))
        return FINALIZER_TIMEOUT;

    return FINALIZER_TRY_AGAIN;
}

static inline enum lwan_read_finalizer
read_request_finalizer(const struct lwan_value *buffer,
                       size_t want_to_read __attribute__((unused)),
                       const struct lwan_request *request,
                       int n_packets)
{
    return read_request_finalizer_from_helper(
        buffer, request->helper, n_packets,
        request->flags & REQUEST_ALLOW_PROXY_REQS);
}

static ALWAYS_INLINE enum lwan_http_status
read_request(struct lwan_request *request)
{
    return client_read(request, request->helper->buffer,
                       DEFAULT_BUFFER_SIZE - 1 /* -1 for NUL byte */,
                       read_request_finalizer);
}

static enum lwan_read_finalizer
body_data_finalizer(const struct lwan_value *buffer,
                    size_t want_to_read,
                    const struct lwan_request *request,
                    int n_packets)
{
    const struct lwan_request_parser_helper *helper = request->helper;

    if (want_to_read == buffer->len)
        return FINALIZER_DONE;

    /* For POST requests, the body can be larger, and due to small MTUs on
     * most ethernet connections, responding with a timeout solely based on
     * number of packets doesn't work.  Use keepalive timeout instead.  */
    if (UNLIKELY(time(NULL) > helper->error_when_time))
        return FINALIZER_TIMEOUT;

    /* In addition to time, also estimate the number of packets based on an
     * usual MTU value and the request body size.  */
    if (UNLIKELY(n_packets > helper->error_when_n_packets))
        return FINALIZER_TIMEOUT;

    return FINALIZER_TRY_AGAIN;
}

static const char *is_dir_good_for_tmp(const char *v)
{
    struct statfs sb;
    struct stat st;

    if (!v)
        return NULL;

    if (*v != '/')
        return NULL;

    if (stat(v, &st) < 0)
        return NULL;

    if (!S_ISDIR(st.st_mode))
        return NULL;

    if (!(st.st_mode & S_ISVTX)) {
        lwan_status_warning(
            "Using %s as temporary directory, but it doesn't have "
            "the sticky bit set.",
            v);
    }

    if (!statfs(v, &sb) && sb.f_type == TMPFS_MAGIC) {
        lwan_status_warning("%s is a tmpfs filesystem, "
                            "not considering it", v);
        return NULL;
    }

    return v;
}

static const char *temp_dir;
static const size_t body_buffer_temp_file_thresh = 1<<20;

static const char *
get_temp_dir(void)
{
    const char *tmpdir;

    tmpdir = is_dir_good_for_tmp(secure_getenv("TMPDIR"));
    if (tmpdir)
        return tmpdir;

    tmpdir = is_dir_good_for_tmp(secure_getenv("TMP"));
    if (tmpdir)
        return tmpdir;

    tmpdir = is_dir_good_for_tmp(secure_getenv("TEMP"));
    if (tmpdir)
        return tmpdir;

    tmpdir = is_dir_good_for_tmp("/var/tmp");
    if (tmpdir)
        return tmpdir;

    tmpdir = is_dir_good_for_tmp(P_tmpdir);
    if (tmpdir)
        return tmpdir;

    lwan_status_warning("Temporary directory could not be determined. POST "
                        "or PUT requests over %zu bytes bytes will fail.",
                        body_buffer_temp_file_thresh);
    return NULL;
}

__attribute__((constructor)) static void initialize_temp_dir(void)
{
    temp_dir = get_temp_dir();
}

static int create_temp_file(void)
{
    char template[PATH_MAX];
    mode_t prev_mask;
    int ret;

    if (UNLIKELY(!temp_dir))
        return -ENOENT;

#if defined(O_TMPFILE)
    int fd = open(temp_dir,
                  O_TMPFILE | O_CREAT | O_RDWR | O_EXCL | O_CLOEXEC |
                      O_NOFOLLOW | O_NOATIME,
                  S_IRUSR | S_IWUSR);
    if (LIKELY(fd >= 0))
        return fd;
#endif

    ret = snprintf(template, sizeof(template), "%s/lwanXXXXXX", temp_dir);
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
free_body_buffer(void *data)
{
    struct file_backed_buffer *buf = data;

    munmap(buf->ptr, buf->size);
    free(buf);
}

static void*
alloc_body_buffer(struct coro *coro, size_t size, bool allow_file)
{
    struct file_backed_buffer *buf;
    void *ptr = (void *)MAP_FAILED;
    int fd;

    if (LIKELY(size < body_buffer_temp_file_thresh)) {
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

    if (MAP_HUGETLB) {
        ptr = mmap(NULL, size, PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_HUGETLB, fd, 0);
    }
    if (UNLIKELY(ptr == MAP_FAILED))
        ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (UNLIKELY(ptr == MAP_FAILED))
        return NULL;

    buf = coro_malloc_full(coro, sizeof(*buf), free_body_buffer);
    if (UNLIKELY(!buf)) {
        munmap(ptr, size);
        return NULL;
    }

    buf->ptr = ptr;
    buf->size = size;
    return ptr;
}

static enum lwan_http_status
get_remaining_body_data_length(struct lwan_request *request,
                               const size_t max_size,
                               size_t *total,
                               size_t *have)
{
    struct lwan_request_parser_helper *helper = request->helper;
    long long parsed_size;

    if (UNLIKELY(!helper->content_length.value))
        return HTTP_BAD_REQUEST;

    parsed_size = parse_long_long(helper->content_length.value, -1);
    if (UNLIKELY(parsed_size < 0))
        return HTTP_BAD_REQUEST;
    if (UNLIKELY((size_t)parsed_size >= max_size))
        return HTTP_TOO_LARGE;
    if (UNLIKELY(!parsed_size))
        return HTTP_OK;

    *total = (size_t)parsed_size;

    if (!helper->next_request) {
        *have = 0;
        return HTTP_PARTIAL_CONTENT;
    }

    char *buffer_end = helper->buffer->value + helper->buffer->len;

    *have = (size_t)(buffer_end - helper->next_request);

    if (*have < *total)
        return HTTP_PARTIAL_CONTENT;

    helper->body_data.value = helper->next_request;
    helper->body_data.len = *total;
    helper->next_request += *total;
    return HTTP_OK;
}

static int read_body_data(struct lwan_request *request)
{
    /* Holy indirection, Batman! */
    const struct lwan_config *config = &request->conn->thread->lwan->config;
    struct lwan_request_parser_helper *helper = request->helper;
    enum lwan_http_status status;
    size_t total, have, max_data_size;
    bool allow_temp_file;
    char *new_buffer;

    switch (lwan_request_get_method(request)) {
    case REQUEST_METHOD_POST:
        allow_temp_file = config->allow_post_temp_file;
        max_data_size = config->max_post_data_size;
        break;
    case REQUEST_METHOD_PUT:
        allow_temp_file = config->allow_put_temp_file;
        max_data_size = config->max_put_data_size;
        break;
    default:
        return -HTTP_NOT_ALLOWED;
    }

    status =
        get_remaining_body_data_length(request, max_data_size, &total, &have);
    if (status != HTTP_PARTIAL_CONTENT)
        return -(int)status;

    new_buffer =
        alloc_body_buffer(request->conn->coro, total + 1, allow_temp_file);
    if (UNLIKELY(!new_buffer))
        return -HTTP_INTERNAL_ERROR;

    if (!(request->flags & REQUEST_IS_HTTP_1_0)) {
        /* §8.2.3 https://www.w3.org/Protocols/rfc2616/rfc2616-sec8.html */
        const char *expect = lwan_request_get_header(request, "Expect");

        if (expect && strncmp(expect, "100-", 4) == 0) {
            static const char continue_header[] = "HTTP/1.1 100 Continue\r\n\r\n";

            lwan_send(request, continue_header, sizeof(continue_header) - 1, 0);
        }
    }

    helper->body_data.value = new_buffer;
    helper->body_data.len = total;
    if (have) {
        new_buffer = mempcpy(new_buffer, helper->next_request, have);
        total -= have;
    }
    helper->next_request = NULL;

    helper->error_when_time = time(NULL) + config->keep_alive_timeout;
    helper->error_when_n_packets = lwan_calculate_n_packets(total);

    struct lwan_value buffer = {.value = new_buffer, .len = total};
    return (int)client_read(request, &buffer, total, body_data_finalizer);
}

static char *
parse_proxy_protocol(struct lwan_request *request, char *buffer)
{
    STRING_SWITCH(buffer) {
    case STR4_INT('P','R','O','X'):
        return parse_proxy_protocol_v1(request, buffer);
    case STR4_INT('\x0D','\x0A','\x0D','\x0A'):
        return parse_proxy_protocol_v2(request, buffer);
    }

    return buffer;
}

static enum lwan_http_status parse_http_request(struct lwan_request *request)
{
    struct lwan_request_parser_helper *helper = request->helper;
    char *buffer = helper->buffer->value;

    if (request->flags & REQUEST_ALLOW_PROXY_REQS) {
        /* REQUEST_ALLOW_PROXY_REQS will be cleared in lwan_process_request() */

        buffer = parse_proxy_protocol(request, buffer);
        if (UNLIKELY(!buffer))
            return HTTP_BAD_REQUEST;
    }

    buffer = ignore_leading_whitespace(buffer);

    if (UNLIKELY(buffer > helper->buffer->value + helper->buffer->len -
                               MIN_REQUEST_SIZE))
        return HTTP_BAD_REQUEST;

    char *path = identify_http_method(request, buffer);
    if (UNLIKELY(!path))
        return HTTP_NOT_ALLOWED;

    buffer = identify_http_path(request, path);
    if (UNLIKELY(!buffer))
        return HTTP_BAD_REQUEST;

    if (UNLIKELY(!parse_headers(helper, buffer)))
        return HTTP_BAD_REQUEST;

    ssize_t decoded_len = url_decode(request->url.value);
    if (UNLIKELY(decoded_len < 0))
        return HTTP_BAD_REQUEST;
    request->original_url.len = request->url.len = (size_t)decoded_len;

    parse_connection_header(request);

    return HTTP_OK;
}

static enum lwan_http_status
prepare_websocket_handshake(struct lwan_request *request, char **encoded)
{
    static const unsigned char websocket_uuid[] =
        "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    unsigned char digest[20];
    sha1_context ctx;

    if (UNLIKELY(request->flags & RESPONSE_SENT_HEADERS))
        return HTTP_INTERNAL_ERROR;

    if (UNLIKELY(!(request->conn->flags & CONN_IS_UPGRADE)))
        return HTTP_BAD_REQUEST;

    const char *upgrade = lwan_request_get_header(request, "Upgrade");
    if (UNLIKELY(!upgrade || !streq(upgrade, "websocket")))
        return HTTP_BAD_REQUEST;

    const char *sec_websocket_key =
        lwan_request_get_header(request, "Sec-WebSocket-Key");
    if (UNLIKELY(!sec_websocket_key))
        return HTTP_BAD_REQUEST;

    const size_t sec_websocket_key_len = strlen(sec_websocket_key);
    if (base64_encoded_len(16) != sec_websocket_key_len)
        return HTTP_BAD_REQUEST;
    if (UNLIKELY(!base64_validate((void *)sec_websocket_key, sec_websocket_key_len)))
        return HTTP_BAD_REQUEST;

    sha1_init(&ctx);
    sha1_update(&ctx, (void *)sec_websocket_key, sec_websocket_key_len);
    sha1_update(&ctx, websocket_uuid, sizeof(websocket_uuid) - 1);
    sha1_finalize(&ctx, digest);

    *encoded = (char *)base64_encode(digest, sizeof(digest), NULL);
    return LIKELY(*encoded) ? HTTP_SWITCHING_PROTOCOLS : HTTP_INTERNAL_ERROR;
}

enum lwan_http_status
lwan_request_websocket_upgrade(struct lwan_request *request)
{
    char header_buf[DEFAULT_HEADERS_SIZE];
    size_t header_buf_len;
    char *encoded;

    enum lwan_http_status r = prepare_websocket_handshake(request, &encoded);
    if (r != HTTP_SWITCHING_PROTOCOLS)
        return r;

    request->flags |= RESPONSE_NO_CONTENT_LENGTH;
    header_buf_len = lwan_prepare_response_header_full(
        request, HTTP_SWITCHING_PROTOCOLS, header_buf, sizeof(header_buf),
        (struct lwan_key_value[]){
            /* Connection: Upgrade is implicit if conn->flags & CONN_IS_UPGRADE */
            {.key = "Sec-WebSocket-Accept", .value = encoded},
            {.key = "Upgrade", .value = "websocket"},
            {},
        });
    free(encoded);
    if (UNLIKELY(!header_buf_len))
        return HTTP_INTERNAL_ERROR;

    request->conn->flags |= CONN_IS_WEBSOCKET;
    lwan_send(request, header_buf, header_buf_len, 0);

    return HTTP_SWITCHING_PROTOCOLS;
}

static inline bool request_has_body(const struct lwan_request *request)
{
    /* 3rd bit set in method: request method has body. See lwan.h,
     * definition of FOR_EACH_REQUEST_METHOD() for more info. */
    return lwan_request_get_method(request) & 1 << 3;
}

static enum lwan_http_status
maybe_read_body_data(const struct lwan_url_map *url_map,
                     struct lwan_request *request)
{
    int status = 0;

    if (url_map->flags & HANDLER_EXPECTS_BODY_DATA) {
        status = read_body_data(request);
        if (status > 0)
            return (enum lwan_http_status)status;
    }

    /* Instead of trying to read the body here, which will require
     * us to allocate and read potentially a lot of bytes, force
     * this connection to be closed as soon as we send a "not allowed"
     * response.  */
    request->conn->flags &= ~CONN_IS_KEEP_ALIVE;

    if (status < 0) {
        status = -status;
        return (enum lwan_http_status)status;
    }

    return HTTP_NOT_ALLOWED;
}

static enum lwan_http_status prepare_for_response(const struct lwan_url_map *url_map,
                                                  struct lwan_request *request)
{
    request->url.value += url_map->prefix_len;
    request->url.len -= url_map->prefix_len;
    while (*request->url.value == '/' && request->url.len > 0) {
        request->url.value++;
        request->url.len--;
    }

    if (UNLIKELY(url_map->flags & HANDLER_MUST_AUTHORIZE)) {
        if (!lwan_http_authorize_urlmap(request, url_map))
            return HTTP_NOT_AUTHORIZED;
    }

    if (UNLIKELY(request_has_body(request)))
        return maybe_read_body_data(url_map, request);

    return HTTP_OK;
}

static bool handle_rewrite(struct lwan_request *request)
{
    struct lwan_request_parser_helper *helper = request->helper;

    request->flags &= ~RESPONSE_URL_REWRITTEN;

    find_query_string(request, request->url.value + request->url.len);

    helper->urls_rewritten++;
    if (UNLIKELY(helper->urls_rewritten > 4)) {
        lwan_default_response(request, HTTP_INTERNAL_ERROR);
        return false;
    }

    return true;
}

const char *lwan_request_get_method_str(const struct lwan_request *request)
{
#define GENERATE_CASE_STMT(upper, lower, mask, constant, probability)          \
    case REQUEST_METHOD_##upper:                                               \
        return #upper;

    switch (lwan_request_get_method(request)) {
        FOR_EACH_REQUEST_METHOD(GENERATE_CASE_STMT)
    default:
        return "UNKNOWN";
    }
#undef GENERATE_CASE_STMT
}

#ifndef NDEBUG
static void log_request(struct lwan_request *request,
                        enum lwan_http_status status,
                        double time_to_read_request,
                        double time_to_process_request)
{
    char ip_buffer[INET6_ADDRSTRLEN];

    lwan_status_debug(
        "%s [%s] %016lx \"%s %s HTTP/%s\" %d %s (r:%.3fms p:%.3fms)",
        lwan_request_get_remote_address(request, ip_buffer),
        request->conn->thread->date.date, lwan_request_get_id(request),
        lwan_request_get_method_str(request), request->original_url.value,
        request->flags & REQUEST_IS_HTTP_1_0 ? "1.0" : "1.1", status,
        request->response.mime_type, time_to_read_request,
        time_to_process_request);
}
#else
#define log_request(...)
#endif

#ifndef NDEBUG
static struct timespec current_precise_monotonic_timespec(void)
{
    struct timespec now;

    if (UNLIKELY(clock_gettime(CLOCK_MONOTONIC, &now) < 0)) {
        lwan_status_perror("clock_gettime");
        return (struct timespec){};
    }

    return now;
}

static double elapsed_time_ms(const struct timespec then)
{
    const struct timespec now = current_precise_monotonic_timespec();
    struct timespec diff = {
        .tv_sec = now.tv_sec - then.tv_sec,
        .tv_nsec = now.tv_nsec - then.tv_nsec,
    };

    if (diff.tv_nsec < 0) {
        diff.tv_sec--;
        diff.tv_nsec += 1000000000l;
    }

    return (double)diff.tv_sec / 1000.0 + (double)diff.tv_nsec / 1000000.0;
}
#endif

void lwan_process_request(struct lwan *l, struct lwan_request *request)
{
    enum lwan_http_status status;
    struct lwan_url_map *url_map;

#ifndef NDEBUG
    struct timespec request_read_begin_time = current_precise_monotonic_timespec();
#endif
    status = read_request(request);

#ifndef NDEBUG
    double time_to_read_request = elapsed_time_ms(request_read_begin_time);

    struct timespec request_begin_time = current_precise_monotonic_timespec();
#endif
    if (UNLIKELY(status != HTTP_OK)) {
        /* If read_request() returns any error at this point, it's probably
         * better to just send an error response and abort the coroutine and
         * let the client handle the error instead: we don't have
         * information to even log the request because it has not been
         * parsed yet at this stage.  Even if there are other requests waiting
         * in the pipeline, this seems like the safer thing to do.  */
        request->conn->flags &= ~CONN_IS_KEEP_ALIVE;
        lwan_default_response(request, status);
        /* Let process_request_coro() gracefully close the connection. */
        return;
    }

    status = parse_http_request(request);
    if (UNLIKELY(status != HTTP_OK))
        goto log_and_return;

lookup_again:
    url_map = lwan_trie_lookup_prefix(&l->url_map_trie, request->url.value);
    if (UNLIKELY(!url_map)) {
        status = HTTP_NOT_FOUND;
        goto log_and_return;
    }

    status = prepare_for_response(url_map, request);
    if (UNLIKELY(status != HTTP_OK))
        goto log_and_return;

    status = url_map->handler(request, &request->response, url_map->data);
    if (UNLIKELY(url_map->flags & HANDLER_CAN_REWRITE_URL)) {
        if (request->flags & RESPONSE_URL_REWRITTEN) {
            if (LIKELY(handle_rewrite(request)))
                goto lookup_again;
            return;
        }
    }

log_and_return:
    lwan_response(request, status);

    log_request(request, status, time_to_read_request, elapsed_time_ms(request_begin_time));
}

static inline void *
value_lookup(const struct lwan_key_value_array *array, const char *key)
{
    const struct lwan_array *la = (const struct lwan_array *)array;

    if (LIKELY(la->elements)) {
        struct lwan_key_value k = { .key = (char *)key };
        struct lwan_key_value *entry;

        entry = bsearch(&k, la->base, la->elements, sizeof(k), key_value_compare);
        if (LIKELY(entry))
            return entry->value;
    }

    return NULL;
}

const char *lwan_request_get_query_param(struct lwan_request *request,
                                         const char *key)
{
    return value_lookup(lwan_request_get_query_params(request), key);
}

const char *lwan_request_get_post_param(struct lwan_request *request,
                                        const char *key)
{
    return value_lookup(lwan_request_get_post_params(request), key);
}

const char *lwan_request_get_cookie(struct lwan_request *request,
                                    const char *key)
{
    return value_lookup(lwan_request_get_cookies(request), key);
}

const char *
lwan_request_get_header_from_helper(struct lwan_request_parser_helper *helper,
                                    const char *header)
{
    const size_t header_len = strlen(header);
    const size_t header_len_with_separator =
        header_len + HEADER_VALUE_SEPARATOR_LEN;

    assert(strchr(header, ':') == NULL);

    for (size_t i = 0; i < helper->n_header_start; i++) {
        const char *start = helper->header_start[i];
        char *end = helper->header_start[i + 1] - HEADER_TERMINATOR_LEN;

        if (UNLIKELY((size_t)(end - start) < header_len_with_separator))
            continue;

        STRING_SWITCH_SMALL (start + header_len) {
        case STR2_INT(':', ' '):
            if (!strncasecmp(start, header, header_len)) {
                *end = '\0';
                return start + header_len_with_separator;
            }
        }
    }

    return NULL;
}

inline const char *lwan_request_get_header(struct lwan_request *request,
                                           const char *header)
{
    return lwan_request_get_header_from_helper(request->helper, header);
}

const char *lwan_request_get_host(struct lwan_request *request)
{
    const struct lwan_request_parser_helper *helper = request->helper;

    return helper->host.len ? helper->host.value : NULL;
}

ALWAYS_INLINE int
lwan_connection_get_fd(const struct lwan *lwan, const struct lwan_connection *conn)
{
    return (int)(intptr_t)(conn - lwan->conns);
}

const char *
lwan_request_get_remote_address_and_port(struct lwan_request *request,
                                         char buffer[static INET6_ADDRSTRLEN],
                                         uint16_t *port)
{
    struct sockaddr_storage non_proxied_addr = {.ss_family = AF_UNSPEC};
    struct sockaddr_storage *sock_addr;

    *port = 0;

    if (request->flags & REQUEST_PROXIED) {
        sock_addr = (struct sockaddr_storage *)&request->proxy->from;

        if (UNLIKELY(sock_addr->ss_family == AF_UNSPEC)) {
            static const char unspecified[] = "*unspecified*";

            static_assert(sizeof(unspecified) <= INET6_ADDRSTRLEN,
                          "Enough space for unspecified address family");
            return memcpy(buffer, unspecified, sizeof(unspecified));
        }
    } else {
        socklen_t sock_len = sizeof(non_proxied_addr);

        sock_addr = &non_proxied_addr;

        if (UNLIKELY(getpeername(request->fd, (struct sockaddr *)sock_addr,
                                 &sock_len) < 0)) {
            return NULL;
        }
    }

    if (sock_addr->ss_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)sock_addr;
        *port = ntohs(sin->sin_port);
        return inet_ntop(AF_INET, &sin->sin_addr, buffer, INET6_ADDRSTRLEN);
    }

    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sock_addr;
    *port = ntohs(sin6->sin6_port);
    return inet_ntop(AF_INET6, &sin6->sin6_addr, buffer, INET6_ADDRSTRLEN);
}

const char *
lwan_request_get_remote_address(struct lwan_request *request,
                                char buffer[static INET6_ADDRSTRLEN])
{
    uint16_t port;
    return lwan_request_get_remote_address_and_port(request, buffer, &port);
}

static void remove_sleep(void *data1, void *data2)
{
    static const enum lwan_connection_flags suspended_sleep =
        CONN_SUSPENDED | CONN_HAS_REMOVE_SLEEP_DEFER;
    struct timeouts *wheel = data1;
    struct timeout *timeout = data2;
    struct lwan_request *request =
        container_of(timeout, struct lwan_request, timeout);

    if ((request->conn->flags & suspended_sleep) == suspended_sleep)
        timeouts_del(wheel, timeout);

    request->conn->flags &= ~CONN_HAS_REMOVE_SLEEP_DEFER;
}

void lwan_request_sleep(struct lwan_request *request, uint64_t ms)
{
    struct lwan_connection *conn = request->conn;
    struct timeouts *wheel = conn->thread->wheel;
    struct timespec now;
    coro_deferred defer = -1;

    /* We need to update the timer wheel right now because
     * a request might have requested to sleep a long time
     * before it was being serviced -- causing the timeout
     * to essentially be a no-op. */
    if (UNLIKELY(clock_gettime(monotonic_clock_id, &now) < 0))
        lwan_status_critical("Could not get monotonic time");
    timeouts_update(wheel, (timeout_t)(now.tv_sec * 1000 + now.tv_nsec / 1000000));

    request->timeout = (struct timeout) {};
    timeouts_add(wheel, &request->timeout, ms);

    if (!(conn->flags & CONN_HAS_REMOVE_SLEEP_DEFER)) {
        defer = coro_defer2(conn->coro, remove_sleep, wheel, &request->timeout);
        conn->flags |= CONN_HAS_REMOVE_SLEEP_DEFER;
    }

    coro_yield(conn->coro, CONN_CORO_SUSPEND);

    if (defer > 0)
        coro_defer_fire_and_disarm(conn->coro, defer);
}

ALWAYS_INLINE int
lwan_request_get_range(struct lwan_request *request, off_t *from, off_t *to)
{
    struct lwan_request_parser_helper *helper = request->helper;

    if (!(request->flags & REQUEST_PARSED_RANGE)) {
        parse_range(helper);
        request->flags |= REQUEST_PARSED_RANGE;
    }

    if (LIKELY(helper->range.raw.len)) {
        *from = helper->range.from;
        *to = helper->range.to;
        return 0;
    }

    return -ENOENT;
}

ALWAYS_INLINE int
lwan_request_get_if_modified_since(struct lwan_request *request, time_t *value)
{
    struct lwan_request_parser_helper *helper = request->helper;

    if (!(request->flags & REQUEST_PARSED_IF_MODIFIED_SINCE)) {
        parse_if_modified_since(helper);
        request->flags |= REQUEST_PARSED_IF_MODIFIED_SINCE;
    }

    if (LIKELY(helper->if_modified_since.raw.len)) {
        *value = helper->if_modified_since.parsed;
        return 0;
    }

    return -ENOENT;
}

ALWAYS_INLINE const struct lwan_value *
lwan_request_get_request_body(struct lwan_request *request)
{
    return &request->helper->body_data;
}

ALWAYS_INLINE const struct lwan_value *
lwan_request_get_content_type(struct lwan_request *request)
{
    return &request->helper->content_type;
}

ALWAYS_INLINE const struct lwan_key_value_array *
lwan_request_get_cookies(struct lwan_request *request)
{
    if (!(request->flags & REQUEST_PARSED_COOKIES)) {
        parse_cookies(request);
        request->flags |= REQUEST_PARSED_COOKIES;
    }

    return &request->helper->cookies;
}

ALWAYS_INLINE const struct lwan_key_value_array *
lwan_request_get_query_params(struct lwan_request *request)
{
    if (!(request->flags & REQUEST_PARSED_QUERY_STRING)) {
        parse_query_string(request);
        request->flags |= REQUEST_PARSED_QUERY_STRING;
    }

    return &request->helper->query_params;
}

ALWAYS_INLINE const struct lwan_key_value_array *
lwan_request_get_post_params(struct lwan_request *request)
{
    if (!(request->flags & REQUEST_PARSED_FORM_DATA)) {
        parse_form_data(request);
        request->flags |= REQUEST_PARSED_FORM_DATA;
    }

    return &request->helper->post_params;
}

ALWAYS_INLINE enum lwan_request_flags
lwan_request_get_accept_encoding(struct lwan_request *request)
{
    if (!(request->flags & REQUEST_PARSED_ACCEPT_ENCODING)) {
        parse_accept_encoding(request);
        request->flags |= REQUEST_PARSED_ACCEPT_ENCODING;
    }

    return request->flags & REQUEST_ACCEPT_MASK;
}

#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
static int useless_coro_for_fuzzing(struct coro *c __attribute__((unused)),
                                    void *data __attribute__((unused)))
{
    return 0;
}

static bool request_seems_complete(struct lwan_request_parser_helper *helper)
{
    return read_request_finalizer_from_helper(helper->buffer, helper, 1,
                                              false) == FINALIZER_DONE;
}

__attribute__((used)) int fuzz_parse_http_request(const uint8_t *data,
                                                  size_t length)
{
    static struct coro_switcher switcher;
    static struct coro *coro;
    static char *header_start[N_HEADER_START];
    static char data_copy[32767] = {0};

    if (length > sizeof(data_copy))
        length = sizeof(data_copy);
    memcpy(data_copy, data, length);

    if (!coro) {
        coro = coro_new(&switcher, useless_coro_for_fuzzing, NULL);

        lwan_job_thread_init();
        lwan_http_authorize_init();
    }

    struct lwan_request_parser_helper helper = {
        .buffer = &(struct lwan_value){.value = data_copy, .len = length},
        .header_start = header_start,
        .error_when_n_packets = 2,
    };
    struct lwan_connection conn = {.coro = coro};
    struct lwan_proxy proxy = {};
    struct lwan_request request = {
        .helper = &helper,
        .conn = &conn,
        .flags = REQUEST_ALLOW_PROXY_REQS,
        .proxy = &proxy,
    };

    /* If the finalizer isn't happy with a request, there's no point in
     * going any further with parsing it. */
    if (!request_seems_complete(&helper))
        return 0;

    /* client_read() NUL-terminates the string */
    data_copy[length - 1] = '\0';

    if (parse_http_request(&request) != HTTP_OK)
        return 0;

    off_t trash1;
    time_t trash2;
    char *trash3;
    size_t gen = coro_deferred_get_generation(coro);

    /* Only pointers were set in helper struct; actually parse them here. */
    parse_accept_encoding(&request);

    /* Requesting these items will force them to be parsed, and also
     * exercise the lookup function. */
    LWAN_NO_DISCARD(lwan_request_get_header(&request, "Non-Existing-Header"));

    /* Usually existing short header */
    LWAN_NO_DISCARD(lwan_request_get_header(&request, "Host"));

    LWAN_NO_DISCARD(lwan_request_get_cookie(&request, "Non-Existing-Cookie"));
    /* Set by some tests */
    LWAN_NO_DISCARD(lwan_request_get_cookie(&request, "FOO"));

    LWAN_NO_DISCARD(
        lwan_request_get_query_param(&request, "Non-Existing-Query-Param"));

    LWAN_NO_DISCARD(
        lwan_request_get_post_param(&request, "Non-Existing-Post-Param"));

    lwan_request_get_range(&request, &trash1, &trash1);
    LWAN_NO_DISCARD(trash1);

    lwan_request_get_if_modified_since(&request, &trash2);
    LWAN_NO_DISCARD(trash2);

    enum lwan_http_status handshake =
        prepare_websocket_handshake(&request, &trash3);
    LWAN_NO_DISCARD(trash3);
    if (handshake == HTTP_SWITCHING_PROTOCOLS)
        free(trash3);

    LWAN_NO_DISCARD(lwan_http_authorize(&request, "Fuzzy Realm", "/dev/null"));

    coro_deferred_run(coro, gen);

    return 0;
}
#endif

static inline int64_t
make_async_yield_value(int fd, enum lwan_connection_coro_yield event)
{
    return (int64_t)(((uint64_t)fd << 32 | event));
}

static inline void async_await_fd(struct coro *coro,
                                  int fd,
                                  enum lwan_connection_coro_yield events)
{
    assert(events >= CONN_CORO_ASYNC_AWAIT_READ &&
           events <= CONN_CORO_ASYNC_AWAIT_READ_WRITE);

    return (void)coro_yield(coro, make_async_yield_value(fd, events));
}

void lwan_request_await_read(struct lwan_request *r, int fd)
{
    return async_await_fd(r->conn->coro, fd, CONN_CORO_ASYNC_AWAIT_READ);
}

void lwan_request_await_write(struct lwan_request *r, int fd)
{
    return async_await_fd(r->conn->coro, fd, CONN_CORO_ASYNC_AWAIT_WRITE);
}

void lwan_request_await_read_write(struct lwan_request *r, int fd)
{
    return async_await_fd(r->conn->coro, fd, CONN_CORO_ASYNC_AWAIT_READ_WRITE);
}

ssize_t lwan_request_async_read_flags(
    struct lwan_request *request, int fd, void *buf, size_t len, int flags)
{
    while (true) {
        ssize_t r = recv(fd, buf, len, MSG_DONTWAIT | MSG_NOSIGNAL | flags);

        if (r < 0) {
            switch (errno) {
            case EWOULDBLOCK:
                lwan_request_await_read(request, fd);
                /* Fallthrough */
            case EINTR:
                continue;
            case EPIPE:
                return -errno;
            }
        }

        return r;
    }
}

ssize_t lwan_request_async_read(struct lwan_request *request,
                                int fd,
                                void *buf,
                                size_t len)
{
    return lwan_request_async_read_flags(request, fd, buf, len, 0);
}

ssize_t lwan_request_async_write(struct lwan_request *request,
                                 int fd,
                                 const void *buf,
                                 size_t len)
{
    while (true) {
        ssize_t r = send(fd, buf, len, MSG_DONTWAIT|MSG_NOSIGNAL);

        if (r < 0) {
            switch (errno) {
            case EWOULDBLOCK:
                lwan_request_await_write(request, fd);
                /* Fallthrough */
            case EINTR:
                continue;
            case EPIPE:
                return -errno;
            }
        }

        return r;
    }
}

ssize_t lwan_request_async_writev(struct lwan_request *request,
                                  int fd,
                                  struct iovec *iov,
                                  int iov_count)
{
    ssize_t total_written = 0;
    int curr_iov = 0;

    for (int tries = 10; tries;) {
        const int remaining_len = (int)(iov_count - curr_iov);
        ssize_t written;

        if (remaining_len == 1) {
            const struct iovec *vec = &iov[curr_iov];
            return lwan_request_async_write(request, fd, vec->iov_base,
                                            vec->iov_len);
        }

        written = writev(fd, iov + curr_iov, remaining_len);
        if (UNLIKELY(written < 0)) {
            /* FIXME: Consider short writes as another try as well? */
            tries--;

            switch (errno) {
            case EAGAIN:
            case EINTR:
                goto try_again;
            default:
                goto out;
            }
        }

        total_written += written;

        while (curr_iov < iov_count &&
               written >= (ssize_t)iov[curr_iov].iov_len) {
            written -= (ssize_t)iov[curr_iov].iov_len;
            curr_iov++;
        }

        if (curr_iov == iov_count)
            return total_written;

        iov[curr_iov].iov_base = (char *)iov[curr_iov].iov_base + written;
        iov[curr_iov].iov_len -= (size_t)written;

    try_again:
        lwan_request_await_write(request, fd);
    }

out:
    coro_yield(request->conn->coro, CONN_CORO_ABORT);
    __builtin_unreachable();
}

void lwan_request_foreach_header_for_cgi(struct lwan_request *request,
                                         void (*cb)(const char *header_name,
                                                    size_t header_len,
                                                    const char *value,
                                                    size_t value_len,
                                                    void *user_data),
                                         void *user_data)
{
    struct lwan_request_parser_helper *helper = request->helper;
    char **header_start = helper->header_start;
    size_t n_header_start = helper->n_header_start;

    for (size_t i = 0; i < n_header_start; i++) {
        const char *header = header_start[i];
        const char *next_header = header_start[i + 1];
        const char *colon = memchr(header, ':', 127 - sizeof("HTTP_: ") - 1);
        char header_name[128];
        int r;

        if (!colon)
            continue;

        const size_t header_len = (size_t)(colon - header);
        const size_t value_len = (size_t)(next_header - colon - 4);

        r = snprintf(header_name, sizeof(header_name), "HTTP_%.*s",
                     (int)header_len, header);
        if (r < 0 || r >= (int)sizeof(header_name))
            continue;

        /* FIXME: RFC7230/RFC3875 compliance */
        for (char *p = header_name; *p; p++) {
            if (isalpha(*p))
                *p &= ~0x20;
            else if (!isdigit(*p))
                *p = '_';
        }

        if (streq(header_name, "HTTP_PROXY")) {
            /* Mitigation for https://httpoxy.org */
            continue;
        }

        cb(header_name, header_len + sizeof("HTTP_") - 1, colon + 2, value_len,
           user_data);
    }
}
