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
#include <unistd.h>

#include "lwan-private.h"

#include "base64.h"
#include "list.h"
#include "lwan-config.h"
#include "lwan-http-authorize.h"
#include "lwan-io-wrappers.h"
#include "sha1.h"

#define N_HEADER_START 64

enum lwan_read_finalizer {
    FINALIZER_DONE,
    FINALIZER_TRY_AGAIN,
    FINALIZER_YIELD_TRY_AGAIN,
    FINALIZER_ERROR_TOO_LARGE,
    FINALIZER_ERROR_TIMEOUT
};

struct lwan_request_parser_helper {
    struct lwan_value *buffer;		/* The whole request buffer */
    char *next_request;			/* For pipelined requests */

    char **header_start;		/* Headers: n: start, n+1: end */
    size_t n_header_start;		/* len(header_start) */

    struct lwan_value accept_encoding;	/* Accept-Encoding: */

    struct lwan_value cookie;		/* Cookie: */
    struct lwan_value query_string;	/* Stuff after ? and before # */
    struct lwan_value fragment;		/* Stuff after # */

    struct lwan_value post_data;	/* Request body for POST */
    struct lwan_value content_type;	/* Content-Type: for POST */
    struct lwan_value content_length;	/* Content-Length: */

    struct lwan_value connection;	/* Connection: */

    struct { /* If-Modified-Since: */
        struct lwan_value raw;
        time_t parsed;
    } if_modified_since;

    struct { /* Range: */
        struct lwan_value raw;
        off_t from, to;
    } range;

    time_t error_when_time;		/* Time to abort request read */
    int error_when_n_packets;		/* Max. number of packets */
    int urls_rewritten;			/* Times URLs have been rewritten */
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
    case MULTICHAR_CONSTANT('T', 'C', 'P', '4'): {
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
    case MULTICHAR_CONSTANT('T', 'C', 'P', '6'): {
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

static ALWAYS_INLINE char *identify_http_method(struct lwan_request *request,
                                                char *buffer)
{
#define GENERATE_CASE_STMT(upper, lower, mask, constant)                       \
    case constant:                                                             \
        request->flags |= (mask);                                              \
        return buffer + sizeof(#upper);

    STRING_SWITCH (buffer) {
        FOR_EACH_REQUEST_METHOD(GENERATE_CASE_STMT)
    }

#undef GENERATE_CASE_STMT

    return NULL;
}

static ALWAYS_INLINE char decode_hex_digit(char ch)
{
    static const char hex_digit_tbl[256] = {
        ['0'] = 0,  ['1'] = 1,  ['2'] = 2,  ['3'] = 3,  ['4'] = 4,  ['5'] = 5,
        ['6'] = 6,  ['7'] = 7,  ['8'] = 8,  ['9'] = 9,  ['a'] = 10, ['b'] = 11,
        ['c'] = 12, ['d'] = 13, ['e'] = 14, ['f'] = 15, ['A'] = 10, ['B'] = 11,
        ['C'] = 12, ['D'] = 13, ['E'] = 14, ['F'] = 15,
    };
    return hex_digit_tbl[(unsigned char)ch];
}

static ssize_t url_decode(char *str)
{
    if (UNLIKELY(!str))
        return -EINVAL;

    char *ch, *decoded;
    for (decoded = ch = str; *ch; ch++) {
        if (*ch == '%') {
            char tmp =
                (char)(decode_hex_digit(ch[1]) << 4 | decode_hex_digit(ch[2]));

            if (UNLIKELY(!tmp))
                return -EINVAL;

            *decoded++ = tmp;
            ch += 2;
        } else if (*ch == '+') {
            *decoded++ = ' ';
        } else {
            *decoded++ = *ch;
        }
    }

    *decoded = '\0';
    return (ssize_t)(decoded - str);
}

static int
key_value_compare(const void *a, const void *b)
{
    return strcmp(((struct lwan_key_value *)a)->key, ((struct lwan_key_value *)b)->key);
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

    if (!helper_value->len)
        return;

    lwan_key_value_array_init(array);
    /* Calling lwan_key_value_array_reset() twice is fine, so even if 'goto
     * error' is executed in this function, nothing bad should happen.  */
    coro_defer(request->conn->coro, reset_key_value_array, array);

    do {
        char *key, *value;

        while (*ptr == ' ' || *ptr == separator)
            ptr++;
        if (UNLIKELY(*ptr == '\0'))
            goto error;

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
    lwan_key_value_array_reset(array);
}

static ssize_t
identity_decode(char *input __attribute__((unused)))
{
    return 1;
}

static void parse_cookies(struct lwan_request *request)
{
    parse_key_values(request, &request->helper->cookie, &request->cookies,
                     identity_decode, ';');
}

static void parse_query_string(struct lwan_request *request)
{
    parse_key_values(request, &request->helper->query_string,
                     &request->query_params, url_decode, '&');
}

static void parse_post_data(struct lwan_request *request)
{
    struct lwan_request_parser_helper *helper = request->helper;
    static const char content_type[] = "application/x-www-form-urlencoded";

    if (helper->content_type.len < sizeof(content_type) - 1)
        return;
    if (UNLIKELY(strncmp(helper->content_type.value, content_type,
                         sizeof(content_type) - 1)))
        return;

    parse_key_values(request, &helper->post_data, &request->post_params,
                     url_decode, '&');
}

static void parse_fragment_and_query(struct lwan_request *request,
                                     const char *space)
{
    struct lwan_request_parser_helper *helper = request->helper;

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
        helper->query_string.len =
            (size_t)((fragment ? fragment : space) - query_string - 1);
        request->url.len -= helper->query_string.len + 1;
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
    parse_fragment_and_query(request, space);
    request->original_url = request->url;

    *space++ = '\0';

    STRING_SWITCH_LARGE(space) {
    case MULTICHAR_CONSTANT_LARGE('H','T','T','P','/','1','.','0'):
        request->flags |= REQUEST_IS_HTTP_1_0;
        break;
    case MULTICHAR_CONSTANT_LARGE('H','T','T','P','/','1','.','1'):
        break;
    default:
        return NULL;
    }

    return end_of_line + 1;
}

#define HEADER_LENGTH(hdr)                                                     \
    ({                                                                         \
        if (UNLIKELY(end - sizeof(hdr) + 1 < p))                               \
            continue;                                                          \
        sizeof(hdr) - 1;                                                       \
    })

#define HEADER(hdr)                                                            \
    ({                                                                         \
        p += HEADER_LENGTH(hdr);                                               \
        if (UNLIKELY(string_as_int16(p) !=                                     \
                     MULTICHAR_CONSTANT_SMALL(':', ' ')))                      \
            continue;                                                          \
        *end = '\0';                                                           \
        char *value = p + sizeof(": ") - 1;                                    \
        (struct lwan_value){.value = value, .len = (size_t)(end - value)};     \
    })

static bool parse_headers(struct lwan_request_parser_helper *helper,
                          char *buffer)
{
    char *buffer_end = helper->buffer->value + helper->buffer->len;
    char **header_start = helper->header_start;
    size_t n_headers = 0;
    char *p;

    for (p = buffer + 1;;) {
        char *next_chr = p;
        char *next_hdr = memchr(next_chr, '\r', (size_t)(buffer_end - p));

        if (!next_hdr)
            break;

        if (next_chr == next_hdr) {
            if (buffer_end - next_chr > 2) {
                STRING_SWITCH_SMALL (next_hdr) {
                case MULTICHAR_CONSTANT_SMALL('\r', '\n'):
                    helper->next_request = next_hdr + 2;
                }
            }
            break;
        }

        /* Is there at least a space for a minimal (H)eader and a (V)alue? */
        if (LIKELY(next_hdr - next_chr > (ptrdiff_t)(sizeof("H: V") - 1))) {
            header_start[n_headers++] = next_chr;
            header_start[n_headers++] = next_hdr;
        } else {
            /* Better to abort early if there's no space. */
            return false;
        }

        p = next_hdr + 2;

        if (n_headers >= N_HEADER_START || p >= buffer_end) {
            helper->n_header_start = 0;
            return false;
        }
    }

    for (size_t i = 0; i < n_headers; i += 2) {
        char *end = header_start[i + 1];

        p = header_start[i];

        STRING_SWITCH_L (p) {
        case MULTICHAR_CONSTANT_L('A', 'c', 'c', 'e'):
            p += HEADER_LENGTH("Accept");

            STRING_SWITCH_L (p) {
            case MULTICHAR_CONSTANT_L('-', 'E', 'n', 'c'):
                helper->accept_encoding = HEADER("-Encoding");
                break;
            }
            break;
        case MULTICHAR_CONSTANT_L('C', 'o', 'n', 'n'):
            helper->connection = HEADER("Connection");
            break;
        case MULTICHAR_CONSTANT_L('C', 'o', 'n', 't'):
            p += HEADER_LENGTH("Content");

            STRING_SWITCH_L (p) {
            case MULTICHAR_CONSTANT_L('-', 'T', 'y', 'p'):
                helper->content_type = HEADER("-Type");
                break;
            case MULTICHAR_CONSTANT_L('-', 'L', 'e', 'n'):
                helper->content_length = HEADER("-Length");
                break;
            }
            break;
        case MULTICHAR_CONSTANT_L('C', 'o', 'o', 'k'):
            helper->cookie = HEADER("Cookie");
            break;
        case MULTICHAR_CONSTANT_L('I', 'f', '-', 'M'):
            helper->if_modified_since.raw = HEADER("If-Modified-Since");
            break;
        case MULTICHAR_CONSTANT_L('R', 'a', 'n', 'g'):
            helper->range.raw = HEADER("Range");
            break;
        }
    }

    helper->n_header_start = n_headers;
    return true;
}
#undef HEADER_LENGTH
#undef HEADER

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

static void
parse_range(struct lwan_request_parser_helper *helper)
{
    if (UNLIKELY(helper->range.raw.len <= (sizeof("bytes=") - 1)))
        return;

    char *range = helper->range.raw.value;
    if (UNLIKELY(strncmp(range, "bytes=", sizeof("bytes=") - 1)))
        return;

    range += sizeof("bytes=") - 1;
    uint64_t from, to;

    if (sscanf(range, "%"SCNu64"-%"SCNu64, &from, &to) == 2) {
        if (UNLIKELY(from > OFF_MAX || to > OFF_MAX))
            goto invalid_range;

        helper->range.from = (off_t)from;
        helper->range.to = (off_t)to;
    } else if (sscanf(range, "-%"SCNu64, &to) == 1) {
        if (UNLIKELY(to > OFF_MAX))
            goto invalid_range;

        helper->range.from = 0;
        helper->range.to = (off_t)to;
    } else if (sscanf(range, "%"SCNu64"-", &from) == 1) {
        if (UNLIKELY(from > OFF_MAX))
            goto invalid_range;

        helper->range.from = (off_t)from;
        helper->range.to = -1;
    } else {
invalid_range:
        helper->range.from = -1;
        helper->range.to = -1;
    }
}

static void
parse_accept_encoding(struct lwan_request *request)
{
    struct lwan_request_parser_helper *helper = request->helper;

    if (!helper->accept_encoding.len)
        return;

    for (const char *p = helper->accept_encoding.value; *p; p++) {
        STRING_SWITCH(p) {
        case MULTICHAR_CONSTANT('d','e','f','l'):
        case MULTICHAR_CONSTANT(' ','d','e','f'):
            request->flags |= REQUEST_ACCEPT_DEFLATE;
            break;
        case MULTICHAR_CONSTANT('g','z','i','p'):
        case MULTICHAR_CONSTANT(' ','g','z','i'):
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
        case MULTICHAR_CONSTANT_L('k','e','e','p'):
        case MULTICHAR_CONSTANT_L(' ', 'k','e','e'):
            has_keep_alive = true;
            break;
        case MULTICHAR_CONSTANT_L('c','l','o','s'):
        case MULTICHAR_CONSTANT_L(' ', 'c','l','o'):
            has_close = true;
            break;
        case MULTICHAR_CONSTANT_L('u','p','g','r'):
        case MULTICHAR_CONSTANT_L(' ', 'u','p','g'):
            request->conn->flags |= CONN_IS_UPGRADE;
            break;
        }

        if (!(p = strchr(p, ',')))
            break;
    }

out:
    if (LIKELY(!(request->flags & REQUEST_IS_HTTP_1_0)))
        has_keep_alive = !has_close;

    if (has_keep_alive)
        request->conn->flags |= CONN_KEEP_ALIVE;
    else
        request->conn->flags &= ~CONN_KEEP_ALIVE;
}

#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
static void save_to_corpus_for_fuzzing(const struct lwan_value *orig_buffer)
{
    struct lwan_value buffer = *orig_buffer;
    char corpus_name[PATH_MAX];
    const char *crlfcrlf;
    int fd;

    if (!(crlfcrlf = memmem(buffer.value, buffer.len, "\r\n\r\n", 4)))
        return;
    buffer.len = (size_t)(crlfcrlf - buffer.value + 4);

try_another_file_name:
    snprintf(corpus_name, sizeof(corpus_name), "corpus-request-%d", rand());

    fd = open(corpus_name, O_WRONLY | O_CLOEXEC | O_CREAT | O_EXCL, 0644);
    if (fd < 0)
        goto try_another_file_name;

    for (ssize_t total_written = 0; total_written != (ssize_t)buffer.len;) {
        ssize_t r = write(fd, buffer.value, buffer.len);

        if (r < 0) {
            if (errno == EAGAIN || errno == EINTR)
                continue;

            close(fd);
            unlink(corpus_name);
            goto try_another_file_name;
        }

        total_written += r;
    }

    close(fd);
    lwan_status_debug("Request saved to %s", corpus_name);
}
#endif

static enum lwan_http_status
read_from_request_socket(struct lwan_request *request,
                         struct lwan_value *buffer,
                         const size_t buffer_size,
                         enum lwan_read_finalizer (*finalizer)(
                             size_t total_read,
                             size_t buffer_size,
                             struct lwan_request *request,
                             int n_packets))
{
    struct lwan_request_parser_helper *helper = request->helper;
    ssize_t n;
    size_t total_read = 0;
    int n_packets = 0;

    if (helper->next_request) {
        const size_t next_request_len = (size_t)(helper->next_request - buffer->value);
        size_t new_len;

        if (__builtin_sub_overflow(buffer->len, next_request_len, &new_len)) {
            helper->next_request = NULL;
        } else {
            /* FIXME: This memmove() could be eventually removed if a better
             * stucture (maybe a ringbuffer, reading with readv(), and each
             * pointer is coro_strdup() if they wrap around?) were used for
             * the request buffer.  */
            total_read = buffer->len = new_len;
            memmove(buffer->value, helper->next_request, new_len);
            goto try_to_finalize;
        }
    }

    for (;; n_packets++) {
        n = read(request->fd, buffer->value + total_read,
                 (size_t)(buffer_size - total_read - 1));
        /* Client has shutdown orderly, nothing else to do; kill coro */
        if (UNLIKELY(n == 0)) {
            coro_yield(request->conn->coro, CONN_CORO_ABORT);
            __builtin_unreachable();
        }

        if (UNLIKELY(n < 0)) {
            switch (errno) {
            case EAGAIN:
                request->conn->flags |= CONN_FLIP_FLAGS;
                coro_yield(request->conn->coro, CONN_CORO_MAY_RESUME);
                /* fallthrough */
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
        switch (finalizer(total_read, buffer_size, request, n_packets)) {
        case FINALIZER_DONE:
            request->conn->flags &= ~CONN_MUST_READ;
            buffer->value[buffer->len] = '\0';

#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
            save_to_corpus_for_fuzzing(buffer);
#endif

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

static inline char *has_crlfcrlf(struct lwan_value *buffer)
{
    return memmem(buffer->value, buffer->len, "\r\n\r\n", 4);
}

static enum lwan_read_finalizer
read_request_finalizer(size_t total_read,
                       size_t buffer_size,
                       struct lwan_request *request,
                       int n_packets)
{
    struct lwan_request_parser_helper *helper = request->helper;

    /* 16 packets should be enough to read a request (without the body, as
     * is the case for POST requests).  This yields a timeout error to avoid
     * clients being intentionally slow and hogging the server.  */
    if (UNLIKELY(n_packets > helper->error_when_n_packets))
        return FINALIZER_ERROR_TIMEOUT;

    if (UNLIKELY(total_read < 4))
        return FINALIZER_YIELD_TRY_AGAIN;

    char *crlfcrlf = has_crlfcrlf(helper->buffer);
    if (LIKELY(crlfcrlf)) {
        if (LIKELY(helper->next_request)) {
            helper->next_request = NULL;
            return FINALIZER_DONE;
        }

        if (crlfcrlf != helper->buffer->value)
            return FINALIZER_DONE;

        if (total_read > 16 && request->flags & REQUEST_ALLOW_PROXY_REQS) {
            /* FIXME: Checking for PROXYv2 protocol header here is a layering
             * violation. */
            STRING_SWITCH_LARGE (crlfcrlf + 4) {
            case MULTICHAR_CONSTANT_LARGE(0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49,
                                          0x54, 0x0a):
                return FINALIZER_DONE;
            }
        }
    }

    if (UNLIKELY(total_read == buffer_size - 1))
        return FINALIZER_ERROR_TOO_LARGE;

    return FINALIZER_TRY_AGAIN;
}

static ALWAYS_INLINE enum lwan_http_status
read_request(struct lwan_request *request)
{
    return read_from_request_socket(request, request->helper->buffer,
                                    DEFAULT_BUFFER_SIZE,
                                    read_request_finalizer);
}

static enum lwan_read_finalizer
post_data_finalizer(size_t total_read,
                    size_t buffer_size,
                    struct lwan_request *request,
                    int n_packets)
{
    struct lwan_request_parser_helper *helper = request->helper;

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

static const char *is_dir(const char *v)
{
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

    return v;
}

static const char *temp_dir;

static const char *
get_temp_dir(void)
{
    const char *tmpdir;

    tmpdir = is_dir(secure_getenv("TMPDIR"));
    if (tmpdir)
        return tmpdir;

    tmpdir = is_dir(secure_getenv("TMP"));
    if (tmpdir)
        return tmpdir;

    tmpdir = is_dir(secure_getenv("TEMP"));
    if (tmpdir)
        return tmpdir;

    tmpdir = is_dir("/var/tmp");
    if (tmpdir)
        return tmpdir;

    tmpdir = is_dir(P_tmpdir);
    if (tmpdir)
        return tmpdir;

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
    void *ptr = (void *)MAP_FAILED;
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

    if (MAP_HUGETLB) {
        ptr = mmap(NULL, size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_HUGETLB, fd, 0);
    }
    if (UNLIKELY(ptr == MAP_FAILED))
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

static enum lwan_http_status read_post_data(struct lwan_request *request)
{
    struct lwan_request_parser_helper *helper = request->helper;
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

    struct lwan_value buffer = {.value = new_buffer,
                                .len = post_data_size - have};
    return read_from_request_socket(request, &buffer, buffer.len,
                                    post_data_finalizer);
}

static char *
parse_proxy_protocol(struct lwan_request *request, char *buffer)
{
    STRING_SWITCH(buffer) {
    case MULTICHAR_CONSTANT('P','R','O','X'):
        return parse_proxy_protocol_v1(request, buffer);
    case MULTICHAR_CONSTANT('\x0D','\x0A','\x0D','\x0A'):
        return parse_proxy_protocol_v2(request, buffer);
    }

    return buffer;
}

static enum lwan_http_status parse_http_request(struct lwan_request *request)
{
    const size_t min_request_size = sizeof("GET / HTTP/1.1\r\n\r\n") - 1;
    struct lwan_request_parser_helper *helper = request->helper;
    char *buffer = helper->buffer->value;

    if (UNLIKELY(helper->buffer->len < min_request_size))
        return HTTP_BAD_REQUEST;

    if (request->flags & REQUEST_ALLOW_PROXY_REQS) {
        /* REQUEST_ALLOW_PROXY_REQS will be cleared in lwan_process_request() */

        buffer = parse_proxy_protocol(request, buffer);
        if (UNLIKELY(!buffer))
            return HTTP_BAD_REQUEST;
    }

    buffer = ignore_leading_whitespace(buffer);

    if (UNLIKELY(buffer >= helper->buffer->value + helper->buffer->len -
                               min_request_size))
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

enum lwan_http_status
lwan_request_websocket_upgrade(struct lwan_request *request)
{
    static const unsigned char websocket_uuid[] =
        "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    char header_buf[DEFAULT_HEADERS_SIZE];
    size_t header_buf_len;
    unsigned char digest[20];
    sha1_context ctx;
    char *encoded;

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
    if (UNLIKELY(!base64_validate((void *)sec_websocket_key, sec_websocket_key_len)))
        return HTTP_BAD_REQUEST;

    sha1_init(&ctx);
    sha1_update(&ctx, (void *)sec_websocket_key, sec_websocket_key_len);
    sha1_update(&ctx, websocket_uuid, sizeof(websocket_uuid) - 1);
    sha1_finalize(&ctx, digest);

    encoded = (char *)base64_encode(digest, sizeof(digest), NULL);
    if (UNLIKELY(!encoded))
        return HTTP_INTERNAL_ERROR;
    coro_defer(request->conn->coro, free, encoded);

    request->flags |= RESPONSE_NO_CONTENT_LENGTH;
    header_buf_len = lwan_prepare_response_header_full(
        request, HTTP_SWITCHING_PROTOCOLS, header_buf, sizeof(header_buf),
        (struct lwan_key_value[]){
            /* Connection: Upgrade is implicit if conn->flags & CONN_IS_UPGRADE */
            {.key = "Sec-WebSocket-Accept", .value = encoded},
            {.key = "Upgrade", .value = "websocket"},
            {},
        });
    if (LIKELY(header_buf_len)) {
        request->conn->flags |= (CONN_FLIP_FLAGS | CONN_IS_WEBSOCKET);

        lwan_send(request, header_buf, header_buf_len, 0);

        coro_yield(request->conn->coro, CONN_CORO_MAY_RESUME);

        return HTTP_SWITCHING_PROTOCOLS;
    }

    return HTTP_INTERNAL_ERROR;
}

static enum lwan_http_status prepare_for_response(struct lwan_url_map *url_map,
                                                  struct lwan_request *request)
{
    request->url.value += url_map->prefix_len;
    request->url.len -= url_map->prefix_len;

    if (url_map->flags & HANDLER_MUST_AUTHORIZE) {
        const char *authorization =
            lwan_request_get_header(request, "Authorization");
        struct lwan_value header = {
            .value = (char*)authorization,
            .len = authorization ? strlen(authorization) : 0,
        };

        if (!lwan_http_authorize(request, &header,
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

    if (url_map->flags & HANDLER_PARSE_ACCEPT_ENCODING)
        parse_accept_encoding(request);

    if (lwan_request_get_method(request) == REQUEST_METHOD_POST) {
        enum lwan_http_status status;

        if (!(url_map->flags & HANDLER_HAS_POST_DATA)) {
            /* FIXME: Discard POST data here? If a POST request is sent
             * to a handler that is not supposed to handle a POST request,
             * the next request in the pipeline will fail because the
             * body of the previous request will be used as the next
             * request itself. */
            return HTTP_NOT_ALLOWED;
        }

        status = read_post_data(request);
        if (UNLIKELY(status != HTTP_OK))
            return status;
    }

    return HTTP_OK;
}

static bool handle_rewrite(struct lwan_request *request)
{
    struct lwan_request_parser_helper *helper = request->helper;

    request->flags &= ~RESPONSE_URL_REWRITTEN;

    parse_fragment_and_query(request, request->url.value + request->url.len);

    helper->urls_rewritten++;
    if (UNLIKELY(helper->urls_rewritten > 4)) {
        lwan_default_response(request, HTTP_INTERNAL_ERROR);
        return false;
    }

    return true;
}

char *lwan_process_request(struct lwan *l,
                           struct lwan_request *request,
                           struct lwan_value *buffer,
                           char *next_request)
{
    char *header_start[N_HEADER_START];
    struct lwan_request_parser_helper helper = {
        .buffer = buffer,
        .next_request = next_request,
        .error_when_n_packets = calculate_n_packets(DEFAULT_BUFFER_SIZE),
        .header_start = header_start,
    };
    enum lwan_http_status status;
    struct lwan_url_map *url_map;

    request->helper = &helper;

    status = read_request(request);
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

    status = parse_http_request(request);
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

    status = prepare_for_response(url_map, request);
    if (UNLIKELY(status != HTTP_OK)) {
        lwan_default_response(request, status);
        goto out;
    }

    status = url_map->handler(request, &request->response, url_map->data);
    if (UNLIKELY(url_map->flags & HANDLER_CAN_REWRITE_URL)) {
        if (request->flags & RESPONSE_URL_REWRITTEN) {
            if (LIKELY(handle_rewrite(request)))
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

        entry = bsearch(&k, la->base, la->elements, sizeof(k), key_value_compare);
        if (LIKELY(entry))
            return entry->value;
    }

    return NULL;
}

const char *lwan_request_get_query_param(struct lwan_request *request,
                                         const char *key)
{
    if (!(request->flags & REQUEST_PARSED_QUERY_STRING)) {
        parse_query_string(request);
        request->flags |= REQUEST_PARSED_QUERY_STRING;
    }

    return value_lookup(&request->query_params, key);
}

const char *lwan_request_get_post_param(struct lwan_request *request,
                                        const char *key)
{
    if (!(request->flags & REQUEST_PARSED_POST_DATA)) {
        parse_post_data(request);
        request->flags |= REQUEST_PARSED_POST_DATA;
    }

    return value_lookup(&request->post_params, key);
}

const char *lwan_request_get_cookie(struct lwan_request *request,
                                    const char *key)
{
    if (!(request->flags & REQUEST_PARSED_COOKIES)) {
        parse_cookies(request);
        request->flags |= REQUEST_PARSED_COOKIES;
    }

    return value_lookup(&request->cookies, key);
}

const char *lwan_request_get_header(struct lwan_request *request,
                                    const char *header)
{
    char name[64];
    int r;

    r = snprintf(name, sizeof(name), "%s: ", header);
    if (UNLIKELY(r < 0 || r >= (int)sizeof(name)))
        return NULL;

    for (size_t i = 0; i < request->helper->n_header_start; i += 2) {
        const char *start = request->helper->header_start[i];
        char *end = request->helper->header_start[i + 1];

        if (UNLIKELY(end - start < r))
            continue;

        if (!strncasecmp(start, name, (size_t)r)) {
            *end = '\0';
            return start + r;
        }
    }

    return NULL;
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

static void remove_sleep(void *data1, void *data2)
{
    struct timeouts *wheel = data1;
    struct timeout *timeout = data2;
    struct lwan_request *request =
        container_of(timeout, struct lwan_request, timeout);

    if (request->conn->flags & CONN_SUSPENDED_BY_TIMER)
        timeouts_del(wheel, timeout);
}

void lwan_request_sleep(struct lwan_request *request, uint64_t ms)
{
    struct lwan_connection *conn = request->conn;
    struct timeouts *wheel = conn->thread->wheel;

    assert(!(conn->flags & CONN_SUSPENDED_BY_TIMER));
    conn->flags |= CONN_SUSPENDED_BY_TIMER;

    request->timeout = (struct timeout) {};
    timeouts_add(wheel, &request->timeout, ms);
    coro_defer2(conn->coro, remove_sleep, wheel, &request->timeout);
    coro_yield(conn->coro, CONN_CORO_MAY_RESUME);

    assert(!(conn->flags & CONN_SUSPENDED_BY_TIMER));
    assert(!(conn->flags & CONN_RESUMED_FROM_TIMER));
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
    return &request->helper->post_data;
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

    return &request->cookies;
}

ALWAYS_INLINE const struct lwan_key_value_array *
lwan_request_get_query_params(struct lwan_request *request)
{
    if (!(request->flags & REQUEST_PARSED_QUERY_STRING)) {
        parse_query_string(request);
        request->flags |= REQUEST_PARSED_QUERY_STRING;
    }

    return &request->query_params;
}

ALWAYS_INLINE const struct lwan_key_value_array *
lwan_request_get_post_params(struct lwan_request *request)
{
    if (!(request->flags & REQUEST_PARSED_POST_DATA)) {
        parse_post_data(request);
        request->flags |= REQUEST_PARSED_POST_DATA;
    }

    return &request->post_params;
}

#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
static int useless_coro_for_fuzzing(struct coro *c __attribute__((unused)),
                                    void *data __attribute__((unused)))
{
    return 0;
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

    if (!coro)
        coro = coro_new(&switcher, useless_coro_for_fuzzing, NULL);

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
    if (read_request_finalizer(length, sizeof(data_copy), &request, 1) !=
        FINALIZER_DONE)
        return 0;

    /* read_from_request_socket() NUL-terminates the string */
    data_copy[length - 1] = '\0';

    if (parse_http_request(&request) == HTTP_OK) {
        size_t gen = coro_deferred_get_generation(coro);

        /* Only pointers were set in helper struct; actually parse them here. */
        parse_post_data(&request);
        parse_query_string(&request);
        parse_cookies(&request);
        parse_accept_encoding(&request);
        parse_if_modified_since(&helper);
        parse_range(&helper);

        coro_deferred_run(coro, gen);
    }

    return 0;
}
#endif
