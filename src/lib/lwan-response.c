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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#define _GNU_SOURCE
#include <assert.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include <endian.h>

#include "lwan-private.h"

#include "int-to-str.h"
#include "lwan-io-wrappers.h"
#include "lwan-template.h"

static struct lwan_tpl *error_template = NULL;

static const char *error_template_str = "<html><head><style>" \
    "body{" \
    "background:#627d4d;" \
    "background:-moz-radial-gradient(center,ellipse cover,#627d4d 15\x25,#1f3b08 100\x25);" \
    "background:-webkit-gradient(radial,center center,0px,center center,100\x25,color-stop(15\x25,#627d4d),color-stop(100\x25,#1f3b08));" \
    "background:-webkit-radial-gradient(center,ellipse cover,#627d4d 15\x25,#1f3b08 100\x25);" \
    "background:-o-radial-gradient(center,ellipse cover,#627d4d 15\x25,#1f3b08 100\x25);" \
    "background:-ms-radial-gradient(center,ellipse cover,#627d4d 15\x25,#1f3b08 100\x25);" \
    "background:radial-gradient(center,ellipse cover,#627d4d 15\x25,#1f3b08 100\x25);" \
    "height:100\x25;font-family:Arial,'Helvetica Neue',Helvetica,sans-serif;text-align:center;border:0;letter-spacing:-1px;margin:0;padding:0}.sorry{color:#244837;font-size:18px;line-height:24px;text-shadow:0" \
    "1px 1px rgba(255,255,255,0.33)}h1{color:#fff;font-size:30px;font-weight:700;text-shadow:0 1px 4px rgba(0,0,0,0.68);letter-spacing:-1px;margin:0}" \
    "</style>" \
    "</head>" \
    "<body>" \
    "<table height=\"100\x25\" width=\"100\x25\"><tr><td align=\"center\" valign=\"middle\">" \
    "<div>" \
    "<h1>{{short_message}}</h1>" \
    "<div class=\"sorry\">" \
    "<p>{{long_message}}</p>" \
    "</div>" \
    "</div>" \
    "</td></tr></table>" \
    "</body>" \
    "</html>";

struct error_template {
    const char *short_message;
    const char *long_message;
};

void lwan_response_init(struct lwan *l)
{
#undef TPL_STRUCT
#define TPL_STRUCT struct error_template
    static const struct lwan_var_descriptor error_descriptor[] = {
        TPL_VAR_STR(short_message), TPL_VAR_STR(long_message),
        TPL_VAR_SENTINEL};

    assert(!error_template);

    lwan_status_debug("Initializing default response");

    if (l->config.error_template) {
        error_template =
            lwan_tpl_compile_file(l->config.error_template, error_descriptor);
    } else {
        error_template = lwan_tpl_compile_string_full(
            error_template_str, error_descriptor, LWAN_TPL_FLAG_CONST_TEMPLATE);
    }

    if (UNLIKELY(!error_template))
        lwan_status_critical_perror("lwan_tpl_compile_string");
}

void lwan_response_shutdown(struct lwan *l __attribute__((unused)))
{
    lwan_status_debug("Shutting down response");
    assert(error_template);
    lwan_tpl_free(error_template);
}

#ifndef NDEBUG
static const char *get_request_method(struct lwan_request *request)
{
#define GENERATE_CASE_STMT(upper, lower, mask, constant)                       \
    case REQUEST_METHOD_##upper:                                               \
        return #upper;

    switch (lwan_request_get_method(request)) {
        FOR_EACH_REQUEST_METHOD(GENERATE_CASE_STMT)
    default:
        return "UNKNOWN";
    }

#undef GENERATE_CASE_STMT
}

static void log_request(struct lwan_request *request,
                        enum lwan_http_status status)
{
    char ip_buffer[INET6_ADDRSTRLEN];

    lwan_status_debug("%s [%s] \"%s %s HTTP/%s\" %d %s",
                      lwan_request_get_remote_address(request, ip_buffer),
                      request->conn->thread->date.date,
                      get_request_method(request), request->original_url.value,
                      request->flags & REQUEST_IS_HTTP_1_0 ? "1.0" : "1.1",
                      status, request->response.mime_type);
}
#else
#define log_request(...)
#endif
#include <stdlib.h>

static inline bool has_response_body(enum lwan_request_flags method,
                                     enum lwan_http_status status)
{
    /* See FOR_EACH_REQUEST_METHOD() in lwan.h */
    return (method & 1 << 0) || status != HTTP_NOT_MODIFIED;
}

void lwan_response(struct lwan_request *request, enum lwan_http_status status)
{
    const struct lwan_response *response = &request->response;
    char headers[DEFAULT_HEADERS_SIZE];

    if (UNLIKELY(request->flags & RESPONSE_CHUNKED_ENCODING)) {
        /* Send last, 0-sized chunk */
        lwan_strbuf_reset(response->buffer);
        lwan_response_send_chunk(request);
        log_request(request, status);
        return;
    }

    if (UNLIKELY(request->flags & RESPONSE_SENT_HEADERS)) {
        lwan_status_debug("Headers already sent, ignoring call");
        return;
    }

    if (UNLIKELY(!response->mime_type)) {
        /* Requests without a MIME Type are errors from handlers that should
           just be handled by lwan_default_response().  */
        lwan_default_response(request, status);
        return;
    }

    log_request(request, status);

    if (request->flags & RESPONSE_STREAM) {
        if (LIKELY(response->stream.callback)) {
            status = response->stream.callback(request, response->stream.data);
        } else {
            status = HTTP_INTERNAL_ERROR;
        }

        if (status >= HTTP_CLASS__CLIENT_ERROR) {
            request->flags &= ~RESPONSE_STREAM;
            lwan_default_response(request, status);
        }

        return;
    }

    size_t header_len =
        lwan_prepare_response_header(request, status, headers, sizeof(headers));
    if (UNLIKELY(!header_len)) {
        lwan_default_response(request, HTTP_INTERNAL_ERROR);
        return;
    }

    if (!has_response_body(lwan_request_get_method(request), status)) {
        lwan_send(request, headers, header_len, 0);
        return;
    }

    char *resp_buf = lwan_strbuf_get_buffer(response->buffer);
    const size_t resp_len = lwan_strbuf_get_length(response->buffer);
    if (sizeof(headers) - header_len > resp_len) {
        /* writev() has to allocate, copy, and validate the response vector,
         * so use send() for responses small enough to fit the headers
         * buffer.  On Linux, this is ~10% faster.  */
        memcpy(headers + header_len, resp_buf, resp_len);
        lwan_send(request, headers, header_len + resp_len, 0);
    } else {
        struct iovec response_vec[] = {
            {.iov_base = headers, .iov_len = header_len},
            {.iov_base = resp_buf, .iov_len = resp_len},
        };

        lwan_writev(request, response_vec, N_ELEMENTS(response_vec));
    }
}

void lwan_default_response(struct lwan_request *request,
                           enum lwan_http_status status)
{
    request->response.mime_type = "text/html";

    lwan_tpl_apply_with_buffer(
        error_template, request->response.buffer,
        &(struct error_template){
            .short_message = lwan_http_status_as_string(status),
            .long_message = lwan_http_status_as_descriptive_string(status),
        });

    lwan_response(request, status);
}

#define RETURN_0_ON_OVERFLOW(len_)                                             \
    if (UNLIKELY(p_headers + (len_) >= p_headers_end))                         \
    return 0

#define APPEND_STRING_LEN(const_str_, len_)                                    \
    do {                                                                       \
        RETURN_0_ON_OVERFLOW(len_);                                            \
        p_headers = mempcpy(p_headers, (const_str_), (len_));                  \
    } while (0)

#define APPEND_STRING(str_)                                                    \
    do {                                                                       \
        size_t len = strlen(str_);                                             \
        APPEND_STRING_LEN((str_), len);                                        \
    } while (0)

#define APPEND_CHAR(value_)                                                    \
    do {                                                                       \
        RETURN_0_ON_OVERFLOW(1);                                               \
        *p_headers++ = (value_);                                               \
    } while (0)

#define APPEND_CHAR_NOCHECK(value_) *p_headers++ = (value_)

#define APPEND_UINT(value_)                                                    \
    do {                                                                       \
        size_t len;                                                            \
        char *tmp = uint_to_string((value_), buffer, &len);                    \
        RETURN_0_ON_OVERFLOW(len);                                             \
        APPEND_STRING_LEN(tmp, len);                                           \
    } while (0)

#define APPEND_CONSTANT(const_str_)                                            \
    APPEND_STRING_LEN((const_str_), sizeof(const_str_) - 1)

size_t lwan_prepare_response_header_full(
    struct lwan_request *request,
    enum lwan_http_status status,
    char headers[],
    size_t headers_buf_size,
    const struct lwan_key_value *additional_headers)
{
    char *p_headers;
    char *p_headers_end = headers + headers_buf_size;
    char buffer[INT_TO_STR_BUFFER_SIZE];
    bool date_overridden = false;
    bool expires_overridden = false;

    p_headers = headers;

    if (request->flags & REQUEST_IS_HTTP_1_0)
        APPEND_CONSTANT("HTTP/1.0 ");
    else
        APPEND_CONSTANT("HTTP/1.1 ");
    APPEND_STRING(lwan_http_status_as_string_with_code(status));

    if (request->flags & RESPONSE_CHUNKED_ENCODING) {
        APPEND_CONSTANT("\r\nTransfer-Encoding: chunked");
    } else if (request->flags & RESPONSE_NO_CONTENT_LENGTH) {
        /* Do nothing. */
    } else if (!(request->flags & RESPONSE_STREAM)) {
        APPEND_CONSTANT("\r\nContent-Length: ");
        APPEND_UINT(lwan_strbuf_get_length(request->response.buffer));
    }

    if ((status < HTTP_BAD_REQUEST && additional_headers)) {
        const struct lwan_key_value *header;

        for (header = additional_headers; header->key; header++) {
            STRING_SWITCH_L(header->key) {
            case STR4_INT_L('S', 'e', 'r', 'v'):
                if (LIKELY(streq(header->key + 4, "er")))
                    continue;
                break;
            case STR4_INT_L('D', 'a', 't', 'e'):
                if (LIKELY(*(header->key + 4) == '\0'))
                    date_overridden = true;
                break;
            case STR4_INT_L('E', 'x', 'p', 'i'):
                if (LIKELY(streq(header->key + 4, "res")))
                    expires_overridden = true;
                break;
            }

            RETURN_0_ON_OVERFLOW(4);
            APPEND_CHAR_NOCHECK('\r');
            APPEND_CHAR_NOCHECK('\n');
            APPEND_STRING(header->key);
            APPEND_CHAR_NOCHECK(':');
            APPEND_CHAR_NOCHECK(' ');
            APPEND_STRING(header->value);
        }
    } else if (status == HTTP_NOT_AUTHORIZED) {
        const struct lwan_key_value *header;

        for (header = additional_headers; header->key; header++) {
            if (streq(header->key, "WWW-Authenticate")) {
                APPEND_CONSTANT("\r\nWWW-Authenticate: ");
                APPEND_STRING(header->value);
                break;
            }
        }
    }

    if (request->conn->flags & CONN_IS_UPGRADE) {
        APPEND_CONSTANT("\r\nConnection: Upgrade");
    } else {
        if (request->conn->flags & CONN_IS_KEEP_ALIVE) {
            APPEND_CONSTANT("\r\nConnection: keep-alive");
        } else {
            APPEND_CONSTANT("\r\nConnection: close");
        }

        if (LIKELY(request->response.mime_type)) {
            APPEND_CONSTANT("\r\nContent-Type: ");
            APPEND_STRING(request->response.mime_type);
        }
    }

    if (LIKELY(!date_overridden)) {
        APPEND_CONSTANT("\r\nDate: ");
        APPEND_STRING_LEN(request->conn->thread->date.date, 29);
    }

    if (LIKELY(!expires_overridden)) {
        APPEND_CONSTANT("\r\nExpires: ");
        APPEND_STRING_LEN(request->conn->thread->date.expires, 29);
    }

    if (request->flags & REQUEST_ALLOW_CORS) {
        APPEND_CONSTANT(
            "\r\nAccess-Control-Allow-Origin: *"
            "\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS"
            "\r\nAccess-Control-Allow-Credentials: true"
            "\r\nAccess-Control-Allow-Headers: Origin, Accept, Content-Type");
    }

    APPEND_CONSTANT("\r\nServer: lwan\r\n\r\n\0");

    return (size_t)(p_headers - headers - 1);
}

#undef APPEND_CHAR
#undef APPEND_CHAR_NOCHECK
#undef APPEND_CONSTANT
#undef APPEND_STRING
#undef APPEND_STRING_LEN
#undef APPEND_UINT
#undef RETURN_0_ON_OVERFLOW

ALWAYS_INLINE size_t lwan_prepare_response_header(struct lwan_request *request,
                                                  enum lwan_http_status status,
                                                  char headers[],
                                                  size_t headers_buf_size)
{
    return lwan_prepare_response_header_full(
        request, status, headers, headers_buf_size, request->response.headers);
}

bool lwan_response_set_chunked(struct lwan_request *request,
                               enum lwan_http_status status)
{
    char buffer[DEFAULT_BUFFER_SIZE];
    size_t buffer_len;

    if (request->flags & RESPONSE_SENT_HEADERS)
        return false;

    request->flags |= RESPONSE_CHUNKED_ENCODING;
    buffer_len = lwan_prepare_response_header(request, status, buffer,
                                              DEFAULT_BUFFER_SIZE);
    if (UNLIKELY(!buffer_len))
        return false;

    request->flags |= RESPONSE_SENT_HEADERS;
    lwan_send(request, buffer, buffer_len, MSG_MORE);

    return true;
}

void lwan_response_send_chunk(struct lwan_request *request)
{
    if (!(request->flags & RESPONSE_SENT_HEADERS)) {
        if (UNLIKELY(!lwan_response_set_chunked(request, HTTP_OK)))
            return;
    }

    size_t buffer_len = lwan_strbuf_get_length(request->response.buffer);
    if (UNLIKELY(!buffer_len)) {
        static const char last_chunk[] = "0\r\n\r\n";
        lwan_send(request, last_chunk, sizeof(last_chunk) - 1, 0);
        return;
    }

    char chunk_size[3 * sizeof(size_t) + 2];
    int converted_len =
        snprintf(chunk_size, sizeof(chunk_size), "%zx\r\n", buffer_len);
    if (UNLIKELY(converted_len < 0 ||
                 (size_t)converted_len >= sizeof(chunk_size))) {
        coro_yield(request->conn->coro, CONN_CORO_ABORT);
        __builtin_unreachable();
    }
    size_t chunk_size_len = (size_t)converted_len;

    struct iovec chunk_vec[] = {
        {.iov_base = chunk_size, .iov_len = chunk_size_len},
        {.iov_base = lwan_strbuf_get_buffer(request->response.buffer),
         .iov_len = buffer_len},
        {.iov_base = "\r\n", .iov_len = 2},
    };

    lwan_writev(request, chunk_vec, N_ELEMENTS(chunk_vec));

    lwan_strbuf_reset(request->response.buffer);
    coro_yield(request->conn->coro, CONN_CORO_WANT_WRITE);
}

bool lwan_response_set_event_stream(struct lwan_request *request,
                                    enum lwan_http_status status)
{
    char buffer[DEFAULT_BUFFER_SIZE];
    size_t buffer_len;

    if (request->flags & RESPONSE_SENT_HEADERS)
        return false;

    request->response.mime_type = "text/event-stream";
    request->flags |= RESPONSE_NO_CONTENT_LENGTH;
    buffer_len = lwan_prepare_response_header(request, status, buffer,
                                              DEFAULT_BUFFER_SIZE);
    if (UNLIKELY(!buffer_len))
        return false;

    request->flags |= RESPONSE_SENT_HEADERS;
    lwan_send(request, buffer, buffer_len, MSG_MORE);

    return true;
}

void lwan_response_send_event(struct lwan_request *request, const char *event)
{
    struct iovec vec[6];
    size_t last = 0;

    if (!(request->flags & RESPONSE_SENT_HEADERS)) {
        if (UNLIKELY(!lwan_response_set_event_stream(request, HTTP_OK)))
            return;
    }

    if (event) {
        vec[last++] = (struct iovec){
            .iov_base = "event: ",
            .iov_len = sizeof("event: ") - 1,
        };
        vec[last++] = (struct iovec){
            .iov_base = (char *)event,
            .iov_len = strlen(event),
        };
        vec[last++] = (struct iovec){
            .iov_base = "\r\n",
            .iov_len = 2,
        };
    }

    size_t buffer_len = lwan_strbuf_get_length(request->response.buffer);
    if (buffer_len) {
        vec[last++] = (struct iovec){
            .iov_base = "data: ",
            .iov_len = sizeof("data: ") - 1,
        };
        vec[last++] = (struct iovec){
            .iov_base = lwan_strbuf_get_buffer(request->response.buffer),
            .iov_len = buffer_len,
        };
    }

    vec[last++] = (struct iovec){
        .iov_base = "\r\n\r\n",
        .iov_len = 4,
    };

    lwan_writev(request, vec, last);

    lwan_strbuf_reset(request->response.buffer);
    coro_yield(request->conn->coro, CONN_CORO_WANT_WRITE);
}
