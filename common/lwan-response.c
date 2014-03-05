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
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

#include "int-to-str.h"
#include "lwan.h"
#include "lwan-io-wrappers.h"
#include "lwan-template.h"

static lwan_tpl_t *error_template = NULL;

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

struct error_template_t {
    const char *short_message;
    const char *long_message;
};

void
lwan_response_init(void)
{
    static lwan_var_descriptor_t error_descriptor[] = {
        TPL_VAR_STR(struct error_template_t, short_message),
        TPL_VAR_STR(struct error_template_t, long_message),
        TPL_VAR_SENTINEL
    };

    assert(!error_template);

    lwan_status_debug("Initializing default response");

    error_template = lwan_tpl_compile_string(error_template_str, error_descriptor);
    if (UNLIKELY(!error_template))
        lwan_status_critical_perror("lwan_tpl_compile_string");
}

void
lwan_response_shutdown(void)
{
    lwan_status_debug("Shutting down response");
    assert(error_template);
    lwan_tpl_free(error_template);
}

#ifndef NDEBUG
static const char *
get_request_method(lwan_request_t *request)
{
    if (request->flags & REQUEST_METHOD_GET)
        return "GET";
    if (request->flags & REQUEST_METHOD_HEAD)
        return "HEAD";
    if (request->flags & REQUEST_METHOD_POST)
        return "POST";
    return "UNKNOWN";
}

static void
log_request(lwan_request_t *request, lwan_http_status_t status)
{
    char ip_buffer[16];

    lwan_status_debug("%s \"%s %s HTTP/%s\" %d %s",
        lwan_request_get_remote_address(request, ip_buffer),
        get_request_method(request),
        request->original_url.value,
        request->flags & REQUEST_IS_HTTP_1_0 ? "1.0" : "1.1",
        status,
        request->response.mime_type);
}
#else
#define log_request(...)
#endif

void
lwan_response(lwan_request_t *request, lwan_http_status_t status)
{
    char headers[DEFAULT_HEADERS_SIZE];

    if (request->flags & RESPONSE_CHUNKED_ENCODING) {
        /* Send last, 0-sized chunk */
        if (UNLIKELY(!strbuf_reset_length(request->response.buffer)))
            coro_yield(request->conn->coro, CONN_CORO_ABORT);
        lwan_response_send_chunk(request);
        return;
    }

    if (UNLIKELY(request->flags & RESPONSE_SENT_HEADERS)) {
        lwan_status_debug("Headers already sent, ignoring call");
        return;
    }

    /* Requests without a MIME Type are errors from handlers that
       should just be handled by lwan_default_response(). */
    if (UNLIKELY(!request->response.mime_type)) {
        lwan_default_response(request, status);
        return;
    } else {
        log_request(request, status);
    }

    if (request->response.stream.callback) {
        lwan_http_status_t callback_status;

        callback_status = request->response.stream.callback(request,
                    request->response.stream.data);
        /* Reset it after it has been called to avoid eternal recursion on errors */
        request->response.stream.callback = NULL;

        if (callback_status >= HTTP_BAD_REQUEST) /* Status < 400: success */
            lwan_default_response(request, callback_status);
        return;
    }

    size_t header_len = lwan_prepare_response_header(request, status, headers, sizeof(headers));
    if (UNLIKELY(!header_len)) {
        lwan_default_response(request, HTTP_INTERNAL_ERROR);
        return;
    }

    if (request->flags & REQUEST_METHOD_HEAD) {
        lwan_write(request, headers, header_len);
        return;
    }

    struct iovec response_vec[] = {
        { .iov_base = headers, .iov_len = header_len },
        { .iov_base = strbuf_get_buffer(request->response.buffer), .iov_len = strbuf_get_length(request->response.buffer) }
    };

    lwan_writev(request, response_vec, N_ELEMENTS(response_vec));
}

void
lwan_default_response(lwan_request_t *request, lwan_http_status_t status)
{
    request->response.mime_type = "text/html";

    lwan_tpl_apply_with_buffer(error_template, request->response.buffer,
        (struct error_template_t[]) {{
            .short_message = lwan_http_status_as_string(status),
            .long_message = lwan_http_status_as_descriptive_string(status)
        }});

    lwan_response(request, status);
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
        APPEND_CHAR_NOCHECK((char)(((value_) / 100) % 10 + '0')); \
        APPEND_CHAR_NOCHECK((char)(((value_) / 10) % 10 + '0')); \
        APPEND_CHAR_NOCHECK((char)((value_) % 10 + '0')); \
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
    char buffer[INT_TO_STR_BUFFER_SIZE];
    size_t len;

    p_headers = headers;

    if (request->flags & REQUEST_IS_HTTP_1_0)
        APPEND_CONSTANT("HTTP/1.0 ");
    else
        APPEND_CONSTANT("HTTP/1.1 ");
    APPEND_INT8(status);
    APPEND_CHAR(' ');
    APPEND_STRING(lwan_http_status_as_string(status));

    if (request->flags & RESPONSE_CHUNKED_ENCODING) {
        APPEND_CONSTANT("\r\nTransfer-Encoding: chunked");
    } else if (request->flags & RESPONSE_NO_CONTENT_LENGTH) {
        /* Do nothing. */
    } else {
        APPEND_CONSTANT("\r\nContent-Length: ");
        if (request->response.stream.callback)
            APPEND_UINT(request->response.content_length);
        else
            APPEND_UINT(strbuf_get_length(request->response.buffer));
    }

    APPEND_CONSTANT("\r\nContent-Type: ");
    APPEND_STRING(request->response.mime_type);

    if (request->conn->flags & CONN_KEEP_ALIVE)
        APPEND_CONSTANT("\r\nConnection: keep-alive");
    else
        APPEND_CONSTANT("\r\nConnection: close");

    if ((status < HTTP_BAD_REQUEST && request->response.headers)) {
        lwan_key_value_t *header;

        for (header = request->response.headers; header->key; header++) {
            APPEND_CHAR('\r');
            APPEND_CHAR('\n');
            APPEND_STRING(header->key);
            APPEND_CHAR(':');
            APPEND_CHAR(' ');
            APPEND_STRING(header->value);
        }
    } else if (status == HTTP_NOT_AUTHORIZED) {
        lwan_key_value_t *header;

        for (header = request->response.headers; header->key; header++) {
            if (!strcmp(header->key, "WWW-Authenticate")) {
                APPEND_CONSTANT("\r\nWWW-Authenticate: ");
                APPEND_STRING(header->value);
                break;
            }
        }
    }

    APPEND_CONSTANT("\r\nDate: ");
    APPEND_STRING_LEN(request->conn->thread->date.date, 29);

    APPEND_CONSTANT("\r\nExpires: ");
    APPEND_STRING_LEN(request->conn->thread->date.expires, 29);

    APPEND_CONSTANT("\r\nServer: lwan\r\n\r\n\0");

    return (size_t)(p_headers - headers - 1);
}

#undef APPEND_STRING_LEN
#undef APPEND_STRING
#undef APPEND_CONSTANT
#undef APPEND_CHAR
#undef APPEND_INT

bool
lwan_response_set_chunked(lwan_request_t *request, lwan_http_status_t status)
{
    char buffer[DEFAULT_BUFFER_SIZE];
    size_t buffer_len;

    if (request->flags & RESPONSE_SENT_HEADERS)
        return false;

    request->flags |= RESPONSE_CHUNKED_ENCODING;
    buffer_len = lwan_prepare_response_header(request, status,
                                                buffer, DEFAULT_BUFFER_SIZE);
    if (UNLIKELY(!buffer_len))
        return false;

    request->flags |= RESPONSE_SENT_HEADERS;
    lwan_send(request, buffer, buffer_len, MSG_MORE);

    return true;
}

void
lwan_response_send_chunk(lwan_request_t *request)
{
    if (!(request->flags & RESPONSE_SENT_HEADERS)) {
        if (UNLIKELY(!lwan_response_set_chunked(request, HTTP_OK)))
            return;
    }

    size_t buffer_len = strbuf_get_length(request->response.buffer);
    if (UNLIKELY(!buffer_len)) {
        static const char last_chunk[] = "0\r\n\r\n";
        lwan_send(request, last_chunk, sizeof(last_chunk) - 1, 0);
        return;
    }

    char chunk_size[3 * sizeof(size_t) + 2];
    int converted_len = snprintf(chunk_size, sizeof(chunk_size), "%lx\r\n", buffer_len);
    if (UNLIKELY(converted_len < 0))
        return;
    size_t chunk_size_len = (size_t)converted_len;

    struct iovec chunk_vec[] = {
        { .iov_base = chunk_size, .iov_len = chunk_size_len },
        { .iov_base = strbuf_get_buffer(request->response.buffer), .iov_len = buffer_len },
        { .iov_base = "\r\n", .iov_len = 2 }
    };

    lwan_writev(request, chunk_vec, N_ELEMENTS(chunk_vec));

    if (UNLIKELY(strbuf_reset_length(request->response.buffer)))
        coro_yield(request->conn->coro, CONN_CORO_MAY_RESUME);
    else
        coro_yield(request->conn->coro, CONN_CORO_ABORT);
}

bool
lwan_response_set_event_stream(lwan_request_t *request,
                               lwan_http_status_t status)
{
    char buffer[DEFAULT_BUFFER_SIZE];
    size_t buffer_len;

    if (request->flags & RESPONSE_SENT_HEADERS)
        return false;

    request->response.mime_type = "text/event-stream";
    request->flags |= RESPONSE_NO_CONTENT_LENGTH;
    buffer_len = lwan_prepare_response_header(request, status,
                                                buffer, DEFAULT_BUFFER_SIZE);
    if (UNLIKELY(!buffer_len))
        return false;

    request->flags |= RESPONSE_SENT_HEADERS;
    lwan_send(request, buffer, buffer_len, MSG_MORE);

    return true;
}

void
lwan_response_send_event(lwan_request_t *request, const char *event)
{
    if (!(request->flags & RESPONSE_SENT_HEADERS)) {
        if (UNLIKELY(!lwan_response_set_event_stream(request, HTTP_OK)))
            return;
    }

    struct iovec vec[6];
    int last = 0;

    if (event) {
        vec[last].iov_base = "event: ";
        vec[last].iov_len = sizeof("event: ") - 1;
        last++;

        vec[last].iov_base = (char *)event;
        vec[last].iov_len = strlen(event);
        last++;

        vec[last].iov_base = "\r\n";
        vec[last].iov_len = 2;
        last++;
    }

    size_t buffer_len = strbuf_get_length(request->response.buffer);
    if (buffer_len) {
        vec[last].iov_base = "data: ";
        vec[last].iov_len = sizeof("data: ") - 1;
        last++;

        vec[last].iov_base = strbuf_get_buffer(request->response.buffer);
        vec[last].iov_len = buffer_len;
        last++;

    }

    vec[last].iov_base = "\r\n\r\n";
    vec[last].iov_len = 4;
    last++;

    lwan_writev(request, vec, last);

    strbuf_reset_length(request->response.buffer);
    coro_yield(request->conn->coro, CONN_CORO_MAY_RESUME);
}
