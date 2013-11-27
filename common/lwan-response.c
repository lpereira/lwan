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
    "background:-moz-radial-gradient(center,ellipse cover,#627d4d 15\%,#1f3b08 100\%);" \
    "background:-webkit-gradient(radial,center center,0px,center center,100\%,color-stop(15\%,#627d4d),color-stop(100\%,#1f3b08));" \
    "background:-webkit-radial-gradient(center,ellipse cover,#627d4d 15\%,#1f3b08 100\%);" \
    "background:-o-radial-gradient(center,ellipse cover,#627d4d 15\%,#1f3b08 100\%);" \
    "background:-ms-radial-gradient(center,ellipse cover,#627d4d 15\%,#1f3b08 100\%);" \
    "background:radial-gradient(center,ellipse cover,#627d4d 15\%,#1f3b08 100\%);" \
    "height:100\%;font-family:Arial,'Helvetica Neue',Helvetica,sans-serif;text-align:center;border:0;letter-spacing:-1px;margin:0;padding:0}.sorry{color:#244837;font-size:18px;line-height:24px;text-shadow:0" \
    "1px 1px rgba(255,255,255,0.33)}h1{color:#fff;font-size:30px;font-weight:700;text-shadow:0 1px 4px rgba(0,0,0,0.68);letter-spacing:-1px;margin:0}" \
    "</style>" \
    "</head>" \
    "<body>" \
    "<table height=\"100\%\" width=\"100\%\"><tr><td align=\"center\" valign=\"middle\">" \
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
    if (!error_template)
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
static void
log_request(lwan_request_t *request, lwan_http_status_t status)
{
    char ip_buffer[16];

    lwan_status_debug("%s \"%s %s HTTP/%s\" %d %s",
        lwan_request_get_remote_address(request, ip_buffer),
        request->flags & REQUEST_METHOD_GET ? "GET" : "HEAD",
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

    /* Requests without a MIME Type are errors from handlers that
       should just be handled by lwan_default_response(). */
    if (UNLIKELY(!request->response.mime_type)) {
        lwan_default_response(request, status);
        return;
    }

    if (request->response.stream.callback) {
        lwan_http_status_t callback_status;

        callback_status = request->response.stream.callback(request,
                    request->response.stream.data);
        /* Reset it after it has been called to avoid eternal recursion on errors */
        request->response.stream.callback = NULL;

        log_request(request, status);

        if (callback_status >= HTTP_BAD_REQUEST) /* Status < 400: success */
            lwan_default_response(request, callback_status);
        return;
    }

    size_t header_len = lwan_prepare_response_header(request, status, headers, sizeof(headers));
    if (UNLIKELY(!header_len)) {
        lwan_default_response(request, HTTP_INTERNAL_ERROR);
        return;
    }

    log_request(request, status);

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

    if (request->flags & REQUEST_IS_HTTP_1_0)
        APPEND_CONSTANT("HTTP/1.0");
    else
        APPEND_CONSTANT("HTTP/1.1");
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
    if (request->conn->flags & CONN_KEEP_ALIVE)
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
