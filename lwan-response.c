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
#include <stdio.h>
#include <stdlib.h>
#include <sys/uio.h>
#include <string.h>
#include <unistd.h>

#include "lwan.h"
#include "int-to-str.h"

static const char* const _http_versions[] = {
    [HTTP_1_0] = "1.0",
    [HTTP_1_1] = "1.1"
};

bool
lwan_response(lwan_request_t *request, lwan_http_status_t status)
{
    char headers[DEFAULT_HEADERS_SIZE];

    /* Requests without a MIME Type are errors from handlers that
       should just be handled by lwan_default_response(). */
    if (UNLIKELY(!request->response.mime_type))
        return lwan_default_response(request, status);

    if (request->response.stream.callback) {
        lwan_http_status_t callback_status;

        callback_status = request->response.stream.callback(request,
                    request->response.stream.data);
        /* Reset it after it has been called to avoid eternal recursion on errors */
        request->response.stream.callback = NULL;

        if (callback_status < HTTP_BAD_REQUEST) /* Status < 400: success */
            return true;
        return !lwan_default_response(request, callback_status);
    }

    size_t header_len = lwan_prepare_response_header(request, status, headers, sizeof(headers));
    if (UNLIKELY(!header_len))
        return lwan_default_response(request, HTTP_INTERNAL_ERROR);

    if (request->method == HTTP_HEAD) {
        if (UNLIKELY(write(request->fd, headers, header_len) < 0)) {
            perror("write");
            return false;
        }
        return true;
    }

    struct iovec response_vec[] = {
        { .iov_base = headers, .iov_len = header_len },
        { .iov_base = strbuf_get_buffer(request->response.buffer), .iov_len = strbuf_get_length(request->response.buffer) }
    };

    if (UNLIKELY(writev(request->fd, response_vec, N_ELEMENTS(response_vec)) < 0)) {
        perror("writev");
        return false;
    }

    return true;
}

bool
lwan_default_response(lwan_request_t *request, lwan_http_status_t status)
{
    static const char *default_response = "<html><head><style>" \
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
        "<div id=\"container\">" \
        "<h1 id=\"l10n_title\">%s</h1>" \
        "<div class=\"sorry\">" \
        "<p>%s</p>" \
        "</div>" \
        "</div>" \
        "</td></tr></table>" \
        "</body>" \
        "</html>";

    request->response.mime_type = "text/html";
    strbuf_printf(request->response.buffer, default_response,
        lwan_http_status_as_string(status),
        lwan_http_status_as_descriptive_string(status));

    return lwan_response(request, status);
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
