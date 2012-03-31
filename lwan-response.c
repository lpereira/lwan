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

#include <stdio.h>
#include <stdlib.h>
#include <sys/uio.h>
#include <unistd.h>

#include "lwan.h"

bool
lwan_response(lwan_t *l, lwan_request_t *request, lwan_http_status_t status)
{
    char headers[512];

    if (UNLIKELY(!request->response.mime_type)) {
        lwan_default_response(l, request, status);
        return false;
    }

    if (request->response.stream_content.callback) {
        lwan_http_status_t callback_status;

        callback_status = request->response.stream_content.callback(l, request,
                    request->response.stream_content.data);
        if (callback_status == HTTP_OK)
            return true;

        lwan_default_response(l, request, callback_status);
        return false;
    }

    size_t header_len = lwan_prepare_response_header(request, status, headers);
    if (!header_len)
        return lwan_default_response(l, request, HTTP_INTERNAL_ERROR);

    if (request->method == HTTP_HEAD) {
        if (write(request->fd, headers, header_len) < 0) {
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
lwan_default_response(lwan_t *l, lwan_request_t *request, lwan_http_status_t status)
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

    return lwan_response(l, request, status);
}
