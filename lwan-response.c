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
    request->response.mime_type = "text/plain";
    strbuf_printf(request->response.buffer, "HTTP Status %d (%s)",
        status, lwan_http_status_as_string(status));

    return lwan_response(l, request, status);
}
