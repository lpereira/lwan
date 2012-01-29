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

#include "lwan.h"

lwan_http_status_t
hello_world(lwan_request_t *request, void *data __attribute__((unused)))
{
    static lwan_response_t response = {
        .mime_type = "text/plain",
        .content = "Hello, world!",
        .content_length = sizeof("Hello, world!") - 1
    };

    lwan_request_set_response(request, &response);
    return HTTP_OK;
}
