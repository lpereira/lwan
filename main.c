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
#include "lwan-serve-files.h"

lwan_http_status_t
hello_world(lwan_request_t *request, void *data __attribute__((unused)))
{
    static lwan_http_header_t headers[] = {
        { .name = "X-The-Answer-To-The-Universal-Question", .value = "42" },
        { NULL, NULL }
    };
    static lwan_response_t response = {
        .mime_type = "text/plain",
        .content = "Hello, world!",
        .content_length = sizeof("Hello, world!") - 1,
        .headers = headers
    };

    lwan_request_set_response(request, &response);
    return HTTP_OK;
}

int
main(void)
{
    lwan_url_map_t default_map[] = {
        { .prefix = "/hello", .callback = hello_world, .data = NULL },
        { .prefix = "/", .callback = serve_files, .data = "./files_root" },
        { .prefix = NULL },
    };
    lwan_t l = {
        .config = {
            .port = 8080,
            .keep_alive_timeout = 5 /*seconds */,
            .enable_thread_affinity = false,
            .enable_linger = true
        }
    };

    lwan_init(&l);
    lwan_set_url_map(&l, default_map);
    lwan_main_loop(&l);
    lwan_shutdown(&l);

    return 0;
}
