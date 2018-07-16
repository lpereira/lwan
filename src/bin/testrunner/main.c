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
#include <stdlib.h>
#include <unistd.h>

#include "lwan.h"

LWAN_HANDLER(quit_lwan)
{
    exit(0);
    return HTTP_OK;
}

LWAN_HANDLER(gif_beacon)
{
    /*
     * 1x1 transparent GIF image generated with tinygif
     * http://www.perlmonks.org/?node_id=7974
     */
    static const unsigned char gif_beacon_data[] = {
        0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x90,
        0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0xF9, 0x04,
        0x05, 0x10, 0x00, 0x00, 0x00, 0x2C, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x04, 0x01
    };

    response->mime_type = "image/gif";
    lwan_strbuf_set_static(response->buffer, (char*)gif_beacon_data, sizeof(gif_beacon_data));

    return HTTP_OK;
}

LWAN_HANDLER(test_chunked_encoding)
{
    int i;

    response->mime_type = "text/plain";

    lwan_strbuf_printf(response->buffer, "Testing chunked encoding! First chunk\n");
    lwan_response_send_chunk(request);

    for (i = 0; i <= 10; i++) {
        lwan_strbuf_printf(response->buffer, "*This is chunk %d*\n", i);
        lwan_response_send_chunk(request);
    }

    lwan_strbuf_printf(response->buffer, "Last chunk\n");
    lwan_response_send_chunk(request);

    return HTTP_OK;
}

LWAN_HANDLER(test_server_sent_event)
{
    int i;

    for (i = 0; i <= 10; i++) {
        lwan_strbuf_printf(response->buffer, "Current value is %d", i);
        lwan_response_send_event(request, "currval");
    }

    return HTTP_OK;
}

LWAN_HANDLER(test_proxy)
{
    struct lwan_key_value *headers = coro_malloc(request->conn->coro, sizeof(*headers) * 2);
    if (UNLIKELY(!headers))
        return HTTP_INTERNAL_ERROR;

    char *buffer = coro_malloc(request->conn->coro, INET6_ADDRSTRLEN);
    if (UNLIKELY(!buffer))
        return HTTP_INTERNAL_ERROR;

    headers[0].key = "X-Proxy";
    headers[0].value = (char*) lwan_request_get_remote_address(request, buffer);
    headers[1].key = NULL;
    headers[1].value = NULL;

    response->headers = headers;

    return HTTP_OK;
}

LWAN_HANDLER(test_post_will_it_blend)
{
    static const char type[] = "application/json";
    static const char request_body[] = "{\"will-it-blend\": true}";
    static const char response_body[] = "{\"did-it-blend\": \"oh-hell-yeah\"}";

    if (!request->header.content_type)
        return HTTP_BAD_REQUEST;
    if (!request->header.content_type->value)
        return HTTP_BAD_REQUEST;
    if (request->header.content_type->len != sizeof(type) - 1)
        return HTTP_BAD_REQUEST;
    if (memcmp(request->header.content_type->value, type, sizeof(type) - 1) != 0)
        return HTTP_BAD_REQUEST;

    if (!request->header.body)
        return HTTP_BAD_REQUEST;
    if (!request->header.body->value)
        return HTTP_BAD_REQUEST;
    if (request->header.body->len != sizeof(request_body) - 1)
        return HTTP_BAD_REQUEST;
    if (memcmp(request->header.body->value, request_body, sizeof(request_body) - 1) != 0)
        return HTTP_BAD_REQUEST;

    response->mime_type = type;
    lwan_strbuf_set_static(response->buffer, response_body, sizeof(response_body) -1);

    return HTTP_OK;
}

LWAN_HANDLER(test_post_big)
{
    static const char type[] = "x-test/trololo";
    size_t i, sum = 0;

    if (!request->header.content_type)
        return HTTP_BAD_REQUEST;
    if (!request->header.content_type->value)
        return HTTP_BAD_REQUEST;
    if (request->header.content_type->len != sizeof(type) - 1)
        return HTTP_BAD_REQUEST;
    if (memcmp(request->header.content_type->value, type, sizeof(type) - 1) != 0)
        return HTTP_BAD_REQUEST;

    for (i = 0; i < request->header.body->len; i++)
        sum += (size_t)request->header.body->value[i];

    response->mime_type = "application/json";
    lwan_strbuf_printf(response->buffer, "{\"received\": %zu, \"sum\": %zu}",
        request->header.body->len, sum);

    return HTTP_OK;
}

LWAN_HANDLER(hello_world)
{
    static struct lwan_key_value headers[] = {
        { .key = "X-The-Answer-To-The-Universal-Question", .value = "42" },
        { NULL, NULL }
    };
    response->headers = headers;
    response->mime_type = "text/plain";

    const char *name = lwan_request_get_query_param(request, "name");
    if (name)
        lwan_strbuf_printf(response->buffer, "Hello, %s!", name);
    else
        lwan_strbuf_set_static(response->buffer, "Hello, world!", sizeof("Hello, world!") -1);

    const char *dump_vars = lwan_request_get_query_param(request, "dump_vars");
    if (!dump_vars)
        goto end;

    lwan_strbuf_append_str(response->buffer, "\n\nCookies\n", 0);
    lwan_strbuf_append_str(response->buffer, "-------\n\n", 0);

    struct lwan_key_value *qs = request->cookies.base.base;
    for (; qs && qs->key; qs++)
        lwan_strbuf_append_printf(response->buffer,
                    "Key = \"%s\"; Value = \"%s\"\n", qs->key, qs->value);

    lwan_strbuf_append_str(response->buffer, "\n\nQuery String Variables\n", 0);
    lwan_strbuf_append_str(response->buffer, "----------------------\n\n", 0);

    for (qs = request->query_params.base.base; qs && qs->key; qs++)
        lwan_strbuf_append_printf(response->buffer,
                    "Key = \"%s\"; Value = \"%s\"\n", qs->key, qs->value);

    if (lwan_request_get_method(request) != REQUEST_METHOD_POST)
        goto end;

    lwan_strbuf_append_str(response->buffer, "\n\nPOST data\n", 0);
    lwan_strbuf_append_str(response->buffer, "---------\n\n", 0);

    for (qs = request->post_data.base.base; qs && qs->key; qs++)
        lwan_strbuf_append_printf(response->buffer,
                    "Key = \"%s\"; Value = \"%s\"\n", qs->key, qs->value);

end:
    return HTTP_OK;
}

LWAN_HANDLER(sleep)
{
    response->mime_type = "text/plain";
    uint64_t ms =
        (uint64_t)parse_long(lwan_request_get_query_param(request, "ms"), 0);

    if (ms) {
        struct timespec t1, t2;
        int64_t diff_ms;

        clock_gettime(CLOCK_MONOTONIC, &t1);

        lwan_request_sleep(request, ms);

        clock_gettime(CLOCK_MONOTONIC, &t2);
        diff_ms = (t2.tv_sec - t1.tv_sec) * 1000;
        diff_ms += (t2.tv_nsec - t1.tv_nsec) / 1000000;

        lwan_strbuf_printf(response->buffer, "Returned from sleep. diff_ms = %ld", diff_ms);
    } else {
        lwan_strbuf_set_static(response->buffer, "Did not sleep", 0);
    }

    return HTTP_OK;
}

int
main()
{
    struct lwan l;

    lwan_init(&l);
    lwan_main_loop(&l);
    lwan_shutdown(&l);

    return EXIT_SUCCESS;
}
