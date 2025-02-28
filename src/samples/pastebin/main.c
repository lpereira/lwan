/*
 * lwan - web server
 * Copyright (c) 2022 L. A. F. Pereira <l@tia.mat.br>
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
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "hash.h"
#include "int-to-str.h"
#include "lwan.h"
#include "lwan-cache.h"
#include "lwan-private.h"

#define CACHE_FOR_HOURS 2

static struct cache *pastes;

struct paste {
    struct cache_entry entry;
    size_t len;
    char value[];
};

static struct cache_entry *create_paste(const void *key __attribute__((unused)),
                                        void *cache_ctx __attribute__((unused)),
                                        void *create_ctx)
{
    const struct lwan_value *body = create_ctx;
    size_t alloc_size;

    if (!body)
        return NULL;

    if (__builtin_add_overflow(sizeof(struct paste), body->len, &alloc_size))
        return NULL;

    struct paste *paste = malloc(alloc_size);
    if (paste) {
        paste->len = body->len;
        memcpy(paste->value, body->value, body->len);
    }

    return (struct cache_entry *)paste;
}

static void destroy_paste(struct cache_entry *entry,
                          void *context __attribute__((unused)))
{
    free(entry);
}

static enum lwan_http_status post_paste(struct lwan_request *request,
                                        struct lwan_response *response)
{
    const struct lwan_value *body = lwan_request_get_request_body(request);

    if (!body)
        return HTTP_BAD_REQUEST;

    for (int try = 0; try < 10; try++) {
        void *key;

        do {
            key = (void *)(uintptr_t)lwan_random_uint64();
        } while (!key);

        struct cache_entry *paste = cache_coro_get_and_ref_entry_with_ctx(
            pastes, request->conn->coro, key, (void *)body);

        if (paste) {
            if (!cache_entry_is_new(paste))
                continue;

            const char *host_hdr = lwan_request_get_host(request);

            if (!host_hdr)
                return HTTP_BAD_REQUEST;

            response->mime_type = "text/plain";
            lwan_strbuf_printf(response->buffer, "https://%s/p/%zu\n\n",
                               host_hdr, (uint64_t)(uintptr_t)key);

            return HTTP_OK;
        }
    }

    return HTTP_UNAVAILABLE;
}

static enum lwan_http_status doc(struct lwan_request *request,
                                 struct lwan_response *response)
{
    const char *host_hdr = lwan_request_get_host(request);

    if (!host_hdr)
        return HTTP_BAD_REQUEST;

    response->mime_type = "text/plain";

    lwan_strbuf_printf(
        response->buffer,
        "Simple Paste Bin\n"
        "================\n"
        "\n"
        "To post a file:     curl -X POST --data-binary @/path/to/filename "
        "https://%s/\n"
        "To post clipboard:  xsel -o | curl -X POST --data-binary @- "
        "https://%s/\n"
        "To view:            Access the URL given as a response.\n"
        "                    Extension suffixes may be used to provide "
        "response with different MIME-type.\n"
        "\n"
        "Items are cached for %d hours and are not stored on disk",
        host_hdr, host_hdr, CACHE_FOR_HOURS);

    return HTTP_OK;
}

LWAN_HANDLER_ROUTE(view_root, "/")
{
    switch (lwan_request_get_method(request)) {
    case REQUEST_METHOD_POST:
        return post_paste(request, response);
    case REQUEST_METHOD_GET:
        return doc(request, response);
    default:
        return HTTP_NOT_ALLOWED;
    }
}

static bool parse_uint64(const char *s, uint64_t *out)
{
    char *endptr;

    if (!*s)
        return false;

    errno = 0;
    *out = strtoull(s, &endptr, 10);

    if (errno != 0)
        return false;

    if (*endptr != '\0' || s == endptr)
        return false;

    return true;
}

LWAN_HANDLER_ROUTE(view_paste, "/p/")
{
    char *dot = memrchr(request->url.value, '.', request->url.len);
    const char *mime_type;

    if (dot) {
        mime_type = lwan_determine_mime_type_for_file_name(dot);
        *dot = '\0';
    } else {
        mime_type = "text/plain";
    }

    uint64_t key;

    if (!parse_uint64(request->url.value, &key))
        return HTTP_BAD_REQUEST;

    struct paste *paste = (struct paste *)cache_coro_get_and_ref_entry(
        pastes, request->conn->coro, (void *)(uintptr_t)key);

    if (!paste)
        return HTTP_NOT_FOUND;

    response->mime_type = mime_type;
    lwan_strbuf_set_static(response->buffer, paste->value, paste->len);

    return HTTP_OK;
}

int main(void)
{
    struct lwan l;

    lwan_init(&l);

    lwan_detect_url_map(&l);

    pastes = cache_create_full(create_paste,
                               destroy_paste,
                               hash_int64_new,
                               NULL,
                               CACHE_FOR_HOURS * 60 * 60);
    if (!pastes)
        lwan_status_critical("Could not create paste cache");

    lwan_main_loop(&l);

    lwan_shutdown(&l);

    return 0;
}
