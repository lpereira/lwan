/*
 * lwan - simple web server
 * Copyright (c) 2014 Leandro A. F. Pereira <leandro@hardinfo.org>
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

#include <string.h>
#include <stdlib.h>

#include "lwan.h"
#include "lwan-mod-redirect.h"

static enum lwan_http_status
redirect_handle_request(struct lwan_request *request,
                        struct lwan_response *response, void *instance)
{
    if (UNLIKELY(!data))
        return HTTP_INTERNAL_ERROR;

    struct lwan_key_value *headers = coro_malloc(request->conn->coro, sizeof(*headers) * 2);
    if (UNLIKELY(!headers))
        return HTTP_INTERNAL_ERROR;

    headers[0].key = "Location";
    headers[0].value = data;
    headers[1].key = NULL;
    headers[1].value = NULL;

    response->headers = headers;

    return HTTP_MOVED_PERMANENTLY;
}

static void *redirect_new(const char *prefix __attribute__((unused)),
                                   void *instance)
{
    struct lwan_redirect_settings *settings = instance;

    return (settings->to) ? strdup(settings->to) : NULL;
}

static void *redirect_new_from_hash(const char *prefix,
                                             const struct hash *hash)
{
    struct lwan_redirect_settings settings = {
        .to = hash_find(hash, "to")
    };

    return redirect_new(prefix, &settings);
}

static const struct lwan_module module = {
    .new = redirect_new,
    .new_from_hash = redirect_new_from_hash,
    .free = free,
    .handle_request = redirect_handle_request,
};

LWAN_REGISTER_MODULE(redirect, &module);
