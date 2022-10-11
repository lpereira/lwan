/*
 * lwan - web server
 * Copyright (c) 2014 L. A. F. Pereira <l@tia.mat.br>
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

#include <stdlib.h>
#include <string.h>

#include "lwan-private.h"
#include "lwan-mod-redirect.h"

struct redirect_priv {
    char *to;
    enum lwan_http_status code;
};

static enum lwan_http_status
redirect_handle_request(struct lwan_request *request,
                        struct lwan_response *response,
                        void *instance)
{
    struct redirect_priv *priv = instance;
    struct lwan_key_value headers[] = {{"Location", priv->to}, {}};

    response->headers =
        coro_memdup(request->conn->coro, headers, sizeof(headers));

    return response->headers ? priv->code : HTTP_INTERNAL_ERROR;
}

static void *redirect_create(const char *prefix __attribute__((unused)),
                             void *instance)
{
    struct lwan_redirect_settings *settings = instance;
    struct redirect_priv *priv = malloc(sizeof(*priv));

    if (!priv)
        return NULL;

    priv->to = strdup(settings->to);
    if (!priv->to) {
        free(priv);
        return NULL;
    }

    priv->code = settings->code;

    return priv;
}

static void redirect_destroy(void *data)
{
    struct redirect_priv *priv = data;

    if (priv) {
        free(priv->to);
        free(priv);
    }
}

static enum lwan_http_status parse_http_code(const char *code,
                                             enum lwan_http_status fallback)
{
    const char *known;
    int as_int;

    if (!code)
        return fallback;

    as_int = parse_int(code, 999);
    if (as_int == 999)
        return fallback;

    known = lwan_http_status_as_string_with_code((enum lwan_http_status)as_int);
    if (!strncmp(known, "999", 3))
        return fallback;

    return (enum lwan_http_status)as_int;
}

static void *redirect_create_from_hash(const char *prefix,
                                       const struct hash *hash)
{
    struct lwan_redirect_settings settings = {
        .to = hash_find(hash, "to"),
        .code =
            parse_http_code(hash_find(hash, "code"), HTTP_MOVED_PERMANENTLY),
    };

    return redirect_create(prefix, &settings);
}

static const struct lwan_module module = {
    .create = redirect_create,
    .create_from_hash = redirect_create_from_hash,
    .destroy = redirect_destroy,
    .handle_request = redirect_handle_request,
};

LWAN_REGISTER_MODULE(redirect, &module);
