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

#include "lwan-mod-redirect.h"
#include "lwan-private.h"

struct redirect_priv {
    char *to;
    int response_code;
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

    return response->headers ? priv->response_code : HTTP_INTERNAL_ERROR;
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

    if (!lwan_http_status_is_valid(settings->response_code)) {
        lwan_log_error("HTTP code %d is not supported",
                       settings->response_code);
        free(priv->to);
        free(priv);
        return NULL;
    }

    priv->response_code = settings->response_code;

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

static void *redirect_create_from_hash(const char *prefix,
                                       const struct hash *hash)
{
    struct lwan_redirect_settings settings = {
        .to = hash_find(hash, "to"),
        .response_code = parse_int(hash_find(hash, "code"), HTTP_MOVED_PERMANENTLY),
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
