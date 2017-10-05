/*
 * lwan - simple web server
 * Copyright (c) 2017 Leandro A. F. Pereira <leandro@hardinfo.org>
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
#include "lwan-mod-response.h"

static enum lwan_http_status
response_handle(struct lwan_request *request __attribute__((unused)),
    struct lwan_response *response __attribute__((unused)),
    void *data)
{
    return (enum lwan_http_status)data;
}

static void *response_init(const char *prefix __attribute__((unused)), void *data)
{
    struct lwan_response_settings *settings = data;

    return (void *)settings->code;
}

static void *response_init_from_hash(const char *prefix, const struct hash *hash)
{
    const char *code = hash_find(hash, "code");

    if (!code) {
        lwan_status_error("`code` not supplied");
        return NULL;
    }

    struct lwan_response_settings settings = {
        .code = (enum lwan_http_status)parse_int(code, 999)
    };

    if (settings.code == 999) {
        lwan_status_error("Unknown error code: %s", code);
        return NULL;
    }

    return response_init(prefix, &settings);
}

const struct lwan_module *lwan_module_response(void)
{
    static const struct lwan_module response_module = {
        .init = response_init,
        .init_from_hash = response_init_from_hash,
        .shutdown = NULL,
        .handle = response_handle,
        .flags = 0
    };

    return &response_module;
}
