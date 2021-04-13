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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#include <stdlib.h>
#include <string.h>

#include "lwan.h"
#include "lwan-mod-response.h"

static enum lwan_http_status
response_handle_request(struct lwan_request *request __attribute__((unused)),
                        struct lwan_response *response __attribute__((unused)),
                        void *instance)
{
    return (enum lwan_http_status)instance;
}

static void *response_create(const char *prefix __attribute__((unused)),
                             void *instance)
{
    struct lwan_response_settings *settings = instance;

    const char *valid_code =
        lwan_http_status_as_string_with_code(settings->code);
    if (!strncmp(valid_code, "999 ", 4)) {
        lwan_status_error("Code %d isn't a known HTTP status code",
                          settings->code);
        return NULL;
    }

    return (void *)settings->code;
}

static void *response_create_from_hash(const char *prefix,
                                       const struct hash *hash)
{
    const char *code = hash_find(hash, "code");

    if (!code) {
        lwan_status_error("`code` not supplied");
        return NULL;
    }

    int code_as_int = parse_int(code, -1);
    if (code_as_int < 0) {
        lwan_status_error("Couldn't parse `code` as an integer");
        return NULL;
    }

    struct lwan_response_settings settings = {
        .code = (enum lwan_http_status)code_as_int,
    };
    return response_create(prefix, &settings);
}

static const struct lwan_module module = {
    .create = response_create,
    .create_from_hash = response_create_from_hash,
    .handle_request = response_handle_request,
};

LWAN_REGISTER_MODULE(response, &module);
