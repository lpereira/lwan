/*
 * lwan - simple web server
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

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "base64.h"
#include "lwan-private.h"
#include "lwan-cache.h"
#include "lwan-config.h"
#include "lwan-http-authorize.h"

struct realm_password_file_t {
    struct cache_entry base;
    struct hash *entries;
};

static struct cache *realm_password_cache = NULL;

static void zero_and_free(void *str)
{
    if (LIKELY(str))
        lwan_always_bzero(str, strlen(str));
}

static struct cache_entry *
create_realm_file(const char *key, void *context __attribute__((unused)))
{
    struct realm_password_file_t *rpf = malloc(sizeof(*rpf));
    const struct config_line *l;
    struct config *f;

    if (UNLIKELY(!rpf))
        return NULL;

    rpf->entries = hash_str_new(zero_and_free, zero_and_free);
    if (UNLIKELY(!rpf->entries))
        goto error_no_close;

#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    static const uint8_t hardcoded_user_config[] = "user=password\n"
                                                   "root=hunter2\n";
    f = config_open_for_fuzzing(hardcoded_user_config,
                                sizeof(hardcoded_user_config));
#else
    f = config_open(key);
#endif
    if (!f)
        goto error_no_close;

    while ((l = config_read_line(f))) {
        /* FIXME: Storing plain-text passwords in memory isn't a good idea. */
        switch (l->type) {
        case CONFIG_LINE_TYPE_LINE: {
            char *username = strdup(l->key);
            if (!username)
                goto error;

            char *password = strdup(l->value);
            if (!password) {
                free(username);
                goto error;
            }

            int err = hash_add_unique(rpf->entries, username, password);
            if (LIKELY(!err))
                continue;

            free(username);
            free(password);

            if (err == -EEXIST) {
                lwan_status_warning(
                    "Username entry already exists, ignoring: \"%s\"", l->key);
                continue;
            }

            goto error;
        }
        default:
            config_error(f, "Expected username = password");
            break;
        }
    }

    if (config_last_error(f)) {
        lwan_status_error("Error on password file \"%s\", line %d: %s", key,
                          config_cur_line(f), config_last_error(f));
        goto error;
    }

    config_close(f);
    return (struct cache_entry *)rpf;

error:
    config_close(f);
error_no_close:
    hash_free(rpf->entries);
    free(rpf);
    return NULL;
}

static void destroy_realm_file(struct cache_entry *entry,
                               void *context __attribute__((unused)))
{
    struct realm_password_file_t *rpf = (struct realm_password_file_t *)entry;
    hash_free(rpf->entries);
    free(rpf);
}

bool lwan_http_authorize_init(void)
{
    realm_password_cache =
        cache_create(create_realm_file, destroy_realm_file, NULL, 60);

    return !!realm_password_cache;
}

void lwan_http_authorize_shutdown(void) { cache_destroy(realm_password_cache); }

static bool authorize(struct coro *coro,
                      const char *header,
                      size_t header_len,
                      const char *password_file)
{
    struct realm_password_file_t *rpf;
    unsigned char *decoded;
    char *colon;
    char *password;
    char *looked_password;
    size_t decoded_len;
    bool password_ok = false;

    rpf = (struct realm_password_file_t *)cache_coro_get_and_ref_entry(
        realm_password_cache, coro, password_file);
    if (UNLIKELY(!rpf))
        return false;

    decoded = base64_decode((unsigned char *)header, header_len, &decoded_len);
    if (UNLIKELY(!decoded))
        return false;

    colon = memchr(decoded, ':', decoded_len);
    if (UNLIKELY(!colon))
        goto out;

    *colon = '\0';
    password = colon + 1;

    looked_password = hash_find(rpf->entries, decoded);
    if (looked_password)
        password_ok = streq(password, looked_password);

out:
    free(decoded);
    return password_ok;
}

bool lwan_http_authorize(struct lwan_request *request,
                         const char *realm,
                         const char *password_file)
{
    static const char authenticate_tmpl[] = "Basic realm=\"%s\"";
    static const size_t basic_len = sizeof("Basic ") - 1;
    const char *authorization =
        lwan_request_get_header(request, "Authorization");

    if (LIKELY(authorization && !strncmp(authorization, "Basic ", basic_len))) {
        const char *header = authorization + basic_len;
        size_t header_len = strlen(authorization) - basic_len;

        if (authorize(request->conn->coro, header, header_len, password_file))
            return true;
    }

    const struct lwan_key_value headers[] = {
        {"WWW-Authenticate",
         coro_printf(request->conn->coro, authenticate_tmpl, realm)},
        {},
    };
    request->response.headers =
        coro_memdup(request->conn->coro, headers, sizeof(headers));

    return false;
}
