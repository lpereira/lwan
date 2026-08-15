/*
 * lwan - web server
 * Copyright (c) 2017 L. A. F. Pereira <l@tia.mat.br>
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
#include <ctype.h>
#include <fcntl.h>
#include <lauxlib.h>
#include <libgen.h>
#include <lualib.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "lwan-private.h"

#include "lwan-array.h"
#include "lwan-cache.h"
#include "lwan-config.h"
#include "lwan-lua.h"
#include "lwan-mod-lua.h"
#include "realpathat.h"

struct lwan_lua_priv {
    char *default_type;
    char *server_pages;
    char *script_file;
    char *script;
    pthread_key_t cache_key;
    unsigned cache_period;
    int server_pages_fd;
};

struct lwan_lua_state {
    struct cache_entry base;
    lua_State *L;
};

char *lwan_mod_lua_lsp_to_lua(const char *filename);

static char *lua_script_from_lsp(const struct lwan_lua_priv *priv,
                                 const char *key)
{
    char resolved_buf[PATH_MAX];
    char *resolved;

    resolved = realpathat(priv->server_pages_fd, priv->server_pages, key,
                          resolved_buf);
    if (UNLIKELY(!resolved))
        return NULL;

    if (LIKELY(!strncmp(resolved, priv->server_pages,
                        strlen(priv->server_pages)))) {
        return lwan_mod_lua_lsp_to_lua(resolved);
    }

    return NULL;
}

static struct cache_entry *state_create(const void *key,
                                        void *cache_ctx,
                                        void *create_ctx
                                        __attribute__((unused)))
{
    struct lwan_lua_priv *priv = cache_ctx;
    struct lwan_lua_state *state = malloc(sizeof(*state));
    char *script;

    if (UNLIKELY(!state))
        return NULL;

    if (priv->server_pages) {
        assert(key != NULL);
        assert(priv->script == NULL);
        assert(priv->script_file == NULL);

        script = lua_script_from_lsp(priv, key);
        if (!script) {
            goto error;
        }
    } else {
        assert(key == NULL);

        script = priv->script;
    }

    state->L = lwan_lua_create_state(priv->script_file, script);
    if (priv->server_pages)
        free(script);
    if (LIKELY(state->L))
        return (struct cache_entry *)state;

error:
    free(state);
    return NULL;
}

static void state_destroy(struct cache_entry *entry,
                          void *context __attribute__((unused)))
{
    struct lwan_lua_state *state = (struct lwan_lua_state *)entry;

    lua_close(state->L);
    free(state);
}

static struct cache *get_or_create_cache(struct lwan_lua_priv *priv)
{
    struct cache *cache = pthread_getspecific(priv->cache_key);

    if (UNLIKELY(!cache)) {
        lwan_log_debug("Creating cache for this thread");
        cache =
            cache_create(state_create, state_destroy, priv, priv->cache_period);
        if (UNLIKELY(!cache))
            lwan_log_error("Could not create cache");
        /* FIXME: This cache instance leaks: store it somewhere and
         * free it on module shutdown */
        pthread_setspecific(priv->cache_key, cache);
    }

    return cache;
}

static void unref_thread(void *data1, void *data2)
{
    lua_State *L = data1;
    int thread_ref = (int)(intptr_t)data2;

    luaL_unref(L, LUA_REGISTRYINDEX, thread_ref);
}

static ALWAYS_INLINE struct lwan_value
get_handle_prefix(struct lwan_request *request)
{
#define ENTRY(s) {.value = s, .len = sizeof(s) - 1}
#define GEN_TABLE_ENTRY(upper, lower, mask, constant, probability)             \
    [REQUEST_METHOD_##upper] = ENTRY("handle_" #lower "_"),

    static const struct lwan_value method2name[REQUEST_METHOD_MASK] = {
        FOR_EACH_REQUEST_METHOD(GEN_TABLE_ENTRY)};

#undef GEN_TABLE_ENTRY
#undef ENTRY

    return method2name[lwan_request_get_method(request)];
}

static bool get_handler_function(lua_State *L,
                                 struct lwan_lua_priv *priv,
                                 struct lwan_request *request)
{
    if (priv->server_pages) {
        lua_getglobal(L, "handle");
        return lua_isfunction(L, -1);
    }

    char handler_name[128];
    struct lwan_value handle_prefix = get_handle_prefix(request);

    if (UNLIKELY(!handle_prefix.len))
        return false;
    if (UNLIKELY(request->url.len >= sizeof(handler_name) - handle_prefix.len))
        return false;

    char *url;
    size_t url_len;
    if (request->url.len) {
        url = strndupa(request->url.value, request->url.len);

        for (char *c = url; *c; c++) {
            if (*c == '/') {
                *c = '\0';
                break;
            }

            if (UNLIKELY(!isalnum(*c) && *c != '_'))
                return false;
        }

        url_len = strlen(url);
    } else {
        url = "root";
        url_len = 4;
    }

    size_t total_len;
    if (UNLIKELY(__builtin_add_overflow(handle_prefix.len, url_len, &total_len)))
        return false;
    if (UNLIKELY(total_len > sizeof(handler_name) - 1))
        return false;

    char *method_name = mempcpy(handler_name, handle_prefix.value, handle_prefix.len);
    memcpy(method_name, url, url_len + 1);

    lua_getglobal(L, handler_name);
    if (lua_isfunction(L, -1))
        return true;

    lua_pop(L, 1);
    lua_getglobal(L, "handle");
    return lua_isfunction(L, -1);
}

static lua_State *push_newthread(lua_State *L, struct coro *coro)
{
    lua_State *L1 = lua_newthread(L);

    if (UNLIKELY(!L1))
        return NULL;

    int thread_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    coro_defer2(coro, unref_thread, L, (void *)(intptr_t)thread_ref);

    return L1;
}

static enum lwan_http_status lua_handle_request(struct lwan_request *request,
                                                struct lwan_response *response,
                                                void *instance)
{
    struct lwan_lua_priv *priv = instance;

    struct cache *cache = get_or_create_cache(priv);
    if (UNLIKELY(!cache))
        return HTTP_INTERNAL_ERROR;

    struct lwan_lua_state *state;

    if (!priv->server_pages) {
        state = (struct lwan_lua_state *)cache_coro_get_and_ref_entry(
            cache, request->conn->coro, NULL);
    } else {
        state = (struct lwan_lua_state *)cache_coro_get_and_ref_entry(
            cache, request->conn->coro, request->url.value);
    }
    if (UNLIKELY(!state))
        return HTTP_NOT_FOUND;

    lua_State *L = push_newthread(state->L, request->conn->coro);
    if (UNLIKELY(!L))
        return HTTP_INTERNAL_ERROR;

    if (UNLIKELY(!get_handler_function(L, priv, request)))
        return HTTP_NOT_FOUND;

    int n_arguments = 1;
    lwan_lua_state_push_request(L, request);
    response->mime_type = priv->default_type;
    while (true) {
        int n_results = 0;
        switch (lua_resume(L, NULL, n_arguments, &n_results)) {
        case LUA_YIELD:
            coro_yield(request->conn->coro, CONN_CORO_YIELD);
            n_arguments = 0;
            break;
        case LUA_OK:
            if (n_results == 0 || lua_isnil(L, -1))
                return HTTP_OK;

            if (lua_isnumber(L, -1)) {
                lua_Integer code = lua_tointeger(L, -1);

                if (lwan_http_status_is_valid((int)code)) {
                    return (enum lwan_http_status)code;
                }
            }

            return HTTP_INTERNAL_ERROR;
        default:
            lwan_log_error("Error from Lua script: %s", lua_tostring(L, -1));
            return HTTP_INTERNAL_ERROR;
        }
    }
}

static void destroy_cache(void *data)
{
    struct cache *cache = data;
    cache_destroy(cache);
}

static void *lua_create(const char *prefix __attribute__((unused)), void *data)
{
    struct lwan_lua_settings *settings = data;
    struct lwan_lua_priv *priv;

    priv = calloc(1, sizeof(*priv));
    if (!priv) {
        lwan_log_error("Could not allocate memory for private Lua struct");
        return NULL;
    }

    priv->server_pages_fd = -1;

    priv->default_type =
        strdup(settings->default_type ? settings->default_type : "text/plain");
    if (!priv->default_type) {
        lwan_log_perror("strdup");
        goto error;
    }

    if (settings->server_pages) {
        priv->server_pages = lwan_get_real_root_path(settings->server_pages);
        if (!priv->server_pages) {
            lwan_log_perror("strdup");
            goto error;
        }
        priv->server_pages_fd = open(
            priv->server_pages, O_RDONLY | O_DIRECTORY | O_PATH | O_CLOEXEC);
        if (priv->server_pages_fd < 0) {
            lwan_log_perror("open");
            goto error;
        }
        lwan_straitjacket_allow_dirfd_ro(priv->server_pages_fd);
    } else if (settings->script) {
        priv->script = strdup(settings->script);
        if (!priv->script) {
            lwan_log_perror("strdup");
            goto error;
        }
    } else if (settings->script_file) {
        priv->script_file = strdup(settings->script_file);
        if (!priv->script_file) {
            lwan_log_perror("strdup");
            goto error;
        }
        lwan_straitjacket_allow_dir_path_ro(dirname(priv->script_file));
    } else {
        lwan_log_error("No Lua script_file, server_pages, or script provided");
        goto error;
    }

    if (pthread_key_create(&priv->cache_key, destroy_cache)) {
        lwan_log_perror("pthread_key_create");
        goto error;
    }

    priv->cache_period = settings->cache_period;

    return priv;

error:
    if (priv->server_pages_fd >= 0) {
        close(priv->server_pages_fd);
    }
    free(priv->server_pages);
    free(priv->script_file);
    free(priv->default_type);
    free(priv->script);
    free(priv);

    return NULL;
}

static void lua_destroy(void *instance)
{
    struct lwan_lua_priv *priv = instance;

    if (priv) {
        pthread_key_delete(priv->cache_key);
        free(priv->server_pages);
        free(priv->default_type);
        free(priv->script_file);
        free(priv->script);
        if (priv->server_pages_fd >= 0) {
            close(priv->server_pages_fd);
        }
        free(priv);
    }
}

static void *lua_create_from_hash(const char *prefix, const struct hash *hash)
{
    struct lwan_lua_settings settings = {
        .default_type = hash_find(hash, "default_type"),
        .script_file = hash_find(hash, "script_file"),
        .cache_period = parse_time_period(hash_find(hash, "cache_period"), 15),
        .script = hash_find(hash, "script"),
        .server_pages = hash_find(hash, "server_pages")};

    return lua_create(prefix, &settings);
}

static const struct lwan_module module = {
    .create = lua_create,
    .create_from_hash = lua_create_from_hash,
    .destroy = lua_destroy,
    .handle_request = lua_handle_request,
    .flags = HANDLER_EXPECTS_BODY_DATA,
};

LWAN_REGISTER_MODULE(lua, &module);
