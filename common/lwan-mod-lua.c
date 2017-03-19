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

#define _GNU_SOURCE
#include <ctype.h>
#include <lauxlib.h>
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

struct lwan_lua_priv {
    char *default_type;
    char *script_file;
    char *script;
    pthread_key_t cache_key;
    unsigned cache_period;
};

struct lwan_lua_state {
    struct cache_entry base;
    lua_State *L;
};

static struct cache_entry *state_create(const char *key __attribute__((unused)),
        void *context)
{
    struct lwan_lua_priv *priv = context;
    struct lwan_lua_state *state = malloc(sizeof(*state));

    if (UNLIKELY(!state))
        return NULL;

    state->L = lwan_lua_create_state(priv->script_file, priv->script);
    if (LIKELY(state->L))
        return (struct cache_entry *)state;

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
        lwan_status_debug("Creating cache for this thread");
        cache = cache_create(state_create, state_destroy, priv, priv->cache_period);
        if (UNLIKELY(!cache))
            lwan_status_error("Could not create cache");
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

static ALWAYS_INLINE const char *get_handle_prefix(struct lwan_request *request, size_t *len)
{
    switch (lwan_request_get_method(request)) {
    case REQUEST_METHOD_GET:
        *len = sizeof("handle_get_");
        return "handle_get_";
    case REQUEST_METHOD_POST:
        *len = sizeof("handle_post_");
        return "handle_post_";
    case REQUEST_METHOD_HEAD:
        *len = sizeof("handle_head_");
        return "handle_head_";
    case REQUEST_METHOD_OPTIONS:
        *len = sizeof("handle_options_");
        return "handle_options_";
    case REQUEST_METHOD_DELETE:
        *len = sizeof("handle_delete_");
        return "handle_delete_";
    default:
        return NULL;
    }
}

static bool get_handler_function(lua_State *L, struct lwan_request *request)
{
    char handler_name[128];
    size_t handle_prefix_len;
    const char *handle_prefix = get_handle_prefix(request, &handle_prefix_len);

    if (UNLIKELY(!handle_prefix))
        return false;
    if (UNLIKELY(request->url.len >= sizeof(handler_name) - handle_prefix_len))
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

    if (UNLIKELY((handle_prefix_len + url_len + 1) > sizeof(handler_name)))
        return false;

    char *method_name = mempcpy(handler_name, handle_prefix, handle_prefix_len);
    memcpy(method_name - 1, url, url_len + 1);

    lua_getglobal(L, handler_name);
    return lua_isfunction(L, -1);
}

void lwan_lua_state_push_request(lua_State *L, struct lwan_request *request)
{
    struct lwan_request **userdata = lua_newuserdata(L, sizeof(struct lwan_request *));
    *userdata = request;
    luaL_getmetatable(L, lwan_request_metatable_name);
    lua_setmetatable(L, -2);
}

static lua_State *push_newthread(lua_State *L, struct coro *coro)
{
    lua_State *L1 = lua_newthread(L);
    if (UNLIKELY(!L1))
        return NULL;

    int thread_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    coro_defer2(coro, CORO_DEFER2(unref_thread), L, (void *)(intptr_t)thread_ref);

    return L1;
}

static enum lwan_http_status
lua_handle_cb(struct lwan_request *request,
              struct lwan_response *response,
              void *data)
{
    struct lwan_lua_priv *priv = data;

    if (UNLIKELY(!priv))
        return HTTP_INTERNAL_ERROR;

    struct cache *cache = get_or_create_cache(priv);
    if (UNLIKELY(!cache))
        return HTTP_INTERNAL_ERROR;

    struct lwan_lua_state *state = (struct lwan_lua_state *)cache_coro_get_and_ref_entry(
            cache, request->conn->coro, "");
    if (UNLIKELY(!state))
        return HTTP_NOT_FOUND;

    lua_State *L = push_newthread(state->L, request->conn->coro);
    if (UNLIKELY(!L))
        return HTTP_INTERNAL_ERROR;

    if (UNLIKELY(!get_handler_function(L, request)))
        return HTTP_NOT_FOUND;

    int n_arguments = 1;
    lwan_lua_state_push_request(L, request);
    response->mime_type = priv->default_type;
    while (true) {
        switch (lua_resume(L, n_arguments)) {
        case LUA_YIELD:
            coro_yield(request->conn->coro, CONN_CORO_MAY_RESUME);
            n_arguments = 0;
            break;
        case 0:
            return HTTP_OK;
        default:
            lwan_status_error("Error from Lua script: %s", lua_tostring(L, -1));
            return HTTP_INTERNAL_ERROR;
        }
    }
}

static void *lua_init(const char *prefix __attribute__((unused)), void *data)
{
    struct lwan_lua_settings *settings = data;
    struct lwan_lua_priv *priv;

    priv = calloc(1, sizeof(*priv));
    if (!priv) {
        lwan_status_error("Could not allocate memory for private Lua struct");
        return NULL;
    }

    priv->default_type = strdup(
        settings->default_type ? settings->default_type : "text/plain");
    if (!priv->default_type) {
        lwan_status_perror("strdup");
        goto error;
    }

    if (settings->script) {
        priv->script = strdup(settings->script);
        if (!priv->script) {
            lwan_status_perror("strdup");
            goto error;
        }
    } else if (settings->script_file) {
        priv->script_file = strdup(settings->script_file);
        if (!priv->script_file) {
            lwan_status_perror("strdup");
            goto error;
        }
    } else {
        lwan_status_error("No Lua script_file or script provided");
        goto error;
    }

    if (pthread_key_create(&priv->cache_key, NULL)) {
        lwan_status_perror("pthread_key_create");
        goto error;
    }

    priv->cache_period = settings->cache_period;

    return priv;

error:
    free(priv->script_file);
    free(priv->default_type);
    free(priv->script);
    free(priv);
    return NULL;
}

static void lua_shutdown(void *data)
{
    struct lwan_lua_priv *priv = data;
    if (priv) {
        pthread_key_delete(priv->cache_key);
        free(priv->default_type);
        free(priv->script_file);
        free(priv->script);
        free(priv);
    }
}

static void *lua_init_from_hash(const char *prefix, const struct hash *hash)
{
    struct lwan_lua_settings settings = {
        .default_type = hash_find(hash, "default_type"),
        .script_file = hash_find(hash, "script_file"),
        .cache_period = parse_time_period(hash_find(hash, "cache_period"), 15),
        .script = hash_find(hash, "script")
    };
    return lua_init(prefix, &settings);
}

const struct lwan_module *lwan_module_lua(void)
{
    static const struct lwan_module lua_module = {
        .init = lua_init,
        .init_from_hash = lua_init_from_hash,
        .shutdown = lua_shutdown,
        .handle = lua_handle_cb,
        .flags = HANDLER_PARSE_QUERY_STRING
            | HANDLER_REMOVE_LEADING_SLASH
            | HANDLER_PARSE_COOKIES
    };

    return &lua_module;
}
