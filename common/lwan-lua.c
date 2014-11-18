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

#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "lwan.h"
#include "lwan-cache.h"
#include "lwan-config.h"
#include "lwan-lua.h"

static const char request_key = 'R';

struct lwan_lua_priv_t {
    char *default_type;
    char *script_file;
    pthread_key_t cache_key;
    unsigned cache_period;
};

struct lwan_lua_state_t {
    struct cache_entry_t base;
    lua_State *L;
};

static lwan_request_t *get_request_from_lua_state(lua_State *L)
{
    lua_pushlightuserdata(L, (void *)&request_key);
    lua_gettable(L, LUA_REGISTRYINDEX);
    return lua_touserdata(L, -1);
}

static int func_say(lua_State *L)
{
    size_t response_str_len;
    const char *response_str = lua_tolstring(L, -1, &response_str_len);
    lwan_request_t *request = get_request_from_lua_state(L);

    strbuf_set(request->response.buffer, response_str, response_str_len);
    lwan_response_send_chunk(request);

    return 1;
}

static int func_yield(lua_State *L)
{
    return lua_yield(L, 0);
}

static int func_set_response(lua_State *L)
{
    size_t response_str_len;
    const char *response_str = lua_tolstring(L, -1, &response_str_len);
    lwan_request_t *request = get_request_from_lua_state(L);

    strbuf_set(request->response.buffer, response_str, response_str_len);
    return 1;
}

static const struct luaL_reg funcs[] = {
    { "yield", func_yield },
    { "set_response", func_set_response },
    { "say", func_say },
    { NULL, NULL }
};

static struct cache_entry_t *state_create(const char *key __attribute__((unused)),
        void *context)
{
    struct lwan_lua_priv_t *priv = context;
    struct lwan_lua_state_t *state = malloc(sizeof(*state));

    if (UNLIKELY(!state))
        return NULL;

    state->L = luaL_newstate();
    if (UNLIKELY(!state->L)) {
        free(state);
        return NULL;
    }

    luaL_openlibs(state->L);
    luaL_register(state->L, "lwan", funcs);

    if (UNLIKELY(luaL_dofile(state->L, priv->script_file) != 0)) {
        lwan_status_error("Error opening Lua script %s", lua_tostring(state->L, -1));
        lua_close(state->L);
        free(state);
        return NULL;
    }

    return (struct cache_entry_t *)state;
}

static void state_destroy(struct cache_entry_t *entry,
        void *context __attribute__((unused)))
{
    struct lwan_lua_state_t *state = (struct lwan_lua_state_t *)entry;

    lua_close(state->L);
    free(state);
}

static struct cache_t *get_or_create_cache(struct lwan_lua_priv_t *priv)
{
    struct cache_t *cache = pthread_getspecific(priv->cache_key);
    if (UNLIKELY(!cache)) {
        lwan_status_debug("Creating cache for this thread");
        cache = cache_create(state_create, state_destroy, priv, priv->cache_period);
        if (UNLIKELY(!cache))
            lwan_status_error("Could not create cache");
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

static lwan_http_status_t
lua_handle_cb(lwan_request_t *request,
              lwan_response_t *response,
              void *data)
{
    struct lwan_lua_priv_t *priv = data;

    if (UNLIKELY(!priv))
        return HTTP_INTERNAL_ERROR;

    struct cache_t *cache = get_or_create_cache(priv);
    if (UNLIKELY(!cache))
        return HTTP_INTERNAL_ERROR;

    struct lwan_lua_state_t *state = (struct lwan_lua_state_t *)cache_coro_get_and_ref_entry(
            cache, request->conn->coro, "entry_point");
    if (UNLIKELY(!state))
        return HTTP_NOT_FOUND;

    lua_State *L = lua_newthread(state->L);
    if (UNLIKELY(!L))
        return HTTP_INTERNAL_ERROR;

    int thread_ref = luaL_ref(state->L, LUA_REGISTRYINDEX);
    coro_defer2(request->conn->coro, CORO_DEFER2(unref_thread),
        state->L, (void *)(intptr_t)thread_ref);

    lua_pushlightuserdata(L, (void *)&request_key);
    lua_pushlightuserdata(L, request);
    lua_settable(L, LUA_REGISTRYINDEX);

    response->mime_type = priv->default_type;

    lua_getglobal(state->L, "entry_point");
    lua_xmove(state->L, L, 1);
    lua_getglobal(L, "entry_point");

    while (true) {
        switch (lua_resume(L, 0)) {
        case LUA_YIELD:
            coro_yield(request->conn->coro, CONN_CORO_MAY_RESUME);
            break;
        case 0:
            return HTTP_OK;
        default:
            return HTTP_INTERNAL_ERROR;
        }
    }
}

static void *lua_init(void *data)
{
    struct lwan_lua_settings_t *settings = data;
    struct lwan_lua_priv_t *priv;

    priv = malloc(sizeof(*priv));
    if (!priv) {
        lwan_status_error("Could not allocate memory for private Lua struct");
        return NULL;
    }

    priv->default_type = strdup(
        settings->default_type ? settings->default_type : "text/plain");
    if (!priv->default_type) {
        lwan_status_perror("strdup");
        goto out_no_default_type;
    }

    if (!settings->script_file) {
        lwan_status_error("No Lua script file provided");
        goto out_no_script_file;
    }
    priv->script_file = strdup(settings->script_file);
    if (!priv->script_file) {
        lwan_status_perror("strdup");
        goto out_no_script_file;
    }

    if (pthread_key_create(&priv->cache_key, NULL)) {
        lwan_status_perror("pthread_key_create");
        goto out_key_create;
    }

    priv->cache_period = settings->cache_period;

    return priv;

out_key_create:
    free(priv->script_file);
out_no_script_file:
    free(priv->default_type);
out_no_default_type:
    free(priv);
    return NULL;
}

static void lua_shutdown(void *data)
{
    struct lwan_lua_priv_t *priv = data;
    if (priv) {
        pthread_key_delete(priv->cache_key);
        free(priv->default_type);
        free(priv->script_file);
        free(priv);
    }
}

static void *lua_init_from_hash(const struct hash *hash)
{
    struct lwan_lua_settings_t settings = {
        .default_type = hash_find(hash, "default type"),
        .script_file = hash_find(hash, "script file"),
        .cache_period = parse_time_period(hash_find(hash, "cache period"), 15)
    };
    return lua_init(&settings);
}

const lwan_module_t *lwan_module_lua(void)
{
    static const lwan_module_t lua_module = {
        .name = "lua",
        .init = lua_init,
        .init_from_hash = lua_init_from_hash,
        .shutdown = lua_shutdown,
        .handle = lua_handle_cb,
        .flags = 0
    };

    return &lua_module;
}
