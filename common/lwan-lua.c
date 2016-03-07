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

#define _GNU_SOURCE
#include <ctype.h>
#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "lwan.h"
#include "lwan-cache.h"
#include "lwan-config.h"
#include "lwan-lua.h"

static const char *request_metatable_name = "Lwan.Request";

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

static ALWAYS_INLINE lwan_request_t *userdata_as_request(lua_State *L, int n)
{
    return *((lwan_request_t **)luaL_checkudata(L, n, request_metatable_name));
}

static int req_say_cb(lua_State *L)
{
    lwan_request_t *request = userdata_as_request(L, 1);
    size_t response_str_len;
    const char *response_str = lua_tolstring(L, -1, &response_str_len);

    strbuf_set_static(request->response.buffer, response_str, response_str_len);
    lwan_response_send_chunk(request);

    return 0;
}

static int req_send_event_cb(lua_State *L)
{
    lwan_request_t *request = userdata_as_request(L, 1);
    size_t event_str_len;
    const char *event_str = lua_tolstring(L, -1, &event_str_len);
    const char *event_name = lua_tostring(L, -2);

    strbuf_set_static(request->response.buffer, event_str, event_str_len);
    lwan_response_send_event(request, event_name);

    return 0;
}

static int req_yield_cb(lua_State *L)
{
    return lua_yield(L, 0);
}

static int req_set_response_cb(lua_State *L)
{
    lwan_request_t *request = userdata_as_request(L, 1);
    size_t response_str_len;
    const char *response_str = lua_tolstring(L, -1, &response_str_len);

    strbuf_set(request->response.buffer, response_str, response_str_len);

    return 0;
}

static int request_param_getter(lua_State *L,
        const char *(*getter)(lwan_request_t *req, const char *key))
{
    lwan_request_t *request = userdata_as_request(L, 1);
    const char *key_str = lua_tostring(L, -1);

    const char *value = getter(request, key_str);
    if (!value)
        lua_pushnil(L);
    else
        lua_pushstring(L, value);

    return 1;
}

static int req_query_param_cb(lua_State *L)
{
    return request_param_getter(L, lwan_request_get_query_param);
}

static int req_post_param_cb(lua_State *L)
{
    return request_param_getter(L, lwan_request_get_post_param);
}

static int req_cookie_cb(lua_State *L)
{
    return request_param_getter(L, lwan_request_get_cookie);
}

static int req_set_headers_cb(lua_State *L)
{
    const size_t max_headers = 16;
    const int table_index = 2;
    const int key_index = 1 + table_index;
    const int value_index = 2 + table_index;
    const int nested_value_index = value_index * 2 - table_index;
    lwan_request_t *request = userdata_as_request(L, 1);
    lwan_key_value_t *headers = coro_malloc(request->conn->coro, max_headers * sizeof(*headers));
    size_t n_headers = 0;

    if (!headers) {
        lua_pushnil(L);
        return 1;
    }

    if (request->flags & RESPONSE_SENT_HEADERS) {
        lua_pushnil(L);
        return 1;
    }

    if (!lua_istable(L, table_index)) {
        lua_pushnil(L);
        return 1;
    }

    lua_pushnil(L);
    while (n_headers < (max_headers - 1) && lua_next(L, table_index) != 0) {
        if (!lua_isstring(L, key_index)) {
            lua_pop(L, 1);
            continue;
        }

        if (lua_isstring(L, value_index)) {
            headers[n_headers].key = coro_strdup(request->conn->coro,
                lua_tostring(L, key_index));
            headers[n_headers].value = coro_strdup(request->conn->coro,
                lua_tostring(L, value_index));

            n_headers++;
        } else if (lua_istable(L, value_index)) {
            char *header_name = coro_strdup(request->conn->coro,
                lua_tostring(L, key_index));

            lua_pushnil(L);
            while (n_headers < (max_headers - 1) && lua_next(L, value_index) != 0) {
                if (lua_isstring(L, nested_value_index)) {
                    headers[n_headers].key = header_name;
                    headers[n_headers].value = coro_strdup(request->conn->coro,
                        lua_tostring(L, nested_value_index));

                    n_headers++;
                }

                lua_pop(L, 1);
            }
        }

        lua_pop(L, 1);
    }
    if (n_headers == (max_headers - 1))
        lua_pop(L, 1);

    headers[n_headers].key = headers[n_headers].value = NULL;
    request->response.headers = headers;

    lua_pushinteger(L, (lua_Integer)n_headers);
    return 1;
}

static const struct luaL_reg lwan_request_meta_regs[] = {
    { "query_param", req_query_param_cb },
    { "post_param", req_post_param_cb },
    { "yield", req_yield_cb },
    { "set_response", req_set_response_cb },
    { "say", req_say_cb },
    { "send_event", req_send_event_cb },
    { "cookie", req_cookie_cb },
    { "set_headers", req_set_headers_cb },
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
    if (UNLIKELY(!state->L))
        goto free_state;

    luaL_openlibs(state->L);

    luaL_newmetatable(state->L, request_metatable_name);
    luaL_register(state->L, NULL, lwan_request_meta_regs);
    lua_setfield(state->L, -1, "__index");

    if (UNLIKELY(luaL_dofile(state->L, priv->script_file) != 0)) {
        lwan_status_error("Error opening Lua script %s", lua_tostring(state->L, -1));
        goto close_lua_state;
    }

    return (struct cache_entry_t *)state;

close_lua_state:
    lua_close(state->L);
free_state:
    free(state);
    return NULL;
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

static ALWAYS_INLINE const char *get_handle_prefix(lwan_request_t *request, size_t *len)
{
    if (request->flags & REQUEST_METHOD_GET) {
        *len = sizeof("handle_get_");
        return "handle_get_";
    }
    if (request->flags & REQUEST_METHOD_POST) {
        *len = sizeof("handle_post_");
        return "handle_post_";
    }
    if (request->flags & REQUEST_METHOD_HEAD) {
        *len = sizeof("handle_head_");
        return "handle_head_";
    }

    return NULL;
}

static bool get_handler_function(lua_State *L, lwan_request_t *request)
{
    size_t handle_prefix_len;
    const char *handle_prefix = get_handle_prefix(request, &handle_prefix_len);
    if (UNLIKELY(!handle_prefix))
        return false;

    char handler_name[128];
    char *method_name = mempcpy(handler_name, handle_prefix, handle_prefix_len);

    char *url;
    size_t url_len;
    if (request->url.len) {
        url = strdupa(request->url.value);
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
    memcpy(method_name - 1, url, url_len + 1);

    lua_getglobal(L, handler_name);
    return lua_isfunction(L, -1);
}

static void push_request(lua_State *L, lwan_request_t *request)
{
    lwan_request_t **userdata = lua_newuserdata(L, sizeof(lwan_request_t *));
    *userdata = request;
    luaL_getmetatable(L, request_metatable_name);
    lua_setmetatable(L, -2);
}

static lua_State *push_newthread(lua_State *L, coro_t *coro)
{
    lua_State *L1 = lua_newthread(L);
    if (UNLIKELY(!L1))
        return NULL;

    int thread_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    coro_defer2(coro, CORO_DEFER2(unref_thread), L, (void *)(intptr_t)thread_ref);

    return L1;
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
            cache, request->conn->coro, "");
    if (UNLIKELY(!state))
        return HTTP_NOT_FOUND;

    lua_State *L = push_newthread(state->L, request->conn->coro);
    if (UNLIKELY(!L))
        return HTTP_INTERNAL_ERROR;

    if (UNLIKELY(!get_handler_function(L, request)))
        return HTTP_NOT_FOUND;

    int n_arguments = 1;
    push_request(L, request);
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
        .default_type = hash_find(hash, "default_type"),
        .script_file = hash_find(hash, "script_file"),
        .cache_period = parse_time_period(hash_find(hash, "cache_period"), 15)
    };
    return lua_init(&settings);
}

const lwan_module_t *lwan_module_lua(void)
{
    static const lwan_module_t lua_module = {
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
