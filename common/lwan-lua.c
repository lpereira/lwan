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
#include <lualib.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "lwan-private.h"

#include "lwan-lua.h"

const char *lwan_request_metatable_name = "Lwan.Request";

static ALWAYS_INLINE struct lwan_request *userdata_as_request(lua_State *L, int n)
{
    return *((struct lwan_request **)luaL_checkudata(L, n, lwan_request_metatable_name));
}

static int req_say_cb(lua_State *L)
{
    struct lwan_request *request = userdata_as_request(L, 1);
    size_t response_str_len;
    const char *response_str = lua_tolstring(L, -1, &response_str_len);

    strbuf_set_static(request->response.buffer, response_str, response_str_len);
    lwan_response_send_chunk(request);

    return 0;
}

static int req_send_event_cb(lua_State *L)
{
    struct lwan_request *request = userdata_as_request(L, 1);
    size_t event_str_len;
    const char *event_str = lua_tolstring(L, -1, &event_str_len);
    const char *event_name = lua_tostring(L, -2);

    strbuf_set_static(request->response.buffer, event_str, event_str_len);
    lwan_response_send_event(request, event_name);

    return 0;
}

static int req_set_response_cb(lua_State *L)
{
    struct lwan_request *request = userdata_as_request(L, 1);
    size_t response_str_len;
    const char *response_str = lua_tolstring(L, -1, &response_str_len);

    strbuf_set(request->response.buffer, response_str, response_str_len);

    return 0;
}

static int request_param_getter(lua_State *L,
        const char *(*getter)(struct lwan_request *req, const char *key))
{
    struct lwan_request *request = userdata_as_request(L, 1);
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

static bool append_key_value(lua_State *L, struct coro *coro,
    struct lwan_key_value_array *arr, char *key, int value_index)
{
    struct lwan_key_value *kv;

    kv = lwan_key_value_array_append(arr);
    if (!kv)
        return false;

    kv->key = key;
    kv->value = coro_strdup(coro, lua_tostring(L, value_index));

    return kv->value != NULL;
}

static int req_set_headers_cb(lua_State *L)
{
    const int table_index = 2;
    const int key_index = 1 + table_index;
    const int value_index = 2 + table_index;
    const int nested_value_index = value_index * 2 - table_index;
    struct lwan_key_value_array *headers;
    struct lwan_request *request = userdata_as_request(L, 1);
    struct coro *coro = request->conn->coro;
    struct lwan_key_value *kv;

    if (request->flags & RESPONSE_SENT_HEADERS)
        goto out;

    if (!lua_istable(L, table_index))
        goto out;

    headers = coro_lwan_key_value_array_new(request->conn->coro);
    if (!headers)
        goto out;

    lua_pushnil(L);
    while (lua_next(L, table_index) != 0) {
        char *key;

        if (!lua_isstring(L, key_index)) {
            lua_pop(L, 1);
            continue;
        }

        key = coro_strdup(request->conn->coro, lua_tostring(L, key_index));
        if (!key)
            goto out;

        if (lua_isstring(L, value_index)) {
            if (!append_key_value(L, coro, headers, key, value_index))
                goto out;
        } else if (lua_istable(L, value_index)) {
            lua_pushnil(L);

            for (; lua_next(L, value_index) != 0; lua_pop(L, 1)) {
                if (lua_isstring(L, nested_value_index))
                    continue;
                if (!append_key_value(L, coro, headers, key, nested_value_index))
                    goto out;
            }
        }

        lua_pop(L, 1);
    }

    kv = lwan_key_value_array_append(headers);
    if (!kv)
        goto out;
    kv->key = kv->value = NULL;

    request->response.headers = headers->base.base;
    lua_pushinteger(L, (lua_Integer)((struct lwan_array *)headers->base.elements));
    return 1;

out:
    lua_pushnil(L);
    return 1;
}

static const struct luaL_reg lwan_request_meta_regs[] = {
    { "query_param", req_query_param_cb },
    { "post_param", req_post_param_cb },
    { "set_response", req_set_response_cb },
    { "say", req_say_cb },
    { "send_event", req_send_event_cb },
    { "cookie", req_cookie_cb },
    { "set_headers", req_set_headers_cb },
    { NULL, NULL }
};

const char *lwan_lua_state_last_error(lua_State *L)
{
    return lua_tostring(L, -1);
}

lua_State *lwan_lua_create_state(const char *script_file, const char *script)
{
    lua_State *L;

    L = luaL_newstate();
    if (UNLIKELY(!L))
        return NULL;

    luaL_openlibs(L);

    luaL_newmetatable(L, lwan_request_metatable_name);
    luaL_register(L, NULL, lwan_request_meta_regs);
    lua_setfield(L, -1, "__index");

    if (script_file) {
        if (UNLIKELY(luaL_dofile(L, script_file) != 0)) {
            lwan_status_error("Error opening Lua script %s: %s",
                script_file, lua_tostring(L, -1));
            goto close_lua_state;
        }
    } else if (UNLIKELY(luaL_dostring(L, script) != 0)) {
        lwan_status_error("Error evaluating Lua script %s", lua_tostring(L, -1));
        goto close_lua_state;
    }

    return L;

close_lua_state:
    lua_close(L);
    return NULL;
}
