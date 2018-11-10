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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
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

static const char *request_metatable_name = "Lwan.Request";

static ALWAYS_INLINE struct lwan_request *userdata_as_request(lua_State *L)
{
    struct lwan_request **r = luaL_checkudata(L, 1, request_metatable_name);

    return *r;
}

LWAN_LUA_METHOD(say)
{
    struct lwan_request *request = userdata_as_request(L);
    size_t response_str_len;
    const char *response_str = lua_tolstring(L, -1, &response_str_len);

    lwan_strbuf_set_static(request->response.buffer, response_str,
                           response_str_len);
    lwan_response_send_chunk(request);

    return 0;
}

LWAN_LUA_METHOD(send_event)
{
    struct lwan_request *request = userdata_as_request(L);
    size_t event_str_len;
    const char *event_str = lua_tolstring(L, -1, &event_str_len);
    const char *event_name = lua_tostring(L, -2);

    lwan_strbuf_set_static(request->response.buffer, event_str, event_str_len);
    lwan_response_send_event(request, event_name);

    return 0;
}

LWAN_LUA_METHOD(set_response)
{
    struct lwan_request *request = userdata_as_request(L);
    size_t response_str_len;
    const char *response_str = lua_tolstring(L, -1, &response_str_len);

    lwan_strbuf_set(request->response.buffer, response_str, response_str_len);

    return 0;
}

static int request_param_getter(lua_State *L,
                                const char *(*getter)(struct lwan_request *req,
                                                      const char *key))
{
    struct lwan_request *request = userdata_as_request(L);
    const char *key_str = lua_tostring(L, -1);

    const char *value = getter(request, key_str);
    if (!value)
        lua_pushnil(L);
    else
        lua_pushstring(L, value);

    return 1;
}

LWAN_LUA_METHOD(header)
{
    return request_param_getter(L, lwan_request_get_header);
}

LWAN_LUA_METHOD(query_param)
{
    return request_param_getter(L, lwan_request_get_query_param);
}

LWAN_LUA_METHOD(post_param)
{
    return request_param_getter(L, lwan_request_get_post_param);
}

LWAN_LUA_METHOD(cookie)
{
    return request_param_getter(L, lwan_request_get_cookie);
}

LWAN_LUA_METHOD(ws_upgrade)
{
    struct lwan_request *request = userdata_as_request(L);
    enum lwan_http_status status = lwan_request_websocket_upgrade(request);

    lua_pushinteger(L, status);

    return 1;
}

LWAN_LUA_METHOD(ws_write)
{
    struct lwan_request *request = userdata_as_request(L);
    size_t data_len;
    const char *data_str = lua_tolstring(L, -1, &data_len);

    lwan_strbuf_set_static(request->response.buffer, data_str, data_len);
    lwan_response_websocket_write(request);

    return 0;
}

LWAN_LUA_METHOD(ws_read)
{
    struct lwan_request *request = userdata_as_request(L);

    if (lwan_response_websocket_read(request)) {
        lua_pushlstring(L, lwan_strbuf_get_buffer(request->response.buffer),
                        lwan_strbuf_get_length(request->response.buffer));
    } else {
        lua_pushnil(L);
    }

    return 1;
}

static bool append_key_value(lua_State *L,
                             struct coro *coro,
                             struct lwan_key_value_array *arr,
                             char *key,
                             int value_index)
{
    struct lwan_key_value *kv;

    kv = lwan_key_value_array_append(arr);
    if (!kv)
        return false;

    kv->key = key;
    kv->value = coro_strdup(coro, lua_tostring(L, value_index));

    return kv->value != NULL;
}

LWAN_LUA_METHOD(set_headers)
{
    const int table_index = 2;
    const int key_index = 1 + table_index;
    const int value_index = 2 + table_index;
    const int nested_value_index = value_index * 2 - table_index;
    struct lwan_key_value_array *headers;
    struct lwan_request *request = userdata_as_request(L);
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
                if (!lua_isstring(L, nested_value_index))
                    continue;
                if (!append_key_value(L, coro, headers, key,
                                      nested_value_index))
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
    lua_pushinteger(L, (lua_Integer)headers->base.elements);
    return 1;

out:
    lua_pushnil(L);
    return 1;
}

LWAN_LUA_METHOD(sleep)
{
    struct lwan_request *request = userdata_as_request(L);
    lua_Integer ms = lua_tointeger(L, -1);

    lwan_request_sleep(request, (uint64_t)ms);

    return 0;
}

DEFINE_ARRAY_TYPE(lwan_lua_method_array, luaL_reg)
static struct lwan_lua_method_array lua_methods;

__attribute__((constructor)) static void register_lua_methods(void)
{
    extern const struct lwan_lua_method_info SECTION_START(lwan_lua_method);
    extern const struct lwan_lua_method_info SECTION_END(lwan_lua_method);
    const struct lwan_lua_method_info *info;
    luaL_reg *r;

    for (info = __start_lwan_lua_method; info < __stop_lwan_lua_method;
         info++) {
        r = lwan_lua_method_array_append(&lua_methods);
        if (!r) {
            lwan_status_critical("Could not register Lua method `%s`",
                                 info->name);
        }

        r->name = info->name;
        r->func = info->func;
    }

    r = lwan_lua_method_array_append(&lua_methods);
    if (!r)
        lwan_status_critical("Could not add Lua method sentinel");

    r->name = NULL;
    r->func = NULL;
}

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

    luaL_newmetatable(L, request_metatable_name);
    luaL_register(L, NULL, lua_methods.base.base);
    lua_setfield(L, -1, "__index");

    if (script_file) {
        if (UNLIKELY(luaL_dofile(L, script_file) != 0)) {
            lwan_status_error("Error opening Lua script %s: %s", script_file,
                              lua_tostring(L, -1));
            goto close_lua_state;
        }
    } else if (UNLIKELY(luaL_dostring(L, script) != 0)) {
        lwan_status_error("Error evaluating Lua script %s",
                          lua_tostring(L, -1));
        goto close_lua_state;
    }

    return L;

close_lua_state:
    lua_close(L);
    return NULL;
}

void lwan_lua_state_push_request(lua_State *L, struct lwan_request *request)
{
    struct lwan_request **userdata =
        lua_newuserdata(L, sizeof(struct lwan_request *));

    *userdata = request;
    luaL_getmetatable(L, request_metatable_name);
    lua_setmetatable(L, -2);
}
