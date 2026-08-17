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

#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <lauxlib.h>
#include <lualib.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>

#include "base64.h"
#include "lwan-private.h"

#include "lwan-lua.h"

static const char *request_metatable_name = "Lwan.Request";

ALWAYS_INLINE struct lwan_request *
lwan_lua_get_request_from_userdata(lua_State *L)
{
    if (UNLIKELY(lua_gettop(L) < 1))
        return NULL;

    struct lwan_request **r = luaL_checkudata(L, 1, request_metatable_name);
    return *r;
}

LWAN_LUA_METHOD(http_version)
{
    if (request->flags & REQUEST_IS_HTTP_1_0)
        lua_pushstring(L, "HTTP/1.0");
    else
        lua_pushstring(L, "HTTP/1.1");
    return 1;
}

LWAN_LUA_METHOD(http_method)
{
    lua_pushstring(L, lwan_request_get_method_str(request));
    return 1;
}

LWAN_LUA_METHOD(http_headers)
{
    const struct lwan_request_parser_helper *helper = request->helper;

    lua_newtable(L);

    for (size_t i = 0; i < helper->n_header_start; i++) {
        const char *header = helper->header_start[i];
        const char *next_header = helper->header_start[i + 1];
        const char *colon = memchr(header, ':', (size_t)(next_header - header));

        if (!colon)
            continue;

        const ptrdiff_t header_len = colon - header;
        const ptrdiff_t value_len = next_header - colon - 4;

        if (header_len < 0 || value_len < 0)
            continue;

        lua_pushlstring(L, header, (size_t)header_len);
        lua_pushlstring(L, colon + 2, (size_t)value_len);
        lua_rawset(L, -3);
    }

    return 1;
}

LWAN_LUA_METHOD(num_http_headers)
{
    const struct lwan_request_parser_helper *helper = request->helper;
    lua_pushinteger(L, (int)helper->n_header_start);
    return 1;
}

LWAN_LUA_METHOD(say)
{
    size_t response_str_len;
    const char *response_str = lua_tolstring(L, -1, &response_str_len);

    if (response_str_len) {
        lwan_strbuf_set_static(request->response.buffer, response_str,
                               response_str_len);
        lwan_response_send_chunk(request);
    }

    return 0;
}

LWAN_LUA_METHOD(write)
{
    size_t response_str_len;
    const char *response_str = lua_tolstring(L, -1, &response_str_len);

    lwan_strbuf_append_str(request->response.buffer, response_str,
                           response_str_len);
    return 0;
}

LWAN_LUA_METHOD(send_event)
{
    size_t event_str_len;
    const char *event_str = lua_tolstring(L, -1, &event_str_len);
    const char *event_name = lua_tostring(L, -2);

    lwan_strbuf_set_static(request->response.buffer, event_str, event_str_len);
    lwan_response_send_event(request, event_name);

    return 0;
}

LWAN_LUA_METHOD(set_response)
{
    size_t response_str_len;
    const char *response_str = lua_tolstring(L, -1, &response_str_len);

    lwan_strbuf_set(request->response.buffer, response_str, response_str_len);

    return 0;
}

static int request_param_getter(lua_State *L,
                                struct lwan_request *request,
                                const char *(*getter)(struct lwan_request *req,
                                                      const char *key))
{
    const char *key_str = lua_tostring(L, -1);
    const char *value = getter(request, key_str);

    if (!value)
        lua_pushnil(L);
    else
        lua_pushstring(L, value);

    return 1;
}

LWAN_LUA_METHOD(remote_address)
{
    char ip_buffer[INET6_ADDRSTRLEN];
    lua_pushstring(L, lwan_request_get_remote_address(request, ip_buffer));
    return 1;
}

LWAN_LUA_METHOD(header)
{
    return request_param_getter(L, request, lwan_request_get_header);
}

LWAN_LUA_METHOD(is_https)
{
    lua_pushboolean(L, !!(request->conn->flags & CONN_TLS));
    return 1;
}

LWAN_LUA_METHOD(path)
{
    lua_pushlstring(L, request->url.value, request->url.len);
    return 1;
}

LWAN_LUA_METHOD(host)
{
    const char *host = lwan_request_get_host(request);

    if (host)
        lua_pushstring(L, host);
    else
        lua_pushnil(L);

    return 1;
}

LWAN_LUA_METHOD(query_string)
{
    if (request->helper->query_string.len) {
        lua_pushlstring(L, request->helper->query_string.value, request->helper->query_string.len);
    } else {
        lua_pushlstring(L, "", 0);
    }
    return 1;
}

LWAN_LUA_METHOD(query_param)
{
    return request_param_getter(L, request, lwan_request_get_query_param);
}

LWAN_LUA_METHOD(post_param)
{
    return request_param_getter(L, request, lwan_request_get_post_param);
}

LWAN_LUA_METHOD(cookie)
{
    return request_param_getter(L, request, lwan_request_get_cookie);
}

LWAN_LUA_METHOD(body)
{
    if (request->helper->body_data.len) {
        lua_pushlstring(L, request->helper->body_data.value, request->helper->body_data.len);
    } else {
        lua_pushlstring(L, "", 0);
    }
    return 1;
}

LWAN_LUA_METHOD(ws_upgrade)
{
    enum lwan_http_status status = lwan_request_websocket_upgrade(request);

    lua_pushinteger(L, status);

    return 1;
}

LWAN_LUA_METHOD(ws_write_text)
{
    size_t data_len;
    const char *data_str = lua_tolstring(L, -1, &data_len);

    lwan_strbuf_set_static(request->response.buffer, data_str, data_len);
    lwan_response_websocket_write_text(request);

    return 0;
}

LWAN_LUA_METHOD(ws_write_binary)
{
    size_t data_len;
    const char *data_str = lua_tolstring(L, -1, &data_len);

    lwan_strbuf_set_static(request->response.buffer, data_str, data_len);
    lwan_response_websocket_write_binary(request);

    return 0;
}

LWAN_LUA_METHOD(ws_write)
{
    size_t data_len;
    const char *data_str = lua_tolstring(L, -1, &data_len);

    lwan_strbuf_set_static(request->response.buffer, data_str, data_len);

    for (size_t i = 0; i < data_len; i++) {
        if ((signed char)data_str[i] < 0) {
            lwan_response_websocket_write_binary(request);
            return 0;
        }
    }

    lwan_response_websocket_write_text(request);
    return 0;
}

LWAN_LUA_METHOD(ws_read)
{
    int r;

    /* FIXME: maybe return a table {status=r, content=buf}? */

    r = lwan_response_websocket_read(request);
    switch (r) {
    case 0:
        lua_pushlstring(L, lwan_strbuf_get_buffer(request->response.buffer),
                        lwan_strbuf_get_length(request->response.buffer));
        break;
    case ENOTCONN:
    case EAGAIN:
        lua_pushinteger(L, r);
        break;
    default:
        lua_pushinteger(L, ENOMSG);
        break;
    }

    return 1;
}

static bool append_key_value(struct lwan_request *request,
                             lua_State *L,
                             struct coro *coro,
                             struct lwan_key_value_array *arr,
                             char *key,
                             int value_index)
{
    size_t len;
    const char *lua_value = lua_tolstring(L, value_index, &len);
    char *value = coro_memdup(coro, lua_value, len + 1);

    if (strcaseequal_neutral(key, "Content-Type")) {
        request->response.mime_type = value;
    } else {
        struct lwan_key_value *kv;

        kv = lwan_key_value_array_append(arr);
        if (!kv)
            return false;

        kv->key = key;
        kv->value = value;
    }

    return value != NULL;
}

LWAN_LUA_METHOD(set_headers)
{
    const int table_index = 2;
    const int key_index = -2;
    const int value_index = -1;
    struct lwan_key_value_array *headers;
    struct coro *coro = request->conn->coro;
    struct lwan_key_value *kv;

    if (request->flags & RESPONSE_SENT_HEADERS)
        goto out;

    if (!lua_istable(L, table_index))
        goto out;

    headers = coro_lwan_key_value_array_new(request->conn->coro);
    if (!headers)
        goto out;

    for (lua_pushnil(L); lua_next(L, table_index) != 0; lua_pop(L, 1)) {
        char *key;

        if (lua_type(L, key_index) != LUA_TSTRING)
            continue;

        key = coro_strdup(request->conn->coro, lua_tostring(L, key_index));
        if (!key)
            goto out;

        switch (lua_type(L, value_index)) {
        case LUA_TSTRING:
            if (!append_key_value(request, L, coro, headers, key, value_index))
                goto out;
            break;
        case LUA_TTABLE:
            for (lua_pushnil(L); lua_next(L, value_index - 1) != 0; lua_pop(L, 1)) {
                if (!lua_isstring(L, value_index))
                    continue;
                if (!append_key_value(request, L, coro, headers, key,
                                      value_index))
                    goto out;
            }
            break;
        }
    }

    kv = lwan_key_value_array_append(headers);
    if (!kv)
        goto out;
    kv->key = kv->value = NULL;

    request->response.headers = lwan_key_value_array_get_array(headers);
    lua_pushinteger(L, (lua_Integer)headers->base.elements);
    return 1;

out:
    lua_pushnil(L);
    return 1;
}

LWAN_LUA_METHOD(sleep)
{
    lua_Integer ms = lua_tointeger(L, -1);

    lwan_request_sleep(request, (uint64_t)ms);

    return 0;
}

LWAN_LUA_METHOD(request_id)
{
    char id[17];
    snprintf(id, 17, "%016lx", lwan_request_get_id(request));
    lua_pushstring(L, id);
    return 1;
}

LWAN_LUA_METHOD(request_date)
{
    lua_pushstring(L, request->conn->thread->date.date);
    return 1;
}

LWAN_LUA_METHOD(set_keep_alive)
{
    if (lua_toboolean(L, -1)) {
        request->conn->flags |= CONN_IS_KEEP_ALIVE;
    } else {
        request->conn->flags &= ~CONN_IS_KEEP_ALIVE;
    }
    return 0;
}

#define FOR_EACH_LOG_FUNCTION(X)                                               \
    X(info) X(warning) X(error) X(critical) X(debug)
#define IMPLEMENT_FUNCTION(name_)                                              \
    LWAN_LUA_LIB_FUNCTION(log, name_)                                          \
    {                                                                          \
        size_t log_str_len = 0;                                                \
        const char *log_str = lua_tolstring(L, -1, &log_str_len);              \
        if (log_str_len) {                                                     \
            lwan_log_##name_("%.*s", (int)log_str_len, log_str);               \
            (void)log_str_len;                                                 \
            (void)log_str;                                                     \
        }                                                                      \
        return 0;                                                              \
    }
FOR_EACH_LOG_FUNCTION(IMPLEMENT_FUNCTION)
#undef IMPLEMENT_FUNCTION

LWAN_LUA_LIB_FUNCTION(utils, base64_encode)
{
    size_t encoded_len, decoded_len;
    const char *decoded = lua_tolstring(L, -1, &decoded_len);
    unsigned char *encoded = base64_encode((const unsigned char *)decoded,
                                           decoded_len, &encoded_len);
    if (encoded) {
        lua_pushstring(L, (const char *)encoded);
        free(encoded);
    } else {
        lua_pushnil(L);
    }
    return 1;
}

LWAN_LUA_LIB_FUNCTION(utils, base64_decode)
{
    size_t encoded_len, decoded_len;
    const char *encoded = lua_tolstring(L, -1, &encoded_len);
    unsigned char *decoded = base64_decode((const unsigned char *)encoded,
                                           encoded_len, &decoded_len);
    if (decoded) {
        lua_pushstring(L, (const char *)decoded);
        free(decoded);
    } else {
        lua_pushnil(L);
    }
    return 1;
}

/* Random functions ported from the Go standard library (math/rand).
 * Copyright 2009 The Go Authors.  Licensed under a 3-clause BSD license.
 */
static uint64_t random_int63(void)
{
    return lwan_random_uint64() & ~(1ULL << 63);
}

static uint64_t random_int63n(uint64_t n)
{
    if ((int64_t)n < 0) {
        lwan_log_critical("invalid argument");
    }
    if ((n & (n - 1)) == 0) {
        return random_int63() & (n - 1);
    }
    uint64_t max = (uint64_t)((1ULL << 63) - 1 - (1ULL << 63) % n);
    uint64_t v = random_int63();
    while (v > max) {
        v = random_int63();
    }
    return v % n;
}

LWAN_LUA_LIB_FUNCTION(utils, random_double)
{
    double v = (double)random_int63n(1ULL << 53) / (1ULL << 53);
    lua_pushnumber(L, v);
    return 1;
}

LWAN_LUA_LIB_FUNCTION(utils, version)
{
    lua_pushstring(L, LWAN_VERSION);
    return 1;
}

LWAN_LUA_LIB_FUNCTION(utils, operating_system)
{
    struct utsname u;
    if (!uname(&u)) {
        lua_pushstring(L, u.sysname);
    } else {
        lua_pushstring(L, "Unknown");
    }
    return 1;
}

LWAN_LUA_LIB_FUNCTION(utils, get_mime_type)
{
    size_t file_name_len;
    const char *file_name_str = lua_tolstring(L, -1, &file_name_len);
    lua_pushstring(L, lwan_determine_mime_type_for_file_name(file_name_str));
    return 1;
}

LWAN_LUA_LIB_FUNCTION(utils, get_response_code_text)
{
    lua_Integer code = lua_tointeger(L, -1);
    if (lwan_http_status_is_valid((int)code)) {
        lua_pushstring(L,
                       lwan_http_status_as_string((enum lwan_http_status)code));
    } else {
        lua_pushnil(L);
    }
    return 1;
}

const char *lwan_lua_state_last_error(lua_State *L)
{
    return lua_tostring(L, -1);
}

LWAN_LUA_LIB(utils)
LWAN_LUA_LIB(log)

lua_State *lwan_lua_create_state(const char *script_file, const char *script)
{
    const luaL_Reg *methinfo;
    lua_State *L;

    L = luaL_newstate();
    if (UNLIKELY(!L))
        return NULL;

    lua_newtable(L);
    lua_setglobal(L, "Lwan");

    luaL_openlibs(L);
    LWAN_SECTION_FOREACH (lwan_lua_lib, methinfo) {
        methinfo->func(L);
    }

    luaL_newmetatable(L, request_metatable_name);
    LWAN_SECTION_FOREACH (lwan_lua_method, methinfo) {
        lua_pushcclosure(L, methinfo->func, 0);
        lua_setfield(L, -2, methinfo->name);
    }
    lua_setfield(L, -1, "__index");

    if (script_file) {
        if (UNLIKELY(luaL_dofile(L, script_file) != 0)) {
            lwan_log_error("Error opening Lua script %s: %s", script_file,
                           lua_tostring(L, -1));
            goto close_lua_state;
        }
    } else if (script) {
        if (UNLIKELY(luaL_dostring(L, script) != 0)) {
            lwan_log_error("Error evaluating Lua script %s",
                           lua_tostring(L, -1));
            goto close_lua_state;
        }
    } else {
        lwan_log_error("Either file or inline script has to be provided");
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
