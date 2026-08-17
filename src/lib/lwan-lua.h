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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#pragma once

#include <lua.h>
#include <lauxlib.h>

struct lwan_request;

#define LWAN_LUA_LIB(lib_)                                                     \
    static int lwan_luaopen_##lib_(lua_State *L)                               \
    {                                                                          \
        const luaL_Reg *info;                                                  \
        lua_getglobal(L, "Lwan");                                              \
        luaL_checkversion(L);                                                  \
        lua_newtable(L);                                                       \
        LWAN_SECTION_FOREACH (lwan_lua_lib_##lib_, info) {                     \
            lua_pushcclosure(L, info->func, 0);                                \
            lua_setfield(L, -2, info->name);                                   \
        }                                                                      \
        lua_setfield(L, -2, #lib_);                                            \
        return 0;                                                              \
    }                                                                          \
    static const luaL_Reg                                                      \
        __attribute__((used, section(LWAN_SECTION_NAME(lwan_lua_lib))))        \
        lwan_luaopen_##lib_##func = {.func = lwan_luaopen_##lib_};

#define LWAN_LUA_LIB_FUNCTION(lib_, function_)                                 \
    static int lwan_lua_lib_func_##lib_##function_(lua_State *L);              \
    static const luaL_Reg                                                      \
        __attribute__((used, section(LWAN_SECTION_NAME(lwan_lua_lib_##lib_)))) \
        lwan_lua_lib_func_info_##lib_##function_ = {                           \
            .name = #function_,                                                \
            .func = lwan_lua_lib_func_##lib_##function_,                       \
    };                                                                         \
    static int lwan_lua_lib_func_##lib_##function_(lua_State *L)

#define LWAN_LUA_METHOD(name_)                                                 \
    static int lwan_lua_method_##name_##_wrapper(lua_State *L);                \
    static int lwan_lua_method_##name_(lua_State *L,                           \
                                       struct lwan_request *request);          \
    static const luaL_Reg __attribute__((                                      \
        used, section(LWAN_SECTION_NAME(                                       \
                  lwan_lua_method)))) lwan_lua_method_info_##name_ = {         \
        .name = #name_,                                                        \
        .func = lwan_lua_method_##name_##_wrapper,                             \
    };                                                                         \
    static int lwan_lua_method_##name_##_wrapper(lua_State *L)                 \
    {                                                                          \
        struct lwan_request *request = lwan_lua_get_request_from_userdata(L);  \
        if (UNLIKELY(!request)) {                                              \
            lwan_log_error("Lua method `%s' called without request parameter", \
                           #name_);                                            \
            return 0;                                                          \
        }                                                                      \
        return lwan_lua_method_##name_(L, request);                            \
    }                                                                          \
    static ALWAYS_INLINE int lwan_lua_method_##name_(                          \
        lua_State *L, struct lwan_request *request)

const char *lwan_lua_state_last_error(lua_State *L);
lua_State *lwan_lua_create_state(const char *script_file, const char *script);

void lwan_lua_state_push_request(lua_State *L, struct lwan_request *request);

struct lwan_request *lwan_lua_get_request_from_userdata(lua_State *L);
