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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#pragma once

#include <lua.h>

struct lwan_request;

struct lwan_lua_method_info {
    const char *name;
    int (*func)();
};

#define LWAN_LUA_METHOD(name_)                                                 \
    static int lwan_lua_method_##name_##_wrapper(lua_State *L);                \
    static int lwan_lua_method_##name_(lua_State *L,                           \
                                       struct lwan_request *request);          \
    static const struct lwan_lua_method_info                                   \
        __attribute__((used, section(LWAN_SECTION_NAME(lwan_lua_method))))     \
        lwan_lua_method_info_##name_ = {                                       \
            .name = #name_, .func = lwan_lua_method_##name_##_wrapper};        \
    static int lwan_lua_method_##name_##_wrapper(lua_State *L)                 \
    {                                                                          \
        struct lwan_request *request = lwan_lua_get_request_from_userdata(L);  \
        return lwan_lua_method_##name_(L, request);                            \
    }                                                                          \
    static ALWAYS_INLINE int lwan_lua_method_##name_(                          \
        lua_State *L, struct lwan_request *request)


const char *lwan_lua_state_last_error(lua_State *L);
lua_State *lwan_lua_create_state(const char *script_file, const char *script);

void lwan_lua_state_push_request(lua_State *L, struct lwan_request *request);

struct lwan_request *lwan_lua_get_request_from_userdata(lua_State *L);
