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

#include "lwan.h"
#include "lwan-lua.h"

static const char request_key = 'R';

struct lwan_lua_priv_t {
    char *default_type;
    char *script_file;
};

static int func_say(lua_State *L)
{
    size_t response_str_len;
    const char *response_str = lua_tolstring(L, -1, &response_str_len);

    lua_pushlightuserdata(L, (void *)&request_key);
    lua_gettable(L, LUA_REGISTRYINDEX);
    lwan_request_t *request = lua_touserdata(L, -1);

    strbuf_set(request->response.buffer, response_str, response_str_len);
    lwan_response_send_chunk(request);

    return 1;
}

static const struct luaL_reg funcs[] = {
    { "say", func_say },
    { NULL, NULL }
};

static lwan_http_status_t
lua_handle_cb(lwan_request_t *request,
              lwan_response_t *response,
              void *data)
{
    lwan_http_status_t status = HTTP_OK;
    struct lwan_lua_priv_t *priv = data;

    if (UNLIKELY(!priv))
        return HTTP_INTERNAL_ERROR;

    /* FIXME: Ideally, for each script file, there would be one lua_State per
     * thread. This way, it would be possible to use lua_newthread() and avoid
     * having to perform all the setup. To allow for scripts to be reloaded,
     * Lwan caching subsystem could be used to cache this for a predetermined
     * amount of time. */
    lua_State *L = luaL_newstate();
    if (UNLIKELY(!L))
        return HTTP_INTERNAL_ERROR;

    luaL_openlibs(L);
    luaL_register(L, "lwan", funcs);

    lua_pushlightuserdata(L, (void *)&request_key);
    lua_pushlightuserdata(L, request);
    lua_settable(L, LUA_REGISTRYINDEX);

    if (UNLIKELY(luaL_loadfile(L, priv->script_file) != 0)) {
        lwan_status_error("Error opening Lua script %s: %s",
                    priv->script_file, lua_tostring(L, -1));
        status = HTTP_INTERNAL_ERROR;
    } else {
        response->mime_type = priv->default_type;

        if (UNLIKELY(lua_pcall(L, 0, LUA_MULTRET, 0) != 0)) {
            lwan_status_error("Error executing Lua script: %s", lua_tostring(L, -1));
            status = HTTP_INTERNAL_ERROR;
        }
    }

    lua_close(L);
    return status;
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

    return priv;

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
        free(priv->default_type);
        free(priv->script_file);
        free(priv);
    }
}

static void *lua_init_from_hash(const struct hash *hash)
{
    struct lwan_lua_settings_t settings = {
        .default_type = hash_find(hash, "default type"),
        .script_file = hash_find(hash, "script file")
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
