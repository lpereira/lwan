/*
 * lwan - simple web server
 * Copyright (c) 2015 Leandro A. F. Pereira <leandro@hardinfo.org>
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
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "lwan-private.h"

#include "lwan-rewrite.h"
#include "list.h"
#include "patterns.h"

#ifdef HAVE_LUA
#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

#include "lwan-lua.h"
#endif

struct private_data {
    struct list_head patterns;
};

struct pattern {
    struct list_node list;
    char *pattern;
    char *expand_pattern;

    enum lwan_http_status (*handle)(struct lwan_request *request, const char *url);
    const char *(*expand)(struct lwan_request *request, struct pattern *pattern,
        const char *orig, char buffer[static PATH_MAX], struct str_find *sf,
        int captures);
};

struct str_builder {
    char *buffer;
    size_t size, len;
};

static enum lwan_http_status
module_redirect_to(struct lwan_request *request, const char *url)
{
    struct lwan_key_value *headers = coro_malloc(request->conn->coro, sizeof(*headers) * 2);
    if (UNLIKELY(!headers))
        return HTTP_INTERNAL_ERROR;

    headers[0].key = "Location";
    headers[0].value = coro_strdup(request->conn->coro, url);
    if (UNLIKELY(!headers[0].value))
        return HTTP_INTERNAL_ERROR;

    headers[1].key = NULL;
    headers[1].value = NULL;
    request->response.headers = headers;

    return HTTP_MOVED_PERMANENTLY;
}

static enum lwan_http_status
module_rewrite_as(struct lwan_request *request, const char *url)
{
    request->url.value = coro_strdup(request->conn->coro, url);
    if (UNLIKELY(!request->url.value))
        return HTTP_INTERNAL_ERROR;

    request->url.len = strlen(request->url.value);
    request->original_url = request->url;
    request->flags |= RESPONSE_URL_REWRITTEN;

    return HTTP_OK;
}

static bool
append_str(struct str_builder *builder, const char *src, size_t src_len)
{
    size_t total_size = builder->len + src_len;
    char *dest;

    if (total_size >= builder->size)
        return false;

    dest = mempcpy(builder->buffer + builder->len, src, src_len);
    *dest = '\0';
    builder->len = total_size;

    return true;
}

static int
parse_int_len(const char *s, size_t len, int default_value)
{
    return parse_int(strndupa(s, len), default_value);
}

static const char *
expand(struct lwan_request *request __attribute__((unused)), struct pattern *pattern,
    const char *orig, char buffer[static PATH_MAX], struct str_find *sf,
    int captures)
{
    const char *expand_pattern = pattern->expand_pattern;
    struct str_builder builder = { .buffer = buffer, .size = PATH_MAX };
    char *ptr;

    ptr = strchr(expand_pattern, '%');
    if (!ptr)
        return expand_pattern;

    do {
        size_t index_len = strspn(ptr + 1, "0123456789");

        if (ptr > expand_pattern) {
            if (UNLIKELY(!append_str(&builder, expand_pattern, (size_t)(ptr - expand_pattern))))
                return NULL;

            expand_pattern += ptr - expand_pattern;
        }

        if (LIKELY(index_len > 0)) {
            int index = parse_int_len(ptr + 1, index_len, -1);

            if (UNLIKELY(index < 0 || index > captures))
                return NULL;

            if (UNLIKELY(!append_str(&builder, orig + sf[index].sm_so,
                    (size_t)(sf[index].sm_eo - sf[index].sm_so))))
                return NULL;

            ptr += index_len;
            expand_pattern += index_len;
        } else if (UNLIKELY(!append_str(&builder, "%", 1))) {
            return NULL;
        }

        expand_pattern++;
    } while ((ptr = strchr(ptr + 1, '%')));

    if (*expand_pattern && !append_str(&builder, expand_pattern, strlen(expand_pattern)))
        return NULL;

    if (UNLIKELY(!builder.len))
        return NULL;

    return builder.buffer;
}

#ifdef HAVE_LUA
static const char *
expand_lua(struct lwan_request *request, struct pattern *pattern, const char *orig,
    char buffer[static PATH_MAX], struct str_find *sf, int captures)
{
    const char *output, *ret;
    size_t output_len;
    int i;
    lua_State *L;

    L = lwan_lua_create_state(NULL, pattern->expand_pattern);
    if (UNLIKELY(!L))
        return NULL;
    coro_defer(request->conn->coro, CORO_DEFER(lua_close), L);

    lua_getglobal(L, "handle_rewrite");
    if (!lua_isfunction(L, -1)) {
        lwan_status_error("Could not obtain reference to `handle_rewrite()` function: %s",
            lwan_lua_state_last_error(L));
        return NULL;
    }

    lwan_lua_state_push_request(L, request);

    lua_createtable(L, captures, 0);
    for (i = 0; i < captures; i++) {
        lua_pushinteger(L, i);
        lua_pushlstring(L, orig + sf[i].sm_so, (size_t)(sf[i].sm_eo - sf[i].sm_so));
        lua_settable(L, -3);
    }

    if (lua_pcall(L, 2, 1, 0) != 0) {
        lwan_status_error("Could not execute `handle_rewrite()` function: %s",
            lwan_lua_state_last_error(L));

        lua_pop(L, 2); /* 2: request + capture table */
        return NULL;
    }

    output = lua_tolstring(L, -1, &output_len);
    if (output_len >= PATH_MAX) {
        lwan_status_error("Rewritten URL exceeds %d bytes (got %ld bytes)",
            PATH_MAX, output_len);

        lua_pop(L, 1); /* 1: return value */
        return NULL;
    }

    ret = memcpy(buffer, output, output_len + 1);
    lua_pop(L, 1); /* 1: return value */
    return ret;
}
#endif

static enum lwan_http_status
module_handle_cb(struct lwan_request *request,
    struct lwan_response *response __attribute__((unused)), void *data)
{
    const char *url = request->url.value;
    char final_url[PATH_MAX];
    struct private_data *pd = data;
    struct pattern *p;

    if (UNLIKELY(!pd))
        return HTTP_INTERNAL_ERROR;

    list_for_each(&pd->patterns, p, list) {
        struct str_find sf[MAXCAPTURES];
        const char *errmsg, *expanded;
        int captures;

        captures = str_find(url, p->pattern, sf, MAXCAPTURES, &errmsg);
        if (captures <= 0)
            continue;

        expanded = p->expand(request, p, url, final_url, sf, captures);
        if (LIKELY(expanded))
            return p->handle(request, expanded);

        return HTTP_INTERNAL_ERROR;
    }

    return HTTP_NOT_FOUND;
}

static void *
module_init(const char *prefix __attribute__((unused)),
    void *data __attribute__((unused)))
{
    struct private_data *pd = malloc(sizeof(*pd));

    if (!pd)
        return NULL;

    list_head_init(&pd->patterns);
    return pd;
}

static void
module_shutdown(void *data)
{
    struct private_data *pd = data;
    struct pattern *iter, *next;

    list_for_each_safe(&pd->patterns, iter, next, list) {
        free(iter->pattern);
        free(iter->expand_pattern);
        free(iter);
    }

    free(pd);
}

static void *
module_init_from_hash(const char *prefix,
    const struct hash *hash __attribute__((unused)))
{
    return module_init(prefix, NULL);
}

static bool
module_parse_conf_pattern(struct private_data *pd, struct config *config, struct config_line *line)
{
    struct pattern *pattern;
    char *redirect_to = NULL, *rewrite_as = NULL;
    bool expand_with_lua = false;

    pattern = calloc(1, sizeof(*pattern));
    if (!pattern)
        goto out_no_free;
    
    pattern->pattern = strdup(line->param);
    if (!pattern->pattern)
        goto out;

    while (config_read_line(config, line)) {
        switch (line->type) {
        case CONFIG_LINE_TYPE_LINE:
            if (streq(line->key, "redirect_to")) {
                redirect_to = strdup(line->value);
                if (!redirect_to)
                    goto out;
            } else if (streq(line->key, "rewrite_as")) {
                rewrite_as = strdup(line->value);
                if (!rewrite_as)
                    goto out;
            } else if (streq(line->key, "expand_with_lua")) {
                expand_with_lua = parse_bool(line->value, false);
            } else {
                config_error(config, "Unexpected key: %s", line->key);
                goto out;
            }
            break;
        case CONFIG_LINE_TYPE_SECTION:
            config_error(config, "Unexpected section: %s", line->name);
            break;
        case CONFIG_LINE_TYPE_SECTION_END:
            if (redirect_to && rewrite_as) {
                config_error(config, "`redirect to` and `rewrite as` are mutually exclusive");
                goto out;
            }
            if (redirect_to) {
                pattern->expand_pattern = redirect_to;
                pattern->handle = module_redirect_to;
            } else if (rewrite_as) {
                pattern->expand_pattern = rewrite_as;
                pattern->handle = module_rewrite_as;
            } else {
                config_error(config, "either `redirect to` or `rewrite as` are required");
                goto out;
            }
            if (expand_with_lua) {
#ifdef HAVE_LUA
                pattern->expand = expand_lua;
#else
                config_error(config, "Lwan has been built without Lua. `expand_with_lua` is not available");
                goto out;
#endif
            } else {
                pattern->expand = expand;
            }
            list_add_tail(&pd->patterns, &pattern->list);
            return true;
        }
    }

out:
    free(pattern->pattern);
    free(redirect_to);
    free(rewrite_as);
    free(pattern);
out_no_free:
    config_error(config, "Could not copy pattern");
    return false;
}

static bool
module_parse_conf(void *data, struct config *config)
{
    struct private_data *pd = data;
    struct config_line line;

    while (config_read_line(config, &line)) {
        switch (line.type) {
        case CONFIG_LINE_TYPE_LINE:
            config_error(config, "Unknown option: %s", line.key);
            break;
        case CONFIG_LINE_TYPE_SECTION:
            if (streq(line.name, "pattern")) {
                module_parse_conf_pattern(pd, config, &line);
            } else {
                config_error(config, "Unknown section: %s", line.name);
            }
            break;
        case CONFIG_LINE_TYPE_SECTION_END:
            break;
        }
    }

    return !config->error_message;
}

const struct lwan_module *
lwan_module_rewrite(void)
{
    static const struct lwan_module rewrite_module = {
        .init = module_init,
        .init_from_hash = module_init_from_hash,
        .parse_conf = module_parse_conf,
        .shutdown = module_shutdown,
        .handle = module_handle_cb,
        .flags = HANDLER_CAN_REWRITE_URL
    };

    return &rewrite_module;
}
