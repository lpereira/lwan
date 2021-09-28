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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#define _GNU_SOURCE
#include <ctype.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "lwan-private.h"

#include "patterns.h"
#include "lwan-array.h"
#include "lwan-mod-rewrite.h"
#include "lwan-strbuf.h"

#ifdef HAVE_LUA
#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

#include "lwan-lua.h"
#endif

enum pattern_flag {
    PATTERN_HANDLE_REWRITE = 1 << 0,
    PATTERN_HANDLE_REDIRECT = 1 << 1,
    PATTERN_HANDLE_MASK = PATTERN_HANDLE_REWRITE | PATTERN_HANDLE_REDIRECT,

    PATTERN_EXPAND_LWAN = 1 << 2,
    PATTERN_EXPAND_LUA = 1 << 3,
    PATTERN_EXPAND_MASK = PATTERN_EXPAND_LWAN | PATTERN_EXPAND_LUA,

    PATTERN_COND_COOKIE = 1 << 4,
    PATTERN_COND_ENV_VAR = 1 << 5,
    PATTERN_COND_STAT = 1 << 6,
    PATTERN_COND_QUERY_VAR = 1 << 7,
    PATTERN_COND_POST_VAR = 1 << 8,
    PATTERN_COND_HEADER = 1 << 9,
    PATTERN_COND_LUA = 1 << 10,
    PATTERN_COND_METHOD = 1 << 11,
    PATTERN_COND_ACCEPT_ENCODING = 1 << 12,
    PATTERN_COND_MASK = PATTERN_COND_COOKIE | PATTERN_COND_ENV_VAR |
                        PATTERN_COND_STAT | PATTERN_COND_QUERY_VAR |
                        PATTERN_COND_POST_VAR | PATTERN_COND_HEADER |
                        PATTERN_COND_LUA | PATTERN_COND_METHOD |
                        PATTERN_COND_ACCEPT_ENCODING,

    PATTERN_COND_STAT__HAS_IS_FILE = 1 << 13,
    PATTERN_COND_STAT__HAS_IS_DIR = 1 << 14,
    PATTERN_COND_STAT__IS_FILE = 1 << 15,
    PATTERN_COND_STAT__IS_DIR = 1 << 16,

    PATTERN_COND_STAT__FILE_CHECK =
        PATTERN_COND_STAT__HAS_IS_FILE | PATTERN_COND_STAT__IS_FILE,
    PATTERN_COND_STAT__DIR_CHECK =
        PATTERN_COND_STAT__HAS_IS_DIR | PATTERN_COND_STAT__IS_DIR,
};

struct pattern {
    char *pattern;
    char *expand_pattern;
    struct {
        struct lwan_key_value cookie;
        struct lwan_key_value env_var;
        struct lwan_key_value query_var;
        struct lwan_key_value post_var;
        struct lwan_key_value header;
        struct {
            char *path;
        } stat;
        struct {
            char *script;
        } lua;
        enum lwan_request_flags request_flags;
        /* FIXME: Use pahole to find alignment holes? */
    } condition;
    enum pattern_flag flags;
};

DEFINE_ARRAY_TYPE(pattern_array, struct pattern)

struct private_data {
    struct pattern_array patterns;
};

static enum lwan_http_status module_redirect_to(struct lwan_request *request,
                                                const char *url)
{
    const struct lwan_key_value headers[] = {
        {"Location", coro_strdup(request->conn->coro, url)},
        {},
    };

    request->response.headers =
        coro_memdup(request->conn->coro, headers, sizeof(headers));

    if (LIKELY(headers[0].value && request->response.headers))
        return HTTP_MOVED_PERMANENTLY;

    return HTTP_INTERNAL_ERROR;
}

static enum lwan_http_status module_rewrite_as(struct lwan_request *request,
                                               const char *url)
{
    request->url.value = coro_strdup(request->conn->coro, url);

    if (UNLIKELY(!request->url.value))
        return HTTP_INTERNAL_ERROR;

    request->url.len = strlen(request->url.value);
    request->original_url = request->url;
    request->flags |= RESPONSE_URL_REWRITTEN;

    return HTTP_OK;
}

#define MAX_INT_DIGITS (3 * sizeof(int))

static __attribute__((noinline)) int parse_int_len(const char *s, size_t len,
                                                   int default_value)
{
    if (UNLIKELY(len > MAX_INT_DIGITS))
        return default_value;

    return parse_int(strndupa(s, len), default_value);
}

static const char *expand_string(const char *expand_pattern,
                                 const char *orig,
                                 char buffer[static PATH_MAX],
                                 const struct str_find *sf,
                                 int captures)
{
    struct lwan_strbuf strbuf;
    const char *ptr;

    ptr = strchr(expand_pattern, '%');
    if (!ptr)
        return expand_pattern;

    if (!lwan_strbuf_init_with_fixed_buffer(&strbuf, buffer, PATH_MAX))
        return NULL;

    do {
        size_t index_len = strspn(ptr + 1, "0123456789");

        if (ptr > expand_pattern) {
            const size_t len = (size_t)(ptr - expand_pattern);

            if (UNLIKELY(!lwan_strbuf_append_str(&strbuf, expand_pattern, len)))
                return NULL;

            expand_pattern += len;
        }

        if (LIKELY(index_len > 0)) {
            const int index = parse_int_len(ptr + 1, index_len, -1);

            if (UNLIKELY(index < 0 || index > captures))
                return NULL;

            if (UNLIKELY(!lwan_strbuf_append_str(
                    &strbuf, orig + sf[index].sm_so,
                    (size_t)(sf[index].sm_eo - sf[index].sm_so))))
                return NULL;

            expand_pattern += index_len;
        } else if (UNLIKELY(!lwan_strbuf_append_char(&strbuf, '%'))) {
            return NULL;
        }

        expand_pattern++;
    } while ((ptr = strchr(expand_pattern, '%')));

    const size_t remaining_len = strlen(expand_pattern);
    if (remaining_len &&
        !lwan_strbuf_append_str(&strbuf, expand_pattern, remaining_len))
        return NULL;

    if (UNLIKELY(!lwan_strbuf_get_length(&strbuf)))
        return NULL;

    return lwan_strbuf_get_buffer(&strbuf);
}

static ALWAYS_INLINE const char *expand(const struct pattern *pattern,
                                        const char *orig,
                                        char buffer[static PATH_MAX],
                                        const struct str_find *sf,
                                        int captures)
{
    return expand_string(pattern->expand_pattern, orig, buffer, sf, captures);
}

#ifdef HAVE_LUA
static void
lua_close_defer(void *data)
{
    lua_close((lua_State *)data);
}

static const char *expand_lua(struct lwan_request *request,
                              struct pattern *pattern, const char *orig,
                              char buffer[static PATH_MAX],
                              const struct str_find *sf, int captures)
{
    const char *output;
    size_t output_len;
    int i;
    lua_State *L;

    L = lwan_lua_create_state(NULL, pattern->expand_pattern);
    if (UNLIKELY(!L))
        return NULL;
    coro_defer(request->conn->coro, lua_close_defer, L);

    lua_getglobal(L, "handle_rewrite");
    if (!lua_isfunction(L, -1)) {
        lwan_status_error(
            "Could not obtain reference to `handle_rewrite()` function: %s",
            lwan_lua_state_last_error(L));
        return NULL;
    }

    lwan_lua_state_push_request(L, request);

    lua_createtable(L, captures, 0);
    for (i = 0; i < captures; i++) {
        lua_pushinteger(L, i);
        lua_pushlstring(L, orig + sf[i].sm_so,
                        (size_t)(sf[i].sm_eo - sf[i].sm_so));
        lua_settable(L, -3);
    }

    if (lua_pcall(L, 2, 1, 0) != 0) {
        lwan_status_error("Could not execute `handle_rewrite()` function: %s",
                          lwan_lua_state_last_error(L));
        return NULL;
    }

    output = lua_tolstring(L, -1, &output_len);
    if (output_len >= PATH_MAX) {
        lwan_status_error("Rewritten URL exceeds %d bytes (got %zu bytes)",
                          PATH_MAX, output_len);
        return NULL;
    }

    return memcpy(buffer, output, output_len + 1);
}
#endif

static bool condition_matches(struct lwan_request *request,
                              const struct pattern *p,
                              const struct str_find *sf,
                              int captures,
                              char expanded_buf[static PATH_MAX])
{
    if (LIKELY(!(p->flags & PATTERN_COND_MASK)))
        return true;

    const char *url = request->url.value;

    if (p->flags & PATTERN_COND_METHOD) {
        const enum lwan_request_flags method =
            p->condition.request_flags & REQUEST_METHOD_MASK;
        if (lwan_request_get_method(request) != method)
            return false;
    }

    if (p->flags & PATTERN_COND_ACCEPT_ENCODING) {
        const enum lwan_request_flags accept =
            p->condition.request_flags & REQUEST_ACCEPT_MASK;
        if (!(lwan_request_get_accept_encoding(request) & accept))
            return false;
    }

    if (p->flags & PATTERN_COND_COOKIE) {
        assert(p->condition.cookie.key);
        assert(p->condition.cookie.value);

        const char *cookie =
            lwan_request_get_cookie(request, p->condition.cookie.key);
        if (!cookie)
            return false;

        const char *val = expand_string(p->condition.cookie.value, url,
                                        expanded_buf, sf, captures);
        if (!val || !streq(val, cookie))
            return false;
    }

    if (p->flags & PATTERN_COND_ENV_VAR) {
        assert(p->condition.env_var.key);
        assert(p->condition.env_var.value);

        const char *env_var = secure_getenv(p->condition.env_var.key);
        if (!env_var)
            return false;

        const char *val = expand_string(p->condition.env_var.value, url,
                                        expanded_buf, sf, captures);
        if (!val || !streq(val, env_var))
            return false;
    }

    if (p->flags & PATTERN_COND_QUERY_VAR) {
        assert(p->condition.query_var.key);
        assert(p->condition.query_var.value);

        const char *query =
            lwan_request_get_query_param(request, p->condition.query_var.key);

        if (!query)
            return false;

        const char *val = expand_string(p->condition.query_var.value, url,
                                        expanded_buf, sf, captures);
        if (!val || !streq(val, query))
            return false;
    }

    if (p->flags & PATTERN_COND_POST_VAR) {
        assert(p->condition.post_var.key);
        assert(p->condition.post_var.value);

        const char *post =
            lwan_request_get_post_param(request, p->condition.post_var.key);
        if (!post)
            return false;

        const char *val = expand_string(p->condition.post_var.value, url,
                                        expanded_buf, sf, captures);
        if (!val || !streq(val, post))
            return false;
    }

    if (p->flags & PATTERN_COND_STAT) {
        assert(p->condition.stat.path);

        struct stat st;

        /* FIXME: Expanding path from a user-controlled URL and use the
         * resulting path to call stat(2) on could lead to some information
         * disclosure vulnerability. Would require the server to be configured
         * in a certain way, though.
         */
        const char *path = expand_string(p->condition.stat.path, url,
                                         expanded_buf, sf, captures);
        if (!path || stat(path, &st) < 0)
            return false;

        if ((p->flags & PATTERN_COND_STAT__FILE_CHECK) ==
                PATTERN_COND_STAT__FILE_CHECK &&
            !S_ISREG(st.st_mode))
            return false;
        if ((p->flags & PATTERN_COND_STAT__DIR_CHECK) ==
                PATTERN_COND_STAT__DIR_CHECK &&
            !S_ISDIR(st.st_mode))
            return false;
    }

#ifdef HAVE_LUA
    if (p->flags & PATTERN_COND_LUA) {
        assert(p->condition.lua.script);

        lua_State *L = lwan_lua_create_state(NULL, p->condition.lua.script);
        if (!L)
            return false;
        coro_defer(request->conn->coro, lua_close_defer, L);

        lua_getglobal(L, "matches");
        if (!lua_isfunction(L, -1)) {
            lwan_status_error(
                "Could not obtain reference to `matches()` function: %s",
                lwan_lua_state_last_error(L));
            return false;
        }

        lwan_lua_state_push_request(L, request);

        if (lua_pcall(L, 1, 1, 0) != 0) {
            lwan_status_error("Could not execute `matches()` function: %s",
                              lwan_lua_state_last_error(L));
            return false;
        }

        if (!lua_toboolean(L, -1))
            return false;
    }
#else
    assert(!(p->flags & PATTERN_COND_LUA));
#endif

    return true;
}

static enum lwan_http_status
rewrite_handle_request(struct lwan_request *request,
                       struct lwan_response *response __attribute__((unused)),
                       void *instance)
{
    struct private_data *pd = instance;
    const char *url = request->url.value;
    char final_url[PATH_MAX];
    struct pattern *p;

    LWAN_ARRAY_FOREACH(&pd->patterns, p) {
        struct str_find sf[MAXCAPTURES];
        const char *expanded = NULL;
        const char *errmsg;
        int captures;

        captures = str_find(url, p->pattern, sf, MAXCAPTURES, &errmsg);
        if (captures <= 0)
            continue;

        if (!condition_matches(request, p, sf, captures, final_url))
            continue;

        switch (p->flags & PATTERN_EXPAND_MASK) {
#ifdef HAVE_LUA
        case PATTERN_EXPAND_LUA:
            expanded = expand_lua(request, p, url, final_url, sf, captures);
            break;
#endif
        case PATTERN_EXPAND_LWAN:
            expanded = expand(p, url, final_url, sf, captures);
            break;
        }

        if (LIKELY(expanded)) {
            switch (p->flags & PATTERN_HANDLE_MASK) {
            case PATTERN_HANDLE_REDIRECT:
                return module_redirect_to(request, expanded);
            case PATTERN_HANDLE_REWRITE:
                return module_rewrite_as(request, expanded);
            }
        }

        return HTTP_INTERNAL_ERROR;
    }

    return HTTP_NOT_FOUND;
}

static void *rewrite_create(const char *prefix __attribute__((unused)),
                            void *instance __attribute__((unused)))
{
    struct private_data *pd = malloc(sizeof(*pd));

    if (!pd)
        return NULL;

    pattern_array_init(&pd->patterns);

    return pd;
}

static void rewrite_destroy(void *instance)
{
    struct private_data *pd = instance;
    struct pattern *iter;

    LWAN_ARRAY_FOREACH(&pd->patterns, iter) {
        free(iter->pattern);
        free(iter->expand_pattern);
        if (iter->flags & PATTERN_COND_COOKIE) {
            free(iter->condition.cookie.key);
            free(iter->condition.cookie.value);
        }
        if (iter->flags & PATTERN_COND_ENV_VAR) {
            free(iter->condition.env_var.key);
            free(iter->condition.env_var.value);
        }
        if (iter->flags & PATTERN_COND_QUERY_VAR) {
            free(iter->condition.query_var.key);
            free(iter->condition.query_var.value);
        }
        if (iter->flags & PATTERN_COND_POST_VAR) {
            free(iter->condition.post_var.key);
            free(iter->condition.post_var.value);
        }
        if (iter->flags & PATTERN_COND_HEADER) {
            free(iter->condition.header.key);
            free(iter->condition.header.value);
        }
        if (iter->flags & PATTERN_COND_STAT) {
            free(iter->condition.stat.path);
        }
#ifdef HAVE_LUA
        if (iter->flags & PATTERN_COND_LUA) {
            free(iter->condition.lua.script);
        }
#endif
    }

    pattern_array_reset(&pd->patterns);
    free(pd);
}

static void *rewrite_create_from_hash(const char *prefix,
                                      const struct hash *hash
                                      __attribute__((unused)))
{
    return rewrite_create(prefix, NULL);
}

static void parse_condition_key_value(struct pattern *pattern,
                                      struct lwan_key_value *key_value,
                                      enum pattern_flag condition_type,
                                      struct config *config,
                                      const struct config_line *line)
{
    char *key = NULL, *value = NULL;

    while ((line = config_read_line(config))) {
        switch (line->type) {
        case CONFIG_LINE_TYPE_SECTION:
            config_error(config, "Unexpected section: %s", line->key);
            goto out;

        case CONFIG_LINE_TYPE_SECTION_END:
            if (!key || !value) {
                config_error(config, "Key/value has not been specified");
                goto out;
            }

            *key_value = (struct lwan_key_value){key, value};
            pattern->flags |= condition_type & PATTERN_COND_MASK;
            return;

        case CONFIG_LINE_TYPE_LINE:
            if (key || value) {
                config_error(config,
                             "Can only condition on a single key/value pair. "
                             "Currently has: %s=%s",
                             key, value);
                goto out;
            }

            key = strdup(line->key);
            if (!key) {
                config_error(config,
                             "Could not copy key while parsing condition");
                goto out;
            }

            value = strdup(line->value);
            if (!value) {
                free(key);
                config_error(config,
                             "Could not copy value while parsing condition");
                goto out;
            }
            break;
        }
    }

out:
    free(key);
    free(value);
}

static void parse_condition_stat(struct pattern *pattern,
                                 struct config *config,
                                 const struct config_line *line)
{
    char *path = NULL, *is_dir = NULL, *is_file = NULL;

    while ((line = config_read_line(config))) {
        switch (line->type) {
        case CONFIG_LINE_TYPE_SECTION:
            config_error(config, "Unexpected section: %s", line->key);
            goto out;

        case CONFIG_LINE_TYPE_SECTION_END:
            if (!path) {
                config_error(config, "Path not specified");
                goto out;
            }

            pattern->condition.stat.path = path;
            if (is_dir) {
                pattern->flags |= PATTERN_COND_STAT__HAS_IS_DIR;
                if (parse_bool(is_dir, false))
                    pattern->flags |= PATTERN_COND_STAT__IS_DIR;
            }
            if (is_file) {
                pattern->flags |= PATTERN_COND_STAT__HAS_IS_FILE;
                if (parse_bool(is_file, false))
                    pattern->flags |= PATTERN_COND_STAT__IS_FILE;
            }
            pattern->flags |= PATTERN_COND_STAT;
            return;

        case CONFIG_LINE_TYPE_LINE:
            if (streq(line->key, "path")) {
                if (path) {
                    config_error(config, "Path `%s` already specified", path);
                    goto out;
                }
                path = strdup(line->value);
                if (!path) {
                    config_error(config, "Could not copy path");
                    goto out;
                }
            } else if (streq(line->key, "is_dir")) {
                is_dir = line->value;
            } else if (streq(line->key, "is_file")) {
                is_file = line->value;
            } else {
                config_error(config, "Unexpected key: %s", line->key);
                goto out;
            }

            break;
        }
    }

out:
    free(path);
}

static void parse_condition_accept_encoding(struct pattern *pattern,
                                            struct config *config)
{
    const struct config_line *line;

    while ((line = config_read_line(config))) {
        switch (line->type) {
        case CONFIG_LINE_TYPE_SECTION:
            config_error(config, "Unexpected section: %s", line->key);
            return;

        case CONFIG_LINE_TYPE_SECTION_END:
            pattern->flags |= PATTERN_COND_ACCEPT_ENCODING;
            return;

        case CONFIG_LINE_TYPE_LINE:
            if (streq(line->key, "deflate")) {
                if (parse_bool(line->value, false))
                    pattern->condition.request_flags |= REQUEST_ACCEPT_DEFLATE;
            } else if (streq(line->key, "gzip")) {
                if (parse_bool(line->value, false))
                    pattern->condition.request_flags |= REQUEST_ACCEPT_GZIP;
            } else if (streq(line->key, "brotli")) {
                if (parse_bool(line->value, false))
                    pattern->condition.request_flags |= REQUEST_ACCEPT_BROTLI;
            } else if (streq(line->key, "zstd")) {
                if (parse_bool(line->value, false))
                    pattern->condition.request_flags |= REQUEST_ACCEPT_ZSTD;
            } else if (!streq(line->key, "none")) {
                config_error(config, "Unsupported encoding for condition: %s",
                             line->key);
                return;
            }
            break;
        }
    }
}

#ifdef HAVE_LUA
static void parse_condition_lua(struct pattern *pattern,
                                struct config *config,
                                const struct config_line *line)
{
    char *script = NULL;

    while ((line = config_read_line(config))) {
        switch (line->type) {
        case CONFIG_LINE_TYPE_SECTION:
            config_error(config, "Unexpected section: %s", line->key);
            goto out;

        case CONFIG_LINE_TYPE_SECTION_END:
            if (!script) {
                config_error(config, "Script not specified");
                goto out;
            }

            pattern->condition.lua.script = script;
            pattern->flags |= PATTERN_COND_LUA;
            return;

        case CONFIG_LINE_TYPE_LINE:
            if (streq(line->key, "script")) {
                if (script) {
                    config_error(config, "Script already specified");
                    goto out;
                }
                script = strdup(line->value);
                if (!script) {
                    config_error(config, "Could not copy script");
                    goto out;
                }
            } else {
                config_error(config, "Unexpected key: %s", line->key);
                goto out;
            }

            break;
        }
    }

out:
    free(script);
}
#endif

static bool get_method_from_string(struct pattern *pattern, const char *string)
{
#define GENERATE_CMP(upper, lower, mask, constant)                             \
    if (!strcasecmp(string, #upper)) {                                         \
        pattern->condition.request_flags = (mask);                                    \
        return true;                                                           \
    }

    FOR_EACH_REQUEST_METHOD(GENERATE_CMP)

#undef GENERATE_CMP

    return false;
}

static void parse_condition(struct pattern *pattern,
                            struct config *config,
                            const struct config_line *line)
{
    if (streq(line->value, "cookie")) {
        return parse_condition_key_value(pattern, &pattern->condition.cookie,
                                         PATTERN_COND_COOKIE, config, line);
    }
    if (streq(line->value, "query")) {
        return parse_condition_key_value(pattern, &pattern->condition.query_var,
                                         PATTERN_COND_QUERY_VAR, config, line);
    }
    if (streq(line->value, "post")) {
        return parse_condition_key_value(pattern, &pattern->condition.post_var,
                                         PATTERN_COND_POST_VAR, config, line);
    }
    if (streq(line->value, "environment")) {
        return parse_condition_key_value(pattern, &pattern->condition.env_var,
                                         PATTERN_COND_ENV_VAR, config, line);
    }
    if (streq(line->value, "header")) {
        return parse_condition_key_value(pattern, &pattern->condition.header,
                                         PATTERN_COND_HEADER, config, line);
    }
    if (streq(line->value, "method")) {
        struct lwan_key_value method = {};

        parse_condition_key_value(pattern, &method,
                                  PATTERN_COND_METHOD, config, line);
        if (config_last_error(config))
            return;

        if (!streq(method.key, "name")) {
            config_error(config, "Method condition requires `name`");
        } else if (!get_method_from_string(pattern, method.value)) {
            config_error(config, "Unknown HTTP method: %s", method.value);
        }

        free(method.key);
        free(method.value);

        return;
    }
    if (streq(line->value, "stat")) {
        return parse_condition_stat(pattern, config, line);
    }
    if (streq(line->value, "encoding")) {
        return parse_condition_accept_encoding(pattern, config);
    }
#ifdef HAVE_LUA
    if (streq(line->value, "lua")) {
        return parse_condition_lua(pattern, config, line);
    }
#endif

    config_error(config, "Condition `%s' not supported", line->value);
}

static bool rewrite_parse_conf_pattern(struct private_data *pd,
                                       struct config *config,
                                       const struct config_line *line)
{
    struct pattern *pattern;
    char *redirect_to = NULL, *rewrite_as = NULL;
    bool expand_with_lua = false;

    pattern = pattern_array_append0(&pd->patterns);
    if (!pattern)
        goto out_no_free;

    pattern->pattern = strdup(line->value);
    if (!pattern->pattern)
        goto out;

    while ((line = config_read_line(config))) {
        switch (line->type) {
        case CONFIG_LINE_TYPE_LINE:
            if (streq(line->key, "redirect_to")) {
                free(redirect_to);

                redirect_to = strdup(line->value);
                if (!redirect_to)
                    goto out;
            } else if (streq(line->key, "rewrite_as")) {
                free(rewrite_as);

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
            if (streq(line->key, "condition")) {
                parse_condition(pattern, config, line);
            } else {
                config_error(config, "Unexpected section: %s", line->key);
            }
            break;
        case CONFIG_LINE_TYPE_SECTION_END:
            if (redirect_to && rewrite_as) {
                config_error(
                    config,
                    "`redirect to` and `rewrite as` are mutually exclusive");
                goto out;
            }
            if (redirect_to) {
                pattern->expand_pattern = redirect_to;
                pattern->flags |= PATTERN_HANDLE_REDIRECT;
            } else if (rewrite_as) {
                pattern->expand_pattern = rewrite_as;
                pattern->flags |= PATTERN_HANDLE_REWRITE;
            } else {
                config_error(
                    config,
                    "either `redirect to` or `rewrite as` are required");
                goto out;
            }
            if (expand_with_lua) {
#ifdef HAVE_LUA
                pattern->flags |= PATTERN_EXPAND_LUA;
#else
                config_error(config, "Lwan has been built without Lua. "
                                     "`expand_with_lua` is not available");
                goto out;
#endif
            } else {
                pattern->flags |= PATTERN_EXPAND_LWAN;
            }

            return true;
        }
    }

out:
    free(pattern->pattern);
    free(redirect_to);
    free(rewrite_as);
out_no_free:
    config_error(config, "Could not copy pattern");
    return false;
}

static bool rewrite_parse_conf(void *instance, struct config *config)
{
    struct private_data *pd = instance;
    const struct config_line *line;

    while ((line = config_read_line(config))) {
        switch (line->type) {
        case CONFIG_LINE_TYPE_LINE:
            config_error(config, "Unknown option: %s", line->key);
            break;
        case CONFIG_LINE_TYPE_SECTION:
            if (streq(line->key, "pattern")) {
                rewrite_parse_conf_pattern(pd, config, line);
            } else {
                config_error(config, "Unknown section: %s", line->key);
            }
            break;
        case CONFIG_LINE_TYPE_SECTION_END:
            break;
        }
    }

    return !config_last_error(config);
}

static const struct lwan_module module = {
    .create = rewrite_create,
    .create_from_hash = rewrite_create_from_hash,
    .parse_conf = rewrite_parse_conf,
    .destroy = rewrite_destroy,
    .handle_request = rewrite_handle_request,
    .flags = HANDLER_CAN_REWRITE_URL
};

LWAN_REGISTER_MODULE(rewrite, &module);
