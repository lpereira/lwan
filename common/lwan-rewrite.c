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

#include "lwan.h"
#include "lwan-rewrite.h"
#include "list.h"
#include "patterns.h"

struct private_data {
    struct list_head patterns;
};

struct pattern {
    struct list_node list;
    char *pattern;
    char *redirect_to;
    char *rewrite_as;
};

struct str_builder {
    char *buffer;
    size_t size, len;
};

static lwan_http_status_t
module_redirect_to(lwan_request_t *request, const char *url)
{
    lwan_key_value_t *headers = coro_malloc(request->conn->coro, sizeof(*headers) * 2);
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

static lwan_http_status_t
module_rewrite_as(lwan_request_t *request, const char *url)
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
    size_t total_size = builder->len + src_len + 1 /* for the \0 */;
    char *dest;

    if (total_size > builder->size)
        return false;

    dest = mempcpy(builder->buffer + builder->len, src, src_len);
    *dest = '\0';
    builder->len = total_size - 1;

    return true;
}

static const char *
expand(const char *pattern, const char *orig, char buffer[static PATH_MAX],
    struct str_find *sf, int captures)
{
    struct str_builder builder = { .buffer = buffer, .size = PATH_MAX };
    char *ptr;

    ptr = strchr(pattern, '%');
    if (!ptr)
        return pattern;

    do {
        size_t index_len = strspn(ptr + 1, "0123456789");

        if (ptr > pattern) {
            if (UNLIKELY(!append_str(&builder, pattern, (size_t)(ptr - pattern))))
                return NULL;

            pattern += ptr - pattern;
        }

        if (LIKELY(index_len > 0)) {
            int index = parse_int(strndupa(ptr + 1, index_len), -1);

            if (UNLIKELY(index < 0 || index > captures))
                return NULL;

            if (UNLIKELY(!append_str(&builder, orig + sf[index].sm_so,
                    (size_t)(sf[index].sm_eo - sf[index].sm_so))))
                return NULL;

            ptr += index_len;
            pattern += index_len;
        } else if (UNLIKELY(!append_str(&builder, "%", 1))) {
            return NULL;
        }

        pattern++;
    } while ((ptr = strchr(ptr + 1, '%')));

    if (*pattern && !append_str(&builder, pattern, strlen(pattern)))
        return NULL;

    if (UNLIKELY(!builder.len))
        return NULL;

    return builder.buffer;
}

static lwan_http_status_t
module_handle_cb(lwan_request_t *request,
    lwan_response_t *response __attribute__((unused)),
    void *data)
{
    const char *url = request->url.value;
    char final_url[PATH_MAX];
    struct private_data *pd = data;
    struct pattern *p;

    if (UNLIKELY(!pd))
        return HTTP_INTERNAL_ERROR;

    list_for_each(&pd->patterns, p, list) {
        lwan_http_status_t (*handle_fn)(lwan_request_t *request, const char *url);
        struct str_find sf[MAXCAPTURES];
        const char *errmsg, *pattern, *expanded;
        int captures;

        captures = str_find(url, p->pattern, sf, MAXCAPTURES, &errmsg);
        if (captures <= 0)
            continue;

        if (p->redirect_to) {
            handle_fn = module_redirect_to;
            pattern = p->redirect_to;
        } else {
            handle_fn = module_rewrite_as;
            pattern = p->rewrite_as;
        }

        expanded = expand(pattern, url, final_url, sf, captures);
        if (UNLIKELY(!expanded))
            return HTTP_INTERNAL_ERROR;

        return handle_fn(request, expanded);
    }

    return HTTP_NOT_FOUND;
}

static void *
module_init(void *data __attribute__((unused)))
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
        free(iter->redirect_to);
        free(iter->rewrite_as);
        free(iter);
    }
    free(pd);
}

static void *
module_init_from_hash(const struct hash *hash __attribute__((unused)))
{
    return module_init(NULL);
}

static bool
module_parse_conf_pattern(struct private_data *pd, config_t *config, config_line_t *line)
{
    struct pattern *pattern;

    pattern = calloc(1, sizeof(*pattern));
    if (!pattern)
        goto out_no_free;
    
    pattern->pattern = strdup(line->section.param);
    if (!pattern->pattern)
        goto out;

    while (config_read_line(config, line)) {
        switch (line->type) {
        case CONFIG_LINE_TYPE_LINE:
            if (!strcmp(line->line.key, "redirect_to")) {
                pattern->redirect_to = strdup(line->line.value);
                if (!pattern->redirect_to)
                    goto out;
            } else if (!strcmp(line->line.key, "rewrite_as")) {
                pattern->rewrite_as = strdup(line->line.value);
                if (!pattern->rewrite_as)
                    goto out;
            } else {
                config_error(config, "Unexpected key: %s", line->line.key);
                goto out;
            }
            break;
        case CONFIG_LINE_TYPE_SECTION:
            config_error(config, "Unexpected section: %s", line->section.name);
            break;
        case CONFIG_LINE_TYPE_SECTION_END:
            if (pattern->redirect_to && pattern->rewrite_as) {
                config_error(config, "`redirect to` and `rewrite as` are mutually exclusive");
                goto out;
            }
            if (!pattern->redirect_to && !pattern->rewrite_as) {
                config_error(config, "either `redirect to` or `rewrite as` are required");
                goto out;
            }
            list_add_tail(&pd->patterns, &pattern->list);
            return true;
        }
    }

out:
    free(pattern->pattern);
    free(pattern->redirect_to);
    free(pattern->rewrite_as);
    free(pattern);
out_no_free:
    config_error(config, "Could not copy pattern");
    return false;
}

static bool
module_parse_conf(void *data, config_t *config)
{
    struct private_data *pd = data;
    config_line_t line;

    while (config_read_line(config, &line)) {
        switch (line.type) {
        case CONFIG_LINE_TYPE_LINE:
            config_error(config, "Unknown option: %s", line.line.key);
            break;
        case CONFIG_LINE_TYPE_SECTION:
            if (!strcmp(line.section.name, "pattern")) {
                module_parse_conf_pattern(pd, config, &line);
            } else {
                config_error(config, "Unknown section: %s", line.section.name);
            }
            break;
        case CONFIG_LINE_TYPE_SECTION_END:
            break;
        }
    }

    return !config->error_message;
}

const lwan_module_t *
lwan_module_rewrite(void)
{
    static const lwan_module_t rewrite_module = {
        .name = "rewrite",
        .init = module_init,
        .init_from_hash = module_init_from_hash,
        .parse_conf = module_parse_conf,
        .shutdown = module_shutdown,
        .handle = module_handle_cb,
        .flags = HANDLER_CAN_REWRITE_URL
    };

    return &rewrite_module;
}
