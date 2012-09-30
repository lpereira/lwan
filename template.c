/*
 * lwan - simple web server
 * Copyright (c) 2012 Leandro A. F. Pereira <leandro@hardinfo.org>
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
/*
 * Ideas from Mustache logic-less templates: http://mustache.github.com/
 */
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "strbuf.h"

typedef struct lwan_tpl_t_ lwan_tpl_t;
typedef struct lwan_tpl_chunk_t_ lwan_tpl_chunk_t;

lwan_tpl_t *lwan_tpl_compile(const char *filename);
void lwan_tpl_free(lwan_tpl_t *tpl);
strbuf_t *lwan_tpl_apply(lwan_tpl_t *, char *(*)(const char *, void *), void *data);

typedef enum {
    TPL_ACTION_APPEND,
    TPL_ACTION_APPEND_CHAR,
    TPL_ACTION_VARIABLE,
    TPL_ACTION_LIST_START_ITER,
    TPL_ACTION_LIST_END_ITER,
    TPL_ACTION_IF_VARIABLE_NOT_EMPTY,
    TPL_ACTION_END_IF_VARIABLE_NOT_EMPTY,
    TPL_ACTION_APPLY_TPL,
    TPL_ACTION_LAST
} lwan_tpl_action_t;

enum {
    STATE_DEFAULT,
    STATE_FIRST_BRACE,
    STATE_SECOND_BRACE,
    STATE_FIRST_CLOSING_BRACE,
    STATE_SECOND_CLOSING_BRACE
};

struct lwan_tpl_chunk_t_ {
    lwan_tpl_action_t action;
    void *data;
    lwan_tpl_chunk_t *next;
};

struct lwan_tpl_t_ {
    lwan_tpl_chunk_t *chunks;  
    size_t minimum_size;
};

static int
compile_append_text(lwan_tpl_t *tpl, strbuf_t *buf)
{
    int length = strbuf_get_length(buf);
    if (!length)
        return 0;

    lwan_tpl_chunk_t *chunk = malloc(sizeof(*chunk));
    if (!chunk)
        return -ENOMEM;

    if (length == 1) {
        chunk->action = TPL_ACTION_APPEND_CHAR;
        chunk->data = (void *)((uintptr_t)strbuf_get_buffer(buf)[0]);
    } else {
        chunk->action = TPL_ACTION_APPEND;
        chunk->data = strdup(strbuf_get_buffer(buf));
    }

    chunk->next = tpl->chunks;
    tpl->chunks = chunk;
    tpl->minimum_size += strbuf_get_length(buf);
    strbuf_reset(buf);

    return 0;
}

static int
compile_append_var(lwan_tpl_t *tpl, strbuf_t *buf)
{
    lwan_tpl_chunk_t *chunk = malloc(sizeof(*chunk));
    if (!chunk)
        return -ENOMEM;

    char *variable = strbuf_get_buffer(buf);
    int length = strbuf_get_length(buf) - 1;

    switch (*variable) {
    case '>': {
        char template_file[PATH_MAX];
        snprintf(template_file, sizeof(template_file), "%s.tpl", variable + 1);

        lwan_tpl_t *included = lwan_tpl_compile(template_file);
        if (!included) {
            free(chunk);
            return -ENOENT;
        }
        chunk->action = TPL_ACTION_APPLY_TPL;
        chunk->data = included;
        break;
    }
    case '#':
        chunk->action = TPL_ACTION_LIST_START_ITER;
        chunk->data = strdup(variable + 1);
        break;
    case '/':
        if (variable[length] == '?') {
            chunk->action = TPL_ACTION_END_IF_VARIABLE_NOT_EMPTY;
            variable[length] = '\0';
        } else {
            chunk->action = TPL_ACTION_LIST_END_ITER;
        }
        chunk->data = strdup(variable + 1);
        break;
    default:
        if (variable[length] == '?') {
            chunk->action = TPL_ACTION_IF_VARIABLE_NOT_EMPTY;
            variable[length] = '\0';
        } else {
            chunk->action = TPL_ACTION_VARIABLE;
        }
        chunk->data = strdup(variable);
    }

    chunk->next = tpl->chunks;
    tpl->chunks = chunk;
    tpl->minimum_size += strbuf_get_length(buf);
    strbuf_reset(buf);

    return 0;
}

static void
free_chunk(lwan_tpl_chunk_t *chunk)
{
    if (!chunk)
        return;

    switch (chunk->action) {
    case TPL_ACTION_APPEND_CHAR:
        /* do nothing */
        break;
    case TPL_ACTION_APPLY_TPL:
        lwan_tpl_free(chunk->data);
        break;
    default:
        free(chunk->data);
    }

    free(chunk);
}

void
lwan_tpl_free(lwan_tpl_t *tpl)
{
    if (!tpl)
        return;
    
    while (tpl->chunks) {
        lwan_tpl_chunk_t *next = tpl->chunks->next;
        free_chunk(tpl->chunks);
        tpl->chunks = next;
    }
    free(tpl);
}

#define PARSE_ERROR(msg,...) \
    do { \
        snprintf(error_msg, sizeof(error_msg), msg, ##__VA_ARGS__); \
        goto error; \
    } while(0)

lwan_tpl_t *
lwan_tpl_compile(const char *filename)
{
    lwan_tpl_t *tpl;
    strbuf_t *buf;
    FILE *file;
    int state = STATE_DEFAULT;
    char error_msg[512];
    
    tpl = calloc(1, sizeof(*tpl));
    if (!tpl)
        return NULL;

    buf = strbuf_new();
    if (!buf) {
        free(tpl);
        return NULL;
    }
    
    file = fopen(filename, "r");
    if (!file) {
        strbuf_free(buf);
        free(tpl);
        return NULL;
    }

    int line = 1;
    int column = 1;
    char ch;
    while ((ch = fgetc(file)) != EOF) {
        if (ch == '\n') {
            if (state == STATE_DEFAULT)
                strbuf_append_char(buf, '\n');

            line++;
            column = 1;
            continue;
        }
        ++column;

        switch (state) {
        case STATE_DEFAULT:
            if (ch == '{') {
                state = STATE_FIRST_BRACE;
                continue;
            }

            strbuf_append_char(buf, ch);
            break;
        case STATE_FIRST_BRACE:
            if (ch == '{') {
                switch (compile_append_text(tpl, buf)) {
                case -ENOMEM:
                    PARSE_ERROR("Out of memory while appending text.");
                }

                state = STATE_SECOND_BRACE;
                continue;
            }

            strbuf_append_char(buf, '{');
            strbuf_append_char(buf, ch);
            state = STATE_DEFAULT;
            break;
        case STATE_SECOND_BRACE:
            if (ch == '{')
                PARSE_ERROR("Unexpected open brace.");

            if (ch == '}') {
                state = STATE_FIRST_CLOSING_BRACE;
                continue;
            }

            strbuf_append_char(buf, ch);
            break;
        case STATE_FIRST_CLOSING_BRACE:
            if (ch == '}') {
                state = STATE_SECOND_CLOSING_BRACE;
                continue;
            }
            PARSE_ERROR("Closing brace expected.");
        case STATE_SECOND_CLOSING_BRACE:
            if (ch == '}')
                PARSE_ERROR("Unexpected close brace.");

            if (strbuf_get_length(buf) == 0)
                PARSE_ERROR("Expecting variable name.");

            switch (compile_append_var(tpl, buf)) {
            case -ENOMEM:
                PARSE_ERROR("Out of memory while appending variable.");
            case -ENOENT:
                PARSE_ERROR("Cannot find included template: ``%s''.", strbuf_get_buffer(buf) + 1);
            }

            if (ch == '{') {
                state = STATE_FIRST_BRACE;
                continue;
            }

            strbuf_append_char(buf, ch);
            state = STATE_DEFAULT;
        }
    }

    switch (state) {
    case STATE_DEFAULT:
        switch (compile_append_text(tpl, buf)) {
        case -ENOMEM:
            PARSE_ERROR("Out of memory while appending text.");
        }
        break;
    case STATE_FIRST_BRACE:
    case STATE_SECOND_BRACE:
        PARSE_ERROR("Expecting close brace.");
    case STATE_FIRST_CLOSING_BRACE:
        PARSE_ERROR("Expecting second close brace.");
    case STATE_SECOND_CLOSING_BRACE:
        if (strbuf_get_length(buf) == 0)
            PARSE_ERROR("Expecting variable name.");

        switch (compile_append_var(tpl, buf)) {
        case -ENOMEM:
            PARSE_ERROR("Out of memory while appending variable.");
        case -ENOENT:
            PARSE_ERROR("Cannot find included template: ``%s''.", strbuf_get_buffer(buf));
        }
    }

    lwan_tpl_chunk_t *last = malloc(sizeof(*last));
    if (!last)
        goto error;
    last->action = TPL_ACTION_LAST;
    last->data = NULL;
    last->next = tpl->chunks;
    tpl->chunks = last;

    lwan_tpl_chunk_t *prev = NULL;
    while (tpl->chunks) {
        lwan_tpl_chunk_t *next = tpl->chunks->next;
        tpl->chunks->next = prev;
        prev = tpl->chunks;
        tpl->chunks = next;
    }
    tpl->chunks = prev;

    strbuf_free(buf);
    return tpl;

error:
    lwan_tpl_free(tpl);
    strbuf_free(buf);
    fclose(file);
    
    printf("Line %d, column %d: %s\n", line, column, error_msg);
    return NULL;
}

#undef PARSE_ERROR

static bool
until_end(lwan_tpl_chunk_t *chunk, void *data __attribute__((unused)))
{
    return chunk->action == TPL_ACTION_LAST;
}

static bool
until_not_empty(lwan_tpl_chunk_t *chunk, void *data __attribute__((unused)))
{
    return !(chunk->action == TPL_ACTION_END_IF_VARIABLE_NOT_EMPTY && !strcmp(data, chunk->data));
}

lwan_tpl_chunk_t *
lwan_tpl_apply_until(lwan_tpl_chunk_t *chunks, strbuf_t *buf,
    char *(*var_get)(const char *name, void *data), void *var_get_data,
    bool (*until)(lwan_tpl_chunk_t *chunk, void *data), void *until_data)
{
    lwan_tpl_chunk_t *chunk = chunks;

    for (; chunk; chunk = chunk->next) {
        if (until(chunk, until_data))
            break;

        switch (chunk->action) {
        case TPL_ACTION_APPEND:
            strbuf_append_str(buf, chunk->data, 0);
            break;
        case TPL_ACTION_APPEND_CHAR:
            strbuf_append_char(buf, (char)(uintptr_t)chunk->data);
            break;
        case TPL_ACTION_VARIABLE:
            {
                char *tmp = var_get((const char*)chunk->data, var_get_data);
                strbuf_append_str(buf, tmp, 0);
                free(tmp);
            }
            break;
        case TPL_ACTION_LIST_START_ITER:
            strbuf_append_str(buf, "[begin_iter:", 0);
            strbuf_append_str(buf, chunk->data, 0);
            strbuf_append_str(buf, "]", 0);
            break;
        case TPL_ACTION_LIST_END_ITER:
            strbuf_append_str(buf, "[end_iter:", 0);
            strbuf_append_str(buf, chunk->data, 0);
            strbuf_append_str(buf, "]", 0);
            break;
        case TPL_ACTION_IF_VARIABLE_NOT_EMPTY:
            {
                const char *var_name = (const char*)chunk->data;
                char *tmp = var_get(var_name, var_get_data);
                if (tmp && *tmp) {
                    chunk = lwan_tpl_apply_until(chunk->next, buf, var_get, var_get_data, 
                                        until_not_empty, chunk->data);
                } else {
                    for (chunk = chunk->next; chunk; chunk = chunk->next) {
                        if (chunk->action == TPL_ACTION_END_IF_VARIABLE_NOT_EMPTY && !strcmp(chunk->data, var_name))
                            break;
                    }
                }
                free(tmp);
            }
            break;
        case TPL_ACTION_END_IF_VARIABLE_NOT_EMPTY:
            /* Shouldn't happen */
            break;
        case TPL_ACTION_APPLY_TPL:
            {
                strbuf_t *tmp = lwan_tpl_apply(chunk->data, var_get, var_get_data);
                strbuf_append_str(buf, strbuf_get_buffer(tmp), strbuf_get_length(tmp));
                strbuf_free(tmp);
            }
            break;
        case TPL_ACTION_LAST:
            /* Shouldn't happen */
            break;
        }
    }

    return chunk;
}

strbuf_t *
lwan_tpl_apply(lwan_tpl_t *tpl,
    char *(*var_get)(const char *name, void *data), void *var_get_data)
{
    strbuf_t *buf = strbuf_new_with_size(tpl->minimum_size);
    lwan_tpl_apply_until(tpl->chunks, buf, var_get, var_get_data, until_end, NULL);
    return buf;
}

static char *
var_getter(const char *name, void *data __attribute__((unused)))
{
    if (!strcmp(name, "empty_test"))
        return strdup("");
    return strdup("var!");
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("Usage: %s file.tpl\n", argv[0]);
        return 1;
    }

    printf("*** Compiling template...\n");
    lwan_tpl_t *tpl = lwan_tpl_compile(argv[1]);
    if (!tpl)
        return 1;

    printf("*** Applying template...\n");
    strbuf_t *applied = lwan_tpl_apply(tpl, var_getter, NULL);
    puts(strbuf_get_buffer(applied));

    strbuf_free(applied);
    lwan_tpl_free(tpl);    
    return 0;
}
