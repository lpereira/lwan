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
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "strbuf.h"
#include "hash.h"
#include "int-to-str.h"

typedef struct lwan_tpl_t_ lwan_tpl_t;
typedef struct lwan_tpl_chunk_t_ lwan_tpl_chunk_t;
typedef struct lwan_var_descriptor_t_ lwan_var_descriptor_t;

lwan_tpl_t *lwan_tpl_compile(const char *filename, lwan_var_descriptor_t *descriptor);
void lwan_tpl_free(lwan_tpl_t *tpl);
strbuf_t *lwan_tpl_apply(lwan_tpl_t *, void *variables);

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
    struct hash *descriptor_hash;
};

struct lwan_var_descriptor_t_ {
    const char *name;
    const off_t offset;
    char *(*get_as_string)(void *ptr, bool *allocated, size_t *length);
    bool (*get_is_empty)(void *ptr);
};

#define TPL_VAR(struct_, var_, get_as_string_, get_is_empty_) \
    { \
        .name = #var_, \
        .offset = offsetof(struct_, var_), \
        .get_as_string = get_as_string_, \
        .get_is_empty = get_is_empty_ \
    }

#define TPL_VAR_INT(struct_, var_) \
    TPL_VAR(struct_, var_, _int_to_str, _int_is_empty)

#define TPL_VAR_STR(struct_, var_) \
    TPL_VAR(struct_, var_, _str_to_str, _str_is_empty)

#define TPL_VAR_SENTINEL \
    { NULL, 0, NULL, NULL }


static char *
_int_to_str(void *ptr, bool *allocated, size_t *length)
{
    char buf[32];
    char *ret;

    ret = int_to_string(*(int *)ptr, buf, length);
    *allocated = true;

    return strdup(ret);
}

static bool
_int_is_empty(void *ptr)
{
    return (*(int *)ptr) == 0;
}

static char *
_str_to_str(void *ptr, bool *allocated, size_t *length)
{
    struct v {
        char *str;
    } *v = ptr;

    *length = strlen(v->str);
    *allocated = false;
    return v->str;
}

bool
_str_is_empty(void *ptr)
{
    char *str = ptr;
    return !str || !*str;
}

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
        chunk->data = strbuf_new_with_size(strbuf_get_length(buf));
        strbuf_set(chunk->data, strbuf_get_buffer(buf), strbuf_get_length(buf));
    }

    chunk->next = tpl->chunks;
    tpl->chunks = chunk;
    tpl->minimum_size += strbuf_get_length(buf);
    strbuf_reset(buf);

    return 0;
}

static int
compile_append_var(lwan_tpl_t *tpl, strbuf_t *buf, lwan_var_descriptor_t *descriptor)
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

        lwan_tpl_t *included = lwan_tpl_compile(template_file, descriptor);
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
        chunk->data = hash_find(tpl->descriptor_hash, variable);
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
    case TPL_ACTION_VARIABLE:
        /* do nothing */
        break;
    case TPL_ACTION_APPEND:
        strbuf_free(chunk->data);
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
lwan_tpl_compile(const char *filename, lwan_var_descriptor_t *descriptor)
{
    lwan_tpl_t *tpl;
    strbuf_t *buf;
    FILE *file;
    int state = STATE_DEFAULT;
    char error_msg[512];
    
    tpl = calloc(1, sizeof(*tpl));
    if (!tpl)
        return NULL;

    tpl->descriptor_hash = hash_str_new(64, NULL, NULL);
    if (!tpl->descriptor_hash) {
        free(tpl);
        return NULL;
    }

    int i;
    for (i = 0; descriptor[i].name; i++)
        hash_add(tpl->descriptor_hash, descriptor[i].name, &descriptor[i]);

    buf = strbuf_new();
    if (!buf) {
        free(tpl);
        return NULL;
    }
    
    file = fopen(filename, "r");
    if (!file) {
        hash_free(tpl->descriptor_hash);
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

            if (strbuf_get_buffer(buf)[0] != '>' &&
                    !hash_find(tpl->descriptor_hash, strbuf_get_buffer(buf)))
                PARSE_ERROR("Variable not found in descriptor: ``%s''.",
                    strbuf_get_buffer(buf));

            switch (compile_append_var(tpl, buf, descriptor)) {
            case -ENOMEM:
                PARSE_ERROR("Out of memory while appending variable.");
            case -ENOENT:
                PARSE_ERROR("Cannot find template to include: ``%s''.",
                    strbuf_get_buffer(buf) + 1);
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

        if (strbuf_get_buffer(buf)[0] != '>' &&
                !hash_find(tpl->descriptor_hash, strbuf_get_buffer(buf)))
            PARSE_ERROR("Variable not found in descriptor: ``%s''.",
                strbuf_get_buffer(buf));

        switch (compile_append_var(tpl, buf, descriptor)) {
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
    hash_free(tpl->descriptor_hash);
    return tpl;

error:
    hash_free(tpl->descriptor_hash);
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
until_not_empty(lwan_tpl_chunk_t *chunk, void *data)
{
    return !(chunk->action == TPL_ACTION_END_IF_VARIABLE_NOT_EMPTY && !strcmp(data, chunk->data));
}

static char*
var_get_as_string(lwan_tpl_chunk_t *chunk,
                  void *variables,
                  bool *allocated,
                  size_t *length)
{
    lwan_var_descriptor_t *descriptor = chunk->data;
    if (!descriptor)
        goto end;

    char *value;
    value = descriptor->get_as_string((void *)(variables + descriptor->offset),
                allocated, length);
    if (value)
        return value;

end:
    if (allocated)
        *allocated = false;

    if (length)
        *length = 0;
    return NULL;
}

static bool
var_get_is_empty(lwan_tpl_chunk_t *chunk,
                 void *variables)
{
    lwan_var_descriptor_t *descriptor = chunk->data;
    if (!descriptor)
        return true;

    return descriptor->get_is_empty((void *)(variables + descriptor->offset));
}

lwan_tpl_chunk_t *
lwan_tpl_apply_until(lwan_tpl_t *tpl,
    lwan_tpl_chunk_t *chunks, strbuf_t *buf,
    void *variables,
    bool (*until)(lwan_tpl_chunk_t *chunk, void *data), void *until_data)
{
    lwan_tpl_chunk_t *chunk = chunks;

    for (; chunk; chunk = chunk->next) {
        if (until(chunk, until_data))
            break;

        switch (chunk->action) {
        case TPL_ACTION_APPEND:
            strbuf_append_str(buf, strbuf_get_buffer(chunk->data),
                        strbuf_get_length(chunk->data));
            break;
        case TPL_ACTION_APPEND_CHAR:
            strbuf_append_char(buf, (char)(uintptr_t)chunk->data);
            break;
        case TPL_ACTION_VARIABLE:
            {
                bool allocated;
                size_t length;
                char *value;

                value = var_get_as_string(chunk, variables,
                        &allocated, &length);
                strbuf_append_str(buf, value, length);
                if (allocated)
                    free(value);
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
                if (var_get_is_empty(chunk, variables)) {
                    chunk = lwan_tpl_apply_until(tpl,
                                        chunk->next,
                                        buf,
                                        variables,
                                        until_not_empty,
                                        chunk->data);
                } else {
                    for (chunk = chunk->next; chunk; chunk = chunk->next) {
                        if (chunk->action == TPL_ACTION_END_IF_VARIABLE_NOT_EMPTY && !strcmp(chunk->data, var_name))
                            break;
                    }
                }
            }
            break;
        case TPL_ACTION_APPLY_TPL:
            {
                strbuf_t *tmp = lwan_tpl_apply(chunk->data, variables);
                strbuf_append_str(buf, strbuf_get_buffer(tmp), strbuf_get_length(tmp));
                strbuf_free(tmp);
            }
            break;
        case TPL_ACTION_END_IF_VARIABLE_NOT_EMPTY:
        case TPL_ACTION_LAST:
            /* Shouldn't happen */
            break;
        }
    }

    return chunk;
}

strbuf_t *
lwan_tpl_apply(lwan_tpl_t *tpl, void *variables)
{
    strbuf_t *buf = strbuf_new_with_size(tpl->minimum_size);
    lwan_tpl_apply_until(tpl, tpl->chunks, buf, variables, until_end, NULL);
    return buf;
}

struct test_struct {
    int some_int;
    char *a_string;
};

int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("Usage: %s file.tpl\n", argv[0]);
        return 1;
    }

    printf("*** Compiling template...\n");
    lwan_var_descriptor_t desc[] = {
        TPL_VAR_INT(struct test_struct, some_int),
        TPL_VAR_STR(struct test_struct, a_string),
        TPL_VAR_SENTINEL
    };
    lwan_tpl_t *tpl = lwan_tpl_compile(argv[1], desc);
    if (!tpl)
        return 1;

    printf("*** Applying template...\n");
    strbuf_t *applied = lwan_tpl_apply(tpl, (struct test_struct[]) {{
        .some_int = 42,
        .a_string = "some string"
    }});
    puts(strbuf_get_buffer(applied));

    strbuf_free(applied);
    lwan_tpl_free(tpl);    
    return 0;
}
