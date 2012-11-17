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
    STATE_SECOND_CLOSING_BRACE,
    STATE_PARSE_ERROR
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
        chunk->data = strbuf_new_with_size(length);
        strbuf_set(chunk->data, strbuf_get_buffer(buf), length);
    }

    chunk->next = tpl->chunks;
    tpl->chunks = chunk;
    tpl->minimum_size += length;
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
        if (!chunk->data) {
            free(chunk);
            return -ENOKEY;
        }
    }

    chunk->next = tpl->chunks;
    tpl->chunks = chunk;
    tpl->minimum_size += length + 1;
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
        snprintf(error_msg, 512, msg, ##__VA_ARGS__); \
        return STATE_PARSE_ERROR; \
    } while(0)

static int
feed_into_compiler(lwan_tpl_t *tpl,
    lwan_var_descriptor_t *descriptor,
    int state,
    strbuf_t *buf,
    int ch,
    char *error_msg)
{
    bool last_pass = ch == EOF;

    switch (state) {
    case STATE_DEFAULT:
        if (ch == '{')
            return STATE_FIRST_BRACE;
        if (last_pass)
            goto append_text;

        strbuf_append_char(buf, ch);
        break;

    case STATE_FIRST_BRACE:
        if (ch == '{') {
            state = STATE_SECOND_BRACE;
            goto append_text;
        }

        strbuf_append_char(buf, '{');

        if (last_pass)
            goto append_text;

        strbuf_append_char(buf, ch);

        return STATE_DEFAULT;

    case STATE_SECOND_BRACE:
        if (ch == '{')
            PARSE_ERROR("Unexpected open brace.");
        if (ch == '}')
            return STATE_FIRST_CLOSING_BRACE;
        if (last_pass)
            PARSE_ERROR("Missing close brace.");

        strbuf_append_char(buf, ch);
        break;

    case STATE_FIRST_CLOSING_BRACE:
        if (ch == '}')
            return STATE_SECOND_CLOSING_BRACE;

        PARSE_ERROR("Closing brace expected.");

    case STATE_SECOND_CLOSING_BRACE:
        if (ch == '}')
            PARSE_ERROR("Unexpected close brace.");

        if (strbuf_get_length(buf) == 0)
            PARSE_ERROR("Expecting variable name.");

        switch (compile_append_var(tpl, buf, descriptor)) {
        case -ENOKEY:
            PARSE_ERROR("Unknown variable: ``%s''.", strbuf_get_buffer(buf));
        case -ENOMEM:
            PARSE_ERROR("Out of memory while appending variable.");
        case -ENOENT:
            PARSE_ERROR("Cannot find template to include: ``%s''.",
                strbuf_get_buffer(buf) + 1);
        }

        if (last_pass)
            return STATE_DEFAULT;
        if (ch == '{')
            return STATE_FIRST_BRACE;

        strbuf_append_char(buf, ch);
        return STATE_DEFAULT;
    }

    return state;

append_text:
    switch (compile_append_text(tpl, buf)) {
    case -ENOMEM:
        PARSE_ERROR("Out of memory while appending text.");
    }

    return state;
}

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
        goto error_allocate_tpl;

    tpl->descriptor_hash = hash_str_new(64, NULL, NULL);
    if (!tpl->descriptor_hash)
        goto error_allocate_hash;

    int i;
    for (i = 0; descriptor[i].name; i++)
        hash_add(tpl->descriptor_hash, descriptor[i].name, &descriptor[i]);

    buf = strbuf_new();
    if (!buf)
        goto error_allocate_strbuf;
    
    file = fopen(filename, "r");
    if (!file)
        goto error_open_file;

    int line = 1;
    int column = 1;
    int ch;
    while ((ch = fgetc(file)) != EOF) {
        if (ch == '\n') {
            if (state == STATE_DEFAULT)
                strbuf_append_char(buf, '\n');

            ++line;
            column = 1;
            continue;
        }
        ++column;

        state = feed_into_compiler(tpl, descriptor, state, buf, ch, error_msg);
        if (state == STATE_PARSE_ERROR)
            goto parse_error;
    }

    state = feed_into_compiler(tpl, descriptor, state, buf, ch, error_msg);
    if (state == STATE_PARSE_ERROR)
        goto parse_error;

    lwan_tpl_chunk_t *last = malloc(sizeof(*last));
    if (!last)
        goto error_last_minute;

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
    fclose(file);

    return tpl;

parse_error:
    printf("Line %d, column %d: %s\n", line, column, error_msg);

error_last_minute:
    fclose(file);

error_open_file:
    strbuf_free(buf);

error_allocate_strbuf:
    hash_free(tpl->descriptor_hash);

error_allocate_hash:
    lwan_tpl_free(tpl);

error_allocate_tpl:
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
    if (UNLIKELY(!descriptor))
        goto end;

    char *value;
    value = descriptor->get_as_string((void *)(variables + descriptor->offset),
                allocated, length);
    if (LIKELY(value))
        return value;

end:
    if (LIKELY(allocated))
        *allocated = false;

    if (LIKELY(length))
        *length = 0;
    return NULL;
}

static bool
var_get_is_empty(lwan_tpl_chunk_t *chunk,
                 void *variables)
{
    lwan_var_descriptor_t *descriptor = chunk->data;
    if (UNLIKELY(!descriptor))
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
        case TPL_ACTION_VARIABLE: {
            bool allocated;
            size_t length;
            char *value;

            value = var_get_as_string(chunk, variables,
                    &allocated, &length);
            strbuf_append_str(buf, value, length);
            if (allocated)
                free(value);
            break;
        }
        case TPL_ACTION_IF_VARIABLE_NOT_EMPTY: {
            const char *var_name = (const char*)chunk->data;

            if (UNLIKELY(!chunk->data))
                break;

            if (!var_get_is_empty(chunk, variables)) {
                chunk = lwan_tpl_apply_until(tpl,
                                    chunk->next,
                                    buf,
                                    variables,
                                    until_not_empty,
                                    chunk->data);
                break;
            }

            for (chunk = chunk->next; chunk; chunk = chunk->next) {
                if (chunk->action == TPL_ACTION_END_IF_VARIABLE_NOT_EMPTY &&
                        !strcmp(chunk->data, var_name))
                    break;
            }

            break;
        }
        case TPL_ACTION_APPLY_TPL: {
            strbuf_t *tmp;

            tmp = lwan_tpl_apply(chunk->data, variables);
            strbuf_append_str(buf, strbuf_get_buffer(tmp), strbuf_get_length(tmp));
            strbuf_free(tmp);
            break;
        }
        case TPL_ACTION_LIST_START_ITER:
        case TPL_ACTION_LIST_END_ITER:
            /* Not implemented */
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
