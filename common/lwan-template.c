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
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "hash.h"
#include "int-to-str.h"
#include "list.h"
#include "lwan-private.h"
#include "lwan-template.h"
#include "strbuf.h"

typedef struct lwan_tpl_chunk_t_ lwan_tpl_chunk_t;

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

typedef enum {
    TPL_FLAG_NEGATE = 1<<0
} lwan_tpl_flag_t;

enum {
    STATE_DEFAULT,
    STATE_FIRST_BRACE,
    STATE_SECOND_BRACE,
    STATE_FIRST_CLOSING_BRACE,
    STATE_SECOND_CLOSING_BRACE,
    STATE_PARSE_ERROR
};

struct lwan_tpl_chunk_t_ {
    struct list_node list;
    lwan_tpl_action_t action;
    lwan_tpl_flag_t flags;
    void *data;
};

struct lwan_tpl_t_ {
    struct list_head chunks;
    size_t minimum_size;
};

struct symtab {
    struct hash *hash;
    struct symtab *next;
};

struct parser_state {
    lwan_tpl_t *tpl;
    struct symtab *symtab;
};

struct chunk_descriptor {
    lwan_tpl_chunk_t *chunk;
    lwan_var_descriptor_t *descriptor;
};

static lwan_var_descriptor_t *
symtab_lookup(struct parser_state *state, const char *var_name)
{
    for (struct symtab *tab = state->symtab; tab; tab = tab->next) {
        lwan_var_descriptor_t *var = hash_find(tab->hash, var_name);
        if (var)
            return var;
    }

    return NULL;
}

static bool
symtab_push(struct parser_state *state, const lwan_var_descriptor_t *descriptor)
{
    struct symtab *tab = malloc(sizeof(*tab));

    if (!tab)
        return false;

    tab->hash = hash_str_new(NULL, NULL);
    if (!tab->hash) {
        free(tab);
        return false;
    }

    tab->next = state->symtab;
    state->symtab = tab;

    for (; descriptor->name; descriptor++)
        hash_add(state->symtab->hash, descriptor->name, descriptor);

    return true;
}

static void
symtab_pop(struct parser_state *state)
{
    struct symtab *tab = state->symtab;

    assert(tab);

    hash_free(tab->hash);
    state->symtab = tab->next;
    free(tab);
}

void
lwan_append_int_to_strbuf(strbuf_t *buf, void *ptr)
{
    char convertbuf[INT_TO_STR_BUFFER_SIZE];
    size_t len;
    char *converted;

    converted = int_to_string(*(int *)ptr, convertbuf, &len);
    strbuf_append_str(buf, converted, len);
}

bool
lwan_tpl_int_is_empty(void *ptr)
{
    return (*(int *)ptr) == 0;
}

void
lwan_append_double_to_strbuf(strbuf_t *buf, void *ptr)
{
    strbuf_append_printf(buf, "%f", *(double *)ptr);
}

bool
lwan_tpl_double_is_empty(void *ptr)
{
    return (*(double *)ptr) == 0.0f;
}

void
lwan_append_str_to_strbuf(strbuf_t *buf, void *ptr)
{
    struct v {
        char *str;
    } *v = ptr;

    if (LIKELY(v->str))
        strbuf_append_str(buf, v->str, 0);
}

static bool
is_alphanumeric(const char c)
{
    if (c >= 'A' && c <= 'Z')
        return true;
    if (c >= 'a' && c <= 'z')
        return true;
    if (c >= '0' && c <= '9')
        return true;
    return false;
}

void
lwan_append_str_escaped_to_strbuf(strbuf_t *buf, void *ptr)
{
    struct v {
        char *str;
    } *v = ptr;

    if (UNLIKELY(!v->str))
        return;

    for (char *p = v->str; *p; p++) {
        if (*p == '<')
            strbuf_append_str(buf, "&lt;", 4);
        else if (*p == '>')
            strbuf_append_str(buf, "&gt;", 4);
        else if (*p == '&')
            strbuf_append_str(buf, "&amp;", 5);
        else if (*p == '"')
            strbuf_append_str(buf, "&quot;", 6);
        else if (is_alphanumeric(*p) || lwan_chr_is_space(*p))
            strbuf_append_char(buf, *p);
        else
            strbuf_append_printf(buf, "&#x%x;", *p);
    }
}

bool
lwan_tpl_str_is_empty(void *ptr)
{
    char *str = ptr;
    if (!str)
        return true;
    if (*str == '\0')
        return true;
    return false;
}

static int
compile_append_text(struct parser_state *state, strbuf_t *buf)
{
    size_t length = strbuf_get_length(buf);
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

    list_add_tail(&state->tpl->chunks, &chunk->list);
    state->tpl->minimum_size += length;
    strbuf_reset(buf);

    return 0;
}

static int
compile_append_var(struct parser_state *state, strbuf_t *buf,
            const lwan_var_descriptor_t *descriptor)
{
    lwan_tpl_chunk_t *chunk = malloc(sizeof(*chunk));
    if (!chunk)
        return -ENOMEM;

    char *variable = strbuf_get_buffer(buf);
    size_t length = strbuf_get_length(buf) - 1;

    chunk->flags = 0;

next_char:
    switch (*variable) {
    case '^':
        chunk->flags ^= TPL_FLAG_NEGATE;
        variable++;
        length--;
        if (!length)
            goto nokey;

        goto next_char;

    case '!':
        free(chunk);
        strbuf_reset(buf);
        return 0;

    case '>': {
        char template_file[PATH_MAX];
        snprintf(template_file, sizeof(template_file), "%s.tpl", variable + 1);

        lwan_tpl_t *included = lwan_tpl_compile_file(template_file, descriptor);
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
        chunk->data = symtab_lookup(state, variable + 1);
        if (!chunk->data) {
            goto nokey;
        } else {
            lwan_var_descriptor_t *child = chunk->data;
            symtab_push(state, child->list_desc);
        }
        break;
    case '/': {
        lwan_tpl_chunk_t *start_chunk;
        lwan_var_descriptor_t *descr;
        bool was_if = false;

        if (variable[length] == '?') {
            variable[length] = '\0';
            was_if = true;
        }

        descr = symtab_lookup(state, variable + 1);
        if (!descr)
            goto nokey;

        if (was_if) {
            chunk->action = TPL_ACTION_END_IF_VARIABLE_NOT_EMPTY;
            list_for_each_rev(&state->tpl->chunks, start_chunk, list) {
                if (start_chunk->action != TPL_ACTION_IF_VARIABLE_NOT_EMPTY)
                    continue;
                if (start_chunk->data != descr)
                    continue;

                chunk->data = descr;
                goto add_chunk;
            }
        } else {
            chunk->action = TPL_ACTION_LIST_END_ITER;
            list_for_each_rev(&state->tpl->chunks, start_chunk, list) {
                if (start_chunk->data == descr) {
                    chunk->data = start_chunk;
                    symtab_pop(state);
                    goto add_chunk;
                }
            }
        }

        goto nokey;
    }
    default:
        if (variable[length] == '?') {
            chunk->action = TPL_ACTION_IF_VARIABLE_NOT_EMPTY;
            variable[length] = '\0';
        } else {
            chunk->action = TPL_ACTION_VARIABLE;
        }
        chunk->data = symtab_lookup(state, variable);
        if (!chunk->data)
            goto nokey;
    }

add_chunk:
    list_add_tail(&state->tpl->chunks, &chunk->list);
    state->tpl->minimum_size += length + 1;
    strbuf_reset(buf);

    return 0;

nokey:
    free(chunk);
    return -ENOKEY;
}

static void
free_chunk(lwan_tpl_chunk_t *chunk)
{
    if (!chunk)
        return;

    switch (chunk->action) {
    case TPL_ACTION_LAST:
    case TPL_ACTION_APPEND_CHAR:
    case TPL_ACTION_VARIABLE:
    case TPL_ACTION_END_IF_VARIABLE_NOT_EMPTY:
    case TPL_ACTION_LIST_END_ITER:
        /* do nothing */
        break;
    case TPL_ACTION_IF_VARIABLE_NOT_EMPTY:
    case TPL_ACTION_LIST_START_ITER:
        free(chunk->data);
        break;
    case TPL_ACTION_APPEND:
        strbuf_free(chunk->data);
        break;
    case TPL_ACTION_APPLY_TPL:
        lwan_tpl_free(chunk->data);
        break;
    }

    free(chunk);
}

void
lwan_tpl_free(lwan_tpl_t *tpl)
{
    if (!tpl)
        return;

    lwan_tpl_chunk_t *chunk;
    lwan_tpl_chunk_t *next;
    list_for_each_safe(&tpl->chunks, chunk, next, list) {
        list_del(&chunk->list);
        free_chunk(chunk);
    }

    free(tpl);
}

#define PARSE_ERROR(msg,...) \
    do { \
        snprintf(error_msg, 512, msg, ##__VA_ARGS__); \
        return STATE_PARSE_ERROR; \
    } while(0)

static int
feed_into_compiler(struct parser_state *parser_state,
    const lwan_var_descriptor_t *descriptor,
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

        strbuf_append_char(buf, (char)ch);
        break;

    case STATE_FIRST_BRACE:
        if (ch == '{') {
            state = STATE_SECOND_BRACE;
            goto append_text;
        }

        strbuf_append_char(buf, '{');

        if (last_pass)
            goto append_text;

        strbuf_append_char(buf, (char)ch);

        return STATE_DEFAULT;

    case STATE_SECOND_BRACE:
        if (ch == '{')
            PARSE_ERROR("Unexpected open brace");
        if (ch == '}')
            return STATE_FIRST_CLOSING_BRACE;
        if (last_pass)
            PARSE_ERROR("Missing close brace");

        strbuf_append_char(buf, (char)ch);
        break;

    case STATE_FIRST_CLOSING_BRACE:
        if (ch == '}')
            return STATE_SECOND_CLOSING_BRACE;

        PARSE_ERROR("Closing brace expected");

    case STATE_SECOND_CLOSING_BRACE:
        if (strbuf_get_length(buf) == 0)
            PARSE_ERROR("Expecting variable name");

        switch (compile_append_var(parser_state, buf, descriptor)) {
        case -ENOKEY:
            PARSE_ERROR("Unknown variable: ``%s''", strbuf_get_buffer(buf));
        case -ENOMEM:
            PARSE_ERROR("Out of memory while appending variable");
        case -ENOENT:
            PARSE_ERROR("Cannot find template to include: ``%s''",
                strbuf_get_buffer(buf) + 1);
        }

        if (last_pass)
            return STATE_DEFAULT;
        if (ch == '{')
            return STATE_FIRST_BRACE;

        strbuf_append_char(buf, (char)ch);
        return STATE_DEFAULT;
    }

    return state;

append_text:
    switch (compile_append_text(parser_state, buf)) {
    case -ENOMEM:
        PARSE_ERROR("Out of memory while appending text");
    }

    return state;
}

static void
post_process_template(lwan_tpl_t *tpl)
{
    lwan_tpl_chunk_t *chunk;
    lwan_tpl_chunk_t *prev_chunk;

    list_for_each(&tpl->chunks, chunk, list) {
        if (chunk->action == TPL_ACTION_IF_VARIABLE_NOT_EMPTY) {
            prev_chunk = chunk;

            while ((chunk = (lwan_tpl_chunk_t *) chunk->list.next)) {
                if (chunk->action == TPL_ACTION_LAST)
                    break;
                if (chunk->action == TPL_ACTION_END_IF_VARIABLE_NOT_EMPTY
                            && chunk->data == prev_chunk->data)
                    break;
            }

            struct chunk_descriptor *cd = malloc(sizeof(*cd));
            if (!cd)
                lwan_status_critical_perror("malloc");

            cd->descriptor = prev_chunk->data;
            cd->chunk = chunk;
            prev_chunk->data = cd;
        } else if (chunk->action == TPL_ACTION_LIST_START_ITER) {
            lwan_tpl_flag_t flags = chunk->flags;

            prev_chunk = chunk;

            while ((chunk = (lwan_tpl_chunk_t *) chunk->list.next)) {
                if (chunk->action == TPL_ACTION_LAST)
                    break;
                if (chunk->action == TPL_ACTION_LIST_END_ITER
                            && chunk->data == prev_chunk) {
                    chunk->flags |= flags;
                    break;
                }
            }

            struct chunk_descriptor *cd = malloc(sizeof(*cd));
            if (!cd)
                lwan_status_critical_perror("malloc");

            cd->descriptor = prev_chunk->data;
            prev_chunk->data = cd;

            if (chunk->action == TPL_ACTION_LAST)
                cd->chunk = chunk;
            else
                cd->chunk = (lwan_tpl_chunk_t *)chunk->list.next;
        } else if (chunk->action == TPL_ACTION_LAST) {
            break;
        }
    }
}

lwan_tpl_t *
lwan_tpl_compile_string(const char *string, const lwan_var_descriptor_t *descriptor)
{
    lwan_tpl_t *tpl;
    strbuf_t *buf;
    int state = STATE_DEFAULT;
    char error_msg[512];
    struct parser_state parser_state;

    tpl = calloc(1, sizeof(*tpl));
    if (!tpl)
        goto error_allocate_tpl;

    list_head_init(&tpl->chunks);

    parser_state.tpl = tpl;
    parser_state.symtab = NULL;
    if (!symtab_push(&parser_state, descriptor))
        goto error_symtab_push;

    buf = strbuf_new();
    if (!buf)
        goto error_allocate_strbuf;

    int line = 1;
    int column = 1;
    for (; *string; string++) {
        if (*string == '\n') {
            if (state == STATE_DEFAULT)
                strbuf_append_char(buf, '\n');

            ++line;
            column = 1;
            continue;
        }
        ++column;

        state = feed_into_compiler(&parser_state, descriptor, state,
                    buf, *string, error_msg);
        if (state == STATE_PARSE_ERROR)
            goto parse_error;
    }

    state = feed_into_compiler(&parser_state, descriptor, state,
                buf, EOF, error_msg);
    if (state == STATE_PARSE_ERROR)
        goto parse_error;

    lwan_tpl_chunk_t *last = malloc(sizeof(*last));
    if (!last)
        goto free_strbuf;

    last->action = TPL_ACTION_LAST;
    last->data = NULL;

    list_add_tail(&parser_state.tpl->chunks, &last->list);

    strbuf_free(buf);
    symtab_pop(&parser_state);

    post_process_template(tpl);

    return tpl;

parse_error:
    lwan_status_error("Line %d, column %d: %s", line, column, error_msg);

free_strbuf:
    strbuf_free(buf);

error_allocate_strbuf:
    symtab_pop(&parser_state);

error_symtab_push:
    lwan_tpl_free(tpl);

error_allocate_tpl:
    return NULL;
}

#undef PARSE_ERROR

lwan_tpl_t *
lwan_tpl_compile_file(const char *filename, const lwan_var_descriptor_t *descriptor)
{
    int fd;
    struct stat st;
    char *mapped;
    lwan_tpl_t *tpl = NULL;

    fd = open(filename, O_RDONLY);
    if (fd < 0)
        goto end;

    if (fstat(fd, &st) < 0)
        goto close_file;

    mapped = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_SHARED, fd, 0);
    if (mapped == MAP_FAILED)
        goto close_file;

    tpl = lwan_tpl_compile_string(mapped, descriptor);

    if (munmap(mapped, (size_t)st.st_size) < 0)
        lwan_status_perror("munmap");

close_file:
    close(fd);
end:
    return tpl;
}

static bool
until_end(lwan_tpl_chunk_t *chunk, void *data __attribute__((unused)))
{
    return chunk->action == TPL_ACTION_LAST;
}

static bool
until_found_end_if(lwan_tpl_chunk_t *chunk, void *data)
{
    return chunk == data;
}

static bool
until_iter_end(lwan_tpl_chunk_t *chunk, void *data)
{
    if (chunk->action != TPL_ACTION_LIST_END_ITER)
        return false;
    if (data != chunk->data)
        return false;
    return true;
}

static void
append_var_to_strbuf(lwan_tpl_chunk_t *chunk, void *variables,
                     strbuf_t *buf)
{
    lwan_var_descriptor_t *descriptor = chunk->data;
    if (LIKELY(descriptor))
        descriptor->append_to_strbuf(buf, (char *)variables + descriptor->offset);
}

static bool
var_get_is_empty(lwan_var_descriptor_t *descriptor,
                 void *variables)
{
    if (UNLIKELY(!descriptor))
        return true;

    return descriptor->get_is_empty((void *)((char *)variables + descriptor->offset));
}

static lwan_tpl_chunk_t *
lwan_tpl_apply_until(lwan_tpl_t *tpl,
    lwan_tpl_chunk_t *chunks, strbuf_t *buf,
    void *variables,
    bool (*until)(lwan_tpl_chunk_t *chunk, void *data), void *until_data)
{
    coro_switcher_t switcher;
    coro_t *coro = NULL;
    lwan_tpl_chunk_t *chunk = chunks;

    if (UNLIKELY(!chunk))
        goto out;

    do {
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
            append_var_to_strbuf(chunk, variables, buf);
            break;
        case TPL_ACTION_IF_VARIABLE_NOT_EMPTY: {
            struct chunk_descriptor *cd = chunk->data;
            bool empty = var_get_is_empty(cd->descriptor, variables);
            if (chunk->flags & TPL_FLAG_NEGATE)
                empty = !empty;
            if (empty) {
                chunk = cd->chunk;
            } else {
                chunk = lwan_tpl_apply_until(tpl,
                    (lwan_tpl_chunk_t *) chunk->list.next, buf, variables,
                    until_found_end_if, cd->chunk);
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
        case TPL_ACTION_LIST_START_ITER: {
            if (UNLIKELY(coro != NULL)) {
                lwan_status_warning("Coroutine is not NULL when starting iteration");
                break;
            }

            struct chunk_descriptor *cd = chunk->data;
            coro = coro_new(&switcher, cd->descriptor->generator, variables);

            bool resumed = coro_resume_value(coro, 0);
            lwan_tpl_flag_t flags = chunk->flags;
            if (flags & TPL_FLAG_NEGATE)
                resumed = !resumed;
            if (!resumed) {
                chunk = cd->chunk;
                if (flags & TPL_FLAG_NEGATE) {
                    coro_resume_value(coro, 1);
                    coro_free(coro);
                    coro = NULL;
                    continue;
                }

                coro_free(coro);
                coro = NULL;

                break;
            }

            chunk = lwan_tpl_apply_until(tpl, (lwan_tpl_chunk_t *) chunk->list.next,
                        buf, variables, until_iter_end, chunk);
            continue;
        }
        case TPL_ACTION_LIST_END_ITER: {
            if (UNLIKELY(!coro)) {
                if (!chunk->flags)
                    lwan_status_warning("Coroutine is NULL when finishing iteration");
                break;
            }

            if (!coro_resume_value(coro, 0)) {
                coro_free(coro);
                coro = NULL;
                break;
            }

            lwan_tpl_chunk_t *next = chunk->data;
            next = (lwan_tpl_chunk_t *)next->list.next;

            chunk = lwan_tpl_apply_until(tpl, next, buf, variables, until_iter_end,
                        chunk->data);
            continue;
        }
        case TPL_ACTION_END_IF_VARIABLE_NOT_EMPTY:
        case TPL_ACTION_LAST:
            /* Shouldn't happen */
            break;
        }

        if (!chunk)
            break;
        chunk = (lwan_tpl_chunk_t *)chunk->list.next;
    } while (chunk);

out:
    return chunk;
}

strbuf_t *
lwan_tpl_apply_with_buffer(lwan_tpl_t *tpl, strbuf_t *buf, void *variables)
{
    if (UNLIKELY(!strbuf_reset_length(buf)))
        return NULL;

    if (UNLIKELY(!strbuf_grow_to(buf, tpl->minimum_size)))
        return NULL;

    lwan_tpl_apply_until(tpl, (lwan_tpl_chunk_t *)&tpl->chunks.n, buf, variables, until_end, NULL);
    return buf;
}

strbuf_t *
lwan_tpl_apply(lwan_tpl_t *tpl, void *variables)
{
    strbuf_t *buf = strbuf_new_with_size(tpl->minimum_size);
    return lwan_tpl_apply_with_buffer(tpl, buf, variables);
}

#ifdef TEMPLATE_TEST

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
    lwan_tpl_t *tpl = lwan_tpl_compile_file(argv[1], desc);
    if (!tpl)
        return 1;

    printf("*** Applying template 100000 times...\n");
    for (size_t i = 0; i < 100000; i++) {
        strbuf_t *applied = lwan_tpl_apply(tpl, (struct test_struct[]) {{
            .some_int = 42,
            .a_string = "some string"
        }});
        strbuf_free(applied);
    }

    lwan_tpl_free(tpl);
    return 0;
}

#endif /* TEMPLATE_TEST */
