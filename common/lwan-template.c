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
 * Lexer+parser implemented using ideas from Rob Pike's talk "Lexical Scanning
 * in Go" (https://www.youtube.com/watch?v=HxaD_trXwRE).
 */

#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "hash.h"
#include "int-to-str.h"
#include "list.h"
#include "lwan-template.h"
#include "strbuf.h"
#include "reallocarray.h"

enum action {
    TPL_ACTION_APPEND,
    TPL_ACTION_APPEND_CHAR,
    TPL_ACTION_VARIABLE,
    TPL_ACTION_VARIABLE_STR,
    TPL_ACTION_VARIABLE_STR_ESCAPE,
    TPL_ACTION_START_ITER,
    TPL_ACTION_END_ITER,
    TPL_ACTION_IF_VARIABLE_NOT_EMPTY,
    TPL_ACTION_END_IF_VARIABLE_NOT_EMPTY,
    TPL_ACTION_APPLY_TPL,
    TPL_ACTION_LAST
};

enum flags {
    FLAGS_ALL = -1,
    FLAGS_NEGATE = 1<<0,
    FLAGS_QUOTE = 1<<1
};

enum item_type {
    ITEM_ERROR,
    ITEM_EOF,
    ITEM_IDENTIFIER,
    ITEM_LEFT_META,
    ITEM_HASH,
    ITEM_RIGHT_META,
    ITEM_TEXT,
    ITEM_SLASH,
    ITEM_QUESTION_MARK,
    ITEM_HAT,
    ITEM_GREATER_THAN,
    ITEM_OPEN_CURLY_BRACE,
    ITEM_CLOSE_CURLY_BRACE,
    TOTAL_ITEMS
};

static const char *item_type_str[TOTAL_ITEMS] = {
    [ITEM_ERROR] = "ERROR",
    [ITEM_EOF] = "EOF",
    [ITEM_IDENTIFIER] = "IDENTIFIER",
    [ITEM_LEFT_META] = "LEFT_META",
    [ITEM_HASH] = "HASH",
    [ITEM_RIGHT_META] = "RIGHT_META",
    [ITEM_TEXT] = "TEXT",
    [ITEM_SLASH] = "SLASH",
    [ITEM_QUESTION_MARK] = "QUESTION_MARK",
    [ITEM_HAT] = "HAT",
    [ITEM_GREATER_THAN] = "GREATER_THAN",
    [ITEM_OPEN_CURLY_BRACE] = "ITEM_OPEN_CURLY_BRACE",
    [ITEM_CLOSE_CURLY_BRACE] = "ITEM_CLOSE_CURLY_BRACE"
};

struct chunk {
    enum action action;
    enum flags flags;
    void *data;
};

struct lwan_tpl_t_ {
    struct {
        struct chunk *data;
        size_t used, reserved;
    } chunks;
    size_t minimum_size;
};

struct symtab {
    struct hash *hash;
    struct symtab *next;
};

struct item {
    enum item_type type;
    struct {
        const char *value;
        size_t len;
    } value;
};

struct lexer {
    void *(*state)(struct lexer *);
    const char *start, *pos, *end;

    struct {
        struct item items[4];
        size_t first;
        size_t last;
        size_t population;
    } ring_buffer;
};

struct parser {
    lwan_tpl_t *tpl;
    struct symtab *symtab;
    struct lexer lexer;
    enum flags flags;
    struct list_head stack;
};

struct stacked_item {
    struct list_node stack;
    struct item item;
};

struct chunk_descriptor {
    struct chunk *chunk;
    lwan_var_descriptor_t *descriptor;
};

static const size_t array_increment_step = 16;

static const char left_meta[] = "{{";
static const char right_meta[] = "}}";

static void *lex_inside_action(struct lexer *lexer);
static void *lex_identifier(struct lexer *lexer);
static void *lex_left_meta(struct lexer *lexer);
static void *lex_right_meta(struct lexer *lexer);
static void *lex_text(struct lexer *lexer);

static void *parser_meta(struct parser *parser, struct item *item);
static void *parser_text(struct parser *parser, struct item *item);
static void *parser_iter(struct parser *parser, struct item *item);
static void *parser_slash(struct parser *parser, struct item *item);
static void *parser_end_iter(struct parser *parser, struct item *item);
static void *parser_end_var_not_empty(struct parser *parser, struct item *item);
static void *parser_slash(struct parser *parser, struct item *item);
static void *parser_iter(struct parser *parser, struct item *item);
static void *parser_negate_iter(struct parser *parser, struct item *item);
static void *parser_meta(struct parser *parser, struct item *item);
static void *parser_text(struct parser *parser, struct item *item);

static void *error_vitem(struct item *item, const char *msg, va_list ap)
    __attribute__((format(printf, 2, 0)));
static void *error_item(struct item *item, const char *msg, ...)
    __attribute__((format(printf, 2, 3)));
static void *lex_error(struct lexer *lexer, const char *msg, ...)
    __attribute__((format(printf, 2, 3)));

static lwan_var_descriptor_t *
symtab_lookup(struct parser *parser, const char *var_name)
{
    for (struct symtab *tab = parser->symtab; tab; tab = tab->next) {
        lwan_var_descriptor_t *var = hash_find(tab->hash, var_name);
        if (var)
            return var;
    }

    return NULL;
}

static bool
symtab_push(struct parser *parser, const lwan_var_descriptor_t *descriptor)
{
    struct symtab *tab = malloc(sizeof(*tab));

    if (!tab)
        return false;

    tab->hash = hash_str_new(NULL, NULL);
    if (!tab->hash) {
        free(tab);
        return false;
    }

    tab->next = parser->symtab;
    parser->symtab = tab;

    for (; descriptor->name; descriptor++)
        hash_add(parser->symtab->hash, descriptor->name, descriptor);

    return true;
}

static void
symtab_pop(struct parser *parser)
{
    struct symtab *tab = parser->symtab;

    assert(tab);

    hash_free(tab->hash);
    parser->symtab = tab->next;
    free(tab);
}

static void emit_item(struct lexer *lexer, struct item *item)
{
    lexer->ring_buffer.items[lexer->ring_buffer.last] = *item;
    lexer->ring_buffer.last = (lexer->ring_buffer.last + 1) % N_ELEMENTS(lexer->ring_buffer.items);
    lexer->ring_buffer.population++;

    lexer->start = lexer->pos;
}

static bool consume_item(struct lexer *lexer, struct item **item)
{
    if (!lexer->ring_buffer.population)
        return false;

    *item = &lexer->ring_buffer.items[lexer->ring_buffer.first];
    lexer->ring_buffer.first = (lexer->ring_buffer.first + 1) % N_ELEMENTS(lexer->ring_buffer.items);
    lexer->ring_buffer.population--;

    return true;
}

static void emit(struct lexer *lexer, enum item_type item_type)
{
    struct item item = {
        .type = item_type,
        .value = {
            .value = lexer->start,
            .len = (size_t)(lexer->pos - lexer->start)
        }
    };
    emit_item(lexer, &item);
}

static int next(struct lexer *lexer)
{
    if (lexer->pos >= lexer->end)
        return EOF;
    int r = *lexer->pos;
    lexer->pos++;
    return r;
}

static void ignore(struct lexer *lexer)
{
    lexer->start = lexer->pos;
}

static void backup(struct lexer *lexer)
{
    lexer->pos--;
}

static void *error_vitem(struct item *item, const char *msg, va_list ap)
{
    int r;

    item->type = ITEM_ERROR;

    r = vasprintf((char **)&item->value.value, msg, ap);
    if (r < 0) {
        item->value.value = strdup(strerror(errno));
        if (!item->value.value)
            return NULL;

        item->value.len = strlen(item->value.value);
    } else {
        item->value.len = (size_t)r;
    }

    return NULL;
}

static void *error_item(struct item *item, const char *msg, ...)
{
    void *ret;
    va_list ap;

    va_start(ap, msg);
    ret = error_vitem(item, msg, ap);
    va_end(ap);

    return ret;
}

static void *lex_error(struct lexer *lexer, const char *msg, ...)
{
    struct item item;
    va_list ap;

    va_start(ap, msg);
    error_vitem(&item, msg, ap);
    va_end(ap);

    emit_item(lexer, &item);
    return NULL;
}

static bool isident(int ch)
{
    return isalnum(ch) || ch == '_' || ch == '.';
}

static void *lex_identifier(struct lexer *lexer)
{
    while (isident(next(lexer)))
        ;
    backup(lexer);
    emit(lexer, ITEM_IDENTIFIER);
    return lex_inside_action;
}

static void *lex_quoted_identifier(struct lexer *lexer)
{
    int r;

    emit(lexer, ITEM_OPEN_CURLY_BRACE);
    lex_identifier(lexer);

    r = next(lexer);
    if (r != '}')
        return lex_error(lexer, "expecting `}', found `%c'", r);

    emit(lexer, ITEM_CLOSE_CURLY_BRACE);
    return lex_inside_action;
}

static void *lex_comment(struct lexer *lexer)
{
    size_t brackets = strlen(left_meta);

    assert(strlen(left_meta) == strlen(right_meta));

    do {
        int r = next(lexer);
        if (r == '{')
            brackets++;
        else if (r == '}')
            brackets--;
        else if (r == EOF)
            return lex_error(lexer, "unexpected EOF while scanning comment end");
    } while (brackets);

    ignore(lexer);
    return lex_text;
}

static void *lex_inside_action(struct lexer *lexer)
{
    while (true) {
        int r;

        if (!strncmp(lexer->pos, right_meta, strlen(right_meta)))
            return lex_right_meta;

        r = next(lexer);
        if (r == EOF)
            return lex_error(lexer, "unexpected EOF while scanning action");
        if (r == '\n')
            return lex_error(lexer, "actions cannot span multiple lines");

        if (isspace(r)) {
            ignore(lexer);
        } else if (r == '#') {
            emit(lexer, ITEM_HASH);
        } else if (r == '/') {
            emit(lexer, ITEM_SLASH);
        } else if (r == '?') {
            emit(lexer, ITEM_QUESTION_MARK);
        } else if (r == '^') {
            emit(lexer, ITEM_HAT);
        } else if (r == '>') {
            emit(lexer, ITEM_GREATER_THAN);
        } else if (r == '{') {
            return lex_quoted_identifier;
        } else if (isalnum(r) || r == '_') {
            backup(lexer);
            return lex_identifier;
        } else {
            return lex_error(lexer, "unexpected character: %c", r);
        }
    }
}

static void *lex_left_meta(struct lexer *lexer)
{
    lexer->pos += strlen(left_meta);
    int r = next(lexer);
    if (r == '!')
        return lex_comment;
    backup(lexer);

    emit(lexer, ITEM_LEFT_META);
    return lex_inside_action;
}

static void *lex_right_meta(struct lexer *lexer)
{
    lexer->pos += strlen(right_meta);
    emit(lexer, ITEM_RIGHT_META);
    return lex_text;
}

static void *lex_text(struct lexer *lexer)
{
    do {
        if (!strncmp(lexer->pos, left_meta, strlen(left_meta))) {
            if (lexer->pos > lexer->start)
                emit(lexer, ITEM_TEXT);
            return lex_left_meta;
        }
        if (!strncmp(lexer->pos, right_meta, strlen(right_meta)))
            return lex_error(lexer, "unexpected action close sequence");
    } while (next(lexer) != EOF);
    if (lexer->pos > lexer->start)
        emit(lexer, ITEM_TEXT);
    emit(lexer, ITEM_EOF);
    return NULL;
}

static bool lex_next(struct lexer *lexer, struct item **item)
{
    while (lexer->state) {
        if (consume_item(lexer, item))
            return true;
        lexer->state = lexer->state(lexer);
    }

    return consume_item(lexer, item);
}

static void lex_init(struct lexer *lexer, const char *input)
{
    lexer->state = lex_text;
    lexer->pos = lexer->start = input;
    lexer->end = rawmemchr(input, '\0');
}

static void *unexpected_lexeme(struct item *item)
{
    return error_item(item, "unexpected lexeme: %s [%.*s]",
        item_type_str[item->type], (int)item->value.len, item->value.value);
}

static void *unexpected_lexeme_or_lex_error(struct item *item, struct item *lex_error)
{
    if (lex_error && (lex_error->type == ITEM_ERROR || lex_error->type == ITEM_EOF)) {
        *item = *lex_error;
        return NULL;
    }

    return unexpected_lexeme(item);
}

static bool parser_next_is(struct parser *parser, enum item_type type)
{
    struct item *item;
    return lex_next(&parser->lexer, &item) ? item->type == type : false;
}

static void parser_push_item(struct parser *parser, struct item *item)
{
    struct stacked_item *stacked_item = malloc(sizeof(*stacked_item));
    if (!stacked_item)
        lwan_status_critical_perror("Could not push parser item");

    stacked_item->item = *item;
    list_add(&parser->stack, &stacked_item->stack);
}

static void emit_chunk(struct parser *parser, enum action action,
        enum flags flags, void *data)
{
    struct chunk *chunk;

    if (parser->tpl->chunks.used >= parser->tpl->chunks.reserved) {
        parser->tpl->chunks.reserved += array_increment_step;

        chunk = reallocarray(parser->tpl->chunks.data,
            parser->tpl->chunks.reserved, sizeof(struct chunk));
        if (!chunk)
            lwan_status_critical_perror("Could not emit template chunk");

        parser->tpl->chunks.data = chunk;
    }

    chunk = &parser->tpl->chunks.data[parser->tpl->chunks.used++];
    chunk->action = action;
    chunk->flags = flags;
    chunk->data = data;
}

static bool parser_stack_top_matches(struct parser *parser, struct item *item, enum item_type type)
{
    if (list_empty(&parser->stack)) {
        error_item(item, "unexpected {{/%.*s}}", (int)item->value.len, item->value.value);
        return false;
    }

    struct stacked_item *stacked_item = (struct stacked_item *)parser->stack.n.next;
    bool matches = (stacked_item->item.type == type
            && item->value.len == stacked_item->item.value.len
            && !memcmp(stacked_item->item.value.value, item->value.value, item->value.len));
    if (matches) {
        list_del(&stacked_item->stack);
        free(stacked_item);
        return true;
    }

    error_item(item, "expecting %s `%.*s' but found `%.*s'",
        item_type_str[stacked_item->item.type],
        (int)stacked_item->item.value.len, stacked_item->item.value.value,
        (int)item->value.len, item->value.value);
    return false;
}

static void *parser_end_iter(struct parser *parser, struct item *item)
{
    struct chunk *iter;
    lwan_var_descriptor_t *symbol;
    ssize_t idx;

    if (!parser_stack_top_matches(parser, item, ITEM_IDENTIFIER))
        return NULL;

    symbol = symtab_lookup(parser, strndupa(item->value.value, item->value.len));
    if (!symbol) {
        return error_item(item, "Unknown variable: %.*s", (int)item->value.len,
            item->value.value);
    }

    if (!parser->tpl->chunks.used)
        return error_item(item, "No chunks were emitted but parsing end iter");
    for (idx = (ssize_t)parser->tpl->chunks.used - 1; idx >= 0; idx--) {
        iter = &parser->tpl->chunks.data[idx];

        if (iter->action != TPL_ACTION_START_ITER)
            continue;
        if (iter->data == symbol) {
            emit_chunk(parser, TPL_ACTION_END_ITER, 0, iter);
            symtab_pop(parser);
            return parser_text;
        }
    }

    return error_item(item, "Could not find {{#%.*s}}", (int)item->value.len, item->value.value);
}

static void *parser_end_var_not_empty(struct parser *parser, struct item *item)
{
    struct chunk *iter;
    lwan_var_descriptor_t *symbol;
    ssize_t idx;

    if (!parser_next_is(parser, ITEM_RIGHT_META))
        return unexpected_lexeme(item);
    if (!parser_stack_top_matches(parser, item, ITEM_IDENTIFIER))
        return NULL;

    symbol = symtab_lookup(parser, strndupa(item->value.value, item->value.len));
    if (!symbol) {
        return error_item(item, "Unknown variable: %.*s", (int)item->value.len,
            item->value.value);
    }

    for (idx = (ssize_t)parser->tpl->chunks.used - 1; idx >= 0; idx--) {
        iter = &parser->tpl->chunks.data[idx];
        if (iter->action != TPL_ACTION_IF_VARIABLE_NOT_EMPTY)
            continue;
        if (iter->data == symbol) {
            emit_chunk(parser, TPL_ACTION_END_IF_VARIABLE_NOT_EMPTY, 0, symbol);
            return parser_text;
        }
    }

    return error_item(item, "Could not find {{%.*s?}}", (int)item->value.len, item->value.value);
}

static void *parser_slash(struct parser *parser, struct item *item)
{
    if (item->type == ITEM_IDENTIFIER) {
        struct item *next = NULL;

        if (!lex_next(&parser->lexer, &next))
            return unexpected_lexeme_or_lex_error(item, next);

        if (next->type == ITEM_RIGHT_META)
            return parser_end_iter(parser, item);

        if (next->type == ITEM_QUESTION_MARK)
            return parser_end_var_not_empty(parser, item);

        return unexpected_lexeme_or_lex_error(item, next);
    }

    return unexpected_lexeme(item);
}

static void *parser_iter(struct parser *parser, struct item *item)
{
    if (item->type == ITEM_IDENTIFIER) {
        enum flags negate = parser->flags & FLAGS_NEGATE;
        lwan_var_descriptor_t *symbol = symtab_lookup(parser, strndupa(item->value.value, item->value.len));
        if (!symbol) {
            return error_item(item, "Unknown variable: %.*s", (int)item->value.len,
                item->value.value);
        }

        if (!parser_next_is(parser, ITEM_RIGHT_META))
            return error_item(item, "expecting `}}'");

        if (!symtab_push(parser, symbol->list_desc))
            return error_item(item, "Out of memory");

        emit_chunk(parser, TPL_ACTION_START_ITER, negate, symbol);

        parser_push_item(parser, item);
        parser->flags &= ~FLAGS_NEGATE;
        return parser_text;
    }

    return unexpected_lexeme(item);
}

static void *parser_negate_iter(struct parser *parser, struct item *item)
{
    if (item->type != ITEM_HASH)
        return unexpected_lexeme(item);

    parser->flags ^= FLAGS_NEGATE;
    return parser_iter;
}

static void *parser_meta(struct parser *parser, struct item *item)
{
    struct item *next = NULL;
    bool quote = parser->flags & FLAGS_QUOTE;

    if (item->type == ITEM_OPEN_CURLY_BRACE) {
        parser->flags |= FLAGS_QUOTE;
        return parser_meta;
    }

    if (item->type == ITEM_IDENTIFIER) {
        if (!lex_next(&parser->lexer, &next)) {
            *item = *next;
            return NULL;
        }


        if (quote) {
            parser->flags &= ~FLAGS_QUOTE;
            if (next->type != ITEM_CLOSE_CURLY_BRACE)
                return error_item(item, "Expecting closing brace");
            if (!lex_next(&parser->lexer, &next))
                return unexpected_lexeme_or_lex_error(item, next);
        }

        if (next->type == ITEM_RIGHT_META) {
            lwan_var_descriptor_t *symbol = symtab_lookup(parser, strndupa(item->value.value, item->value.len));
            if (!symbol) {
                return error_item(item, "Unknown variable: %.*s", (int)item->value.len,
                    item->value.value);
            }

            emit_chunk(parser, TPL_ACTION_VARIABLE, quote ? FLAGS_QUOTE : 0, symbol);

            parser->tpl->minimum_size += item->value.len + 1;
            return parser_text;
        }

        if (next->type == ITEM_QUESTION_MARK) {
            lwan_var_descriptor_t *symbol = symtab_lookup(parser, strndupa(item->value.value, item->value.len));
            if (!symbol) {
                return error_item(item, "Unknown variable: %.*s", (int)item->value.len,
                    item->value.value);
            }

            if (!parser_next_is(parser, ITEM_RIGHT_META))
                return unexpected_lexeme_or_lex_error(item, next);

            emit_chunk(parser, TPL_ACTION_IF_VARIABLE_NOT_EMPTY, 0, symbol);
            parser_push_item(parser, item);

            return parser_text;
        }

        return unexpected_lexeme_or_lex_error(item, next);
    }

    if (item->type == ITEM_GREATER_THAN)
        return error_item(item, "Template inclusion not supported yet");

    if (item->type == ITEM_HASH)
        return parser_iter;

    if (item->type == ITEM_HAT)
        return parser_negate_iter;

    if (item->type == ITEM_SLASH)
        return parser_slash;

    return unexpected_lexeme(item);
}

static void *parser_text(struct parser *parser, struct item *item)
{
    if (item->type == ITEM_LEFT_META)
        return parser_meta;
    if (item->type == ITEM_TEXT) {
        if (item->value.len == 1) {
            emit_chunk(parser, TPL_ACTION_APPEND_CHAR, 0, (void *)(uintptr_t)*item->value.value);
        } else {
            strbuf_t *buf = strbuf_new_with_size(item->value.len);
            if (!buf)
                return error_item(item, "Out of memory");
            strbuf_set(buf, item->value.value, item->value.len);
            emit_chunk(parser, TPL_ACTION_APPEND, 0, buf);
        }
        parser->tpl->minimum_size += item->value.len;
        return parser_text;
    }
    if (item->type == ITEM_EOF) {
        emit_chunk(parser, TPL_ACTION_LAST, 0, NULL);
        return NULL;
    }

    return unexpected_lexeme(item);
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
    const char *str = *(char **)ptr;

    if (LIKELY(str))
        strbuf_append_str(buf, str, 0);
}

void
lwan_append_str_escaped_to_strbuf(strbuf_t *buf, void *ptr)
{
    if (UNLIKELY(!ptr))
        return;

    const char *str = *(char **)ptr;
    if (UNLIKELY(!str))
        return;

    for (const char *p = str; *p; p++) {
        if (*p == '<')
            strbuf_append_str(buf, "&lt;", 4);
        else if (*p == '>')
            strbuf_append_str(buf, "&gt;", 4);
        else if (*p == '&')
            strbuf_append_str(buf, "&amp;", 5);
        else if (*p == '"')
            strbuf_append_str(buf, "&quot;", 6);
        else if (*p == '\'')
            strbuf_append_str(buf, "&#x27;", 6);
        else if (*p == '/')
            strbuf_append_str(buf, "&#x2f;", 6);
        else
            strbuf_append_char(buf, *p);
    }
}

bool
lwan_tpl_str_is_empty(void *ptr)
{
    if (UNLIKELY(!ptr))
        return true;

    const char *str = *(char **)ptr;
    return LIKELY(str) && *str;
}

static void
free_chunk(struct chunk *chunk)
{
    if (!chunk)
        return;

    switch (chunk->action) {
    case TPL_ACTION_LAST:
    case TPL_ACTION_APPEND_CHAR:
    case TPL_ACTION_VARIABLE:
    case TPL_ACTION_VARIABLE_STR:
    case TPL_ACTION_VARIABLE_STR_ESCAPE:
    case TPL_ACTION_END_IF_VARIABLE_NOT_EMPTY:
    case TPL_ACTION_END_ITER:
        /* do nothing */
        break;
    case TPL_ACTION_IF_VARIABLE_NOT_EMPTY:
    case TPL_ACTION_START_ITER:
        free(chunk->data);
        break;
    case TPL_ACTION_APPEND:
        strbuf_free(chunk->data);
        break;
    case TPL_ACTION_APPLY_TPL:
        lwan_tpl_free(chunk->data);
        break;
    }
}

void
lwan_tpl_free(lwan_tpl_t *tpl)
{
    size_t idx;
    if (!tpl)
        return;

    for (idx = 0; idx < tpl->chunks.used; idx++)
        free_chunk(&tpl->chunks.data[idx]);
    free(tpl->chunks.data);
    free(tpl);
}

static bool
post_process_template(lwan_tpl_t *tpl)
{
    size_t idx;
    struct chunk *prev_chunk, *resized;

    for (idx = 0; idx < tpl->chunks.used; idx++) {
        struct chunk *chunk = &tpl->chunks.data[idx];

        if (chunk->action == TPL_ACTION_IF_VARIABLE_NOT_EMPTY) {
            for (prev_chunk = chunk; ; chunk++) {
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

            chunk = prev_chunk + 1;
        } else if (chunk->action == TPL_ACTION_START_ITER) {
            enum flags flags = chunk->flags;

            for (prev_chunk = chunk; ; chunk++) {
                if (chunk->action == TPL_ACTION_LAST)
                    break;
                if (chunk->action == TPL_ACTION_END_ITER && chunk->data == prev_chunk) {
                    chunk->flags |= flags;
                    break;
                }
            }

            struct chunk_descriptor *cd = malloc(sizeof(*cd));
            if (!cd)
                lwan_status_critical_perror("malloc");

            cd->descriptor = prev_chunk->data;
            prev_chunk->data = cd;

            if (!chunk || chunk->action == TPL_ACTION_LAST)
                cd->chunk = chunk;
            else
                cd->chunk = chunk + 1;

            chunk = prev_chunk + 1;
        } else if (chunk->action == TPL_ACTION_VARIABLE) {
            lwan_var_descriptor_t *descriptor = chunk->data;
            bool escape = chunk->flags & FLAGS_QUOTE;

            if (descriptor->append_to_strbuf == lwan_append_str_to_strbuf) {
                if (escape)
                    chunk->action = TPL_ACTION_VARIABLE_STR_ESCAPE;
                else
                    chunk->action = TPL_ACTION_VARIABLE_STR;
                chunk->data = (void *)descriptor->offset;
            } else if (escape) {
                lwan_status_error("Variable must be string to be escaped");
                return false;
            } else if (!descriptor->append_to_strbuf) {
                lwan_status_error("Invalid variable descriptor");
                return false;
            }
        } else if (chunk->action == TPL_ACTION_LAST) {
            break;
        }
    }

    lwan_status_debug("Template parsing done, reallocating array from %zu to %zu elements",
        tpl->chunks.reserved, tpl->chunks.used);
    resized = reallocarray(tpl->chunks.data, tpl->chunks.used, sizeof(struct chunk));
    if (resized)
        tpl->chunks.data = resized;

    return true;
}

static bool parse_string(lwan_tpl_t *tpl, const char *string, const lwan_var_descriptor_t *descriptor)
{
    struct parser parser = { .tpl = tpl, .symtab = NULL };
    void *(*state)(struct parser *parser, struct item *item) = parser_text;
    struct item *item = NULL;
    bool success = true;

    if (!symtab_push(&parser, descriptor))
        return false;

    lex_init(&parser.lexer, string);
    list_head_init(&parser.stack);

    while (state && lex_next(&parser.lexer, &item))
        state = state(&parser, item);

    if (!state && item->type == ITEM_ERROR && item->value.value) {
        lwan_status_error("Parser error: %.*s", (int)item->value.len, item->value.value);
        free((char *)item->value.value);

        success = false;
    }

    if (!list_empty(&parser.stack)) {
        struct stacked_item *stacked, *stacked_next;

        list_for_each_safe(&parser.stack, stacked, stacked_next, stack) {
            lwan_status_error("Parser error: EOF while looking for matching {{/%.*s}}",
                (int)stacked->item.value.len, stacked->item.value.value);
            list_del(&stacked->stack);
            free(stacked);
        }

        success = false;
    }

    symtab_pop(&parser);
    if (parser.symtab) {
        lwan_status_error("Parser error: Symbol table not empty when finishing parser");

        while (parser.symtab)
            symtab_pop(&parser);

        success = false;
    }

    return success;
}

lwan_tpl_t *
lwan_tpl_compile_string(const char *string, const lwan_var_descriptor_t *descriptor)
{
    lwan_tpl_t *tpl;

    tpl = calloc(1, sizeof(*tpl));
    if (!tpl)
        return NULL;

    tpl->chunks.used = 0;
    tpl->chunks.reserved = array_increment_step;
    tpl->chunks.data = reallocarray(NULL, tpl->chunks.reserved, sizeof(struct chunk));
    if (!tpl->chunks.data) {
        free(tpl);
        return NULL;
    }

    if (parse_string(tpl, string, descriptor)) {
        if (post_process_template(tpl))
            return tpl;
    }

    lwan_tpl_free(tpl);
    return NULL;
}

lwan_tpl_t *
lwan_tpl_compile_file(const char *filename, const lwan_var_descriptor_t *descriptor)
{
    int fd;
    struct stat st;
    char *mapped;
    lwan_tpl_t *tpl = NULL;

    fd = open(filename, O_RDONLY | O_CLOEXEC);
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

static struct chunk *
apply_until(lwan_tpl_t *tpl, struct chunk *chunks, strbuf_t *buf, void *variables,
            void *until_data)
{
    static const void *const dispatch_table[] = {
        [TPL_ACTION_APPEND] = &&action_append,
        [TPL_ACTION_APPEND_CHAR] = &&action_append_char,
        [TPL_ACTION_VARIABLE] = &&action_variable,
        [TPL_ACTION_VARIABLE_STR] = &&action_variable_str,
        [TPL_ACTION_VARIABLE_STR_ESCAPE] = &&action_variable_str_escape,
        [TPL_ACTION_IF_VARIABLE_NOT_EMPTY] = &&action_if_variable_not_empty,
        [TPL_ACTION_END_IF_VARIABLE_NOT_EMPTY] = &&action_end_if_variable_not_empty,
        [TPL_ACTION_APPLY_TPL] = &&action_apply_tpl,
        [TPL_ACTION_START_ITER] = &&action_start_iter,
        [TPL_ACTION_END_ITER] = &&action_end_iter,
        [TPL_ACTION_LAST] = &&finalize
    };
    coro_switcher_t switcher;
    coro_t *coro = NULL;
    struct chunk *chunk = chunks;

    if (UNLIKELY(!chunk))
        return NULL;

#define DISPATCH()	do { goto *dispatch_table[chunk->action]; } while(false)
#define NEXT_ACTION()	do { chunk++; DISPATCH(); } while(false)

    DISPATCH();

action_append:
    strbuf_append_str(buf, strbuf_get_buffer(chunk->data),
                strbuf_get_length(chunk->data));
    NEXT_ACTION();

action_append_char:
    strbuf_append_char(buf, (char)(uintptr_t)chunk->data);
    NEXT_ACTION();

action_variable: {
        lwan_var_descriptor_t *descriptor = chunk->data;
        descriptor->append_to_strbuf(buf, (char *)variables + descriptor->offset);
        NEXT_ACTION();
    }

action_variable_str:
    lwan_append_str_to_strbuf(buf, (char *)variables + (uintptr_t)chunk->data);
    NEXT_ACTION();

action_variable_str_escape:
    lwan_append_str_escaped_to_strbuf(buf, (char *)variables + (uintptr_t)chunk->data);
    NEXT_ACTION();

action_if_variable_not_empty: {
        struct chunk_descriptor *cd = chunk->data;
        bool empty = cd->descriptor->get_is_empty((char *)variables + cd->descriptor->offset);
        if (chunk->flags & FLAGS_NEGATE)
            empty = !empty;
        if (empty) {
            chunk = cd->chunk;
        } else {
            chunk = apply_until(tpl, chunk + 1, buf, variables, cd->chunk);
        }
        NEXT_ACTION();
    }

action_end_if_variable_not_empty:
    if (LIKELY(until_data == chunk))
        goto finalize;
    NEXT_ACTION();

action_apply_tpl: {
        strbuf_t *tmp = lwan_tpl_apply(chunk->data, variables);
        strbuf_append_str(buf, strbuf_get_buffer(tmp), strbuf_get_length(tmp));
        strbuf_free(tmp);
        NEXT_ACTION();
    }

action_start_iter:
    if (UNLIKELY(coro != NULL)) {
        lwan_status_warning("Coroutine is not NULL when starting iteration");
        NEXT_ACTION();
    }

    struct chunk_descriptor *cd = chunk->data;
    coro = coro_new(&switcher, cd->descriptor->generator, variables);

    bool resumed = coro_resume_value(coro, 0);
    enum flags negate = chunk->flags & FLAGS_NEGATE;
    if (negate)
        resumed = !resumed;
    if (!resumed) {
        chunk = cd->chunk;

        if (negate)
            coro_resume_value(coro, 1);

        coro_free(coro);
        coro = NULL;

        if (negate)
            DISPATCH();
        NEXT_ACTION();
    }

    chunk = apply_until(tpl, chunk + 1, buf, variables, chunk);
    DISPATCH();

action_end_iter:
    if (until_data == chunk->data)
        goto finalize;

    if (UNLIKELY(!coro)) {
        if (!chunk->flags)
            lwan_status_warning("Coroutine is NULL when finishing iteration");
        NEXT_ACTION();
    }

    if (!coro_resume_value(coro, 0)) {
        coro_free(coro);
        coro = NULL;
        NEXT_ACTION();
    }

    chunk = apply_until(tpl, ((struct chunk *)chunk->data) + 1, buf, variables, chunk->data);
    DISPATCH();

finalize:
    return chunk;
#undef DISPATCH
#undef NEXT_ACTION
}

strbuf_t *
lwan_tpl_apply_with_buffer(lwan_tpl_t *tpl, strbuf_t *buf, void *variables)
{
    if (UNLIKELY(!strbuf_reset_length(buf)))
        return NULL;

    if (UNLIKELY(!strbuf_grow_to(buf, tpl->minimum_size)))
        return NULL;

    apply_until(tpl, tpl->chunks.data, buf, variables, NULL);

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
        strbuf_t *applied = lwan_tpl_apply(tpl, &(struct test_struct) {
            .some_int = 42,
            .a_string = "some string"
        });
        strbuf_free(applied);
    }

    lwan_tpl_free(tpl);
    return 0;
}

#endif /* TEMPLATE_TEST */
