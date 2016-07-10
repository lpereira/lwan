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

#include "lwan-private.h"

#include "hash.h"
#include "int-to-str.h"
#include "list.h"
#include "lwan-template.h"
#include "strbuf.h"
#include "reallocarray.h"

enum action {
    ACTION_APPEND,
    ACTION_APPEND_CHAR,
    ACTION_VARIABLE,
    ACTION_VARIABLE_STR,
    ACTION_VARIABLE_STR_ESCAPE,
    ACTION_START_ITER,
    ACTION_END_ITER,
    ACTION_IF_VARIABLE_NOT_EMPTY,
    ACTION_END_IF_VARIABLE_NOT_EMPTY,
    ACTION_APPLY_TPL,
    ACTION_LAST
};

enum flags {
    FLAGS_ALL = -1,
    FLAGS_NEGATE = 1<<0,
    FLAGS_QUOTE = 1<<1,
    FLAGS_NO_FREE = 1<<2,
};

enum lexeme_type {
    LEXEME_ERROR,
    LEXEME_EOF,
    LEXEME_IDENTIFIER,
    LEXEME_LEFT_META,
    LEXEME_HASH,
    LEXEME_RIGHT_META,
    LEXEME_TEXT,
    LEXEME_SLASH,
    LEXEME_QUESTION_MARK,
    LEXEME_HAT,
    LEXEME_GREATER_THAN,
    LEXEME_OPEN_CURLY_BRACE,
    LEXEME_CLOSE_CURLY_BRACE,
    TOTAL_LEXEMES
};

static const char *lexeme_type_str[TOTAL_LEXEMES] = {
    [LEXEME_ERROR] = "ERROR",
    [LEXEME_EOF] = "EOF",
    [LEXEME_IDENTIFIER] = "IDENTIFIER",
    [LEXEME_LEFT_META] = "LEFT_META",
    [LEXEME_HASH] = "HASH",
    [LEXEME_RIGHT_META] = "RIGHT_META",
    [LEXEME_TEXT] = "TEXT",
    [LEXEME_SLASH] = "SLASH",
    [LEXEME_QUESTION_MARK] = "QUESTION_MARK",
    [LEXEME_HAT] = "HAT",
    [LEXEME_GREATER_THAN] = "GREATER_THAN",
    [LEXEME_OPEN_CURLY_BRACE] = "LEXEME_OPEN_CURLY_BRACE",
    [LEXEME_CLOSE_CURLY_BRACE] = "LEXEME_CLOSE_CURLY_BRACE"
};

struct chunk {
    enum action action;
    void *data;
    enum flags flags;
};

struct lwan_tpl_t_ {
    struct chunk *chunks;
    size_t minimum_size;
};

struct symtab {
    struct hash *hash;
    struct symtab *next;
};

struct lexeme {
    enum lexeme_type type;
    struct {
        const char *value;
        size_t len;
    } value;
};

struct lexer {
    void *(*state)(struct lexer *);
    const char *start, *pos, *end;

    struct {
        struct lexeme lexemes[4];
        size_t first;
        size_t last;
        size_t population;
    } ring_buffer;
};

struct parser {
    lwan_tpl_t *tpl;
    const lwan_var_descriptor_t *descriptor;
    struct symtab *symtab;
    struct lexer lexer;
    enum flags flags;
    struct list_head stack;
    struct {
        struct chunk *data;
        size_t used, reserved;
    } chunks;
    lwan_tpl_flag_t template_flags;
};

struct stacked_lexeme {
    struct list_node stack;
    struct lexeme lexeme;
};

struct chunk_descriptor {
    struct chunk *chunk;
    lwan_var_descriptor_t *descriptor;
};

static const size_t array_increment_step = 16;

static const char left_meta[] = "{{";
static const char right_meta[] = "}}";
static_assert(sizeof(left_meta) == sizeof(right_meta),
    "right_meta and left_meta are the same length");

static void *lex_inside_action(struct lexer *lexer);
static void *lex_identifier(struct lexer *lexer);
static void *lex_left_meta(struct lexer *lexer);
static void *lex_right_meta(struct lexer *lexer);
static void *lex_text(struct lexer *lexer);

static void *parser_meta(struct parser *parser, struct lexeme *lexeme);
static void *parser_text(struct parser *parser, struct lexeme *lexeme);
static void *parser_iter(struct parser *parser, struct lexeme *lexeme);
static void *parser_slash(struct parser *parser, struct lexeme *lexeme);
static void *parser_end_iter(struct parser *parser, struct lexeme *lexeme);
static void *parser_end_var_not_empty(struct parser *parser, struct lexeme *lexeme);
static void *parser_slash(struct parser *parser, struct lexeme *lexeme);
static void *parser_iter(struct parser *parser, struct lexeme *lexeme);
static void *parser_negate_iter(struct parser *parser, struct lexeme *lexeme);
static void *parser_meta(struct parser *parser, struct lexeme *lexeme);
static void *parser_text(struct parser *parser, struct lexeme *lexeme);

static void error_vlexeme(struct lexeme *lexeme, const char *msg, va_list ap)
    __attribute__((format(printf, 2, 0)));
static void *error_lexeme(struct lexeme *lexeme, const char *msg, ...)
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

static int
symtab_push(struct parser *parser, const lwan_var_descriptor_t *descriptor)
{
    struct symtab *tab;
    int r;

    if (!descriptor)
        return -ENODEV;

    tab = malloc(sizeof(*tab));
    if (!tab)
        return -errno;

    tab->hash = hash_str_new(NULL, NULL);
    if (!tab->hash) {
        r = -ENOMEM;
        goto hash_new_err;
    }

    tab->next = parser->symtab;
    parser->symtab = tab;

    for (; descriptor->name; descriptor++) {
        r = hash_add(parser->symtab->hash, descriptor->name, descriptor);

        if (r < 0)
            goto hash_add_err;
    }

    return 0;

hash_add_err:
    hash_free(tab->hash);
hash_new_err:
    free(tab);

    return r;
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

static void emit_lexeme(struct lexer *lexer, struct lexeme *lexeme)
{
    assert(lexer->ring_buffer.population < N_ELEMENTS(lexer->ring_buffer.lexemes));

    lexer->ring_buffer.lexemes[lexer->ring_buffer.last] = *lexeme;
    lexer->ring_buffer.last = (lexer->ring_buffer.last + 1) % N_ELEMENTS(lexer->ring_buffer.lexemes);
    lexer->ring_buffer.population++;

    lexer->start = lexer->pos;
}

static bool consume_lexeme(struct lexer *lexer, struct lexeme **lexeme)
{
    if (!lexer->ring_buffer.population)
        return false;

    *lexeme = &lexer->ring_buffer.lexemes[lexer->ring_buffer.first];
    lexer->ring_buffer.first = (lexer->ring_buffer.first + 1) % N_ELEMENTS(lexer->ring_buffer.lexemes);
    lexer->ring_buffer.population--;

    return true;
}

static void emit(struct lexer *lexer, enum lexeme_type lexeme_type)
{
    struct lexeme lexeme = {
        .type = lexeme_type,
        .value = {
            .value = lexer->start,
            .len = (size_t)(lexer->pos - lexer->start)
        }
    };
    emit_lexeme(lexer, &lexeme);
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

static void error_vlexeme(struct lexeme *lexeme, const char *msg, va_list ap)
{
    int r;

    lexeme->type = LEXEME_ERROR;

    r = vasprintf((char **)&lexeme->value.value, msg, ap);
    if (r < 0) {
        lexeme->value.value = strdup(strerror(errno));
        if (!lexeme->value.value)
            return;

        lexeme->value.len = strlen(lexeme->value.value);
    } else {
        lexeme->value.len = (size_t)r;
    }
}

static void *error_lexeme(struct lexeme *lexeme, const char *msg, ...)
{
    va_list ap;

    va_start(ap, msg);
    error_vlexeme(lexeme, msg, ap);
    va_end(ap);

    return NULL;
}

static void *lex_error(struct lexer *lexer, const char *msg, ...)
{
    struct lexeme lexeme;
    va_list ap;

    va_start(ap, msg);
    error_vlexeme(&lexeme, msg, ap);
    va_end(ap);

    emit_lexeme(lexer, &lexeme);
    return NULL;
}

static bool isident(int ch)
{
    return isalnum(ch) || ch == '_' || ch == '.' || ch == '/';
}

static void *lex_identifier(struct lexer *lexer)
{
    while (isident(next(lexer)))
        ;
    backup(lexer);
    emit(lexer, LEXEME_IDENTIFIER);
    return lex_inside_action;
}

static void *lex_partial(struct lexer *lexer)
{
    while (true) {
        int r = next(lexer);

        if (r == EOF)
            return lex_error(lexer, "unexpected EOF while scanning action");
        if (r == '\n')
            return lex_error(lexer, "actions cannot span multiple lines");
        if (isspace(r)) {
            ignore(lexer);
            continue;
        }
        if (isident(r)) {
            backup(lexer);
            return lex_identifier;
        }
        return lex_error(lexer, "unexpected character: %c", r);
    }
}

static void *lex_quoted_identifier(struct lexer *lexer)
{
    int r;

    emit(lexer, LEXEME_OPEN_CURLY_BRACE);
    lex_identifier(lexer);

    r = next(lexer);
    if (r != '}')
        return lex_error(lexer, "expecting `}', found `%c'", r);

    emit(lexer, LEXEME_CLOSE_CURLY_BRACE);
    return lex_inside_action;
}

static void *lex_comment(struct lexer *lexer)
{
    size_t brackets = strlen(left_meta);

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
            emit(lexer, LEXEME_HASH);
        } else if (r == '?') {
            emit(lexer, LEXEME_QUESTION_MARK);
        } else if (r == '^') {
            emit(lexer, LEXEME_HAT);
        } else if (r == '>') {
            emit(lexer, LEXEME_GREATER_THAN);
            return lex_partial;
        } else if (r == '{') {
            return lex_quoted_identifier;
        } else if (r == '/') {
            emit(lexer, LEXEME_SLASH);
        } else if (isident(r)) {
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

    emit(lexer, LEXEME_LEFT_META);
    return lex_inside_action;
}

static void *lex_right_meta(struct lexer *lexer)
{
    lexer->pos += strlen(right_meta);
    emit(lexer, LEXEME_RIGHT_META);
    return lex_text;
}

static void *lex_text(struct lexer *lexer)
{
    do {
        if (!strncmp(lexer->pos, left_meta, strlen(left_meta))) {
            if (lexer->pos > lexer->start)
                emit(lexer, LEXEME_TEXT);
            return lex_left_meta;
        }
        if (!strncmp(lexer->pos, right_meta, strlen(right_meta)))
            return lex_error(lexer, "unexpected action close sequence");
    } while (next(lexer) != EOF);
    if (lexer->pos > lexer->start)
        emit(lexer, LEXEME_TEXT);
    emit(lexer, LEXEME_EOF);
    return NULL;
}

static bool lex_next(struct lexer *lexer, struct lexeme **lexeme)
{
    while (lexer->state) {
        if (consume_lexeme(lexer, lexeme))
            return true;
        lexer->state = lexer->state(lexer);
    }

    return consume_lexeme(lexer, lexeme);
}

static void lex_init(struct lexer *lexer, const char *input)
{
    lexer->state = lex_text;
    lexer->pos = lexer->start = input;
    lexer->end = rawmemchr(input, '\0');
}

static void *unexpected_lexeme(struct lexeme *lexeme)
{
    return error_lexeme(lexeme, "unexpected lexeme: %s [%.*s]",
        lexeme_type_str[lexeme->type], (int)lexeme->value.len, lexeme->value.value);
}

static void *unexpected_lexeme_or_lex_error(struct lexeme *lexeme, struct lexeme *lex_error)
{
    if (lex_error && (lex_error->type == LEXEME_ERROR || lex_error->type == LEXEME_EOF)) {
        *lexeme = *lex_error;
        return NULL;
    }

    return unexpected_lexeme(lexeme);
}

static void parser_push_lexeme(struct parser *parser, struct lexeme *lexeme)
{
    struct stacked_lexeme *stacked_lexeme = malloc(sizeof(*stacked_lexeme));
    if (!stacked_lexeme)
        lwan_status_critical_perror("Could not push parser lexeme");

    stacked_lexeme->lexeme = *lexeme;
    list_add(&parser->stack, &stacked_lexeme->stack);
}

static void emit_chunk(struct parser *parser, enum action action,
        enum flags flags, void *data)
{
    struct chunk *chunk;

    if (parser->chunks.used >= parser->chunks.reserved) {
        parser->chunks.reserved += array_increment_step;

        chunk = reallocarray(parser->chunks.data,
            parser->chunks.reserved, sizeof(struct chunk));
        if (!chunk)
            lwan_status_critical_perror("Could not emit template chunk");

        parser->tpl->chunks = parser->chunks.data = chunk;
    }

    chunk = &parser->chunks.data[parser->chunks.used++];
    chunk->action = action;
    chunk->flags = flags;
    chunk->data = data;
}

static bool parser_stack_top_matches(struct parser *parser, struct lexeme *lexeme, enum lexeme_type type)
{
    if (list_empty(&parser->stack)) {
        error_lexeme(lexeme, "unexpected {{/%.*s}}", (int)lexeme->value.len, lexeme->value.value);
        return false;
    }

    struct stacked_lexeme *stacked_lexeme = (struct stacked_lexeme *)parser->stack.n.next;
    bool matches = (stacked_lexeme->lexeme.type == type
            && lexeme->value.len == stacked_lexeme->lexeme.value.len
            && !memcmp(stacked_lexeme->lexeme.value.value, lexeme->value.value, lexeme->value.len));
    if (matches) {
        list_del(&stacked_lexeme->stack);
        free(stacked_lexeme);
        return true;
    }

    error_lexeme(lexeme, "expecting %s `%.*s' but found `%.*s'",
        lexeme_type_str[stacked_lexeme->lexeme.type],
        (int)stacked_lexeme->lexeme.value.len, stacked_lexeme->lexeme.value.value,
        (int)lexeme->value.len, lexeme->value.value);
    return false;
}

static void *parser_right_meta(struct parser *parser __attribute__((unused)),
    struct lexeme *lexeme)
{
    if (lexeme->type != LEXEME_RIGHT_META)
        return unexpected_lexeme(lexeme);
    return parser_text;
}

static void *parser_end_iter(struct parser *parser, struct lexeme *lexeme)
{
    struct chunk *iter;
    lwan_var_descriptor_t *symbol;
    ssize_t idx;

    if (!parser_stack_top_matches(parser, lexeme, LEXEME_IDENTIFIER))
        return NULL;

    symbol = symtab_lookup(parser, strndupa(lexeme->value.value, lexeme->value.len));
    if (!symbol) {
        return error_lexeme(lexeme, "Unknown variable: %.*s", (int)lexeme->value.len,
            lexeme->value.value);
    }

    if (!parser->chunks.used)
        return error_lexeme(lexeme, "No chunks were emitted but parsing end iter");
    for (idx = (ssize_t)parser->chunks.used - 1; idx >= 0; idx--) {
        iter = &parser->chunks.data[idx];

        if (iter->action != ACTION_START_ITER)
            continue;
        if (iter->data == symbol) {
            emit_chunk(parser, ACTION_END_ITER, 0, (void *)(ptrdiff_t)idx);
            symtab_pop(parser);
            return parser_text;
        }
    }

    return error_lexeme(lexeme, "Could not find {{#%.*s}}", (int)lexeme->value.len, lexeme->value.value);
}

static void *parser_end_var_not_empty(struct parser *parser, struct lexeme *lexeme)
{
    struct chunk *iter;
    lwan_var_descriptor_t *symbol;
    ssize_t idx;

    if (!parser_stack_top_matches(parser, lexeme, LEXEME_IDENTIFIER))
        return NULL;

    symbol = symtab_lookup(parser, strndupa(lexeme->value.value, lexeme->value.len));
    if (!symbol) {
        return error_lexeme(lexeme, "Unknown variable: %.*s", (int)lexeme->value.len,
            lexeme->value.value);
    }

    for (idx = (ssize_t)parser->chunks.used - 1; idx >= 0; idx--) {
        iter = &parser->chunks.data[idx];
        if (iter->action != ACTION_IF_VARIABLE_NOT_EMPTY)
            continue;
        if (iter->data == symbol) {
            emit_chunk(parser, ACTION_END_IF_VARIABLE_NOT_EMPTY, 0, symbol);
            return parser_right_meta;
        }
    }

    return error_lexeme(lexeme, "Could not find {{%.*s?}}", (int)lexeme->value.len, lexeme->value.value);
}

static void *parser_slash(struct parser *parser, struct lexeme *lexeme)
{
    if (lexeme->type == LEXEME_IDENTIFIER) {
        struct lexeme *next = NULL;

        if (!lex_next(&parser->lexer, &next))
            return unexpected_lexeme_or_lex_error(lexeme, next);

        if (next->type == LEXEME_RIGHT_META)
            return parser_end_iter(parser, lexeme);

        if (next->type == LEXEME_QUESTION_MARK)
            return parser_end_var_not_empty(parser, lexeme);

        return unexpected_lexeme_or_lex_error(lexeme, next);
    }

    return unexpected_lexeme(lexeme);
}

static void *parser_iter(struct parser *parser, struct lexeme *lexeme)
{
    if (lexeme->type == LEXEME_IDENTIFIER) {
        enum flags negate = parser->flags & FLAGS_NEGATE;
        const char *symname = strndupa(lexeme->value.value, lexeme->value.len);
        lwan_var_descriptor_t *symbol = symtab_lookup(parser, symname);
        if (!symbol) {
            return error_lexeme(lexeme, "Unknown variable: %.*s", (int)lexeme->value.len,
                lexeme->value.value);
        }

        int r = symtab_push(parser, symbol->list_desc);
        if (r < 0) {
            if (r == -ENODEV)
                return error_lexeme(lexeme, "Couldn't find descriptor for variable `%s'", symname);
            return error_lexeme(lexeme, "Could not push symbol table (out of memory)");
        }

        emit_chunk(parser, ACTION_START_ITER, negate | FLAGS_NO_FREE, symbol);

        parser_push_lexeme(parser, lexeme);
        parser->flags &= ~FLAGS_NEGATE;
        return parser_right_meta;
    }

    return unexpected_lexeme(lexeme);
}

static void *parser_negate_iter(struct parser *parser, struct lexeme *lexeme)
{
    if (lexeme->type != LEXEME_HASH)
        return unexpected_lexeme(lexeme);

    parser->flags ^= FLAGS_NEGATE;
    return parser_iter;
}

static void *parser_identifier(struct parser *parser, struct lexeme *lexeme)
{
    struct lexeme *next = NULL;

    if (!lex_next(&parser->lexer, &next)) {
        if (next)
            *lexeme = *next;
        return NULL;
    }

    if (parser->flags & FLAGS_QUOTE) {
        if (next->type != LEXEME_CLOSE_CURLY_BRACE)
            return error_lexeme(lexeme, "Expecting closing brace");
        if (!lex_next(&parser->lexer, &next))
            return unexpected_lexeme_or_lex_error(lexeme, next);
    }

    if (next->type == LEXEME_RIGHT_META) {
        lwan_var_descriptor_t *symbol = symtab_lookup(parser, strndupa(lexeme->value.value, lexeme->value.len));
        if (!symbol) {
            return error_lexeme(lexeme, "Unknown variable: %.*s", (int)lexeme->value.len,
                lexeme->value.value);
        }

        emit_chunk(parser, ACTION_VARIABLE, parser->flags, symbol);

        parser->flags &= ~FLAGS_QUOTE;
        parser->tpl->minimum_size += lexeme->value.len + 1;
        return parser_text;
    }

    if (next->type == LEXEME_QUESTION_MARK) {
        lwan_var_descriptor_t *symbol = symtab_lookup(parser, strndupa(lexeme->value.value, lexeme->value.len));
        if (!symbol) {
            return error_lexeme(lexeme, "Unknown variable: %.*s", (int)lexeme->value.len,
                lexeme->value.value);
        }

        emit_chunk(parser, ACTION_IF_VARIABLE_NOT_EMPTY, FLAGS_NO_FREE, symbol);
        parser_push_lexeme(parser, lexeme);

        return parser_right_meta;
    }

    return unexpected_lexeme_or_lex_error(lexeme, next);
}

static void *parser_partial(struct parser *parser, struct lexeme *lexeme)
{
    lwan_tpl_t *tpl;
    char *filename = strndupa(lexeme->value.value, lexeme->value.len);

    if (lexeme->type != LEXEME_IDENTIFIER)
        return unexpected_lexeme(lexeme);

    tpl = lwan_tpl_compile_file(filename, parser->descriptor);
    if (tpl) {
        emit_chunk(parser, ACTION_APPLY_TPL, 0, tpl);
        return parser_right_meta;
    }

    return error_lexeme(lexeme, "Could not compile template ``%s''", filename);
}

static void *parser_meta(struct parser *parser, struct lexeme *lexeme)
{
    if (lexeme->type == LEXEME_OPEN_CURLY_BRACE) {
        if (parser->flags & FLAGS_QUOTE)
            return unexpected_lexeme(lexeme);

        parser->flags |= FLAGS_QUOTE;
        return parser_meta;
    }

    if (lexeme->type == LEXEME_IDENTIFIER)
        return parser_identifier(parser, lexeme);

    if (lexeme->type == LEXEME_GREATER_THAN)
        return parser_partial;

    if (lexeme->type == LEXEME_HASH)
        return parser_iter;

    if (lexeme->type == LEXEME_HAT)
        return parser_negate_iter;

    if (lexeme->type == LEXEME_SLASH)
        return parser_slash;

    return unexpected_lexeme(lexeme);
}

static strbuf_t *strbuf_from_lexeme(struct parser *parser, struct lexeme *lexeme)
{
    if (parser->template_flags & LWAN_TPL_FLAG_CONST_TEMPLATE)
        return strbuf_new_static(lexeme->value.value, lexeme->value.len);

    strbuf_t *buf = strbuf_new_with_size(lexeme->value.len);
    if (buf)
        strbuf_set(buf, lexeme->value.value, lexeme->value.len);

    return buf;
}

static void *parser_text(struct parser *parser, struct lexeme *lexeme)
{
    if (lexeme->type == LEXEME_LEFT_META)
        return parser_meta;

    if (lexeme->type == LEXEME_TEXT) {
        if (lexeme->value.len == 1) {
            emit_chunk(parser, ACTION_APPEND_CHAR, 0, (void *)(uintptr_t)*lexeme->value.value);
        } else {
            strbuf_t *buf = strbuf_from_lexeme(parser, lexeme);
            if (!buf)
                return error_lexeme(lexeme, "Out of memory");

            emit_chunk(parser, ACTION_APPEND, 0, buf);
        }
        parser->tpl->minimum_size += lexeme->value.len;
        return parser_text;
    }

    if (lexeme->type == LEXEME_EOF) {
        emit_chunk(parser, ACTION_LAST, 0, NULL);
        return NULL;
    }

    return unexpected_lexeme(lexeme);
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

    const char *str = *(const char **)ptr;
    return !str || *str == '\0';
}

static void
free_chunk(struct chunk *chunk)
{
    if (!chunk)
        return;
    if (chunk->flags & FLAGS_NO_FREE)
        return;

    switch (chunk->action) {
    case ACTION_LAST:
    case ACTION_APPEND_CHAR:
    case ACTION_VARIABLE:
    case ACTION_VARIABLE_STR:
    case ACTION_VARIABLE_STR_ESCAPE:
    case ACTION_END_IF_VARIABLE_NOT_EMPTY:
    case ACTION_END_ITER:
        /* do nothing */
        break;
    case ACTION_IF_VARIABLE_NOT_EMPTY:
    case ACTION_START_ITER:
        free(chunk->data);
        break;
    case ACTION_APPEND:
        strbuf_free(chunk->data);
        break;
    case ACTION_APPLY_TPL:
        lwan_tpl_free(chunk->data);
        break;
    }
}

void
lwan_tpl_free(lwan_tpl_t *tpl)
{
    struct chunk *iter;

    if (!tpl)
        return;

    if (tpl->chunks) {
        for (iter = tpl->chunks; iter->action != ACTION_LAST; iter++)
            free_chunk(iter);
        free(tpl->chunks);
    }

    free(tpl);
}

static bool
post_process_template(struct parser *parser)
{
    size_t idx;
    struct chunk *prev_chunk;

#define CHUNK_IDX(c) (size_t)(ptrdiff_t)((c) - parser->chunks.data)

    for (idx = 0; idx < parser->chunks.used; idx++) {
        struct chunk *chunk = &parser->chunks.data[idx];

        if (chunk->action == ACTION_IF_VARIABLE_NOT_EMPTY) {
            for (prev_chunk = chunk; ; chunk++) {
                if (chunk->action == ACTION_LAST)
                    break;
                if (chunk->action == ACTION_END_IF_VARIABLE_NOT_EMPTY
                            && chunk->data == prev_chunk->data)
                    break;
            }

            struct chunk_descriptor *cd = malloc(sizeof(*cd));
            if (!cd)
                lwan_status_critical_perror("malloc");

            cd->descriptor = prev_chunk->data;
            cd->chunk = chunk;
            prev_chunk->data = cd;
            prev_chunk->flags &= ~FLAGS_NO_FREE;

            idx = CHUNK_IDX(prev_chunk) + 1;
        } else if (chunk->action == ACTION_START_ITER) {
            enum flags flags = chunk->flags;

            for (prev_chunk = chunk; ; chunk++) {
                if (chunk->action == ACTION_LAST)
                    break;
                if (chunk->action == ACTION_END_ITER) {
                    struct chunk *end_iter_data = parser->chunks.data + (ptrdiff_t)chunk->data;

                    if (end_iter_data == prev_chunk) {
                        chunk->data = end_iter_data;
                        chunk->flags |= flags;
                        break;
                    }
                }
            }

            struct chunk_descriptor *cd = malloc(sizeof(*cd));
            if (!cd)
                lwan_status_critical_perror("malloc");

            cd->descriptor = prev_chunk->data;
            prev_chunk->data = cd;
            prev_chunk->flags &= ~FLAGS_NO_FREE;

            if (chunk->action == ACTION_LAST)
                cd->chunk = chunk;
            else
                cd->chunk = chunk + 1;

            idx = CHUNK_IDX(prev_chunk) + 1;
        } else if (chunk->action == ACTION_VARIABLE) {
            lwan_var_descriptor_t *descriptor = chunk->data;
            bool escape = chunk->flags & FLAGS_QUOTE;

            if (descriptor->append_to_strbuf == lwan_append_str_to_strbuf) {
                if (escape)
                    chunk->action = ACTION_VARIABLE_STR_ESCAPE;
                else
                    chunk->action = ACTION_VARIABLE_STR;
                chunk->data = (void *)(uintptr_t)descriptor->offset;
            } else if (escape) {
                lwan_status_error("Variable must be string to be escaped");
                return false;
            } else if (!descriptor->append_to_strbuf) {
                lwan_status_error("Invalid variable descriptor");
                return false;
            }
        } else if (chunk->action == ACTION_LAST) {
            break;
        }
    }

    parser->tpl->chunks = parser->chunks.data;

    return true;

#undef CHUNK_IDX
}

static bool parser_init(struct parser *parser, const lwan_var_descriptor_t *descriptor,
    const char *string)
{
    struct chunk *chunks;

    if (symtab_push(parser, descriptor) < 0)
        return false;

    chunks = reallocarray(NULL, parser->chunks.reserved, sizeof(struct chunk));
    parser->tpl->chunks = parser->chunks.data = chunks;
    if (!chunks) {
        symtab_pop(parser);
        return false;
    }

    lex_init(&parser->lexer, string);
    list_head_init(&parser->stack);

    return true;
}

static bool parser_shutdown(struct parser *parser, struct lexeme *lexeme)
{
    bool success = true;

    if (lexeme->type == LEXEME_ERROR && lexeme->value.value) {
        lwan_status_error("Parser error: %.*s", (int)lexeme->value.len, lexeme->value.value);
        free((char *)lexeme->value.value);

        success = false;
    }

    if (!list_empty(&parser->stack)) {
        struct stacked_lexeme *stacked, *stacked_next;

        list_for_each_safe(&parser->stack, stacked, stacked_next, stack) {
            lwan_status_error("Parser error: EOF while looking for matching {{/%.*s}}",
                (int)stacked->lexeme.value.len, stacked->lexeme.value.value);
            list_del(&stacked->stack);
            free(stacked);
        }

        success = false;
    }

    symtab_pop(parser);
    if (parser->symtab) {
        lwan_status_error("Parser error: Symbol table not empty when finishing parser");

        while (parser->symtab)
            symtab_pop(parser);

        success = false;
    }

    if (parser->flags & FLAGS_NEGATE) {
        lwan_status_error("Parser error: unmatched negation");
        success = false;
    }
    if (parser->flags & FLAGS_QUOTE) {
        lwan_status_error("Parser error: unmatched quote");
        success = false;
    }

    if (success)
        success = post_process_template(parser);

    if (!success) {
        /* Emit a ACTION_LAST chunk so that lwan_tpl_free() knows when to stop */
        emit_chunk(parser, ACTION_LAST, 0, NULL);
    }

    return success;
}

static bool parse_string(lwan_tpl_t *tpl, const char *string, const lwan_var_descriptor_t *descriptor,
    lwan_tpl_flag_t flags)
{
    struct parser parser = {
        .tpl = tpl,
        .symtab = NULL,
        .chunks = { .used = 0, .reserved = array_increment_step },
        .descriptor = descriptor,
        .template_flags = flags
    };
    void *(*state)(struct parser *parser, struct lexeme *lexeme) = parser_text;
    struct lexeme *lexeme = NULL;

    if (!parser_init(&parser, descriptor, string))
        return false;

    while (state && lex_next(&parser.lexer, &lexeme) && lexeme->type != LEXEME_ERROR)
        state = state(&parser, lexeme);

    return parser_shutdown(&parser, lexeme);
}

lwan_tpl_t *
lwan_tpl_compile_string_full(const char *string, const lwan_var_descriptor_t *descriptor,
    lwan_tpl_flag_t flags)
{
    lwan_tpl_t *tpl;

    tpl = calloc(1, sizeof(*tpl));
    if (tpl) {
        if (parse_string(tpl, string, descriptor, flags))
            return tpl;
    }

    lwan_tpl_free(tpl);
    return NULL;
}

lwan_tpl_t *
lwan_tpl_compile_string(const char *string, const lwan_var_descriptor_t *descriptor)
{
    return lwan_tpl_compile_string_full(string, descriptor, 0);
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
        [ACTION_APPEND] = &&action_append,
        [ACTION_APPEND_CHAR] = &&action_append_char,
        [ACTION_VARIABLE] = &&action_variable,
        [ACTION_VARIABLE_STR] = &&action_variable_str,
        [ACTION_VARIABLE_STR_ESCAPE] = &&action_variable_str_escape,
        [ACTION_IF_VARIABLE_NOT_EMPTY] = &&action_if_variable_not_empty,
        [ACTION_END_IF_VARIABLE_NOT_EMPTY] = &&action_end_if_variable_not_empty,
        [ACTION_APPLY_TPL] = &&action_apply_tpl,
        [ACTION_START_ITER] = &&action_start_iter,
        [ACTION_END_ITER] = &&action_end_iter,
        [ACTION_LAST] = &&finalize
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

    apply_until(tpl, tpl->chunks, buf, variables, NULL);

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
