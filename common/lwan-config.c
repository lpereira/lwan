/*
 * lwan - simple web server
 * Copyright (c) 2017 Leandro A. F. Pereira <leandro@hardinfo.org>
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
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "lwan-status.h"
#include "lwan-config.h"
#include "strbuf.h"

enum lexeme_type {
    LEXEME_ERROR,
    LEXEME_STRING,
    LEXEME_EQUAL,
    LEXEME_OPEN_BRACKET,
    LEXEME_CLOSE_BRACKET,
    LEXEME_LINEFEED,
    LEXEME_VARIABLE,
    LEXEME_EOF,
    TOTAL_LEXEMES
};

static const char *lexeme_type_str[TOTAL_LEXEMES] = {
    [LEXEME_ERROR] = "ERROR",
    [LEXEME_STRING] = "STRING",
    [LEXEME_EQUAL] = "EQUAL",
    [LEXEME_OPEN_BRACKET] = "OPEN_BRACKET",
    [LEXEME_CLOSE_BRACKET] = "CLOSE_BRACKET",
    [LEXEME_LINEFEED] = "LINEFEED",
    [LEXEME_EOF] = "EOF",
    [LEXEME_VARIABLE] = "VARIABLE",
};

struct lexeme {
    enum lexeme_type type;
    struct {
        const char *value;
        size_t len;
    } value;
};

struct lexeme_ring_buffer {
    struct lexeme lexemes[16];
    size_t first, last, population;
};

struct config_ring_buffer {
    struct config_line items[16];
    size_t first, last, population;
};

struct lexer {
    void *(*state)(struct lexer *);
    const char *start, *pos, *end;
    struct lexeme_ring_buffer buffer;
    int cur_line;
};

struct parser {
    void *(*state)(struct parser *);
    struct lexer lexer;
    struct lexeme_ring_buffer buffer;
    struct config_ring_buffer items;
    struct strbuf strbuf;
};

struct config {
    struct parser parser;
    char *error_message;
    struct {
        void *addr;
        size_t sz;
    } mapped;
};

unsigned int parse_time_period(const char *str, unsigned int default_value)
{
    unsigned int total = 0;
    unsigned int period;
    char multiplier;

    if (!str)
        return default_value;

    while (*str && sscanf(str, "%u%c", &period, &multiplier) == 2) {
        switch (multiplier) {
        case 's': total += period; break;
        case 'm': total += period * ONE_MINUTE; break;
        case 'h': total += period * ONE_HOUR; break;
        case 'd': total += period * ONE_DAY; break;
        case 'w': total += period * ONE_WEEK; break;
        case 'M': total += period * ONE_MONTH; break;
        case 'y': total += period * ONE_YEAR; break;
        default:
            lwan_status_warning("Ignoring unknown multiplier: %c",
                        multiplier);
        }

        str = (const char *)rawmemchr(str, multiplier) + 1;
    }

    return total ? total : default_value;
}

long parse_long(const char *value, long default_value)
{
    char *endptr;
    long parsed;

    errno = 0;
    parsed = strtol(value, &endptr, 0);

    if (errno != 0)
        return default_value;

    if (*endptr != '\0' || value == endptr)
        return default_value;

    return parsed;
}

int parse_int(const char *value, int default_value)
{
    long long_value = parse_long(value, default_value);

    if ((long)(int)long_value != long_value)
        return default_value;

    return (int)long_value;
}

bool parse_bool(const char *value, bool default_value)
{
    if (!value)
        return default_value;

    if (streq(value, "true") || streq(value, "on") || streq(value, "yes"))
        return true;

    if (streq(value, "false") || streq(value, "off") || streq(value, "no"))
        return false;

    return parse_int(value, default_value);
}

bool config_error(struct config *conf, const char *fmt, ...)
{
    va_list values;
    int len;
    char *output;

    if (conf->error_message)
        return false;

    va_start(values, fmt);
    len = vasprintf(&output, fmt, values);
    va_end(values);

    if (len >= 0) {
        conf->error_message = output;
        return true;
    }

    conf->error_message = NULL;
    return false;
}

static bool config_buffer_consume(struct config_ring_buffer *buf,
    struct config_line **line)
{
    if (!buf->population)
        return false;

    *line = &buf->items[buf->first];
    buf->first = (buf->first + 1) % 16;
    buf->population--;

    return true;
}

static bool config_buffer_emit(struct config_ring_buffer *buf,
    struct config_line *line)
{
    if (buf->population == 16)
        return false;

    buf->items[buf->last] = *line;
    buf->last = (buf->last + 1) % 16;
    buf->population++;

    return true;
}

static bool lexeme_buffer_consume(struct lexeme_ring_buffer *buf,
    struct lexeme **lexeme)
{
    if (!buf->population)
        return false;

    *lexeme = &buf->lexemes[buf->first];
    buf->first = (buf->first + 1) % 16;
    buf->population--;

    return true;
}

static bool lexeme_buffer_emit(struct lexeme_ring_buffer *buf,
    struct lexeme *lexeme)
{
    if (buf->population == 16)
        return false;

    buf->lexemes[buf->last] = *lexeme;
    buf->last = (buf->last + 1) % 16;
    buf->population++;

    return true;
}

static void emit_lexeme(struct lexer *lexer, struct lexeme *lexeme)
{
    if (!lexeme_buffer_emit(&lexer->buffer, lexeme))
        return;

    lexer->start = lexer->pos;
}

static void emit(struct lexer *lexer, enum lexeme_type type)
{
    struct lexeme lexeme = {
        .type = type,
        .value = {
            .value = lexer->start,
            .len = (size_t)(lexer->pos - lexer->start)
        }
    };
    emit_lexeme(lexer, &lexeme);
}

static int next(struct lexer *lexer)
{
    if (lexer->pos >= lexer->end) {
        lexer->pos = lexer->end + 1;
        return '\0';
    }

    int r = *lexer->pos;
    lexer->pos++;

    if (r == '\n')
        lexer->cur_line++;

    return r;
}

static void ignore(struct lexer *lexer)
{
    lexer->start = lexer->pos;
}

static void backup(struct lexer *lexer)
{
    lexer->pos--;

    if (*lexer->pos == '\n')
        lexer->cur_line--;
}

static void *lex_config(struct lexer *lexer);

static bool isstring(int chr)
{
    return chr && !isspace(chr) && chr != '=' && chr != '#';
}

static void *lex_string(struct lexer *lexer)
{
    while (isstring(next(lexer)))
        ;
    backup(lexer);
    emit(lexer, LEXEME_STRING);
    return lex_config;
}

static bool isvariable(int chr)
{
    return isalpha(chr) || chr == '_';
}

static void *lex_variable(struct lexer *lexer)
{
    ignore(lexer);
    while (isvariable(next(lexer)))
        ;
    backup(lexer);
    emit(lexer, LEXEME_VARIABLE);
    return lex_config;
}

static void *lex_error(struct lexer *lexer, const char *msg)
{
    struct lexeme lexeme = {
        .type = LEXEME_ERROR,
        .value = {
            .value = msg,
            .len = strlen(msg)
        }
    };

    emit_lexeme(lexer, &lexeme);

    return NULL;
}

static void *lex_multiline_string(struct lexer *lexer)
{
    ignore(lexer);

    if (next(lexer) != '\'')
        return lex_error(lexer, "Expecting '");
    if (next(lexer) != '\'')
        return lex_error(lexer, "Expecting '");

    ignore(lexer);
    ignore(lexer);

    while (true) {
        if (!strncmp(lexer->pos, "'''", 3)) {
            emit(lexer, LEXEME_STRING);
            lexer->pos += 3;

            return lex_config;
        }

        int chr = next(lexer);
        if (chr == '\0')
            return lex_error(lexer, "EOF while scanning multiline string");
    }
}

static bool iscomment(int chr)
{
    if (chr == '\0')
        return false;
    if (chr == '\n')
        return false;
    return true;
}

static void *lex_comment(struct lexer *lexer)
{
    while (iscomment(next(lexer)))
        ;
    backup(lexer);
    return lex_config;
}

static bool isvalue(int chr)
{
    return chr != '\n' && !iscomment(chr);
}

static void *lex_equal(struct lexer *lexer)
{
    while (isvalue(next(lexer)))
        ;
    backup(lexer);
    return lex_config;
}

static void *lex_config(struct lexer *lexer)
{
    while (true) {
        int chr = next(lexer);

        if (chr == '\0')
            break;

        if (chr == '\n') {
            emit(lexer, LEXEME_LINEFEED);
            return lex_config;
        }

        if (isspace(chr)) {
            ignore(lexer);
            continue;
        }

        if (chr == '{') {
            emit(lexer, LEXEME_OPEN_BRACKET);
            return lex_config;
        }

        if (chr == '}') {
            emit(lexer, LEXEME_CLOSE_BRACKET);
            return lex_config;
        }

        if (chr == '=') {
            emit(lexer, LEXEME_EQUAL);
            return lex_equal;
        }

        if (chr == '#')
            return lex_comment;

        if (chr == '\'')
            return lex_multiline_string;

        if (chr == '$')
            return lex_variable;

        if (isstring(chr))
            return lex_string;

        return lex_error(lexer, "Invalid character");
    }

    emit(lexer, LEXEME_LINEFEED);
    emit(lexer, LEXEME_EOF);

    return NULL;
}

static bool lex_next(struct lexer *lexer, struct lexeme **lexeme)
{
    while (lexer->state) {
        if (lexeme_buffer_consume(&lexer->buffer, lexeme))
            return true;

        lexer->state = lexer->state(lexer);
    }

    return lexeme_buffer_consume(&lexer->buffer, lexeme);
}

static void *parse_config(struct parser *parser);

static void *parse_key_value(struct parser *parser)
{
    struct config_line line = { .type = CONFIG_LINE_TYPE_LINE };
    struct lexeme *lexeme;
    size_t key_size;

    while (lexeme_buffer_consume(&parser->buffer, &lexeme)) {
        strbuf_append_str(&parser->strbuf, lexeme->value.value, lexeme->value.len);

        if (parser->buffer.population >= 1)
            strbuf_append_char(&parser->strbuf, '_');
    }
    key_size = strbuf_get_length(&parser->strbuf);
    strbuf_append_char(&parser->strbuf, '\0');

    while (lex_next(&parser->lexer, &lexeme)) {
        switch (lexeme->type) {
        case LEXEME_VARIABLE: {
            const char *value;

            value = secure_getenv(strndupa(lexeme->value.value, lexeme->value.len));
            if (!value) {
                lwan_status_error("Variable '$%.*s' not defined in environment",
                    (int)lexeme->value.len, lexeme->value.value);
                return NULL;
            }

            strbuf_append_str(&parser->strbuf, value, 0);
            break;
        }

        case LEXEME_EQUAL:
            strbuf_append_char(&parser->strbuf, '=');
            break;

        case LEXEME_STRING:
            strbuf_append_str(&parser->strbuf, lexeme->value.value, lexeme->value.len);
            break;

        case LEXEME_CLOSE_BRACKET:
            backup(&parser->lexer);
            /* fallthrough */

        case LEXEME_LINEFEED:
            line.key = strbuf_get_buffer(&parser->strbuf);
            line.value = line.key + key_size + 1;
            if (!config_buffer_emit(&parser->items, &line))
                return NULL;

            return parse_config;

        default:
            lwan_status_error("Unexpected token while parsing key-value: %s",
                lexeme_type_str[lexeme->type]);
            return NULL;
        }
    }

    lwan_status_error("EOF while parsing key-value");
    return NULL;
}

static void *parse_section(struct parser *parser)
{
    struct lexeme *lexeme;
    size_t name_len;

    if (!lexeme_buffer_consume(&parser->buffer, &lexeme))
        return NULL;

    strbuf_append_str(&parser->strbuf, lexeme->value.value, lexeme->value.len);
    name_len = lexeme->value.len;
    strbuf_append_char(&parser->strbuf, '\0');

    while (lexeme_buffer_consume(&parser->buffer, &lexeme)) {
        strbuf_append_str(&parser->strbuf, lexeme->value.value, lexeme->value.len);

        if (parser->buffer.population >= 1)
            strbuf_append_char(&parser->strbuf, ' ');
    }

    struct config_line line = {
        .type = CONFIG_LINE_TYPE_SECTION,
        .name = strbuf_get_buffer(&parser->strbuf),
        .param = line.name + name_len + 1
    };
    if (!config_buffer_emit(&parser->items, &line))
        return NULL;

    return parse_config;
}

static void *parse_section_shorthand(struct parser *parser)
{
    void *next_state = parse_section(parser);

    if (next_state) {
        struct config_line line = { .type = CONFIG_LINE_TYPE_SECTION_END };

        if (!config_buffer_emit(&parser->items, &line))
            return NULL;

        return next_state;
    }

    return NULL;
}

static void *parse_config(struct parser *parser)
{
    struct lexeme *lexeme;

    while (lex_next(&parser->lexer, &lexeme)) {
        switch (lexeme->type) {
        case LEXEME_EQUAL:
            return parse_key_value;

        case LEXEME_OPEN_BRACKET:
            return parse_section;

        case LEXEME_LINEFEED:
            if (parser->buffer.population)
                return parse_section_shorthand;

            return parse_config;

        case LEXEME_STRING:
            lexeme_buffer_emit(&parser->buffer, lexeme);
            break;

        case LEXEME_CLOSE_BRACKET: {
            struct config_line line = { .type = CONFIG_LINE_TYPE_SECTION_END };

            config_buffer_emit(&parser->items, &line);

            return parse_config;
        }

        case LEXEME_EOF:
            return NULL;

        default:
            lwan_status_error("Unexpected lexeme type: %s",
                lexeme_type_str[lexeme->type]);
            return NULL;
        }
    }

    return NULL;
}

static bool parser_next(struct parser *parser, struct config_line **line)
{
    while (parser->state) {
        if (config_buffer_consume(&parser->items, line))
            return true;

        strbuf_reset_length(&parser->strbuf);

        parser->state = parser->state(parser);
    }

    return config_buffer_consume(&parser->items, line);
}

struct config *config_open(const char *path)
{
    struct config *config;
    struct stat st;
    void *data;
    int fd;

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        lwan_status_perror("Could not open configuration file: %s", path);
        return NULL;
    }

    if (fstat(fd, &st) < 0) {
        close(fd);
        return NULL;
    }

    data = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_SHARED, fd, 0);
    close(fd);
    if (data == MAP_FAILED)
        return NULL;

    config = malloc(sizeof(*config));
    if (!config) {
        munmap(data, (size_t)st.st_size);
        return NULL;
    }

    config->parser = (struct parser) {
        .state = parse_config,
        .lexer = {
            .state = lex_config,
            .pos = data,
            .start = data,
            .end = (char *)data + st.st_size,
            .cur_line = 1,
        }
    };
    config->mapped.addr = data;
    config->mapped.sz = (size_t)st.st_size;
    config->error_message = NULL;

    strbuf_init(&config->parser.strbuf);

    return config;
}

void config_close(struct config *config)
{
    if (!config)
        return;

    if (config->mapped.addr)
        munmap(config->mapped.addr, config->mapped.sz);

    free(config->error_message);
    strbuf_free(&config->parser.strbuf);
    free(config);
}

bool config_read_line(struct config *conf, struct config_line *cl)
{
    struct config_line *ptr;
    bool ret;

    if (conf->error_message)
        return false;

    ret = parser_next(&conf->parser, &ptr);
    if (ret)
        *cl = *ptr;

    return ret;
}

static bool find_section_end(struct config *config, struct config_line *line,
    int recursion_level)
{
    if (recursion_level > 10) {
        config_error(config, "Recursion level too deep");
        return false;
    }

    while (config_read_line(config, line)) {
        switch (line->type) {
        case CONFIG_LINE_TYPE_LINE:
            continue;

        case CONFIG_LINE_TYPE_SECTION:
            if (!find_section_end(config, line, recursion_level + 1))
                return false;
            break;

        case CONFIG_LINE_TYPE_SECTION_END:
            ignore(&config->parser.lexer);
            return true;
        }
    }

    return false;
}

struct config *config_isolate_section(struct config *current_conf,
    struct config_line *current_line)
{
    struct lexer *lexer;
    struct config *isolated;
    const char *pos;

    if (current_line->type != CONFIG_LINE_TYPE_SECTION)
        return NULL;

    isolated = malloc(sizeof(*isolated));
    if (!isolated)
        return NULL;

    memcpy(isolated, current_conf, sizeof(*isolated));
    isolated->mapped.addr = NULL;
    isolated->mapped.sz = 0;

    lexer = &isolated->parser.lexer;
    pos = lexer->pos;
    lexer->start = lexer->pos;

    pos = isolated->parser.lexer.pos;
    if (!find_section_end(isolated, current_line, 0)) {
        free(isolated);
        return NULL;
    }

    lexer->end = lexer->pos;
    lexer->start = lexer->pos = pos;

    strbuf_init(&isolated->parser.strbuf);

    return isolated;
}

bool config_skip_section(struct config *conf, struct config_line *line)
{
    struct config_line *cl;
    int cur_level = 1;

    if (conf->error_message)
        return false;
    if (line->type != CONFIG_LINE_TYPE_SECTION)
        return false;

    while (parser_next(&conf->parser, &cl)) {
        if (cl->type == CONFIG_LINE_TYPE_SECTION) {
            cur_level++;
        } else if (cl->type == CONFIG_LINE_TYPE_SECTION_END) {
            cur_level--;

            if (!cur_level)
                return true;
        }
    }

    return false;
}

const char *config_last_error(struct config *conf)
{
    return conf->error_message;
}

int config_cur_line(struct config *conf)
{
    return conf->parser.lexer.cur_line;
}
