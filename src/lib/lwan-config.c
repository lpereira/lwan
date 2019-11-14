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

#include "lwan-private.h"
#include "lwan-status.h"
#include "lwan-config.h"
#include "lwan-strbuf.h"

#include "ringbuffer.h"

#define FOR_EACH_LEXEME(X)                                                     \
    X(ERROR) X(STRING) X(EQUAL) X(OPEN_BRACKET) X(CLOSE_BRACKET) X(LINEFEED)   \
    X(VARIABLE) X(VARIABLE_DEFAULT) X(EOF)

#define GENERATE_ENUM(id) LEXEME_ ## id,
#define GENERATE_ARRAY_ITEM(id) [LEXEME_ ## id] = #id,

enum lexeme_type {
    FOR_EACH_LEXEME(GENERATE_ENUM)
    TOTAL_LEXEMES
};

static const char *lexeme_type_str[TOTAL_LEXEMES] = {
    FOR_EACH_LEXEME(GENERATE_ARRAY_ITEM)
};

#undef GENERATE_ENUM
#undef GENERATE_ARRAY_ITEM

struct lexeme {
    enum lexeme_type type;
    struct {
        const char *value;
        size_t len;
    } value;
};

DEFINE_RING_BUFFER_TYPE(lexeme_ring_buffer, struct lexeme, 4)
DEFINE_RING_BUFFER_TYPE(config_ring_buffer, struct config_line, 4)

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
    struct lwan_strbuf strbuf;
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

static void emit_lexeme(struct lexer *lexer, struct lexeme *lexeme)
{
    if (lexeme_ring_buffer_try_put(&lexer->buffer, lexeme))
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

static void advance_n(struct lexer *lexer, size_t n)
{
    lexer->pos += n;
    ignore(lexer);
}

static void backup(struct lexer *lexer)
{
    lexer->pos--;

    if (*lexer->pos == '\n')
        lexer->cur_line--;
}

static int peek(struct lexer *lexer)
{
    int chr = next(lexer);

    backup(lexer);

    return chr;
}

static size_t remaining(struct lexer *lexer)
{
    return (size_t)(lexer->end - lexer->pos);
}

static void *lex_config(struct lexer *lexer);
static void *lex_variable(struct lexer *lexer);

static bool isstring(int chr)
{
    return chr && !isspace(chr) && chr != '=' && chr != '#';
}

static void *lex_string(struct lexer *lexer)
{
    int chr;

    do {
        chr = next(lexer);

        if (chr == '$' && peek(lexer) == '{') {
            backup(lexer);
            emit(lexer, LEXEME_STRING);

            advance_n(lexer, strlen("{"));

            return lex_variable;
        }
    } while (isstring(chr));

    backup(lexer);
    emit(lexer, LEXEME_STRING);

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

static bool lex_streq(struct lexer *lexer, const char *str, size_t s)
{
    if (remaining(lexer) < s)
        return false;

    return !strncmp(lexer->pos, str, s);
}

static void *lex_multiline_string(struct lexer *lexer)
{
    const char *end = (peek(lexer) == '"') ? "\"\"\"" : "'''";

    advance_n(lexer, strlen("'''") - 1);

    do {
        if (lex_streq(lexer, end, 3)) {
            emit(lexer, LEXEME_STRING);
            lexer->pos += 3;

            return lex_config;
        }
    } while (next(lexer) != '\0');

    return lex_error(lexer, "EOF while scanning multiline string");
}

static bool isvariable(int chr)
{
    return isalpha(chr) || chr == '_';
}

static void *lex_variable_default(struct lexer *lexer)
{
    int chr;

    do {
        chr = next(lexer);

        if (chr == '}') {
            backup(lexer);
            emit(lexer, LEXEME_STRING);

            advance_n(lexer, strlen("}"));

            return lex_config;
        }
    } while (chr != '\0');

    return lex_error(lexer, "EOF while scanning for end of variable");
}

static void *lex_variable(struct lexer *lexer)
{
    int chr;

    advance_n(lexer, strlen("${") - 1);

    do {
        chr = next(lexer);

        if (chr == ':') {
            backup(lexer);
            emit(lexer, LEXEME_VARIABLE_DEFAULT);
            advance_n(lexer, strlen(":"));
            return lex_variable_default;
        }

        if (chr == '}') {
            backup(lexer);
            emit(lexer, LEXEME_VARIABLE);
            advance_n(lexer, strlen("}"));

            return lex_config;
        }
    } while (isvariable(chr));

    return lex_error(lexer, "EOF while scanning for end of variable");
}

static bool iscomment(int chr)
{
    return chr != '\0' && chr != '\n';
}

static void *lex_comment(struct lexer *lexer)
{
    while (iscomment(next(lexer)))
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
            return lex_config;
        }

        if (chr == '#')
            return lex_comment;

        if (chr == '\'' && lex_streq(lexer, "''", 2))
            return lex_multiline_string;
        if (chr == '"' && lex_streq(lexer, "\"\"", 2))
            return lex_multiline_string;

        if (chr == '$' && peek(lexer) == '{')
            return lex_variable;

        if (isstring(chr))
            return lex_string;

        return lex_error(lexer, "Invalid character");
    }

    emit(lexer, LEXEME_LINEFEED);
    emit(lexer, LEXEME_EOF);

    return NULL;
}

static const struct lexeme *lex_next(struct lexer *lexer)
{
    while (lexer->state) {
        const struct lexeme *lexeme;

        if ((lexeme = lexeme_ring_buffer_get_ptr_or_null(&lexer->buffer)))
            return lexeme;

        lexer->state = lexer->state(lexer);
    }

    return lexeme_ring_buffer_get_ptr_or_null(&lexer->buffer);
}

static void *parse_config(struct parser *parser);

#define ENV_VAR_NAME_LEN_MAX 64

static __attribute__((noinline)) const char *secure_getenv_len(const char *key, size_t len)
{
    if (UNLIKELY(len > ENV_VAR_NAME_LEN_MAX)) {
        lwan_status_error("Variable name exceeds %d bytes", ENV_VAR_NAME_LEN_MAX);
        return NULL;
    }

    return secure_getenv(strndupa(key, len));
}

static void *parse_key_value(struct parser *parser)
{
    struct config_line line = {.type = CONFIG_LINE_TYPE_LINE};
    const struct lexeme *lexeme;
    size_t key_size;

    while ((lexeme = lexeme_ring_buffer_get_ptr_or_null(&parser->buffer))) {
        lwan_strbuf_append_str(&parser->strbuf, lexeme->value.value,
                               lexeme->value.len);

        if (!lexeme_ring_buffer_empty(&parser->buffer))
            lwan_strbuf_append_char(&parser->strbuf, '_');
    }
    key_size = lwan_strbuf_get_length(&parser->strbuf);
    lwan_strbuf_append_char(&parser->strbuf, '\0');

    while ((lexeme = lex_next(&parser->lexer))) {
        switch (lexeme->type) {
        case LEXEME_VARIABLE_DEFAULT:
        case LEXEME_VARIABLE: {
            const char *value;

            value = secure_getenv_len(lexeme->value.value, lexeme->value.len);
            if (lexeme->type == LEXEME_VARIABLE) {
                if (!value) {
                    lwan_status_error(
                        "Variable '$%.*s' not defined in environment",
                        (int)lexeme->value.len, lexeme->value.value);
                    return NULL;
                } else {
                    lwan_strbuf_append_strz(&parser->strbuf, value);
                }
            } else {
                const struct lexeme *var_name = lexeme;

                if (!(lexeme = lex_next(&parser->lexer))) {
                    lwan_status_error(
                        "Default value for variable '$%.*s' not given",
                        (int)var_name->value.len, var_name->value.value);
                    return NULL;
                }

                if (lexeme->type != LEXEME_STRING) {
                    lwan_status_error("Wrong format for default value");
                    return NULL;
                }

                if (!value) {
                    lwan_status_debug(
                        "Using default value of '%.*s' for variable '${%.*s}'",
                        (int)lexeme->value.len, lexeme->value.value,
                        (int)var_name->value.len, var_name->value.value);
                    lwan_strbuf_append_str(&parser->strbuf, lexeme->value.value,
                                           lexeme->value.len);
                } else {
                    lwan_strbuf_append_strz(&parser->strbuf, value);
                }
            }

            break;
        }

        case LEXEME_EQUAL:
            lwan_strbuf_append_char(&parser->strbuf, '=');
            break;

        case LEXEME_STRING:
            lwan_strbuf_append_str(&parser->strbuf, lexeme->value.value,
                                   lexeme->value.len);
            break;

        case LEXEME_CLOSE_BRACKET:
            backup(&parser->lexer);
            /* fallthrough */

        case LEXEME_LINEFEED:
            line.key = lwan_strbuf_get_buffer(&parser->strbuf);
            line.value = line.key + key_size + 1;
            return config_ring_buffer_try_put(&parser->items, &line)
                       ? parse_config
                       : NULL;

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
    const struct lexeme *lexeme;
    size_t name_len;

    if (!(lexeme = lexeme_ring_buffer_get_ptr_or_null(&parser->buffer)))
        return NULL;

    lwan_strbuf_append_str(&parser->strbuf, lexeme->value.value,
                           lexeme->value.len);
    name_len = lexeme->value.len;
    lwan_strbuf_append_char(&parser->strbuf, '\0');

    while ((lexeme = lexeme_ring_buffer_get_ptr_or_null(&parser->buffer))) {
        lwan_strbuf_append_str(&parser->strbuf, lexeme->value.value,
                               lexeme->value.len);

        if (!lexeme_ring_buffer_empty(&parser->buffer))
            lwan_strbuf_append_char(&parser->strbuf, ' ');
    }

    struct config_line line = {
        .type = CONFIG_LINE_TYPE_SECTION,
        .key = lwan_strbuf_get_buffer(&parser->strbuf),
        .value = lwan_strbuf_get_buffer(&parser->strbuf) + name_len + 1,
    };
    return config_ring_buffer_try_put(&parser->items, &line) ? parse_config
                                                             : NULL;
}

static void *parse_section_shorthand(struct parser *parser)
{
    void *next_state = parse_section(parser);

    if (next_state) {
        struct config_line line = {.type = CONFIG_LINE_TYPE_SECTION_END};

        if (config_ring_buffer_try_put(&parser->items, &line))
            return next_state;
    }

    return NULL;
}

static void *parse_config(struct parser *parser)
{
    const struct lexeme *lexeme;

    if (!(lexeme = lex_next(&parser->lexer)))
        return NULL;

    switch (lexeme->type) {
    case LEXEME_EQUAL:
        return parse_key_value;

    case LEXEME_OPEN_BRACKET:
        return parse_section;

    case LEXEME_LINEFEED:
        if (!lexeme_ring_buffer_empty(&parser->buffer))
            return parse_section_shorthand;

        return parse_config;

    case LEXEME_STRING:
        lexeme_ring_buffer_try_put(&parser->buffer, lexeme);

        return parse_config;

    case LEXEME_CLOSE_BRACKET: {
        struct config_line line = { .type = CONFIG_LINE_TYPE_SECTION_END };

        config_ring_buffer_try_put(&parser->items, &line);

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

static const struct config_line *parser_next(struct parser *parser)
{
    while (parser->state) {
        const struct config_line *line;

        if ((line = config_ring_buffer_get_ptr_or_null(&parser->items)))
            return line;

        lwan_strbuf_reset(&parser->strbuf);

        parser->state = parser->state(parser);
    }

    return config_ring_buffer_get_ptr_or_null(&parser->items);
}

static struct config *
config_open_path(const char *path, void **data, size_t *size)
{
    struct config *config;
    struct stat st;
    void *mapped;
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

    mapped = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_SHARED, fd, 0);
    close(fd);
    if (mapped == MAP_FAILED)
        return NULL;

    config = malloc(sizeof(*config));
    if (!config) {
        munmap(mapped, (size_t)st.st_size);
        return NULL;
    }

    *data = config->mapped.addr = mapped;
    *size = config->mapped.sz = (size_t)st.st_size;

    return config;
}

static struct config *
config_init_data(struct config *config, const void *data, size_t len)
{
    config->parser = (struct parser){
        .state = parse_config,
        .lexer =
            {
                .state = lex_config,
                .pos = data,
                .start = data,
                .end = (char *)data + len,
                .cur_line = 1,
            },
    };

    config->error_message = NULL;

    lwan_strbuf_init(&config->parser.strbuf);
    config_ring_buffer_init(&config->parser.items);
    lexeme_ring_buffer_init(&config->parser.buffer);

    return config;
}

struct config *config_open(const char *path)
{
    struct config *config;
    void *data;
    size_t len;

    config = config_open_path(path, &data, &len);
    return config ? config_init_data(config, data, len) : NULL;
}

#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
struct config *config_open_for_fuzzing(const uint8_t *data, size_t len)
{
    struct config *config = malloc(sizeof(*config));

    if (config) {
        config->mapped.addr = NULL;
        config->mapped.sz = 0;

        return config_init_data(config, data, len - 1);
    }

    return NULL;
}
#endif

void config_close(struct config *config)
{
    if (!config)
        return;

#if !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    if (config->mapped.addr)
        munmap(config->mapped.addr, config->mapped.sz);
#endif

    free(config->error_message);
    lwan_strbuf_free(&config->parser.strbuf);
    free(config);
}

const struct config_line *config_read_line(struct config *conf)
{
    return conf->error_message ? NULL : parser_next(&conf->parser);
}

static bool find_section_end(struct config *config)
{
    const struct config_line *line;
    int cur_level = 1;

    if (config->error_message)
        return false;

    while ((line = parser_next(&config->parser))) {
        if (line->type == CONFIG_LINE_TYPE_SECTION) {
            cur_level++;
        } else if (line->type == CONFIG_LINE_TYPE_SECTION_END) {
            cur_level--;

            if (!cur_level)
                return true;
        }
    }

    return false;
}

struct config *config_isolate_section(struct config *current_conf,
                                      const struct config_line *current_line)
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
    lwan_strbuf_init(&isolated->parser.strbuf);

    isolated->mapped.addr = NULL;
    isolated->mapped.sz = 0;

    lexer = &isolated->parser.lexer;
    lexer->start = lexer->pos;

    pos = isolated->parser.lexer.pos;
    if (!find_section_end(isolated)) {
        lwan_strbuf_free(&isolated->parser.strbuf);
        free(isolated);

        config_error(current_conf,
                     "Could not find section end while trying to isolate");

        return NULL;
    }

    lexer->end = lexer->pos;
    lexer->start = lexer->pos = pos;

    return isolated;
}

bool config_skip_section(struct config *conf, const struct config_line *line)
{
    if (line->type != CONFIG_LINE_TYPE_SECTION)
        return false;

    return find_section_end(conf);
}

const char *config_last_error(struct config *conf)
{
    return conf->error_message;
}

int config_cur_line(struct config *conf)
{
    return conf->parser.lexer.cur_line;
}
