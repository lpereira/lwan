/*
 * lwan - web server
 * Copyright (c) 2017 L. A. F. Pereira <l@tia.mat.br>
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

#define LEX_ERROR(lexer, fmt, ...)                                             \
    ({                                                                         \
        config_error(config_from_lexer(lexer), "%s" fmt,                       \
                     "Syntax error: ", ##__VA_ARGS__);                         \
        NULL;                                                                  \
    })

#define PARSER_ERROR(parser, fmt, ...)                                         \
    ({                                                                         \
        config_error(config_from_parser(parser), "%s" fmt,                     \
                     "Parsing error: ", ##__VA_ARGS__);                        \
        NULL;                                                                  \
    })

#define INTERNAL_ERROR(parser, fmt, ...)                                       \
    ({                                                                         \
        config_error(config_from_parser(parser), "%s" fmt,                     \
                     "Internal error: ", ##__VA_ARGS__);                       \
        NULL;                                                                  \
    })

#define FOR_EACH_LEXEME(X)                                                      \
    X(STRING) X(EQUAL) X(OPEN_BRACKET) X(CLOSE_BRACKET) X(LINEFEED) X(VARIABLE) \
    X(VARIABLE_DEFAULT) X(EOF)

#define GENERATE_ENUM(id) LEXEME_ ## id,

enum lexeme_type {
    FOR_EACH_LEXEME(GENERATE_ENUM)
    TOTAL_LEXEMES
};

#undef GENERATE_ENUM

struct lexeme {
    enum lexeme_type type;
    struct lwan_value value;
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
    struct hash *constants;
    struct {
        void *addr;
        size_t sz;
    } mapped;
    int opened_brackets;
};

unsigned int parse_time_period(const char *str, unsigned int default_value)
{
    unsigned int total = 0;
    unsigned int period;
    int ignored_spaces = 0;
    char multiplier;

    if (!str)
        return default_value;

    while (*str) {
        /* This check is necessary to avoid making sscanf() take an incredible
         * amount of time while trying to scan the input for a number.  Fix for
         * https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=44910 */
        if (isspace(*str)) {
            ignored_spaces++;
            str++;

            if (ignored_spaces > 1024)
                return default_value;

            continue;
        }

        if (sscanf(str, "%u%c", &period, &multiplier) != 2)
            break;

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

        str = strchr(str, multiplier) + 1;
    }

    return total ? total : default_value;
}

static bool _parse_i64(const char *s, int64_t *out)
{
    /* FIXME: we only need overflow checks if strlen(s) > thresh */
    const char *orig_s = s;
    int64_t r = 0;
    bool negative = false;

    if (*s == '-') {
        s++;
        negative = true;
    }

    if (UNLIKELY(*s < '0' && *s > '9'))
        return false;

    goto elide_mult_for_first_iter;

    while (*s >= '0' && *s <= '9') {
        if (UNLIKELY(__builtin_mul_overflow(r, 10, &r)))
            return false;
elide_mult_for_first_iter:
        if (UNLIKELY(__builtin_add_overflow(r, *s - '0', &r)))
            return false;
        s++;
    }

    if (negative) {
        *out = -r;
    } else if (r <= 1ll<<62) {
        *out = r;
    } else {
        return false;
    }

    return s != orig_s && *s == '\0';
}

static bool _parse_i32(const char *s, int32_t *out)
{
    int64_t parsed;

    if (_parse_i64(s, &parsed) && (int64_t)(int32_t)parsed == parsed) {
        *out = (int32_t)parsed;
        return true;
    }

    return false;
}

long long parse_long_long(const char *value, long long default_value)
{
    int64_t out;

    if (_parse_i64(value, &out))
        return (long long)out;

    return default_value;
}

int parse_int(const char *value, int default_value)
{
    int32_t out;

    if (_parse_i32(value, &out))
        return out;

    return default_value;
}

long parse_long(const char *value, long default_value)
{
    if (sizeof(long) == sizeof(long long))
        return (long)parse_long_long(value, default_value);
    return (long)parse_int(value, (int)default_value);
}

bool parse_bool(const char *value, bool default_value)
{
    if (!value)
        return default_value;

    if (strcaseequal_neutral(value, "true") ||
        strcaseequal_neutral(value, "on") || strcaseequal_neutral(value, "yes"))
        return true;

    if (strcaseequal_neutral(value, "false") ||
        strcaseequal_neutral(value, "off") || strcaseequal_neutral(value, "no"))
        return false;

    return parse_int(value, default_value);
}

LWAN_SELF_TEST(parse_bool)
{
    assert(parse_bool("true", false) == true);
    assert(parse_bool("on", false) == true);
    assert(parse_bool("yes", false) == true);

    assert(parse_bool("false", true) == false);
    assert(parse_bool("off", true) == false);
    assert(parse_bool("no", true) == false);

    assert(parse_bool("0", 1) == false);
    assert(parse_bool("1", 0) == true);

    assert(parse_bool("abacate", true) == true);
    assert(parse_bool("abacate", false) == false);
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

static size_t current_len(struct lexer *lexer)
{
    return (size_t)(lexer->pos - lexer->start);
}

static void emit(struct lexer *lexer, enum lexeme_type type)
{
    struct lexeme lexeme = {
        .type = type,
        .value = {.value = (char *)lexer->start, .len = current_len(lexer)},
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

static bool is_string(int chr)
{
    return chr && !isspace(chr) && chr != '=' && chr != '#' && chr != '{' && chr != '}';
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
    } while (is_string(chr));

    backup(lexer);
    emit(lexer, LEXEME_STRING);

    return lex_config;
}

static struct config *config_from_parser(struct parser *parser)
{
    return container_of(parser, struct config, parser);
}

static struct config *config_from_lexer(struct lexer *lexer)
{
    struct parser *parser = container_of(lexer, struct parser, lexer);

    return config_from_parser(parser);
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

    return LEX_ERROR(lexer, "EOF while scanning multiline string");
}

static bool is_variable(int chr)
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

    return LEX_ERROR(lexer, "EOF while scanning for default value for variable");
}

static void *lex_variable(struct lexer *lexer)
{
    int chr;

    advance_n(lexer, strlen("${") - 1);

    do {
        chr = next(lexer);

        if (chr == ':') {
            backup(lexer);

            if (!current_len(lexer))
                return LEX_ERROR(lexer, "Expecting environment variable name");

            emit(lexer, LEXEME_VARIABLE_DEFAULT);
            advance_n(lexer, strlen(":"));
            return lex_variable_default;
        }

        if (chr == '}') {
            backup(lexer);

            if (!current_len(lexer))
                return LEX_ERROR(lexer, "Expecting environment variable name");

            emit(lexer, LEXEME_VARIABLE);
            advance_n(lexer, strlen("}"));

            return lex_config;
        }
    } while (is_variable(chr));

    return LEX_ERROR(lexer, "EOF while scanning for end of variable");
}

static bool is_comment(int chr)
{
    return chr != '\0' && chr != '\n';
}

static void *lex_comment(struct lexer *lexer)
{
    while (is_comment(next(lexer)))
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
            /* Emitting a linefeed lexeme before a close bracket lexeme
             * simplifies the parser and allows for situations where a
             * section is closed when declaring a key/value pair
             * (e.g. "section{key=value}" all in a single line).
             */
            emit(lexer, LEXEME_LINEFEED);
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

        if (is_string(chr))
            return lex_string;

        return LEX_ERROR(lexer, "Invalid character: '%c'", chr);
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
static void *parse_section_end(struct parser *parser);

#define ENV_VAR_NAME_LEN_MAX 64

static __attribute__((noinline)) const char *
get_constant(struct parser *parser, const char *key, size_t len)
{
    if (UNLIKELY(len > ENV_VAR_NAME_LEN_MAX)) {
        return PARSER_ERROR(parser, "Variable name \"%.*s\" exceeds %d bytes",
                            (int)len, key, ENV_VAR_NAME_LEN_MAX);
    }

    const char *key_copy = strndupa(key, len);
    const char *value =
        hash_find(config_from_parser(parser)->constants, key_copy);
    return value ? value : secure_getenv(key_copy);
}

static void *parse_key_value(struct parser *parser)
{
    struct config_line line = {.type = CONFIG_LINE_TYPE_LINE};
    const struct lexeme *lexeme;
    enum lexeme_type last_lexeme = TOTAL_LEXEMES;
    size_t key_size;

    while ((lexeme = lexeme_ring_buffer_get_ptr_or_null(&parser->buffer))) {
        if (lexeme->type != LEXEME_STRING)
            return PARSER_ERROR(parser, "Expecting string");

        lwan_strbuf_append_value(&parser->strbuf, &lexeme->value);

        if (!lexeme_ring_buffer_empty(&parser->buffer))
            lwan_strbuf_append_char(&parser->strbuf, '_');
    }
    key_size = lwan_strbuf_get_length(&parser->strbuf);
    lwan_strbuf_append_char(&parser->strbuf, '\0');

    while ((lexeme = lex_next(&parser->lexer))) {
        if (UNLIKELY(lwan_strbuf_get_length(&parser->strbuf) > 1ull<<20)) {
            /* 1MiB is more than sufficient for a value. (Without this validation
             * here, fuzzers often generates values that are gigabite sized.) */
            return PARSER_ERROR(parser, "Value too long");
        }

        switch (lexeme->type) {
        case LEXEME_VARIABLE: {
            const char *value =
                get_constant(parser, lexeme->value.value, lexeme->value.len);
            if (!value) {
                return PARSER_ERROR(
                    parser,
                    "Variable '$%.*s' not defined in a constants section "
                    "or as an environment variable",
                    (int)lexeme->value.len, lexeme->value.value);
            }

            lwan_strbuf_append_strz(&parser->strbuf, value);

            break;
        }

        case LEXEME_VARIABLE_DEFAULT: {
            const char *value =
                get_constant(parser, lexeme->value.value, lexeme->value.len);
            const struct lexeme *var_name = lexeme;

            if (!(lexeme = lex_next(&parser->lexer))) {
                return PARSER_ERROR(
                    parser, "Default value for constant '$%.*s' not given",
                    (int)var_name->value.len, var_name->value.value);
            }

            if (lexeme->type != LEXEME_STRING)
                return PARSER_ERROR(parser, "Wrong format for default value");

            if (!value) {
                lwan_status_debug(
                    "Using default value of '%.*s' for variable '${%.*s}'",
                    (int)lexeme->value.len, lexeme->value.value,
                    (int)var_name->value.len, var_name->value.value);
                lwan_strbuf_append_value(&parser->strbuf, &lexeme->value);
            } else {
                lwan_strbuf_append_strz(&parser->strbuf, value);
            }

            break;
        }

        case LEXEME_EQUAL:
            lwan_strbuf_append_char(&parser->strbuf, '=');
            break;

        case LEXEME_STRING:
            if (last_lexeme == LEXEME_STRING)
                lwan_strbuf_append_char(&parser->strbuf, ' ');

            lwan_strbuf_append_value(&parser->strbuf, &lexeme->value);

            break;

        case LEXEME_LINEFEED:
            line.key = lwan_strbuf_get_buffer(&parser->strbuf);
            line.value = line.key + key_size + 1;

            if (config_ring_buffer_try_put(&parser->items, &line))
                return parse_config;

            return PARSER_ERROR(parser,
                                "Could not add key/value to ring buffer");

        case LEXEME_OPEN_BRACKET:
            return PARSER_ERROR(parser, "Open bracket not expected here");

        case LEXEME_CLOSE_BRACKET:
            return INTERNAL_ERROR(
                parser, "Close bracket found while parsing key/value");

        case LEXEME_EOF:
            return INTERNAL_ERROR(
                parser, "EOF found while parsing key/value");

        case TOTAL_LEXEMES:
            __builtin_unreachable();
        }

        last_lexeme = lexeme->type;
    }

    return PARSER_ERROR(parser, "EOF while parsing key-value");
}

static void *parse_section(struct parser *parser)
{
    const struct lexeme *lexeme;
    size_t name_len;

    lexeme = lexeme_ring_buffer_get_ptr_or_null(&parser->buffer);
    if (!lexeme || lexeme->type != LEXEME_STRING)
        return PARSER_ERROR(parser, "Expecting a string");

    lwan_strbuf_append_value(&parser->strbuf, &lexeme->value);
    name_len = lexeme->value.len;
    lwan_strbuf_append_char(&parser->strbuf, '\0');

    while ((lexeme = lexeme_ring_buffer_get_ptr_or_null(&parser->buffer))) {
        if (lexeme->type != LEXEME_STRING)
            return PARSER_ERROR(parser, "Expecting a string");

        lwan_strbuf_append_value(&parser->strbuf, &lexeme->value);

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

        return INTERNAL_ERROR(parser, "couldn't append line to internal ring buffer");
    }

    return NULL;
}

static void *parse_section_end(struct parser *parser)
{
    struct config_line line = {.type = CONFIG_LINE_TYPE_SECTION_END};
    struct config *config = config_from_parser(parser);

    if (!config->opened_brackets)
        return PARSER_ERROR(parser, "Section closed before it opened");

    if (!lexeme_ring_buffer_empty(&parser->buffer))
        return PARSER_ERROR(parser, "Not expecting a close bracket here");

    if (!config_ring_buffer_try_put(&parser->items, &line)) {
        return INTERNAL_ERROR(parser,
                              "could not store section end in ring buffer");
    }

    config->opened_brackets--;

    return parse_config;
}

static void *parse_config(struct parser *parser)
{
    const struct lexeme *lexeme = lex_next(&parser->lexer);

    if (!lexeme) {
        /* EOF is signaled by a LEXEME_EOF from the parser, so
         * this should never happen. */
        return INTERNAL_ERROR(parser, "could not obtain lexeme");
    }

    switch (lexeme->type) {
    case LEXEME_EQUAL:
        if (lexeme_ring_buffer_empty(&parser->buffer))
            return PARSER_ERROR(parser, "Keys can´t be empty");

        return parse_key_value;

    case LEXEME_OPEN_BRACKET:
        if (lexeme_ring_buffer_empty(&parser->buffer))
            return PARSER_ERROR(parser, "Section names can´t be empty");

        config_from_parser(parser)->opened_brackets++;

        return parse_section;

    case LEXEME_LINEFEED:
        if (!lexeme_ring_buffer_empty(&parser->buffer))
            return parse_section_shorthand;

        return parse_config;

    case LEXEME_STRING:
        if (!lexeme_ring_buffer_try_put(&parser->buffer, lexeme))
            return INTERNAL_ERROR(parser, "could not store string in ring buffer");

        return parse_config;

    case LEXEME_CLOSE_BRACKET:
        return parse_section_end;

    case LEXEME_EOF:
        if (config_from_parser(parser)->opened_brackets)
            return PARSER_ERROR(parser, "EOF while looking for a close bracket");

        if (!lexeme_ring_buffer_empty(&parser->buffer))
            return INTERNAL_ERROR(parser, "premature EOF");

        break;

    case LEXEME_VARIABLE:
    case LEXEME_VARIABLE_DEFAULT:
        return PARSER_ERROR(parser, "Variable '%.*s' can't be used here",
                            (int)lexeme->value.len, lexeme->value.value);

    case TOTAL_LEXEMES:
        __builtin_unreachable();
    }

    return NULL;
}

static const struct config_line *parser_next_internal(struct parser *parser)
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

static bool parse_constants(struct config *config, const struct config_line *l)
{
    while ((l = config_read_line(config))) {
        switch (l->type) {
        case CONFIG_LINE_TYPE_LINE: {
            char *k = strdup(l->key);
            char *v = strdup(l->value);

            if (!k || !v)
                lwan_status_critical("Can't allocate memory for constant");

            hash_add(config->constants, k, v);
            break;
        }

        case CONFIG_LINE_TYPE_SECTION_END:
            return true;

        case CONFIG_LINE_TYPE_SECTION:
            config_error(config, "Constants section can't be nested");
            return false;
        }
    }

    return true;
}

static const struct config_line *parser_next(struct parser *parser)
{
    while (true) {
        const struct config_line *l = parser_next_internal(parser);

        if (!l)
            return NULL;

        if (l->type == CONFIG_LINE_TYPE_SECTION && streq(l->key, "constants") &&
            config_from_parser(parser)->opened_brackets == 1) {
            struct config *config = config_from_parser(parser);

            if (parse_constants(config, l))
                continue;

            return PARSER_ERROR(parser, "Could not parse constants section: %s",
                                config_last_error(config));
        }

        return l;
    }
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

    mapped = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
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
    config->opened_brackets = 0;

    config->constants = hash_str_new(free, free);

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

    hash_unref(config->constants);

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

    isolated->constants = hash_ref(current_conf->constants);

    isolated->mapped.addr = NULL;
    isolated->mapped.sz = 0;
    /* Keep opened_brackets from the original */

    lexer = &isolated->parser.lexer;
    lexer->start = lexer->pos;

    pos = isolated->parser.lexer.pos;
    if (!find_section_end(isolated)) {
        config_error(current_conf,
                     "Could not find section end while trying to isolate: %s",
                     config_last_error(isolated));

        hash_unref(isolated->constants);
        lwan_strbuf_free(&isolated->parser.strbuf);
        free(isolated);

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
