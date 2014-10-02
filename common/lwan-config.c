/*
 * lwan - simple web server
 * Copyright (c) 2013 Leandro A. F. Pereira <leandro@hardinfo.org>
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
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lwan-config.h"
#include "hash.h"

bool parse_bool(const char *value, bool default_value)
{
    if (!strcmp(value, "true") || !strcmp(value, "1")
            || !strcmp(value, "on") || !strcmp(value, "yes"))
        return true;

    if (!strcmp(value, "false") || !strcmp(value, "0")
            || !strcmp(value, "off") || !strcmp(value, "no"))
        return false;

    return default_value;
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

bool config_error(config_t *conf, const char *fmt, ...)
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

static char *remove_comments(char *line)
{
    char *tmp = strrchr(line, '#');
    if (tmp)
        *tmp = '\0';
    return line;
}

static char *remove_trailing_spaces(char *line)
{
    char *end = rawmemchr(line, '\0');

    for (end--; isspace(*end); end--);
    *(end + 1) = '\0';

    return line;
}

static char *remove_leading_spaces(char *line)
{
    while (isspace(*line))
        line++;
    return line;
}

static char *find_line_end(char *line)
{
    if (*line == '\0')
        return line;
    return (char *)rawmemchr(line, '\0') - 1;
}

static bool parse_section(char *line, config_line_t *l)
{
    char *name, *param;
    char *bracket = strrchr(line, '{');
    if (!bracket)
        return false;

    char *space = strchr(line, ' ');
    if (!space)
        return false;

    *bracket = '\0';
    *space = '\0';
    name = remove_trailing_spaces(remove_leading_spaces(line));
    param = remove_trailing_spaces(remove_leading_spaces(space + 1));

    l->section.name = name;
    l->section.param = param;
    l->type = CONFIG_LINE_TYPE_SECTION;

    return true;
}

static bool parse_line(char *line, config_line_t *l)
{
    char *equal = strchr(line, '=');
    if (!equal)
        return false;

    *equal = '\0';
    l->line.key = remove_trailing_spaces(remove_leading_spaces(line));
    l->line.value = remove_leading_spaces(equal + 1);
    l->type = CONFIG_LINE_TYPE_LINE;

    return true;
}

bool config_read_line(config_t *conf, config_line_t *l)
{
    char *line, *line_end;

    if (conf->error_message)
        return false;

retry:
    if (!fgets(l->buffer, sizeof(l->buffer), conf->file))
        return false;

    conf->line++;

    line = remove_comments(l->buffer);
    line = remove_leading_spaces(line);
    line = remove_trailing_spaces(line);
    line_end = find_line_end(line);

    if (*line_end == '{') {
        if (!parse_section(line, l)) {
            config_error(conf, "Malformed section opening");
            return false;
        }
    } else if (*line == '\0') {
        goto retry;
    } else if (*line == '}' && line == line_end) {
        l->type = CONFIG_LINE_TYPE_SECTION_END;
    } else if (strchr(line, '=')) {
        if (!parse_line(line, l)) {
            config_error(conf, "Malformed key=value line");
            return false;
        }
    } else {
        config_error(conf, "Expecting section or key=value");
        return false;
    }

    return true;
}

bool config_open(config_t *conf, const char *path)
{
    if (!conf)
        return false;
    if (!path)
        return false;
    conf->file = fopen(path, "r");
    if (!conf->file)
        return false;
    conf->line = 0;
    conf->error_message = NULL;
    return true;
}

void config_close(config_t *conf)
{
    if (!conf)
        return;
    if (!conf->file)
        return;
    fclose(conf->file);
    free(conf->error_message);
}
