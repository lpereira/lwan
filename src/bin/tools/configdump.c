/*
 * lwan - simple web server
 * Copyright (c) 2019 Leandro A. F. Pereira <leandro@hardinfo.org>
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

#include <stdio.h>
#include <string.h>

#include "lwan-config.h"
#include "lwan-status.h"

static void indent(int level)
{
    for (int i = 0; i < level; i++) {
        putchar(' ');
        putchar(' ');
    }
}

static void
dump(struct config *config, int indent_level)
{
    const struct config_line *line;

    if (indent_level > 64) {
        lwan_status_critical("Indent level %d above limit, aborting",
                             indent_level);
        return;
    }

    while ((line = config_read_line(config))) {
        switch (line->type) {
        case CONFIG_LINE_TYPE_LINE:
            indent(indent_level);

            if (strchr(line->value, '\n'))
                printf("%s = '''%s'''\n", line->key, line->value);
            else
                printf("%s = %s\n", line->key, line->value);
            break;

        case CONFIG_LINE_TYPE_SECTION_END:
            if (indent_level == 0)
                lwan_status_critical("Section ended before it started");
            return;

        case CONFIG_LINE_TYPE_SECTION:
            indent(indent_level);
            printf("%s %s {\n", line->key, line->value);

            dump(config, indent_level + 1);

            indent(indent_level);
            printf("}\n");
            break;
        }
    }
}

int main(int argc, char *argv[])
{
    struct config *config;

    if (argc < 2) {
        lwan_status_critical("Usage: %s /path/to/config/file.conf", argv[0]);
        return 1;
    }

    config = config_open(argv[1]);
    if (!config) {
        lwan_status_critical_perror("Could not open configuration file %s",
                                    argv[1]);
        return 1;
    }

    dump(config, 0);

    if (config_last_error(config)) {
        lwan_status_critical("Error while reading configuration file (line %d): %s\n",
                             config_cur_line(config),
                             config_last_error(config));
    }

    config_close(config);

    return 0;
}
