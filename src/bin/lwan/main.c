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

#define _GNU_SOURCE
#include <getopt.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>

#include "lwan.h"
#include "lwan-mod-serve-files.h"

enum args {
    ARGS_FAILED,
    ARGS_USE_CONFIG,
    ARGS_SERVE_FILES
};

static enum args
parse_args(int argc, char *argv[], struct lwan_config *config, char *root,
    struct lwan_straitjacket *sj)
{
    static const struct option opts[] = {
        { .name = "root", .has_arg = 1, .val = 'r' },
        { .name = "listen", .has_arg = 1, .val = 'l' },
        { .name = "help", .val = 'h' },
        { .name = "config", .has_arg = 1, .val = 'c' },
        { .name = "chroot", .val = 'C' },
        { .name = "user", .val = 'u', .has_arg = 1 },
        { }
    };
    int c, optidx = 0;
    enum args result = ARGS_USE_CONFIG;

    while ((c = getopt_long(argc, argv, "hr:l:c:u:C", opts, &optidx)) != -1) {
        switch (c) {
        case 'u':
            free((char *)sj->user_name);
            sj->user_name = (const char *)strdup(optarg);
            break;

        case 'C':
            sj->chroot_path = root;
            break;

        case 'c':
            free(config->config_file_path);
            config->config_file_path = strdup(optarg);
            result = ARGS_USE_CONFIG;
            break;

        case 'l':
            free(config->listener);
            config->listener = strdup(optarg);
            result = ARGS_SERVE_FILES;
            break;

        case 'r': {
            size_t len = strlen(optarg);

            if (len >= PATH_MAX) {
                fprintf(stderr, "Root path length exeeds %d characters\n", PATH_MAX);
                return ARGS_FAILED;
            }

            memcpy(root, optarg, len + 1);
            result = ARGS_SERVE_FILES;
            break;
        }

        case 'h':
            printf("Usage: %s [--root /path/to/root/dir] [--listen addr:port]\n", argv[0]);
            printf("\t[--config] [--user username] [--chroot]\n");
            printf("Serve files through HTTP.\n\n");
            printf("Defaults to listening on %s, serving from ./wwwroot.\n\n", config->listener);
            printf("Options:\n");
            printf("\t-r, --root      Path to serve files from (default: ./wwwroot).\n");
            printf("\t-l, --listen    Listener (default: %s).\n", config->listener);
            printf("\t-c, --config    Path to config file path.\n");
            printf("\t-u, --user      Username to drop privileges to (root required).\n");
            printf("\t-C, --chroot    Chroot to path passed to --root (root required).\n");
            printf("\t-h, --help      This.\n");
            printf("\n");
            printf("Examples:\n");
            printf("  Serve system-wide documentation: %s -r /usr/share/doc\n", argv[0]);
            printf("        Serve on a different port: %s -l '*:1337'\n", argv[0]);
            printf("\n");
            printf("Report bugs at <https://github.com/lpereira/lwan>.\n");
            return ARGS_FAILED;

        default:
            printf("Run %s --help for usage information.\n", argv[0]);
            return ARGS_FAILED;
        }
    }

    return result;
}

int
main(int argc, char *argv[])
{
    struct lwan l;
    struct lwan_config c;
    struct lwan_straitjacket sj = {};
    char root_buf[PATH_MAX];
    char *root = root_buf;
    int ret = EXIT_SUCCESS;

    if (!getcwd(root, PATH_MAX))
        return 1;

    c = *lwan_get_default_config();
    c.listener = strdup("*:8080");

    switch (parse_args(argc, argv, &c, root, &sj)) {
    case ARGS_SERVE_FILES:
        lwan_status_info("Serving files from %s", root);

        if (sj.chroot_path) {
            root = "/";
        }
        lwan_straitjacket_enforce(&sj);

        lwan_init_with_config(&l, &c);

        const struct lwan_url_map map[] = {
            { .prefix = "/", SERVE_FILES(root) },
            { }
        };
        lwan_set_url_map(&l, map);
        break;
    case ARGS_USE_CONFIG:
        lwan_straitjacket_enforce(&sj);
        if (c.config_file_path)
            lwan_init_with_config(&l, &c);
        else
            lwan_init(&l);
        break;
    case ARGS_FAILED:
        ret = EXIT_FAILURE;
        goto out;
    }

    lwan_main_loop(&l);
    lwan_shutdown(&l);

out:
    free(c.listener);
    free(c.config_file_path);
    free((char *)sj.user_name);

    return ret;
}
