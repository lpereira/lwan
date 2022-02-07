/*
 * lwan - simple web server
 * Copyright (c) 2012 L. A. F. Pereira <l@tia.mat.br>
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

#include "lwan-private.h"
#include "lwan-mod-serve-files.h"

enum args {
    ARGS_FAILED,
    ARGS_USE_CONFIG,
    ARGS_SERVE_FILES
};

static void print_module_info(void)
{
    const struct lwan_module_info *module;

    printf("Available modules:\n");
    LWAN_SECTION_FOREACH(lwan_module, module) {
        printf(" * %s\n", module->name);
    }
}

static void
print_handler_info(void)
{
    const struct lwan_handler_info *handler;

    printf("Available handlers:\n");
    LWAN_SECTION_FOREACH(lwan_handler, handler) {
        printf(" * %s\n", handler->name);
    }
}

static void
print_build_time_configuration(void)
{
    printf("Build-time configuration:");
#ifdef HAVE_LUA
    printf(" Lua");
#endif
#ifdef HAVE_BROTLI
    printf(" Brotli");
#endif
#ifdef HAVE_ZSTD
    printf(" zstd");
#endif
#ifdef HAVE_MBEDTLS
    printf(" mbedTLS");
#endif
#ifdef HAVE_LIBUCONTEXT
    printf(" libucontext");
#endif
#ifdef HAVE_EPOLL
    printf(" epoll");
#endif
#ifdef HAVE_KQUEUE
    printf(" kqueue");
#endif
#ifdef HAVE_SO_ATTACH_REUSEPORT_CBPF
    printf(" sockopt-reuseport-CBPF");
#endif
#ifdef HAVE_SO_INCOMING_CPU
    printf(" sockopt-reuseport-incoming-cpu");
#endif
#ifdef HAVE_VALGRIND
    printf(" valgrind");
#endif
#ifdef HAVE_SYSLOG
    printf(" syslog");
#endif
    printf(".\n");
}

static void
print_help(const char *argv0, const struct lwan_config *config)
{
    char path_buf[PATH_MAX];
    char *current_dir = get_current_dir_name();
    const char *config_file = lwan_get_config_path(path_buf, sizeof(path_buf));

    printf("Usage: %s [--root /path/to/root/dir] [--listen addr:port]\n", argv0);
    printf("       [--config] [--user username] [--chroot] [--modules|--handlers]\n");
    printf("\n");
    printf("Serve files through HTTP.\n\n");
    printf("Options:\n");
    printf("  -r, --root      Path to serve files from (default: ./wwwroot).\n");
    printf("  -l, --listen    Listener (default: %s).\n", config->listener);
    printf("  -c, --config    Path to config file path.\n");
    printf("  -u, --user      Username to drop privileges to (root required).\n");
    printf("  -C, --chroot    Chroot to path passed to --root (root required).\n");
    printf("  -m, --modules   Print information about available modules.\n");
    printf("  -H, --handlers  Print information about available handlers.\n");
    printf("  -h, --help      This.\n");
    printf("\n");
    printf("Examples:\n");
    printf("  Serve system-wide documentation:\n");
    printf("    %s -r /usr/share/doc\n", argv0);
    printf("  Serve on a different port:\n");
    printf("    %s -l '*:1337'\n", argv0);
    printf("  Use %s from %s:\n", config_file, current_dir);
    printf("    %s\n", argv0);
    printf("  Use /etc/%s:\n", config_file);
    printf("    %s -c /etc/%s\n", argv0, config_file);
    printf("\n");
    print_build_time_configuration();
    printf("\n");
    printf("Report bugs at <https://github.com/lpereira/lwan>.\n");

    free(current_dir);
}

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
        { .name = "modules", .val = 'm' },
        { .name = "handlers", .val = 'H' },
        { }
    };
    int c, optidx = 0;
    enum args result = ARGS_USE_CONFIG;

    while ((c = getopt_long(argc, argv, "Hmhr:l:c:u:C", opts, &optidx)) != -1) {
        switch (c) {
        case 'H':
            print_handler_info();
            return ARGS_FAILED;

        case 'm':
            print_module_info();
            return ARGS_FAILED;

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
            print_help(argv[0], config);
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
            { .prefix = "/", SERVE_FILES_SETTINGS(root, "index.html", true) },
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
