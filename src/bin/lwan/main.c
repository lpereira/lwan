/*
 * lwan - web server
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
    int count = 0;

    printf("Built-in modules:");
    LWAN_SECTION_FOREACH(lwan_module, module) {
        printf(" %s", module->name);
        count++;
    }
    printf(count ? ".\n" : " (none)\n");
}

static void
print_handler_info(void)
{
    const struct lwan_handler_info *handler;
    int count = 0;

    printf("Built-in handlers:");
    LWAN_SECTION_FOREACH(lwan_handler, handler) {
        if (!handler->route)
            continue;

        printf(" %s", handler->name);
        count++;
    }
    printf(count ? ".\n" : " (none)\n");
}

static void
print_build_time_configuration(void)
{
    printf("Build-time configuration:");

#if defined(LWAN_HAVE_LUA_JIT)
    printf(" LuaJIT");
#elif defined(LWAN_HAVE_LUA)
    printf(" Lua");
#endif

#if defined(LWAN_HAVE_BROTLI)
    printf(" Brotli");
#endif
#if defined(LWAN_HAVE_ZSTD)
    printf(" zstd");
#endif

#if defined(LWAN_HAVE_MBEDTLS)
    printf(" mbedTLS");
#endif

#if defined(LWAN_HAVE_LIBUCONTEXT)
    printf(" libucontext-coroutine");
#else
    printf(" builtin-coroutine");
#endif

#if defined(LWAN_HAVE_EPOLL)
    printf(" epoll");
#elif defined(LWAN_HAVE_KQUEUE)
    printf(" kqueue");
#endif

#if defined(LWAN_HAVE_SO_ATTACH_REUSEPORT_CBPF)
    printf(" sockopt-reuseport-CBPF");
#elif defined(LWAN_HAVE_SO_INCOMING_CPU)
    printf(" sockopt-reuseport-incoming-cpu");
#endif

#if defined(LWAN_HAVE_VALGRIND)
    printf(" valgrind");
#endif

#if defined(LWAN_HAVE_SYSLOG)
    printf(" syslog");
#endif

#if defined(LWAN_HAVE_UNDEFINED_SANITIZER)
    printf(" ubsan");
#endif

#if defined(LWAN_HAVE_ADDRESS_SANITIZER)
    printf(" asan");
#endif

#if defined(LWAN_HAVE_THREAD_SANITIZER)
    printf(" tsan");
#endif

#if !defined(NDEBUG)
    printf(" debug");
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
#if defined(LWAN_HAVE_MBEDTLS)
    printf("       [--tls-listen addr:port] [--cert-path /cert/path] [--cert-key /key/path]\n");
#endif
    printf("       [--config /path/to/config/file] [--user username]\n");
    printf("       [--chroot /path/to/chroot/directory]\n");
    printf("\n");
#if defined(LWAN_HAVE_MBEDTLS)
    printf("Serve files through HTTP or HTTPS.\n\n");
#else
    printf("Serve files through HTTP.\n\n");
#endif
    printf("Options:\n");
    printf("  -r, --root       Path to serve files from (default: ./wwwroot).\n");
    printf("\n");
    printf("  -l, --listen     Listener (default: %s).\n", config->listener);
#if defined(LWAN_HAVE_MBEDTLS)
    printf("  -L, --tls-listen TLS Listener (default: %s).\n",
            config->tls_listener ?
            config->tls_listener : "not listening");
#endif
    printf("\n");
    printf("  -c, --config     Path to config file path.\n");
    printf("  -u, --user       Username to drop privileges to (root required).\n");
    printf("  -C, --chroot     Chroot to path passed to --root (root required).\n");
#if defined(LWAN_HAVE_MBEDTLS)
    printf("\n");
    printf("  -P, --cert-path  Path to TLS certificate.\n");
    printf("  -K, --cert-key   Path to TLS key.\n");
#endif
    printf("\n");
    printf("  -h, --help       This.\n");
    printf("\n");
    printf("Examples:\n");
    if (!access("/usr/share/doc", R_OK)) {
        printf("  Serve system-wide documentation:\n");
        printf("    %s -r /usr/share/doc\n", argv0);
    }
    printf("  Serve on a different port:\n");
    printf("    %s -l '*:1337'\n", argv0);
    printf("  Use %s from %s:\n", config_file, current_dir);
    printf("    %s\n", argv0);
    printf("  Use /etc/%s:\n", config_file);
    printf("    %s -c /etc/%s\n", argv0, config_file);
#if defined(LWAN_HAVE_MBEDTLS)
    printf("  Serve system docs with HTTP and HTTPS:\n");
    printf("    %s -P /path/to/cert.pem -K /path/to/cert.key \\\n"
           "       -l '*:8080' -L '*:8081' -r /usr/share/doc\n", argv0);
#endif
    printf("\n");
    print_build_time_configuration();
    print_module_info();
    print_handler_info();
    printf("\n");
    printf("Report bugs at <https://github.com/lpereira/lwan>.\n");
    printf("For security-related reports, mail them to <security@tia.mat.br>.\n");

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
#if defined(LWAN_HAVE_MBEDTLS)
        { .name = "tls-listen", .val = 'L', .has_arg = 1 },
        { .name = "cert-path", .val = 'P', .has_arg = 1 },
        { .name = "cert-key", .val = 'K', .has_arg = 1 },
#endif
        { }
    };
    int c, optidx = 0;
    enum args result = ARGS_USE_CONFIG;

    while ((c = getopt_long(argc, argv, "L:P:K:hr:l:c:u:C", opts, &optidx)) != -1) {
        switch (c) {
#if defined(LWAN_HAVE_MBEDTLS)
        case 'L':
            free(config->tls_listener);
            config->tls_listener = strdup(optarg);
            result = ARGS_SERVE_FILES;
            break;

        case 'P':
            free(config->ssl.cert);
            config->ssl.cert = strdup(optarg);
            break;

        case 'K':
            free(config->ssl.key);
            config->ssl.key = strdup(optarg);
            break;
#endif
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
