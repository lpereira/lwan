/*
 * lwan - simple web server
 * Copyright (c) 2012, 2013 Leandro A. F. Pereira <leandro@hardinfo.org>
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
#include <assert.h>
#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#if defined(__FreeBSD__)
#include <sys/sysctl.h>
#endif

#include "lwan.h"
#include "lwan-private.h"

#include "lwan-config.h"
#include "lwan-http-authorize.h"
#include "lwan-redirect.h"
#include "lwan-rewrite.h"
#include "lwan-serve-files.h"

#if defined(HAVE_LUA)
#include "lwan-lua.h"
#endif

static const lwan_config_t default_config = {
    .listener = "localhost:8080",
    .keep_alive_timeout = 15,
    .quiet = false,
    .reuse_port = false,
    .proxy_protocol = false,
    .expires = 1 * ONE_WEEK,
    .n_threads = 0
};

static void lwan_module_init(lwan_t *l)
{
    if (!l->module_registry) {
        lwan_status_debug("Initializing module registry");
        l->module_registry = hash_str_new(NULL, NULL);
    }
}

static void lwan_module_shutdown(lwan_t *l)
{
    hash_free(l->module_registry);
}

static void *find_handler_symbol(const char *name)
{
    void *symbol = dlsym(RTLD_NEXT, name);
    if (!symbol)
        symbol = dlsym(RTLD_DEFAULT, name);
    return symbol;
}

static const lwan_module_t *lwan_module_find(lwan_t *l, const char *name)
{
    lwan_module_t *module = hash_find(l->module_registry, name);
    if (!module) {
        lwan_module_t *(*module_fn)(void);
        char module_symbol[128];
        int r;

        for (const char *p = name; *p; p++) {
            if (isalnum(*p) || *p == '_')
                continue;

            lwan_status_error("Module name (%s) contains invalid character: %c",
                name, *p);
            return NULL;
        }

        r = snprintf(module_symbol, sizeof(module_symbol),
            "lwan_module_%s", name);
        if (r < 0 || r >= (int)sizeof(module_symbol)) {
            lwan_status_error("Module name too long: %s", name);
            return NULL;
        }

        module_fn = find_handler_symbol(module_symbol);
        if (!module_fn) {
            lwan_status_error("Module \"%s\" does not exist", name);
            return NULL;
        }

        module = module_fn();
        if (!module) {
            lwan_status_error("Function \"%s()\" didn't return a module",
                module_symbol);
            return NULL;
        }

        lwan_status_debug("Module \"%s\" registered", name);
        hash_add(l->module_registry, name, module);
    }

    return module;
}

static void destroy_urlmap(void *data)
{
    lwan_url_map_t *url_map = data;

    if (url_map->module) {
        const lwan_module_t *module = url_map->module;
        if (module->shutdown)
            module->shutdown(url_map->data);
    } else if (url_map->data && url_map->flags & HANDLER_DATA_IS_HASH_TABLE) {
        hash_free(url_map->data);
    }

    free(url_map->authorization.realm);
    free(url_map->authorization.password_file);
    free((char *)url_map->prefix);
    free(url_map);
}

static lwan_url_map_t *add_url_map(lwan_trie_t *t, const char *prefix, const lwan_url_map_t *map)
{
    lwan_url_map_t *copy = malloc(sizeof(*copy));

    if (!copy)
        lwan_status_critical_perror("Could not copy URL map");

    memcpy(copy, map, sizeof(*copy));

    copy->prefix = strdup(prefix ? prefix : copy->prefix);
    copy->prefix_len = strlen(copy->prefix);
    lwan_trie_add(t, copy->prefix, copy);

    return copy;
}

static void parse_listener_prefix_authorization(config_t *c,
                    config_line_t *l, lwan_url_map_t *url_map)
{
    if (strcmp(l->section.param, "basic")) {
        config_error(c, "Only basic authorization supported");
        return;
    }

    memset(&url_map->authorization, 0, sizeof(url_map->authorization));

    while (config_read_line(c, l)) {
        switch (l->type) {
        case CONFIG_LINE_TYPE_LINE:
            if (!strcmp(l->line.key, "realm")) {
                free(url_map->authorization.realm);
                url_map->authorization.realm = strdup(l->line.value);
            } else if (!strcmp(l->line.key, "password_file")) {
                free(url_map->authorization.password_file);
                url_map->authorization.password_file = strdup(l->line.value);
            }
            break;

        case CONFIG_LINE_TYPE_SECTION:
            config_error(c, "Unexpected section: %s", l->section.name);
            goto error;

        case CONFIG_LINE_TYPE_SECTION_END:
            if (!url_map->authorization.realm)
                url_map->authorization.realm = strdup("Lwan");
            if (!url_map->authorization.password_file)
                url_map->authorization.password_file = strdup("htpasswd");

            url_map->flags |= HANDLER_MUST_AUTHORIZE;
            goto out;
        }
    }

out:
    return;

error:
    free(url_map->authorization.realm);
    free(url_map->authorization.password_file);
}

static void parse_listener_prefix(config_t *c, config_line_t *l, lwan_t *lwan,
    const lwan_module_t *module)
{
    lwan_url_map_t url_map = { };
    struct hash *hash = hash_str_new(free, free);
    void *handler = NULL;
    char *prefix = strdupa(l->line.value);
    config_t isolated = { };

    if (!config_isolate_section(c, l, &isolated)) {
        config_error(c, "Could not isolate configuration file");
        goto out;
    }

    while (config_read_line(c, l)) {
      switch (l->type) {
      case CONFIG_LINE_TYPE_LINE:
          if (!strcmp(l->line.key, "module")) {
              if (module) {
                  config_error(c, "Module already specified");
                  goto out;
              }
              module = lwan_module_find(lwan, l->line.value);
              if (!module) {
                  config_error(c, "Could not find module \"%s\"", l->line.value);
                  goto out;
              }
          } else if (!strcmp(l->line.key, "handler")) {
              handler = find_handler_symbol(l->line.value);
              if (!handler) {
                  config_error(c, "Could not find handler \"%s\"", l->line.value);
                  goto out;
              }
          } else {
              hash_add(hash, strdup(l->line.key), strdup(l->line.value));
          }

          break;
      case CONFIG_LINE_TYPE_SECTION:
          if (!strcmp(l->section.name, "authorization")) {
              parse_listener_prefix_authorization(c, l, &url_map);
          } else {
              if (!config_skip_section(c, l)) {
                  config_error(c, "Could not skip section");
                  goto out;
              }
          }

          break;
      case CONFIG_LINE_TYPE_SECTION_END:
          goto add_map;
      }
    }

    config_error(c, "Expecting section end while parsing prefix");
    goto out;

add_map:
    if (module == handler && !handler) {
        config_error(c, "Missing module or handler");
        goto out;
    }
    if (module && handler) {
        config_error(c, "Handler and module are mutually exclusive");
        goto out;
    }

    if (handler) {
        url_map.handler = handler;
        url_map.flags |= HANDLER_PARSE_MASK | HANDLER_DATA_IS_HASH_TABLE;
        url_map.data = hash;
        url_map.module = NULL;

        hash = NULL;
    } else if (module && module->init_from_hash && module->handle) {
        url_map.data = module->init_from_hash(hash);
        if (isolated.file && module->parse_conf) {
            if (!module->parse_conf(url_map.data, &isolated)) {
                config_error(c, "Error from module: %s",
                    isolated.error_message ? isolated.error_message : "Unknown");
                goto out;
            }
        }
        url_map.handler = module->handle;
        url_map.flags |= module->flags;
        url_map.module = module;
    } else {
        config_error(c, "Invalid handler");
        goto out;
    }

    add_url_map(&lwan->url_map_trie, prefix, &url_map);

out:
    hash_free(hash);
    config_close(&isolated);
}

void lwan_set_url_map(lwan_t *l, const lwan_url_map_t *map)
{
    lwan_trie_destroy(&l->url_map_trie);
    if (UNLIKELY(!lwan_trie_init(&l->url_map_trie, destroy_urlmap)))
        lwan_status_critical_perror("Could not initialize trie");

    for (; map->prefix; map++) {
        lwan_url_map_t *copy = add_url_map(&l->url_map_trie, NULL, map);

        if (UNLIKELY(!copy))
            continue;

        if (copy->module && copy->module->init) {
            copy->data = copy->module->init(copy->args);
            copy->flags = copy->module->flags;
            copy->handler = copy->module->handle;
        } else {
            copy->flags = HANDLER_PARSE_MASK;
        }
    }
}

static void parse_listener(config_t *c, config_line_t *l, lwan_t *lwan)
{
    lwan->config.listener = strdup(l->section.param);

    while (config_read_line(c, l)) {
        switch (l->type) {
        case CONFIG_LINE_TYPE_LINE:
            config_error(c, "Expecting prefix section");
            return;
        case CONFIG_LINE_TYPE_SECTION:
            if (!strcmp(l->section.name, "prefix")) {
                parse_listener_prefix(c, l, lwan, NULL);
            } else {
                const lwan_module_t *module = lwan_module_find(lwan, l->section.name);
                if (!module) {
                    config_error(c, "Invalid section name or module not found: %s",
                        l->section.name);
                } else {
                    parse_listener_prefix(c, l, lwan, module);
                }
            }
            break;
        case CONFIG_LINE_TYPE_SECTION_END:
            return;
        }
    }

    config_error(c, "Expecting section end while parsing listener");
}

const char *get_config_path(char *path_buf)
{
    char buffer[PATH_MAX];
    char *path = NULL;
    int ret;

#if defined(__linux__)
    ssize_t path_len;

    path_len = readlink("/proc/self/exe", buffer, PATH_MAX);
    if (path_len < 0 || path_len >= PATH_MAX) {
        lwan_status_perror("readlink");
        goto out;
    }
    buffer[path_len] = '\0';
#elif defined(__FreeBSD__)
    size_t path_len = PATH_MAX;
    int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_PATHNAME, -1 };

    ret = sysctl(mib, N_ELEMENTS(mib), buffer, &path_len, NULL, 0);
    if (ret < 0) {
        lwan_status_perror("sysctl");
        goto out;
    }
#else
    goto out;
#endif

    path = strrchr(buffer, '/');
    if (!path)
        goto out;
    ret = snprintf(path_buf, PATH_MAX, "%s.conf", path + 1);
    if (ret < 0 || ret >= PATH_MAX)
        goto out;

    return path_buf;

out:
    return "lwan.conf";
}

static bool setup_from_config(lwan_t *lwan)
{
    config_t conf;
    config_line_t line;
    bool has_listener = false;
    char path_buf[PATH_MAX];
    const char *path;

    path = get_config_path(path_buf);
    lwan_status_info("Loading configuration file: %s", path);

    if (!lwan_trie_init(&lwan->url_map_trie, destroy_urlmap))
        return false;

    if (!config_open(&conf, path))
        return false;

    while (config_read_line(&conf, &line)) {
        switch (line.type) {
        case CONFIG_LINE_TYPE_LINE:
            if (!strcmp(line.line.key, "keep_alive_timeout"))
                lwan->config.keep_alive_timeout = (unsigned short)parse_long(line.line.value,
                            default_config.keep_alive_timeout);
            else if (!strcmp(line.line.key, "quiet"))
                lwan->config.quiet = parse_bool(line.line.value,
                            default_config.quiet);
            else if (!strcmp(line.line.key, "reuse_port"))
                lwan->config.reuse_port = parse_bool(line.line.value,
                            default_config.reuse_port);
            else if (!strcmp(line.line.key, "proxy_protocol"))
                lwan->config.proxy_protocol = parse_bool(line.line.value,
                            default_config.proxy_protocol);
            else if (!strcmp(line.line.key, "expires"))
                lwan->config.expires = parse_time_period(line.line.value,
                            default_config.expires);
            else if (!strcmp(line.line.key, "error_template")) {
                free(lwan->config.error_template);
                lwan->config.error_template = strdup(line.line.value);
            } else if (!strcmp(line.line.key, "threads")) {
                long n_threads = parse_long(line.line.value, default_config.n_threads);
                if (n_threads < 0)
                    config_error(&conf, "Invalid number of threads: %d", n_threads);
                lwan->config.n_threads = (unsigned short int)n_threads;
            }
            else
                config_error(&conf, "Unknown config key: %s", line.line.key);
            break;
        case CONFIG_LINE_TYPE_SECTION:
            if (!strcmp(line.section.name, "listener")) {
                if (!has_listener) {
                    parse_listener(&conf, &line, lwan);
                    has_listener = true;
                } else {
                    config_error(&conf, "Only one listener supported");
                }
            } else if (!strcmp(line.section.name, "straitjacket")) {
                lwan_straitjacket_enforce(&conf, &line);
            } else {
                config_error(&conf, "Unknown section type: %s", line.section.name);
            }
            break;
        case CONFIG_LINE_TYPE_SECTION_END:
            config_error(&conf, "Unexpected section end");
        }
    }

    if (conf.error_message) {
        lwan_status_critical("Error on config file \"%s\", line %d: %s",
              path, conf.line, conf.error_message);
    }

    config_close(&conf);

    return true;
}

static rlim_t
setup_open_file_count_limits(void)
{
    struct rlimit r;

    if (getrlimit(RLIMIT_NOFILE, &r) < 0)
        lwan_status_critical_perror("getrlimit");

    if (r.rlim_max != r.rlim_cur) {
        if (r.rlim_max == RLIM_INFINITY)
            r.rlim_cur *= 8;
        else if (r.rlim_cur < r.rlim_max)
            r.rlim_cur = r.rlim_max;
        if (setrlimit(RLIMIT_NOFILE, &r) < 0)
            lwan_status_critical_perror("setrlimit");
    }

    return r.rlim_cur;
}

static void
allocate_connections(lwan_t *l, size_t max_open_files)
{
#if defined(_ISOC11_SOURCE)
    const size_t sz = max_open_files * sizeof(lwan_connection_t);

    l->conns = aligned_alloc(64, sz);
    if (!l->conns)
        lwan_status_critical_perror("aligned_alloc");

    memset(l->conns, 0, sz);
#else
    l->conns = calloc(max_open_files, sizeof(lwan_connection_t));

    if (!l->conns)
        lwan_status_critical_perror("calloc");
#endif
}

static unsigned short int
get_number_of_cpus(void)
{
    long n_online_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (UNLIKELY(n_online_cpus < 0)) {
        lwan_status_warning("Could not get number of online CPUs, assuming 1 CPU");
        return 1;
    }
    return (unsigned short int)n_online_cpus;
}

void
lwan_init(lwan_t *l)
{
    lwan_init_with_config(l, &default_config);
}

const lwan_config_t *
lwan_get_default_config(void)
{
    return &default_config;
}

void
lwan_init_with_config(lwan_t *l, const lwan_config_t *config)
{
    /* Load defaults */
    memset(l, 0, sizeof(*l));
    memcpy(&l->config, config, sizeof(*config));

    /* Initialize status first, as it is used by other things during
     * their initialization. */
    lwan_status_init(l);

    /* These will only print debugging messages. Debug messages are always
     * printed if we're on a debug build, so the quiet setting will be
     * respected. */
    lwan_job_thread_init();
    lwan_tables_init();

    lwan_module_init(l);

    /* Load the configuration file. */
    if (config == &default_config) {
        if (!setup_from_config(l))
            lwan_status_warning("Could not read config file, using defaults");

        /* `quiet` key might have changed value. */
        lwan_status_init(l);
    }

    lwan_response_init(l);

    /* Continue initialization as normal. */
    lwan_status_debug("Initializing lwan web server");

    if (!l->config.n_threads) {
        l->thread.count = get_number_of_cpus();
        if (l->thread.count == 1)
            l->thread.count = 2;
    } else {
        l->thread.count = l->config.n_threads;
    }

    rlim_t max_open_files = setup_open_file_count_limits();
    allocate_connections(l, (size_t)max_open_files);

    l->thread.max_fd = (unsigned)max_open_files / (unsigned)l->thread.count;
    lwan_status_info("Using %d threads, maximum %d sockets per thread",
        l->thread.count, l->thread.max_fd);

    signal(SIGPIPE, SIG_IGN);

    lwan_thread_init(l);
    lwan_socket_init(l);
    lwan_http_authorize_init();
}

void
lwan_shutdown(lwan_t *l)
{
    lwan_status_info("Shutting down");

    if (l->config.listener != default_config.listener)
        free(l->config.listener);
    free(l->config.error_template);

    lwan_job_thread_shutdown();
    lwan_thread_shutdown(l);

    lwan_status_debug("Shutting down URL handlers");
    lwan_trie_destroy(&l->url_map_trie);

    free(l->conns);

    lwan_response_shutdown(l);
    lwan_tables_shutdown();
    lwan_status_shutdown(l);
    lwan_http_authorize_shutdown();
    lwan_module_shutdown(l);
}

static ALWAYS_INLINE void
schedule_client(lwan_t *l, int fd)
{
    int thread;
#ifdef __x86_64__
    static_assert(sizeof(lwan_connection_t) == 32,
                                        "Two connections per cache line");
    /* Since lwan_connection_t is guaranteed to be 32-byte long, two of them
     * can fill up a cache line.  This formula will group two connections
     * per thread in a way that false-sharing is avoided.  This gives wrong
     * results when fd=0, but this shouldn't happen (as 0 is either the
     * standard input or the main socket, but even if that changes,
     * scheduling will still work).  */
    thread = ((fd - 1) / 2) % l->thread.count;
#else
    static int counter = 0;
    thread = counter++ % l->thread.count;
#endif
    lwan_thread_t *t = &l->thread.threads[thread];
    lwan_thread_add_client(t, fd);
}

static volatile sig_atomic_t main_socket = -1;

static_assert(sizeof(main_socket) >= sizeof(int), "size of sig_atomic_t > size of int");

static void
sigint_handler(int signal_number __attribute__((unused)))
{
    if (main_socket < 0)
        return;
    shutdown((int)main_socket, SHUT_RDWR);
    close((int)main_socket);
    main_socket = -1;
}

void
lwan_main_loop(lwan_t *l)
{
    assert(main_socket == -1);
    main_socket = l->main_socket;
    if (signal(SIGINT, sigint_handler) == SIG_ERR)
        lwan_status_critical("Could not set signal handler");

    lwan_status_info("Ready to serve");

    for (;;) {
        int client_fd = accept4((int)main_socket, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (UNLIKELY(client_fd < 0)) {
            switch (errno) {
            case EBADF:
            case ECONNABORTED:
                if (main_socket < 0) {
                    lwan_status_info("Signal 2 (Interrupt) received");
                } else {
                    lwan_status_info("Main socket closed for unknown reasons");
                }
                return;
            }

            lwan_status_perror("accept");
        } else {
            schedule_client(l, client_fd);
        }
    }
}
