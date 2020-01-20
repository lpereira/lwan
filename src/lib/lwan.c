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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#define _GNU_SOURCE
#include <assert.h>
#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "lwan-private.h"

#include "lwan-config.h"
#include "lwan-http-authorize.h"

#if defined(HAVE_LUA)
#include "lwan-lua.h"
#endif

/* See detect_fastest_monotonic_clock() */
clockid_t monotonic_clock_id = CLOCK_MONOTONIC;

static const struct lwan_config default_config = {
    .listener = "localhost:8080",
    .keep_alive_timeout = 15,
    .quiet = false,
    .reuse_port = false,
    .proxy_protocol = false,
    .allow_cors = false,
    .expires = 1 * ONE_WEEK,
    .n_threads = 0,
    .max_post_data_size = 10 * DEFAULT_BUFFER_SIZE,
    .allow_post_temp_file = false,
};

LWAN_HANDLER(brew_coffee)
{
    /* Placeholder handler so that __start_lwan_handler and __stop_lwan_handler
     * symbols will get defined.
     */
    return HTTP_I_AM_A_TEAPOT;
}

__attribute__((no_sanitize_address))
static void *find_handler(const char *name)
{
    const struct lwan_handler_info *handler;

    LWAN_SECTION_FOREACH(lwan_handler, handler) {
        if (streq(handler->name, name))
            return handler->handler;
    }

    return NULL;
}

__attribute__((no_sanitize_address))
static const struct lwan_module *find_module(const char *name)
{
    const struct lwan_module_info *module;

    LWAN_SECTION_FOREACH(lwan_module, module) {
        if (streq(module->name, name))
            return module->module;
    }

    return NULL;
}

static void destroy_urlmap(void *data)
{
    struct lwan_url_map *url_map = data;

    if (url_map->module) {
        const struct lwan_module *module = url_map->module;

        if (module->destroy)
            module->destroy(url_map->data);
    } else if (url_map->data && url_map->flags & HANDLER_DATA_IS_HASH_TABLE) {
        hash_free(url_map->data);
    }

    free(url_map->authorization.realm);
    free(url_map->authorization.password_file);
    free((char *)url_map->prefix);
    free(url_map);
}

static struct lwan_url_map *add_url_map(struct lwan_trie *t, const char *prefix,
                                        const struct lwan_url_map *map)
{
    struct lwan_url_map *copy = malloc(sizeof(*copy));

    if (!copy)
        lwan_status_critical_perror("Could not copy URL map");

    memcpy(copy, map, sizeof(*copy));

    copy->prefix = strdup(prefix ? prefix : copy->prefix);
    if (!copy->prefix)
        lwan_status_critical_perror("Could not copy URL prefix");

    copy->prefix_len = strlen(copy->prefix);
    lwan_trie_add(t, copy->prefix, copy);

    return copy;
}

static void parse_listener_prefix_authorization(struct config *c,
                                                const struct config_line *l,
                                                struct lwan_url_map *url_map)
{
    if (!streq(l->value, "basic")) {
        config_error(c, "Only basic authorization supported");
        return;
    }

    memset(&url_map->authorization, 0, sizeof(url_map->authorization));

    while ((l = config_read_line(c))) {
        switch (l->type) {
        case CONFIG_LINE_TYPE_LINE:
            if (streq(l->key, "realm")) {
                free(url_map->authorization.realm);
                url_map->authorization.realm = strdup(l->value);
            } else if (streq(l->key, "password_file")) {
                free(url_map->authorization.password_file);
                url_map->authorization.password_file = realpath(l->value, NULL);
                if (!url_map->authorization.password_file)
                    config_error(c, "Could not determine full path for password file: %s", l->value);
            }
            break;

        case CONFIG_LINE_TYPE_SECTION:
            config_error(c, "Unexpected section: %s", l->key);
            goto error;

        case CONFIG_LINE_TYPE_SECTION_END:
            if (!url_map->authorization.realm)
                url_map->authorization.realm = strdup("Lwan");
            if (!url_map->authorization.password_file)
                url_map->authorization.password_file = strdup("htpasswd");

            url_map->flags |= HANDLER_MUST_AUTHORIZE;
            return;
        }
    }

    config_error(c, "Could not find end of authorization section");

error:
    free(url_map->authorization.realm);
    free(url_map->authorization.password_file);
}

static void parse_listener_prefix(struct config *c,
                                  const struct config_line *l,
                                  struct lwan *lwan,
                                  const struct lwan_module *module,
                                  void *handler)
{
    struct lwan_url_map url_map = {};
    struct hash *hash = hash_str_new(free, free);
    char *prefix = strdupa(l->value);
    struct config *isolated;

    isolated = config_isolate_section(c, l);
    if (!isolated) {
        config_error(c, "Could not isolate configuration file");
        goto out;
    }

    while ((l = config_read_line(c))) {
        switch (l->type) {
        case CONFIG_LINE_TYPE_LINE:
            hash_add(hash, strdup(l->key), strdup(l->value));
            break;

        case CONFIG_LINE_TYPE_SECTION:
            if (streq(l->key, "authorization")) {
                parse_listener_prefix_authorization(c, l, &url_map);
            } else if (!config_skip_section(c, l)) {
                config_error(c, "Could not skip section");
                goto out;
            }
            break;

        case CONFIG_LINE_TYPE_SECTION_END:
            goto add_map;
        }
    }

    config_error(c, "Expecting section end while parsing prefix");
    goto out;

add_map:
    assert((handler && !module) || (!handler && module));

    if (handler) {
        url_map.handler = handler;
        url_map.flags |= HANDLER_PARSE_MASK | HANDLER_DATA_IS_HASH_TABLE;
        url_map.data = hash;
        url_map.module = NULL;

        hash = NULL;
    } else if (module->create_from_hash && module->handle_request) {
        url_map.data = module->create_from_hash(prefix, hash);
        if (!url_map.data) {
            config_error(c, "Could not create module instance");
            goto out;
        }

        if (module->parse_conf && !module->parse_conf(url_map.data, isolated)) {
            const char *msg = config_last_error(isolated);

            config_error(c, "Error from module: %s", msg ? msg : "Unknown");
            goto out;
        }

        url_map.handler = module->handle_request;
        url_map.flags |= module->flags;
        url_map.module = module;
    } else if (UNLIKELY(!module->create_from_hash)) {
        config_error(c, "Module isn't prepared to load settings from a file; "
                        "create_from_hash() method isn't present");
        goto out;
    } else if (UNLIKELY(!module->handle_request)) {
        config_error(c, "Module does not have handle_request() method");
        goto out;
    }

    add_url_map(&lwan->url_map_trie, prefix, &url_map);

out:
    hash_free(hash);
    config_close(isolated);
}

void lwan_set_url_map(struct lwan *l, const struct lwan_url_map *map)
{
    lwan_trie_destroy(&l->url_map_trie);
    if (UNLIKELY(!lwan_trie_init(&l->url_map_trie, destroy_urlmap)))
        lwan_status_critical_perror("Could not initialize trie");

    for (; map->prefix; map++) {
        struct lwan_url_map *copy = add_url_map(&l->url_map_trie, NULL, map);

        if (copy->module && copy->module->create) {
            copy->data = copy->module->create (map->prefix, copy->args);
            copy->flags = copy->module->flags;
            copy->handler = copy->module->handle_request;
        } else {
            copy->flags = HANDLER_PARSE_MASK;
        }
    }
}

static void parse_listener(struct config *c,
                           const struct config_line *l,
                           struct lwan *lwan)
{
    free(lwan->config.listener);
    lwan->config.listener = strdup(l->value);

    while ((l = config_read_line(c))) {
        switch (l->type) {
        case CONFIG_LINE_TYPE_LINE:
            config_error(c, "Expecting prefix section");
            return;
        case CONFIG_LINE_TYPE_SECTION:
            if (l->key[0] == '&') {
                void *handler = find_handler(l->key + 1);
                if (handler) {
                    parse_listener_prefix(c, l, lwan, NULL, handler);
                    continue;
                }

                config_error(c, "Could not find handler name: %s", l->key + 1);
                return;
            }

            const struct lwan_module *module = find_module(l->key);
            if (module) {
                parse_listener_prefix(c, l, lwan, module, NULL);
                continue;
            }

            config_error(c, "Invalid section or module not found: %s", l->key);
            return;
        case CONFIG_LINE_TYPE_SECTION_END:
            return;
        }
    }

    config_error(c, "Expecting section end while parsing listener");
}

const char *lwan_get_config_path(char *path_buf, size_t path_buf_len)
{
    char buffer[PATH_MAX];

    if (proc_pidpath(getpid(), buffer, sizeof(buffer)) < 0)
        goto out;

    char *path = strrchr(buffer, '/');
    if (!path)
        goto out;
    int ret = snprintf(path_buf, path_buf_len, "%s.conf", path + 1);
    if (ret < 0 || ret >= (int)path_buf_len)
        goto out;

    return path_buf;

out:
    return "lwan.conf";
}

static bool setup_from_config(struct lwan *lwan, const char *path)
{
    const struct config_line *line;
    struct config *conf;
    bool has_listener = false;
    char path_buf[PATH_MAX];

    if (!path)
        path = lwan_get_config_path(path_buf, sizeof(path_buf));
    lwan_status_info("Loading configuration file: %s", path);

    conf = config_open(path);
    if (!conf)
        return false;

    if (!lwan_trie_init(&lwan->url_map_trie, destroy_urlmap))
        return false;

    while ((line = config_read_line(conf))) {
        switch (line->type) {
        case CONFIG_LINE_TYPE_LINE:
            if (streq(line->key, "keep_alive_timeout")) {
                lwan->config.keep_alive_timeout = (unsigned short)parse_long(
                    line->value, default_config.keep_alive_timeout);
            } else if (streq(line->key, "quiet")) {
                lwan->config.quiet =
                    parse_bool(line->value, default_config.quiet);
            } else if (streq(line->key, "reuse_port")) {
                lwan->config.reuse_port =
                    parse_bool(line->value, default_config.reuse_port);
            } else if (streq(line->key, "proxy_protocol")) {
                lwan->config.proxy_protocol =
                    parse_bool(line->value, default_config.proxy_protocol);
            } else if (streq(line->key, "allow_cors")) {
                lwan->config.allow_cors =
                    parse_bool(line->value, default_config.allow_cors);
            } else if (streq(line->key, "expires")) {
                lwan->config.expires =
                    parse_time_period(line->value, default_config.expires);
            } else if (streq(line->key, "error_template")) {
                free(lwan->config.error_template);
                lwan->config.error_template = strdup(line->value);
            } else if (streq(line->key, "threads")) {
                long n_threads =
                    parse_long(line->value, default_config.n_threads);
                if (n_threads < 0)
                    config_error(conf, "Invalid number of threads: %ld",
                                 n_threads);
                lwan->config.n_threads = (unsigned short int)n_threads;
            } else if (streq(line->key, "max_post_data_size")) {
                long max_post_data_size = parse_long(
                    line->value, (long)default_config.max_post_data_size);
                if (max_post_data_size < 0)
                    config_error(conf, "Negative maximum post data size");
                else if (max_post_data_size > 128 * (1 << 20))
                    config_error(conf,
                                 "Maximum post data can't be over 128MiB");
                lwan->config.max_post_data_size = (size_t)max_post_data_size;
            } else if (streq(line->key, "allow_temp_files")) {
                lwan->config.allow_post_temp_file =
                    !!strstr(line->value, "post");
            } else {
                config_error(conf, "Unknown config key: %s", line->key);
            }
            break;
        case CONFIG_LINE_TYPE_SECTION:
            if (streq(line->key, "listener")) {
                if (!has_listener) {
                    parse_listener(conf, line, lwan);
                    has_listener = true;
                } else {
                    config_error(conf, "Only one listener supported");
                }
            } else if (streq(line->key, "straitjacket")) {
                lwan_straitjacket_enforce_from_config(conf);
            } else {
                config_error(conf, "Unknown section type: %s", line->key);
            }
            break;
        case CONFIG_LINE_TYPE_SECTION_END:
            config_error(conf, "Unexpected section end");
        }
    }

    if (config_last_error(conf)) {
        lwan_status_critical("Error on config file \"%s\", line %d: %s", path,
                             config_cur_line(conf), config_last_error(conf));
    }

    config_close(conf);

    return true;
}

static void try_setup_from_config(struct lwan *l,
                                  const struct lwan_config *config)
{
    if (!setup_from_config(l, config->config_file_path)) {
        if (config->config_file_path) {
            lwan_status_critical("Could not read config file: %s",
                                 config->config_file_path);
        }
    }

    lwan_status_init(l); /* `quiet` key might have changed value. */

    l->config.request_flags =
        (l->config.proxy_protocol ? REQUEST_ALLOW_PROXY_REQS : 0) |
        (l->config.allow_cors ? REQUEST_ALLOW_CORS : 0);
}

static rlim_t setup_open_file_count_limits(void)
{
    struct rlimit r;

    if (getrlimit(RLIMIT_NOFILE, &r) < 0) {
        lwan_status_perror("Could not obtain maximum number of file "
                           "descriptors. Assuming %d",
                           OPEN_MAX);
        return OPEN_MAX;
    }

    if (r.rlim_max != r.rlim_cur) {
        const rlim_t current = r.rlim_cur;

        if (r.rlim_max == RLIM_INFINITY && r.rlim_cur < OPEN_MAX) {
            r.rlim_cur = OPEN_MAX;
        } else if (r.rlim_cur < r.rlim_max) {
            r.rlim_cur = r.rlim_max;
        } else {
            /* Shouldn't happen, so just return the current value. */
            goto out;
        }

        if (setrlimit(RLIMIT_NOFILE, &r) < 0) {
            lwan_status_perror("Could not raise maximum number of file "
                               "descriptors to %" PRIu64 ". Leaving at "
                               "%" PRIu64, r.rlim_max, current);
            r.rlim_cur = current;
        }
    }

out:
    return r.rlim_cur;
}

static void allocate_connections(struct lwan *l, size_t max_open_files)
{
    const size_t sz = max_open_files * sizeof(struct lwan_connection);

    l->conns = lwan_aligned_alloc(sz, 64);
    if (UNLIKELY(!l->conns))
        lwan_status_critical_perror("lwan_alloc_aligned");

    memset(l->conns, 0, sz);
}

static unsigned short int get_number_of_cpus(void)
{
    long n_online_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (UNLIKELY(n_online_cpus < 0)) {
        lwan_status_warning(
            "Could not get number of online CPUs, assuming 1 CPU");
        return 1;
    }
    return (unsigned short int)n_online_cpus;
}

void lwan_init(struct lwan *l) { lwan_init_with_config(l, &default_config); }

const struct lwan_config *lwan_get_default_config(void)
{
    return &default_config;
}

static char *dup_or_null(const char *s)
{
    return s ? strdup(s) : NULL;
}

void lwan_init_with_config(struct lwan *l, const struct lwan_config *config)
{
    /* Load defaults */
    memset(l, 0, sizeof(*l));
    memcpy(&l->config, config, sizeof(*config));
    l->config.listener = dup_or_null(l->config.listener);
    l->config.config_file_path = dup_or_null(l->config.config_file_path);

    /* Initialize status first, as it is used by other things during
     * their initialization. */
    lwan_status_init(l);

    /* These will only print debugging messages. Debug messages are always
     * printed if we're on a debug build, so the quiet setting will be
     * respected. */
    lwan_job_thread_init();
    lwan_tables_init();

    try_setup_from_config(l, config);

    lwan_response_init(l);

    /* Continue initialization as normal. */
    lwan_status_debug("Initializing lwan web server");

    l->n_cpus = get_number_of_cpus();
    if (!l->config.n_threads) {
        l->thread.count = l->n_cpus;
        if (l->thread.count == 1)
            l->thread.count = 2;
    } else if (l->config.n_threads > 3 * l->n_cpus) {
        l->thread.count = (short unsigned int)(l->n_cpus * 3);

        lwan_status_warning("%d threads requested, but only %d online CPUs; "
                            "capping to %d threads",
                            l->config.n_threads, l->n_cpus, 3 * l->n_cpus);
    } else if (l->config.n_threads > 255) {
        l->thread.count = 256;

        lwan_status_warning("%d threads requested, but max 256 supported",
            l->config.n_threads);
    } else {
        l->thread.count = l->config.n_threads;
    }

    rlim_t max_open_files = setup_open_file_count_limits();
    allocate_connections(l, (size_t)max_open_files);

    l->thread.max_fd = (unsigned)max_open_files / (unsigned)l->thread.count;
    lwan_status_info("Using %d threads, maximum %d sockets per thread",
                     l->thread.count, l->thread.max_fd);

    signal(SIGPIPE, SIG_IGN);

    lwan_readahead_init();
    lwan_thread_init(l);
    lwan_socket_init(l);
    lwan_http_authorize_init();
}

void lwan_shutdown(struct lwan *l)
{
    lwan_status_info("Shutting down");

    free(l->config.listener);
    free(l->config.error_template);
    free(l->config.config_file_path);

    lwan_job_thread_shutdown();
    lwan_thread_shutdown(l);

    lwan_status_debug("Shutting down URL handlers");
    lwan_trie_destroy(&l->url_map_trie);

    free(l->conns);

    lwan_response_shutdown(l);
    lwan_tables_shutdown();
    lwan_status_shutdown(l);
    lwan_http_authorize_shutdown();
    lwan_readahead_shutdown();
}

static ALWAYS_INLINE int schedule_client(struct lwan *l, int fd)
{
    struct lwan_thread *thread = l->conns[fd].thread;

    lwan_thread_add_client(thread, fd);

    return (int)(thread - l->thread.threads);
}

static volatile sig_atomic_t main_socket = -1;

static_assert(sizeof(main_socket) >= sizeof(int),
              "size of sig_atomic_t > size of int");

static void sigint_handler(int signal_number __attribute__((unused)))
{
    if (main_socket < 0)
        return;

    shutdown((int)main_socket, SHUT_RDWR);
    close((int)main_socket);

    main_socket = -1;
}

enum herd_accept { HERD_MORE = 0, HERD_GONE = -1, HERD_SHUTDOWN = 1 };

struct core_bitmap {
    uint64_t bitmap[4];
};

static ALWAYS_INLINE enum herd_accept
accept_one(struct lwan *l, struct core_bitmap *cores)
{
    int fd = accept4((int)main_socket, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);

    if (LIKELY(fd >= 0)) {
        int core = schedule_client(l, fd);

        cores->bitmap[core / 64] |= UINT64_C(1)<<(core % 64);

        return HERD_MORE;
    }

    switch (errno) {
    case EAGAIN:
        return HERD_GONE;

    case EBADF:
    case ECONNABORTED:
    case EINVAL:
        if (main_socket < 0) {
            lwan_status_info("Signal 2 (Interrupt) received");
        } else {
            lwan_status_info("Main socket closed for unknown reasons");
        }
        return HERD_SHUTDOWN;

    default:
        lwan_status_perror("accept");
        return HERD_MORE;
    }
}

void lwan_main_loop(struct lwan *l)
{
    struct core_bitmap cores = {};

    assert(main_socket == -1);
    main_socket = l->main_socket;

    if (signal(SIGINT, sigint_handler) == SIG_ERR)
        lwan_status_critical("Could not set signal handler");

    lwan_status_info("Ready to serve");

    while (true) {
        enum herd_accept ha;

        fcntl(l->main_socket, F_SETFL, 0);
        ha = accept_one(l, &cores);
        if (ha == HERD_MORE) {
            fcntl(l->main_socket, F_SETFL, O_NONBLOCK);

            do {
                ha = accept_one(l, &cores);
            } while (ha == HERD_MORE);
        }

        if (UNLIKELY(ha > HERD_MORE))
            break;

        for (size_t i = 0; i < N_ELEMENTS(cores.bitmap); i++) {
            for (uint64_t c = cores.bitmap[i]; c; c ^= c & -c) {
                size_t core = (size_t)__builtin_ctzl(c);
                lwan_thread_nudge(&l->thread.threads[i * 64 + core]);
            }
        }
        cores = (struct core_bitmap){};
    }
}

#ifdef CLOCK_MONOTONIC_COARSE
__attribute__((constructor)) static void detect_fastest_monotonic_clock(void)
{
    struct timespec ts;

    if (!clock_gettime(CLOCK_MONOTONIC_COARSE, &ts))
        monotonic_clock_id = CLOCK_MONOTONIC_COARSE;
}
#endif

void lwan_set_thread_name(const char *name)
{
    char thread_name[16];
    char process_name[PATH_MAX];
    char *tmp;
    int ret;

    if (proc_pidpath(getpid(), process_name, sizeof(process_name)) < 0)
        return;

    tmp = strrchr(process_name, '/');
    if (!tmp)
        return;

    ret = snprintf(thread_name, sizeof(thread_name), "%s %s", tmp + 1, name);
    if (ret < 0)
        return;

    pthread_set_name_np(pthread_self(), thread_name);
}
