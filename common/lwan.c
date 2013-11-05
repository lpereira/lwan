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
#include <dlfcn.h>
#include <limits.h>
#include <setjmp.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <unistd.h>

#include "lwan.h"
#include "lwan-private.h"
#include "lwan-config.h"
#include "lwan-serve-files.h"
#include "hash.h"

static jmp_buf cleanup_jmp_buf;

static const lwan_config_t default_config = {
    .port = 8080,
    .keep_alive_timeout = 15,
    .quiet = false,
    .reuse_port = false
};

static void *find_symbol(const char *name)
{
    /* FIXME: This is pretty ugly. Find a better way of doing this. */
    void *symbol = dlsym(RTLD_NEXT, name);
    if (!symbol)
        symbol = dlsym(RTLD_DEFAULT, name);
    if (!symbol) {
        if (!strcmp(name, "serve_files"))
            symbol = &serve_files;
    }
    return symbol;
}

static void destroy_urlmap(void *data)
{
    lwan_url_map_t *url_map = data;
    lwan_handler_t *handler = url_map->handler;

    if (handler && handler->shutdown)
        handler->shutdown(url_map->data);
    free(url_map->prefix);
    free(url_map);
}

static lwan_url_map_t *add_url_map(lwan_trie_t *t, const char *prefix, const lwan_url_map_t *map)
{
    lwan_url_map_t *copy = malloc(sizeof(*copy));

    if (!copy) {
        lwan_status_perror("Could not copy URL map");
        return NULL; /* Not reached */
    }

    memcpy(copy, map, sizeof(*copy));

    copy->prefix = strdup(prefix ? prefix : copy->prefix);
    copy->prefix_len = strlen(copy->prefix);
    lwan_trie_add(t, copy->prefix, copy);

    return copy;
}

static void parse_listener_prefix(config_t *c, config_line_t *l, lwan_t *lwan)
{
    lwan_url_map_t url_map;
    struct hash *hash = hash_str_new(free, free);
    lwan_handler_t *handler = NULL;
    void *callback = NULL;
    char *prefix = strdupa(l->line.value);
    void *data = NULL;

    while (config_read_line(c, l)) {
      switch (l->type) {
      case CONFIG_LINE_TYPE_LINE:
          if (!strcmp(l->line.key, "handler")) {
              handler = find_symbol(l->line.value);
              if (!handler) {
                  config_error(c, "Could not find handler \"%s\"", l->line.value);
                  goto out;
              }
          } else if (!strcmp(l->line.key, "callback")) {
              callback = find_symbol(l->line.value);
              if (!callback) {
                  config_error(c, "Could not find callback \"%s\"", l->line.value);
                  goto out;
              }
          } else {
              hash_add(hash, strdup(l->line.key), strdup(l->line.value));
          }

          break;
      case CONFIG_LINE_TYPE_SECTION:
          config_error(c, "Expecting line or section end");
          goto out;
      case CONFIG_LINE_TYPE_SECTION_END:
          goto add_map;
      }
    }

    config_error(c, "Expecting section end while parsing prefix");
    goto out;

add_map:
    if (handler == callback && !callback) {
        config_error(c, "Missing callback or handler");
        goto out;
    }
    if (handler && callback) {
        config_error(c, "Callback and handler are mutually exclusive");
        goto out;
    }

    if (callback) {
        url_map.callback = callback;
        url_map.flags = HANDLER_PARSE_MASK;
        url_map.data = data;
        url_map.handler = NULL;
    } else if (handler && handler->init_from_hash && handler->handle) {
        url_map.data = handler->init_from_hash(hash);
        url_map.callback = handler->handle;
        url_map.flags = handler->flags;
        url_map.handler = handler;
    } else {
        config_error(c, "Invalid handler");
        goto out;
    }

    add_url_map(lwan->url_map_trie, prefix, &url_map);

out:
    hash_free(hash);
}

void lwan_set_url_map(lwan_t *l, const lwan_url_map_t *map)
{
    lwan_trie_destroy(l->url_map_trie);
    l->url_map_trie = lwan_trie_new(destroy_urlmap);

    for (; map->prefix; map++) {
        lwan_url_map_t *copy = add_url_map(l->url_map_trie, NULL, map);

        if (copy->handler && copy->handler->init) {
            copy->data = copy->handler->init(copy->args);
            copy->flags = copy->handler->flags;
            copy->callback = copy->handler->handle;
        } else {
            copy->flags = HANDLER_PARSE_MASK;
        }
    }
}

static void parse_listener(config_t *c, config_line_t *l, lwan_t *lwan)
{
    lwan->config.port = parse_int(l->section.param, 8080);

    while (config_read_line(c, l)) {
        switch (l->type) {
        case CONFIG_LINE_TYPE_LINE:
            config_error(c, "Expecting prefix section");
            return;
        case CONFIG_LINE_TYPE_SECTION:
            if (!strcmp(l->section.name, "prefix"))
                parse_listener_prefix(c, l, lwan);
            else
                config_error(c, "Unknown section type: %s", l->section.name);
            break;
        case CONFIG_LINE_TYPE_SECTION_END:
            return;
        }
    }

    config_error(c, "Expecting section end while parsing listener");
}

const char *get_config_path(char *path_buf)
{
    char *path = NULL;
    ssize_t path_len;

    /* FIXME: This should ideally (and portably) done by using argv[0] */

    path_len = readlink("/proc/self/exe", path_buf, PATH_MAX);
    if (path_len < 0)
        goto out;
    path_buf[path_len] = '\0';
    path = strrchr(path_buf, '/');
    if (!path)
        goto out;
    if (snprintf(path_buf, PATH_MAX, "%s.conf", path + 1) < 0)
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

    lwan->url_map_trie = lwan_trie_new(destroy_urlmap);

    if (!config_open(&conf, path))
        return false;

    while (config_read_line(&conf, &line)) {
        switch (line.type) {
        case CONFIG_LINE_TYPE_LINE:
            if (!strcmp(line.line.key, "keep_alive_timeout"))
                lwan->config.keep_alive_timeout = parse_int(line.line.value,
                            default_config.keep_alive_timeout);
            else if (!strcmp(line.line.key, "quiet"))
                lwan->config.quiet = parse_bool(line.line.value,
                            default_config.quiet);
            else if (!strcmp(line.line.key, "reuse_port"))
                lwan->config.reuse_port = parse_bool(line.line.value,
                            default_config.reuse_port);
            else
                config_error(&conf, "Unknown config key: %s", line.line.key);
            break;
        case CONFIG_LINE_TYPE_SECTION:
            if (!has_listener) {
                has_listener = true;
                if (!strcmp(line.section.name, "listener"))
                    parse_listener(&conf, &line, lwan);
                else
                    config_error(&conf, "Unknown section type: %s", line.section.name);
            } else {
                config_error(&conf, "Only one listener supported");
            }
            break;
        case CONFIG_LINE_TYPE_SECTION_END:
            ;
        }
    }

    if (conf.error_message) {
        lwan_status_critical("Error on config file \"%s\", line %d: %s",
              path, conf.line, conf.error_message);
    }

    config_close(&conf);

    return true;
}

void
lwan_init(lwan_t *l)
{
    int max_threads = sysconf(_SC_NPROCESSORS_ONLN);
    struct rlimit r;

    /* Load defaults */
    memcpy(&l->config, &default_config, sizeof(default_config));

    /* Initialize status first, as it is used by other things during
     * their initialization. */
    lwan_status_init(l);

    /* These will only print debugging messages. Debug messages are always
     * printed if we're on a debug build, so the quiet setting will be
     * respected. */
    lwan_job_thread_init();
    lwan_response_init();
    lwan_tables_init();

    /* Load the configuration file. */
    if (!setup_from_config(l))
        lwan_status_warning("Could not read config file, using defaults");

    /* Continue initialization as normal. */
    lwan_status_debug("Initializing lwan web server");

    l->thread.count = max_threads > 0 ? max_threads : 2;

    if (getrlimit(RLIMIT_NOFILE, &r) < 0)
        lwan_status_critical_perror("getrlimit");

    if (r.rlim_max == RLIM_INFINITY)
        r.rlim_cur *= 8;
    else if (r.rlim_cur < r.rlim_max)
        r.rlim_cur = r.rlim_max;
    if (setrlimit(RLIMIT_NOFILE, &r) < 0)
        lwan_status_critical_perror("setrlimit");

    l->requests = calloc(r.rlim_cur, sizeof(lwan_request_t));
    l->thread.max_fd = r.rlim_cur / l->thread.count;
    lwan_status_info("Using %d threads, maximum %d sockets per thread",
        l->thread.count, l->thread.max_fd);

    for (--r.rlim_cur; r.rlim_cur; --r.rlim_cur)
        l->requests[r.rlim_cur].response.buffer = strbuf_new();

    srand(time(NULL));
    signal(SIGPIPE, SIG_IGN);
    close(STDIN_FILENO);

    lwan_thread_init(l);
    lwan_socket_init(l);
}

void
lwan_shutdown(lwan_t *l)
{
    lwan_status_info("Shutting down");

    lwan_job_thread_shutdown();
    lwan_thread_shutdown(l);
    lwan_socket_shutdown(l);

    lwan_status_debug("Shutting down URL handlers");
    lwan_trie_destroy(l->url_map_trie);

    int i;
    for (i = l->thread.max_fd * l->thread.count - 1; i >= 0; --i)
        strbuf_free(l->requests[i].response.buffer);

    free(l->requests);

    lwan_response_shutdown();
    lwan_tables_shutdown();
    lwan_status_shutdown(l);
}

static ALWAYS_INLINE void
_push_request_fd(lwan_t *l, int fd, struct sockaddr_in *addr)
{
    static int counter = 0;
    unsigned thread = counter++ % l->thread.count;
    int epoll_fd = l->thread.threads[thread].epoll_fd;
    struct epoll_event event = {
        .events = EPOLLIN | EPOLLRDHUP | EPOLLERR | EPOLLET,
        .data.fd = fd
    };

    l->requests[fd].remote_address = addr->sin_addr.s_addr;
    l->requests[fd].thread = &l->thread.threads[thread];

    if (UNLIKELY(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event) < 0))
        lwan_status_critical_perror("epoll_ctl");
}

static void
_signal_handler(int signal_number)
{
    lwan_status_info("Signal %d (%s) received",
                                signal_number, strsignal(signal_number));
    longjmp(cleanup_jmp_buf, 1);
}

void
lwan_main_loop(lwan_t *l)
{
    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0)
        lwan_status_critical_perror("epoll_create1");

    if (setjmp(cleanup_jmp_buf))
        goto end;

    signal(SIGINT, _signal_handler);

    struct epoll_event events[128];
    struct epoll_event socket_ev = {
        .events = EPOLLIN,
        .data.u32 = 0
    };
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, l->main_socket, &socket_ev) < 0)
        lwan_status_critical_perror("epoll_ctl");

    lwan_status_info("Ready to serve");

    for (;;) {
        int n_fds = epoll_wait(epoll_fd, events, N_ELEMENTS(events), -1);
        for (; n_fds > 0; --n_fds) {
            struct sockaddr_in addr;
            int child_fd;
            socklen_t addr_size = sizeof(struct sockaddr_in);

            child_fd = accept4(l->main_socket, (struct sockaddr *)&addr,
                               &addr_size, SOCK_NONBLOCK);
            if (UNLIKELY(child_fd < 0)) {
                lwan_status_perror("accept");
                continue;
            }

            _push_request_fd(l, child_fd, &addr);
        }
    }

end:
    close(epoll_fd);
}
