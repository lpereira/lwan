/*
 * lwan - simple web server
 * Copyright (c) 2022 L. A. F. Pereira <l@tia.mat.br>
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
/* Implementation of a (subset of) FastCGI according to
 * https://fastcgi-archives.github.io/FastCGI_Specification.html
 * Some things are not fully implemented, but this seems enough to get
 * Lwan to proxy PHP-FPM through FastCGI.
 */
/* FIXME: not a lot of the private APIs that needed to be added to
 * support this module have a good API. Revisit this someday. */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/un.h>

#include "lwan-private.h"

#include "int-to-str.h"
#include "patterns.h"
#include "realpathat.h"
#include "lwan-cache.h"
#include "lwan-mod-fastcgi.h"
#include "lwan-strbuf.h"

#define FASTCGI_ROLE_RESPONDER 1

/* FIXME: use this to pool connections later? */
#define FASTCGI_FLAGS_KEEP_CONN 1

#define FASTCGI_TYPE_BEGIN_REQUEST 1
#define FASTCGI_TYPE_END_REQUEST 3
#define FASTCGI_TYPE_PARAMS 4
#define FASTCGI_TYPE_STDIN 5
#define FASTCGI_TYPE_STDOUT 6
#define FASTCGI_TYPE_STDERR 7

struct private_data {
    union {
        struct sockaddr_un un_addr;
        struct sockaddr_in in_addr;
        struct sockaddr_in6 in6_addr;
        struct sockaddr_storage sock_addr;
    };
    sa_family_t addr_family;
    socklen_t addr_size;

    struct cache *script_name_cache;

    struct lwan_value default_index;

    char *script_path;
    int script_path_fd;
};

struct record {
    uint8_t version;
    uint8_t type;
    uint16_t id;
    uint16_t len_content;
    uint8_t len_padding;
    uint8_t reserved;
} __attribute__((packed));

static_assert(sizeof(struct record) == 8, "Sane record size");

struct begin_request_body {
    uint16_t role;
    uint8_t flags;
    uint8_t padding[5];
} __attribute__((packed));

static_assert(sizeof(struct begin_request_body) == 8,
              "Sane begin_request_body size");

struct request_header {
    struct record begin_request;
    struct begin_request_body begin_request_body;
    struct record begin_params;
} __attribute__((packed));

struct request_footer {
    struct record end_params;
    struct record empty_stdin;
} __attribute__((packed));

struct script_name_cache_entry {
    struct cache_entry base;
    char *script_name;
    char *script_filename;
};

static void close_fd(void *data)
{
    int fd = (int)(intptr_t)data;

    close(fd);
}

static void add_param_len(struct lwan_strbuf *strbuf,
                          const char *key,
                          size_t len_key,
                          const char *value,
                          size_t len_value)
{
    /* FIXME: these should be enabled for release builds, too! */
    assert(len_key <= INT_MAX);
    assert(len_value <= INT_MAX);

    if (len_key <= 127) {
        lwan_strbuf_append_char(strbuf, (char)len_key);
    } else {
        uint32_t len_net = htonl((uint32_t)len_key) | 1u << 31;
        lwan_strbuf_append_str(strbuf, (char *)&len_net, 4);
    }

    if (len_value <= 127) {
        lwan_strbuf_append_char(strbuf, (char)len_value);
    } else {
        uint32_t len_net = htonl((uint32_t)len_value) | 1u << 31;
        lwan_strbuf_append_str(strbuf, (char *)&len_net, 4);
    }

    lwan_strbuf_append_str(strbuf, key, len_key);
    lwan_strbuf_append_str(strbuf, value, len_value);
}

static inline void
add_param(struct lwan_strbuf *strbuf, const char *key, const char *value)
{
    return add_param_len(strbuf, key, strlen(key), value, strlen(value));
}

static inline void
add_int_param(struct lwan_strbuf *strbuf, const char *key, ssize_t value)
{
    size_t len;
    char buffer[INT_TO_STR_BUFFER_SIZE];
    char *p = int_to_string(value, buffer, &len);

    return add_param_len(strbuf, key, strlen(key), p, len);
}

static struct cache_entry *create_script_name(const char *key, void *context)
{
    struct private_data *pd = context;
    struct script_name_cache_entry *entry;
    struct lwan_value url;
    char temp[PATH_MAX];
    int r;

    entry = malloc(sizeof(*entry));
    if (!entry)
        return NULL;

    if (*key) {
        url = (struct lwan_value){.value = (char *)key, .len = strlen(key)};
    } else {
        url = pd->default_index;
    }

    /* SCRIPT_NAME */
    r = snprintf(temp, sizeof(temp), "/%.*s", (int)url.len, url.value);
    if (r < 0 || r >= (int)sizeof(temp))
        goto free_entry;

    entry->script_name = strdup(temp);
    if (!entry->script_name)
        goto free_entry;

    /* SCRIPT_FILENAME */
    r = snprintf(temp, sizeof(temp), "%s/%.*s", pd->script_path, (int)url.len,
                 url.value);
    if (r < 0 || r >= (int)sizeof(temp))
        goto free_script_name;

    entry->script_filename =
        realpathat(pd->script_path_fd, pd->script_path, temp, NULL);
    if (!entry->script_filename)
        goto free_script_name;

    if (strncmp(entry->script_filename, pd->script_path, strlen(pd->script_path)))
        goto free_script_filename;

    return &entry->base;

free_script_filename:
    free(entry->script_filename);
free_script_name:
    free(entry->script_name);
free_entry:
    free(entry);

    return NULL;
}

static void destroy_script_name(struct cache_entry *entry, void *context)
{
    struct script_name_cache_entry *snce =
        (struct script_name_cache_entry *)entry;

    free(snce->script_name);
    free(snce->script_filename);
    free(snce);
}

static bool add_script_paths(const struct private_data *pd,
                             struct lwan_request *request,
                             struct lwan_response *response)
{
    struct script_name_cache_entry *snce =
        (struct script_name_cache_entry *)cache_coro_get_and_ref_entry(
            pd->script_name_cache, request->conn->coro, request->url.value);

    if (snce) {
        add_param(response->buffer, "SCRIPT_NAME", snce->script_name);
        add_param(response->buffer, "SCRIPT_FILENAME", snce->script_filename);
        return true;
    }

    return false;
}

static bool add_params(const struct private_data *pd,
                       struct lwan_request *request,
                       struct lwan_response *response)
{
    const struct lwan_request_parser_helper *request_helper = request->helper;
    struct lwan_strbuf *strbuf = response->buffer;

    char remote_addr[INET6_ADDRSTRLEN];
    uint16_t remote_port;

    /* FIXME: let's use some hardcoded values for now so that we can
     *        verify that the implementation is working first */

    /* Very compliant. Much CGI. Wow. */
    add_param(strbuf, "GATEWAY_INTERFACE", "CGI/1.1");

    add_param(strbuf, "REMOTE_ADDR",
              lwan_request_get_remote_address_and_port(request, remote_addr,
                                                       &remote_port));
    add_int_param(strbuf, "REMOTE_PORT", remote_port);

    add_param(strbuf, "SERVER_ADDR", "127.0.0.1");

    /* FIXME: get the actual port from thread->listen_fd or
     * thread->tls_listen_fd */
    if (request->conn->flags & CONN_TLS) {
        add_param(strbuf, "SERVER_PORT", "0");
        add_param(strbuf, "HTTPS", "on");
    } else {
        add_param(strbuf, "SERVER_PORT", "0");
        add_param(strbuf, "HTTPS", "");
    }

    add_param(strbuf, "SERVER_SOFTWARE", "Lwan");
    add_param(strbuf, "SERVER_PROTOCOL",
              request->flags & REQUEST_IS_HTTP_1_0 ? "HTTP/1.0" : "HTTP/1.1");

    add_param(strbuf, "REQUEST_METHOD", lwan_request_get_method_str(request));

    /* FIXME: Should we support PATH_INFO?  This is pretty shady. See
     * e.g. https://httpd.apache.org/docs/2.4/mod/core.html#acceptpathinfo  */
    add_param(strbuf, "PATH_INFO", "");

    add_param(strbuf, "DOCUMENT_URI", request->original_url.value);
    add_param(strbuf, "DOCUMENT_ROOT", pd->script_path);

    const char *query_string = request_helper->query_string.value;
    if (query_string) {
        char *temp;

        /* FIXME: maybe we should add something that lets us
         *        forward a va_arg to strbuf_append_printf() instead? */
        if (asprintf(&temp, "%s?%s", request->original_url.value,
                     query_string) < 0) {
            return false;
        }

        add_param(strbuf, "QUERY_STRING", query_string ? query_string : "");
        add_param(strbuf, "REQUEST_URI", temp);

        free(temp);
    } else {
        add_param(strbuf, "QUERY_STRING", "");
        add_param(strbuf, "REQUEST_URI", request->original_url.value);
    }

    for (size_t i = 0; i < request_helper->n_header_start; i++) {
        const char *header = request_helper->header_start[i];
        const char *next_header = request_helper->header_start[i + 1];
        const char *colon = memchr(header, ':', 127 - sizeof("HTTP_: ") - 1);
        char header_name[128];
        int r;

        if (!colon)
            continue;

        const size_t header_len = (size_t)(colon - header);
        const size_t value_len = (size_t)(next_header - colon - 4);

        r = snprintf(header_name, sizeof(header_name), "HTTP_%.*s",
                     (int)header_len, header);
        if (r < 0 || r >= (int)sizeof(header_name))
            continue;

        /* FIXME: RFC7230/RFC3875 compliance */
        for (char *p = header_name; *p; p++) {
            if (isalpha(*p))
                *p &= ~0x20;
            else if (!isdigit(*p))
                *p = '_';
        }

        if (streq(header_name, "HTTP_PROXY")) {
            /* Mitigation for https://httpoxy.org */
            continue;
        }

        add_param_len(strbuf, header_name, header_len + sizeof("HTTP_") - 1,
                      colon + 2, value_len);
    }

    return true;
}

static bool
handle_stdout(struct lwan_request *request, const struct record *record, int fd)
{
    size_t to_read = (size_t)ntohs(record->len_content);
    char *buffer = lwan_strbuf_extend_unsafe(request->response.buffer, to_read);

    if (!buffer)
        return false;

    while (to_read) {
        ssize_t r = lwan_request_async_read(request, fd, buffer, to_read);

        if (r < 0)
            return false;

        to_read -= (size_t)r;
        buffer += r;
    }

    if (record->len_padding) {
        char padding[256];
        lwan_request_async_read_flags(request, fd, padding,
                                      (size_t)record->len_padding, MSG_TRUNC);
    }

    return true;
}

static bool
handle_stderr(struct lwan_request *request, const struct record *record, int fd)
{
    /* Even though we only use buffer within this function, we need to use
     * coro_malloc() to allocate this buffer.  Otherwise, if
     * lwan_request_async_read() yields the coroutine, the main loop might
     * terminate the coroutine if either connection is dropped.  */
    size_t to_read = (size_t)ntohs(record->len_content);
    char *buffer = coro_malloc(request->conn->coro, to_read);

    if (!buffer)
        return false;

    for (char *p = buffer; to_read;) {
        ssize_t r = lwan_request_async_read(request, fd, p, to_read);

        if (r < 0)
            return false;

        p += r;
        to_read -= (size_t)r;
    }

    lwan_status_error("FastCGI stderr output: %.*s",
                      (int)ntohs(record->len_content), buffer);

    if (record->len_padding) {
        char padding[256];
        lwan_request_async_read_flags(request, fd, padding,
                                      (size_t)ntohs(record->len_padding),
                                      MSG_TRUNC);
    }

    return true;
}

static bool discard_unknown_record(struct lwan_request *request,
                                   const struct record *record,
                                   int fd)
{
    char buffer[256];
    size_t to_read =
        (size_t)ntohs(record->len_content) + (size_t)ntohs(record->len_padding);

    if (record->type > 11) {
        /* Per the spec, 11 is the maximum (unknown type), so anything
         * above it is unspecified. */
        lwan_status_warning(
            "FastCGI server sent unknown/invalid record type %d", record->type);
        return false;
    }

    lwan_status_debug("Discarding record of type %d (%zu bytes incl. padding)",
                      record->type, to_read);

    while (to_read) {
        ssize_t r;

        r = lwan_request_async_read_flags(
            request, fd, buffer, LWAN_MIN(sizeof(buffer), to_read), MSG_TRUNC);
        if (r < 0)
            return false;

        to_read -= (size_t)r;
    }

    return true;
}

static bool try_initiating_chunked_response(struct lwan_request *request)
{
    struct lwan_response *response = &request->response;
    char *header_start[N_HEADER_START];
    enum lwan_http_status status_code = HTTP_OK;
    struct lwan_value buffer = {
        .value = lwan_strbuf_get_buffer(response->buffer),
        .len = lwan_strbuf_get_length(response->buffer),
    };
    struct lwan_request_parser_helper helper = {.buffer = &buffer,
                                                .header_start = header_start};

    assert(!(request->flags &
             (RESPONSE_CHUNKED_ENCODING | RESPONSE_SENT_HEADERS)));

    if (!lwan_request_seems_complete(&helper))
        return true;

    /* FIXME: Maybe split parse_headers() into a function that finds all
     * headers and another that looks at the found headers?   We don't use
     * the second part of this function here. */
    if (!lwan_parse_headers(&helper, buffer.value))
        return false;

    /* FIXME: Maybe use a lwan_key_value_array here? */
    struct lwan_key_value *additional_headers =
        calloc(helper.n_header_start + 1, sizeof(struct lwan_key_value));
    if (!additional_headers)
        return false;

    struct coro_defer *free_additional_headers =
        coro_defer(request->conn->coro, free, additional_headers);

    for (size_t i = 0, j = 0; i < helper.n_header_start; i++) {
        char *begin = helper.header_start[i];
        char *end = helper.header_start[i + 1];
        char *p;

        p = strchr(begin, ':');
        if (!p) /* Shouldn't happen, but... */
            continue;
        *p = '\0';

        *(end - 2) = '\0';

        char *key = begin;
        char *value = p + 2;

        if (!strcasecmp(key, "X-Powered-By")) {
            /* This is set by PHP-FPM.  Do not advertise this for privacy
             * reasons.  */
        } else if (!strcasecmp(key, "Content-Type")) {
            response->mime_type = coro_strdup(request->conn->coro, value);
        } else if (!strcasecmp(key, "Status")) {
            if (strlen(value) < 4) {
                status_code = HTTP_INTERNAL_ERROR;
                continue;
            }

            value[3] = '\0';
            int status_as_int = parse_int(value, -1);

            if (status_as_int < 100 || status_as_int >= 600)
                status_code = HTTP_INTERNAL_ERROR;
            else
                status_code = (enum lwan_http_status)status_as_int;
        } else {
            additional_headers[j++] =
                (struct lwan_key_value){.key = key, .value = value};
        }
    }

    if (!lwan_response_set_chunked_full(request, status_code,
                                        additional_headers)) {
        return false;
    }

    coro_defer_fire_and_disarm(request->conn->coro, free_additional_headers);

    char *chunk_start = header_start[helper.n_header_start];
    size_t chunk_len = buffer.len - (size_t)(chunk_start - buffer.value);

    if (chunk_len) {
        struct lwan_strbuf first_chunk;

        lwan_strbuf_init(&first_chunk);
        lwan_strbuf_set_static(&first_chunk, chunk_start, chunk_len);
        lwan_response_send_chunk_full(request, &first_chunk);

        /* We sent the chunk using a temporary strbuf, so reset the
         * actual buffer that had the headers+first chunk */
        lwan_strbuf_reset(response->buffer);
    }

    return true;
}

static enum lwan_http_status
fastcgi_handle_request(struct lwan_request *request,
                       struct lwan_response *response,
                       void *instance)
{
    struct private_data *pd = instance;
    int remaining_tries_for_chunked = 10;
    int fcgi_fd;

    fcgi_fd =
        socket(pd->addr_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fcgi_fd < 0)
        return HTTP_INTERNAL_ERROR;

    coro_defer(request->conn->coro, close_fd, (void *)(intptr_t)fcgi_fd);

    if (connect(fcgi_fd, (struct sockaddr *)&pd->sock_addr, pd->addr_size) < 0)
        return HTTP_UNAVAILABLE;

    lwan_strbuf_reset(response->buffer);
    if (!add_params(pd, request, response))
        return HTTP_BAD_REQUEST;
    if (!add_script_paths(pd, request, response))
        return HTTP_NOT_FOUND;
    if (UNLIKELY(lwan_strbuf_get_length(response->buffer) > 0xffffu)) {
        /* Should not happen because DEFAULT_BUFFER_SIZE is a lot smaller
         * than 65535, but check anyway.  (If anything, we could send multiple
         * PARAMS records, but that's very unlikely to happen anyway until
         * we change how request headers are read.) */
        static_assert(DEFAULT_BUFFER_SIZE <= 0xffffu,
                      "only needs one PARAMS record");
        return HTTP_BAD_REQUEST;
    }

    struct request_header request_header = {
        .begin_request = {.version = 1,
                          .type = FASTCGI_TYPE_BEGIN_REQUEST,
                          .id = htons(1),
                          .len_content = htons(
                              (uint16_t)sizeof(struct begin_request_body))},
        .begin_request_body = {.role = htons(FASTCGI_ROLE_RESPONDER)},
        .begin_params = {.version = 1,
                         .type = FASTCGI_TYPE_PARAMS,
                         .id = htons(1),
                         .len_content = htons((uint16_t)lwan_strbuf_get_length(
                             response->buffer))},
    };
    struct request_footer request_footer = {
        .end_params = {.version = 1,
                       .type = FASTCGI_TYPE_PARAMS,
                       .id = htons(1)},
        /* FIXME: do we need a STDIN record if there's no request body is empty?
         */
        .empty_stdin = {.version = 1,
                        .type = FASTCGI_TYPE_STDIN,
                        .id = htons(1)},
    };

    struct iovec vec[] = {
        {.iov_base = &request_header, .iov_len = sizeof(request_header)},
        {.iov_base = lwan_strbuf_get_buffer(response->buffer),
         .iov_len = lwan_strbuf_get_length(response->buffer)},
        {.iov_base = &request_footer, .iov_len = sizeof(request_footer)},
    };
    lwan_request_async_writev(request, fcgi_fd, vec, N_ELEMENTS(vec));

    lwan_strbuf_reset(response->buffer);

    /* FIXME: the header parser starts at the \r from an usual
     * HTTP request with the verb line, etc. */
    lwan_strbuf_append_char(response->buffer, '\r');

    request->flags |= RESPONSE_NO_EXPIRES;

    while (true) {
        struct record record;
        ssize_t r;

        r = lwan_request_async_read(request, fcgi_fd, &record, sizeof(record));
        if (r < 0)
            return HTTP_UNAVAILABLE;
        if (r != (ssize_t)sizeof(record))
            return HTTP_INTERNAL_ERROR;

        switch (record.type) {
        case FASTCGI_TYPE_STDOUT:
            if (!handle_stdout(request, &record, fcgi_fd))
                return HTTP_INTERNAL_ERROR;

            /* Fallthrough */

        case FASTCGI_TYPE_END_REQUEST:
            if (request->flags & RESPONSE_CHUNKED_ENCODING) {
                if (lwan_strbuf_get_length(response->buffer) != 0) {
                    /* Avoid buffering all the records from the FastCGI
                     * server and send chunks as we get them if we know we're
                     * already responding with chunked encoding.  */
                    lwan_response_send_chunk(request);
                }
            } else {
                /* See if we can parse the headers at this point; if we can,
                 * then we can also send the first chunk with the additional
                 * headers we just parsed from FastCGI.  */
                remaining_tries_for_chunked--;
                if (!remaining_tries_for_chunked)
                    return HTTP_UNAVAILABLE;

                if (!try_initiating_chunked_response(request))
                    return HTTP_BAD_REQUEST;
            }

            if (record.type == FASTCGI_TYPE_END_REQUEST)
                return HTTP_OK;

            break;

        case FASTCGI_TYPE_STDERR:
            if (!handle_stderr(request, &record, fcgi_fd))
                return HTTP_INTERNAL_ERROR;
            break;

        default:
            if (!discard_unknown_record(request, &record, fcgi_fd))
                return HTTP_INTERNAL_ERROR;
            break;
        }
    }

    __builtin_unreachable();
}

static void *fastcgi_create(const char *prefix __attribute__((unused)),
                            void *user_settings)
{
    struct lwan_fastcgi_settings *settings = user_settings;
    struct private_data *pd;

    if (!settings->address) {
        lwan_status_error("FastCGI: `address` not specified");
        return NULL;
    }
    if (!settings->script_path) {
        lwan_status_error("FastCGI: `script_path` not specified");
        return NULL;
    }

    if (!settings->default_index)
        settings->default_index = "index.php";

    pd = malloc(sizeof(*pd));
    if (!pd) {
        lwan_status_perror("FastCGI: Could not allocate memory for module");
        return NULL;
    }

    pd->script_name_cache =
        cache_create(create_script_name, destroy_script_name, pd, 60);
    if (!pd->script_name_cache) {
        lwan_status_error("FastCGI: could not create cache for script_name");
        goto free_pd;
    }

    pd->default_index = (struct lwan_value){
        .value = strdup(settings->default_index),
        .len = strlen(settings->default_index),
    };
    if (!pd->default_index.value) {
        lwan_status_error("FastCGI: could not copy default_address for module");
        goto destroy_cache;
    }

    pd->script_path = realpath(settings->script_path, NULL);
    if (!pd->script_path) {
        lwan_status_perror("FastCGI: `script_path` of '%s' is invalid",
                           settings->script_path);
        goto free_default_index;
    }

    pd->script_path_fd = open(pd->script_path, O_PATH | O_DIRECTORY);
    if (pd->script_path_fd < 0) {
        lwan_status_perror("FastCGI: Could not open `script_path` at '%s'",
                           pd->script_path);
        goto free_script_path;
    }

    if (*settings->address == '/') {
        struct stat st;

        if (stat(settings->address, &st) < 0) {
            lwan_status_perror("FastCGI: `address` not found: %s",
                               settings->address);
            goto close_script_path_fd;
        }

        if (!(st.st_mode & S_IFSOCK)) {
            lwan_status_error("FastCGI: `address` is not a socket: %s",
                              settings->address);
            goto close_script_path_fd;
        }

        if (strlen(settings->address) >= sizeof(pd->un_addr.sun_path)) {
            lwan_status_error(
                "FastCGI: `address` is too long for a sockaddr_un: %s",
                settings->address);
            goto close_script_path_fd;
        }

        pd->addr_family = AF_UNIX;
        pd->un_addr = (struct sockaddr_un){.sun_family = AF_UNIX};
        pd->addr_size = sizeof(pd->un_addr);
        memcpy(pd->un_addr.sun_path, settings->address,
               strlen(settings->address) + 1);
        return pd;
    }

    char *node, *port, *address_copy;

    address_copy = strdup(settings->address);
    if (!address_copy)
        goto free_address_copy;

    pd->addr_family = lwan_socket_parse_address(address_copy, &node, &port);

    int int_port = parse_int(port, -1);
    if (int_port < 0 || int_port > 0xffff) {
        lwan_status_error("FastCGI: Port %d is not in valid range [0-65535]",
                          int_port);
        goto free_address_copy;
    }

    switch (pd->addr_family) {
    case AF_MAX:
        lwan_status_error("FastCGI: Could not parse '%s' as 'address:port'",
                          settings->address);
        goto free_address_copy;

    case AF_INET: {
        struct in_addr in_addr;

        if (inet_pton(AF_INET, node, &in_addr) < 0) {
            lwan_status_perror("FastCGI: Could not parse IPv4 address '%s'",
                               node);
            goto free_address_copy;
        }

        pd->in_addr =
            (struct sockaddr_in){.sin_family = AF_INET,
                                 .sin_addr = in_addr,
                                 .sin_port = htons((uint16_t)int_port)};
        pd->addr_size = sizeof(in_addr);
        free(address_copy);
        return pd;
    }

    case AF_INET6: {
        struct in6_addr in6_addr;

        if (inet_pton(AF_INET6, node, &in6_addr) < 0) {
            lwan_status_perror("FastCGI: Could not parse IPv6 address '%s'",
                               node);
            goto free_address_copy;
        }

        pd->in6_addr =
            (struct sockaddr_in6){.sin6_family = AF_INET6,
                                  .sin6_addr = in6_addr,
                                  .sin6_port = htons((uint16_t)int_port)};
        pd->addr_size = sizeof(in6_addr);
        free(address_copy);
        return pd;
    }
    }

    return pd;

free_address_copy:
    free(address_copy);
close_script_path_fd:
    close(pd->script_path_fd);
free_script_path:
    free(pd->script_path);
free_default_index:
    free(pd->default_index.value);
destroy_cache:
    cache_destroy(pd->script_name_cache);
free_pd:
    free(pd);
    return NULL;
}

static void fastcgi_destroy(void *instance)
{
    struct private_data *pd = instance;

    cache_destroy(pd->script_name_cache);
    free(pd->default_index.value);
    close(pd->script_path_fd);
    free(pd->script_path);
    free(pd);
}

static void *fastcgi_create_from_hash(const char *prefix,
                                      const struct hash *hash)
{
    struct lwan_fastcgi_settings settings = {
        .address = hash_find(hash, "address"),
        .script_path = hash_find(hash, "script_path"),
        .default_index = hash_find(hash, "default_index"),
    };
    return fastcgi_create(prefix, &settings);
}

static const struct lwan_module module = {
    .create = fastcgi_create,
    .create_from_hash = fastcgi_create_from_hash,
    .destroy = fastcgi_destroy,
    .handle_request = fastcgi_handle_request,
};

LWAN_REGISTER_MODULE(fastcgi, &module);
