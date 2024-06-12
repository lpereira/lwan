/*
 * lwan - web server
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
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>

#include "lwan-private.h"

#include "int-to-str.h"
#include "realpathat.h"
#include "lwan-cache.h"
#include "lwan-io-wrappers.h"
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

static struct cache_entry *
create_script_name(const void *keyptr, void *context, void *create_contex)
{
    struct private_data *pd = context;
    struct script_name_cache_entry *entry;
    const struct lwan_value *url = keyptr;
    int r;

    entry = malloc(sizeof(*entry));
    if (!entry)
        return NULL;

    if (!url->len)
        url = &pd->default_index;

    /* SCRIPT_NAME */
    r = asprintf(&entry->script_name, "/%.*s", (int)url->len, url->value);
    if (r < 0)
        goto free_entry;

    /* SCRIPT_FILENAME */
    char temp[PATH_MAX];
    r = snprintf(temp, sizeof(temp), "%s/%.*s", pd->script_path, (int)url->len,
                 url->value);
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

static enum lwan_http_status add_script_paths(const struct private_data *pd,
                                              struct lwan_request *request,
                                              struct lwan_response *response)
{
    struct script_name_cache_entry *snce =
        (struct script_name_cache_entry *)cache_coro_get_and_ref_entry(
            pd->script_name_cache, request->conn->coro, &request->url);

    if (snce) {
        add_param(response->buffer, "SCRIPT_NAME", snce->script_name);
        add_param(response->buffer, "SCRIPT_FILENAME", snce->script_filename);
        return HTTP_OK;
    }

    return HTTP_NOT_FOUND;
}

static void add_header_to_strbuf(const char *header,
                                 size_t header_len,
                                 const char *value,
                                 size_t value_len,
                                 void *user_data)
{
    struct lwan_strbuf *strbuf = user_data;
    return add_param_len(strbuf, header, header_len, value, value_len);
}

static bool fill_addr_and_port(const struct lwan_request *r,
                               struct lwan_strbuf *strbuf)
{
    const struct lwan_thread *t = r->conn->thread;
    char local_addr_buf[INET6_ADDRSTRLEN], remote_addr_buf[INET6_ADDRSTRLEN];
    struct sockaddr_storage sockaddr = {.ss_family = AF_UNSPEC};
    uint16_t local_port, remote_port;
    socklen_t len = sizeof(sockaddr);
    const char *local_addr, *remote_addr;
    int listen_fd;

    if (r->conn->flags & CONN_TLS) {
        listen_fd = t->tls_listen_fd;
        add_param(strbuf, "HTTPS", "on");
    } else {
        listen_fd = t->listen_fd;
        add_param(strbuf, "HTTPS", "");
    }

    if (getsockname(listen_fd, (struct sockaddr *)&sockaddr, &len) < 0)
        return false;

    if (sockaddr.ss_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&sockaddr;

        local_addr = inet_ntop(AF_INET6, &sin6->sin6_addr, local_addr_buf,
                               sizeof(local_addr_buf));
        local_port = ntohs(sin6->sin6_port);
    } else if (sockaddr.ss_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)&sockaddr;

        local_addr = inet_ntop(AF_INET, &sin->sin_addr, local_addr_buf,
                               sizeof(local_addr_buf));
        local_port = ntohs(sin->sin_port);
    } else {
        return false;
    }

    remote_addr = lwan_request_get_remote_address_and_port(r, remote_addr_buf,
                                                           &remote_port);

    if (!local_addr)
        return false;

    if (!remote_addr)
        return false;

    add_param(strbuf, "SERVER_ADDR", local_addr);
    add_int_param(strbuf, "SERVER_PORT", local_port);

    add_param(strbuf, "REMOTE_ADDR", remote_addr);
    add_int_param(strbuf, "REMOTE_PORT", remote_port);

    return true;
}

static enum lwan_http_status add_params(const struct private_data *pd,
                                        struct lwan_request *request,
                                        struct lwan_response *response)
{
    const struct lwan_request_parser_helper *request_helper = request->helper;
    struct lwan_strbuf *strbuf = response->buffer;

    /* Very compliant. Much CGI. Wow. */
    add_param(strbuf, "GATEWAY_INTERFACE", "CGI/1.1");

    if (!fill_addr_and_port(request, strbuf))
        return HTTP_INTERNAL_ERROR;

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
            return HTTP_INTERNAL_ERROR;
        }

        add_param(strbuf, "QUERY_STRING", query_string ? query_string : "");
        add_param(strbuf, "REQUEST_URI", temp);

        free(temp);
    } else {
        add_param(strbuf, "QUERY_STRING", "");
        add_param(strbuf, "REQUEST_URI", request->original_url.value);
    }

    lwan_request_foreach_header_for_cgi(request, add_header_to_strbuf, strbuf);

    return HTTP_OK;
}

static bool
handle_stdout(struct lwan_request *request, const struct record *record, int fd)
{
    size_t to_read = record->len_content;
    char *buffer = lwan_strbuf_extend_unsafe(request->response.buffer, to_read);

    if (!buffer)
        return false;

    while (to_read) {
        ssize_t r = lwan_recv_fd(request, fd, buffer, to_read, 0);

        if (r < 0)
            return false;

        to_read -= (size_t)r;
        buffer += r;
    }

    if (record->len_padding) {
        char padding[256];
        if (lwan_recv_fd(request, fd, padding, (size_t)record->len_padding,
                         MSG_TRUNC) < 0) {
            return false;
        }
    }

    return true;
}

static bool
handle_stderr(struct lwan_request *request, const struct record *record, int fd)
{
    size_t to_read = record->len_content;
    char *buffer = malloc(to_read);

    if (!buffer)
        return false;

    coro_deferred buffer_free_defer =
        coro_defer(request->conn->coro, free, buffer);

    for (char *p = buffer; to_read;) {
        ssize_t r = lwan_recv_fd(request, fd, p, to_read, 0);

        if (r < 0)
            return false;

        p += r;
        to_read -= (size_t)r;
    }

    lwan_status_error("FastCGI stderr output: %.*s", (int)record->len_content,
                      buffer);

    coro_defer_fire_and_disarm(request->conn->coro, buffer_free_defer);

    if (record->len_padding) {
        char padding[256];
        if (lwan_recv_fd(request, fd, padding, (size_t)record->len_padding,
                         MSG_TRUNC) < 0) {
            return false;
        }
    }

    return true;
}

static bool discard_unknown_record(struct lwan_request *request,
                                   const struct record *record,
                                   int fd)
{
    char buffer[256];
    size_t to_read = (size_t)record->len_content + (size_t)record->len_padding;

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

        r = lwan_recv_fd(request, fd, buffer, LWAN_MIN(sizeof(buffer), to_read),
                         MSG_TRUNC);
        if (r < 0)
            return false;

        to_read -= (size_t)r;
    }

    return true;
}

DEFINE_ARRAY_TYPE_INLINEFIRST(header_array, struct lwan_key_value)

static void reset_additional_header(void *data)
{
    struct header_array *array = data;
    header_array_reset(array);
}

static enum lwan_http_status
try_initiating_chunked_response(struct lwan_request *request)
{
    if (request->flags & REQUEST_IS_HTTP_1_0) {
        /* Chunked encoding is not supported in HTTP/1.0.  We don't have a
         * way to buffer the responses in this module yet, so return an
         * error here.  */
        return HTTP_NOT_IMPLEMENTED;
    }

    struct lwan_response *response = &request->response;
    char *header_start[N_HEADER_START];
    char *next_request;
    enum lwan_http_status status_code = HTTP_OK;
    struct lwan_value buffer = {
        .value = lwan_strbuf_get_buffer(response->buffer),
        .len = lwan_strbuf_get_length(response->buffer),
    };

    assert(!(request->flags &
             (RESPONSE_CHUNKED_ENCODING | RESPONSE_SENT_HEADERS)));

    if (!memmem(buffer.value, buffer.len, "\r\n\r\n", 4))
        return HTTP_OK;

    ssize_t n_headers = lwan_find_headers(header_start, &buffer, &next_request);
    if (n_headers < 0)
        return HTTP_BAD_REQUEST;

    struct header_array additional_headers;

    header_array_init(&additional_headers);
    coro_deferred additional_headers_reset = coro_defer(request->conn->coro,
                          reset_additional_header, &additional_headers);

    for (ssize_t i = 0; i < n_headers; i++) {
        char *begin = header_start[i];
        char *end = header_start[i + 1];
        char *p;

        p = strchr(begin, ':');
        if (!p) /* Shouldn't happen, but... */
            continue;
        *p = '\0';

        *(end - 2) = '\0';

        char *key = begin;
        char *value = p + 2;

        if (strcaseequal_neutral(key, "X-Powered-By")) {
            /* This is set by PHP-FPM.  Do not advertise this for privacy
             * reasons.  */
        } else if (strcaseequal_neutral(key, "Content-Type")) {
            response->mime_type = coro_strdup(request->conn->coro, value);
        } else if (strcaseequal_neutral(key, "Status")) {
            if (strlen(value) < 3) {
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
            struct lwan_key_value *header = header_array_append(&additional_headers);

            if (!header)
                goto free_array_and_disarm;

            *header = (struct lwan_key_value){.key = key, .value = value};
        }
    }

    struct lwan_key_value *header = header_array_append(&additional_headers);
    if (!header)
        goto free_array_and_disarm;
    *header = (struct lwan_key_value){};

    if (!lwan_response_set_chunked_full(request, status_code,
                                        header_array_get_array(&additional_headers))) {
        goto free_array_and_disarm;
    }

    coro_defer_fire_and_disarm(request->conn->coro, additional_headers_reset);

    char *chunk_start = header_start[n_headers];
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

    return HTTP_OK;

free_array_and_disarm:
    coro_defer_fire_and_disarm(request->conn->coro, additional_headers_reset);
    return HTTP_INTERNAL_ERROR;
}

DEFINE_ARRAY_TYPE_INLINEFIRST(iovec_array, struct iovec)
DEFINE_ARRAY_TYPE_INLINEFIRST(record_array, struct record)

static bool build_stdin_records(struct lwan_request *request,
                                struct iovec_array *iovec_array,
                                struct record_array *record_array,
                                int fcgi_fd,
                                const struct lwan_value *body_data)
{
    if (!body_data)
        return true;

    size_t to_send = body_data->len;
    char *buffer = body_data->value;

    while (to_send) {
        struct record *record;
        struct iovec *iovec;
        size_t block_size = LWAN_MIN(0xffffull, to_send);

        record = record_array_append(record_array);
        if (UNLIKELY(!record))
            return false;
        *record = (struct record){
            .version = 1,
            .type = FASTCGI_TYPE_STDIN,
            .id = htons(1),
            .len_content = htons((uint16_t)block_size),
        };

        iovec = iovec_array_append(iovec_array);
        if (UNLIKELY(!iovec))
            return false;
        *iovec = (struct iovec){.iov_base = record, .iov_len = sizeof(*record)};

        iovec = iovec_array_append(iovec_array);
        if (UNLIKELY(!iovec))
            return false;
        *iovec = (struct iovec){.iov_base = buffer, .iov_len = block_size};

        if (iovec_array_len(iovec_array) == LWAN_ARRAY_INCREMENT) {
            if (lwan_writev_fd(request, fcgi_fd,
                               iovec_array_get_array(iovec_array),
                               (int)iovec_array_len(iovec_array)) < 0) {
                return false;
            }
            iovec_array_reset(iovec_array);
            record_array_reset(record_array);
        }

        to_send -= block_size;
        buffer += block_size;
    }

    return true;
}

static enum lwan_http_status send_request(struct private_data *pd,
                                          struct lwan_request *request,
                                          struct lwan_response *response,
                                          int fcgi_fd)
{
    enum lwan_http_status status;

    status = add_params(pd, request, response);
    if (status != HTTP_OK)
        return status;

    status = add_script_paths(pd, request, response);
    if (status != HTTP_OK)
        return status;

    if (UNLIKELY(lwan_strbuf_get_length(response->buffer) > 0xffffu)) {
        /* Should not happen because DEFAULT_BUFFER_SIZE is a lot smaller
         * than 65535, but check anyway.  (If anything, we could send multiple
         * PARAMS records, but that's very unlikely to happen anyway until
         * we change how request headers are read.) */
        static_assert(DEFAULT_BUFFER_SIZE <= 0xffffu,
                      "only needs one PARAMS record");
        return HTTP_TOO_LARGE;
    }

    struct iovec_array iovec_array;
    struct record_array record_array;
    struct iovec *iovec;

    /* These arrays should never go beyond the inlinefirst threshold, so they
     * shouldn't leak -- thus requiring no defer to reset them. */
    record_array_init(&record_array);
    iovec_array_init(&iovec_array);

    iovec = iovec_array_append(&iovec_array);
    if (UNLIKELY(!iovec))
        return HTTP_INTERNAL_ERROR;
    *iovec = (struct iovec){
        .iov_base =
            &(struct request_header){
                .begin_request = {.version = 1,
                                  .type = FASTCGI_TYPE_BEGIN_REQUEST,
                                  .id = htons(1),
                                  .len_content = htons((uint16_t)sizeof(
                                      struct begin_request_body))},
                .begin_request_body = {.role = htons(FASTCGI_ROLE_RESPONDER)},
                .begin_params = {.version = 1,
                                 .type = FASTCGI_TYPE_PARAMS,
                                 .id = htons(1),
                                 .len_content =
                                     htons((uint16_t)lwan_strbuf_get_length(
                                         response->buffer))}},
        .iov_len = sizeof(struct request_header),
    };

    iovec = iovec_array_append(&iovec_array);
    if (UNLIKELY(!iovec))
        return HTTP_INTERNAL_ERROR;
    *iovec =
        (struct iovec){.iov_base = lwan_strbuf_get_buffer(response->buffer),
                       .iov_len = lwan_strbuf_get_length(response->buffer)};

    iovec = iovec_array_append(&iovec_array);
    if (UNLIKELY(!iovec))
        return HTTP_INTERNAL_ERROR;
    *iovec = (struct iovec){
        .iov_base = &(struct record){.version = 1,
                                     .type = FASTCGI_TYPE_PARAMS,
                                     .id = htons(1)},
        .iov_len = sizeof(struct record),
    };

    if (!build_stdin_records(request, &iovec_array, &record_array, fcgi_fd,
                             lwan_request_get_request_body(request))) {
        return HTTP_INTERNAL_ERROR;
    }

    iovec = iovec_array_append(&iovec_array);
    if (UNLIKELY(!iovec))
        return HTTP_INTERNAL_ERROR;
    *iovec = (struct iovec){
        .iov_base = &(struct record){.version = 1,
                                     .type = FASTCGI_TYPE_STDIN,
                                     .id = htons(1)},
        .iov_len = sizeof(struct record),
    };

    if (lwan_writev_fd(request, fcgi_fd, iovec_array_get_array(&iovec_array),
                       (int)iovec_array_len(&iovec_array)) < 0) {
        return HTTP_INTERNAL_ERROR;
    }
    iovec_array_reset(&iovec_array);
    record_array_reset(&record_array);

    lwan_strbuf_reset(response->buffer);

    return HTTP_OK;
}

static bool try_connect(struct lwan_request *request,
                        int sock_fd,
                        struct sockaddr *sockaddr,
                        socklen_t socklen)
{
    if (LIKELY(!connect(sock_fd, sockaddr, socklen)))
        return true;

    /* Since socket has been created in non-blocking mode, connection
     * might not be completed immediately.  Depending on the socket type,
     * connect() might return EAGAIN or EINPROGRESS.  */
    if (errno != EAGAIN && errno != EINPROGRESS)
        return false;

    /* If we get any of the above errors, try checking for socket error
     * codes and loop until we get no errors.  We await for writing here
     * because that's what the Linux man page for connect(2) says we should
     * do in this case.  */
    for (int try = 0; try < 10; try++) {
        socklen_t sockerrnolen = (socklen_t)sizeof(int);
        int sockerrno;

        lwan_request_await_write(request, sock_fd);

        if (getsockopt(sock_fd, SOL_SOCKET, SO_ERROR, &sockerrno,
                       &sockerrnolen) < 0) {
            break;
        }

        switch (sockerrno) {
        case EISCONN:
        case 0:
            return true;

        case EAGAIN:
        case EINPROGRESS:
        case EINTR:
            continue;

        default:
            return false;
        }
    }

    return false;
}

static enum lwan_http_status
fastcgi_handle_request(struct lwan_request *request,
                       struct lwan_response *response,
                       void *instance)
{
    struct private_data *pd = instance;
    enum lwan_http_status status;
    int remaining_tries_for_chunked = 10;
    int fcgi_fd;

    fcgi_fd =
        socket(pd->addr_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fcgi_fd < 0)
        return HTTP_INTERNAL_ERROR;

    coro_defer(request->conn->coro, close_fd, (void *)(intptr_t)fcgi_fd);

    if (!try_connect(request, fcgi_fd, (struct sockaddr *)&pd->sock_addr,
                     pd->addr_size)) {
        return HTTP_UNAVAILABLE;
    }

    status = send_request(pd, request, response, fcgi_fd);
    if (status != HTTP_OK)
        return status;

    /* FIXME: the header parser starts at the \r from an usual
     * HTTP request with the verb line, etc. */
    lwan_strbuf_append_char(response->buffer, '\r');

    request->flags |= RESPONSE_NO_EXPIRES;

    while (true) {
        struct record record;
        ssize_t r;

        r = lwan_recv_fd(request, fcgi_fd, &record, sizeof(record), 0);
        if (r < 0)
            return HTTP_UNAVAILABLE;
        if (r != (ssize_t)sizeof(record))
            return HTTP_INTERNAL_ERROR;

        record.len_content = ntohs(record.len_content);
        record.id = htons(record.id);

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

                status = try_initiating_chunked_response(request);
                if (status != HTTP_OK)
                    return status;
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

    pd->script_path_fd = open(pd->script_path, O_PATH | O_DIRECTORY | O_CLOEXEC);
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

    lwan_status_error("FastCGI: Address '%s' isn't a valid Unix Domain Socket, IPv4, or IPv6 address",
                      settings->address);

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
