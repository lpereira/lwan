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
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <zlib.h>

#include "lwan.h"
#include "lwan-sendfile.h"
#include "lwan-dir-watch.h"
#include "realpathat.h"
#include "hash.h"

#define NOW 0
#define ONE_HOUR 3600
#define ONE_DAY (ONE_HOUR * 24)
#define ONE_WEEK (ONE_DAY * 7)
#define ONE_MONTH (ONE_DAY * 31)

static void *serve_files_init(void *args);
static void serve_files_shutdown(void *data);
static lwan_http_status_t serve_files_handle_cb(lwan_request_t *request, lwan_response_t *response, void *data);

lwan_handler_t serve_files = {
    .init = serve_files_init,
    .shutdown = serve_files_shutdown,
    .handle = serve_files_handle_cb,
    .flags = HANDLER_PARSE_IF_MODIFIED_SINCE | HANDLER_PARSE_RANGE
};

struct serve_files_priv_t {
    char *root_path;
    size_t root_path_len;
    int root_fd;
    struct hash *cache;
    pthread_mutex_t cache_mutex;
};

struct cache_entry_t {
    struct {
        void *contents;
        off_t size;
    } compressed, uncompressed;
    const char *mime_type;
    char last_modified[32];
};

static ALWAYS_INLINE bool
_rfc_time(time_t t, char buffer[32])
{
    time_t tt = (t <= ONE_MONTH) ? time(NULL) + t : t;
    return !!strftime(buffer, 31, "%a, %d %b %Y %H:%M:%S GMT", gmtime(&tt));
}

static void *
_my_zalloc(void *opaque __attribute__((unused)), uInt items, uInt size)
{
    return malloc(items * size);
}

static void
_my_zfree(void *opaque __attribute__((unused)), void *address)
{
    free(address);
}

static void
_compress_cached_entry(struct cache_entry_t *ce)
{
    z_stream zs = {
        .zalloc = _my_zalloc,
        .zfree = _my_zfree,
        .opaque = Z_NULL,
        .next_in = Z_NULL
    };
    void *tailored = NULL;
    void *copy;

    copy = malloc(ce->uncompressed.size);
    if (UNLIKELY(!copy))
        goto error_zero_out;

    if (UNLIKELY(deflateInit(&zs, 8) != Z_OK))
        goto error_zero_out_and_free_copy;

    ce->compressed.contents = malloc(ce->uncompressed.size);
    if (!ce->compressed.contents)
        goto error;

    memcpy(copy, ce->uncompressed.contents, ce->uncompressed.size);
    zs.next_in = copy;
    zs.avail_in = ce->uncompressed.size;
    zs.next_out = ce->compressed.contents;
    zs.avail_out = ce->uncompressed.size;

    deflate(&zs, Z_FULL_FLUSH);
    if (UNLIKELY(zs.msg != NULL))
        goto error;

    deflateEnd(&zs);
    if (UNLIKELY(zs.msg != NULL))
        goto error;

    tailored = realloc(ce->compressed.contents, ce->uncompressed.size - zs.avail_out);
    if (UNLIKELY(!tailored))
        goto error;

    ce->compressed.contents = tailored;
    ce->compressed.size = ce->uncompressed.size - zs.avail_out;

    free(copy);

    return;

error:
    free(tailored);
    free(ce->compressed.contents);
error_zero_out_and_free_copy:
    free(copy);
error_zero_out:
    ce->compressed.contents = NULL;
    ce->compressed.size = 0;
}

static void
_free_cached_entry(void *data)
{
    struct cache_entry_t *ce = data;

    munmap(ce->uncompressed.contents, ce->uncompressed.size);
    free(ce->compressed.contents);
    free(ce);
}

static void
_cache_one_file(struct serve_files_priv_t *priv, char *full_path, off_t size, time_t mtime)
{
    /* Assumes priv->cache_mutex locked */
    struct cache_entry_t *ce;
    int file_fd;

    if (size > 16384)
        return;

    file_fd = open(full_path, O_RDONLY | O_NOATIME);
    if (UNLIKELY(file_fd < 0))
        return;

    ce = malloc(sizeof(*ce));
    if (UNLIKELY(!ce)) {
        close(file_fd);
        return;
    }

    ce->uncompressed.contents = mmap(NULL, size, PROT_READ, MAP_SHARED, file_fd, 0);
    if (UNLIKELY(ce->uncompressed.contents == MAP_FAILED)) {
        free(ce);
        goto close_file;
    }

    if (UNLIKELY(madvise(ce->uncompressed.contents, size, MADV_WILLNEED) < 0))
        perror("madvise");

    ce->uncompressed.size = size;
    ce->mime_type = lwan_determine_mime_type_for_file_name(full_path + priv->root_path_len);

    _rfc_time(mtime, ce->last_modified);
    _compress_cached_entry(ce);

    hash_add(priv->cache, strdup(full_path + priv->root_path_len + 1), ce);

close_file:
    close(file_fd);
}

static void _cache_small_files_recurse(struct serve_files_priv_t *priv, char *root, int levels);

static void
_watched_dir_changed(char *name, char *root, lwan_dir_watch_event_t event, void *data)
{
    struct serve_files_priv_t *priv = data;

    if (UNLIKELY(pthread_mutex_lock(&priv->cache_mutex) < 0))
        return;

    switch (event) {
    case DIR_WATCH_MOD:
        hash_del(priv->cache, name);
        /* Fallthrough */
    case DIR_WATCH_ADD: {
            char path[PATH_MAX];
            struct stat st;

            if (UNLIKELY(snprintf(path, PATH_MAX, "%s/%s", root, name) < 0))
                goto end;
            if (UNLIKELY(stat(path, &st) < 0))
                goto end;

            if (S_ISDIR(st.st_mode))
                _cache_small_files_recurse(priv, path, 0);
            else if (st.st_size)
                _cache_one_file(priv, path, st.st_size, st.st_mtime);
        }
        break;
    case DIR_WATCH_DEL:
        hash_del(priv->cache, name);
        break;
    }

end:
    if (UNLIKELY(pthread_mutex_unlock(&priv->cache_mutex) < 0))
        perror("pthread_mutex_unlock");
}

static void
_cache_small_files_recurse(struct serve_files_priv_t *priv, char *root, int levels)
{
    /* Assumes priv->cache_mutex locked */
    DIR *dir;
    struct dirent *entry;
    int fd;

    if (levels > 16)
        return;

    dir = opendir(root);
    if (UNLIKELY(!dir))
        return;

    fd = dirfd(dir);
    if (UNLIKELY(fd < 0))
        goto error;

    while ((entry = readdir(dir))) {
        char full_path[PATH_MAX];
        struct stat st;

        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;

        if (UNLIKELY(fstatat(fd, entry->d_name, &st, 0) < 0))
            continue;

        snprintf(full_path, PATH_MAX, "%s/%s", root, entry->d_name);
        if (S_ISDIR(st.st_mode))
            _cache_small_files_recurse(priv, full_path, levels + 1);
        else
            _cache_one_file(priv, full_path, st.st_size, st.st_mtime);
    }

    lwan_dir_watch_add(root, _watched_dir_changed, priv);

error:
    closedir(dir);
}

static void
_cache_small_files(struct serve_files_priv_t *priv)
{
    priv->cache = hash_str_new(256, free, _free_cached_entry);
    if (UNLIKELY(!priv->cache))
        return;

    if (UNLIKELY(pthread_mutex_lock(&priv->cache_mutex) < 0))
        return;

    _cache_small_files_recurse(priv, priv->root_path, 0);

    if (UNLIKELY(pthread_mutex_unlock(&priv->cache_mutex) < 0))
        perror("pthread_mutex_unlock");
}

static void *
serve_files_init(void *args)
{
    const char *root_path = args;
    char *canonical_root;
    int root_fd;
    struct serve_files_priv_t *priv;

    canonical_root = realpath(root_path, NULL);
    if (!canonical_root) {
        perror("serve_files_init");
        goto out_realpath;
    }

    root_fd = open(canonical_root, O_RDONLY | O_NOATIME);
    if (root_fd < 0) {
        perror("serve_files_init");
        goto out_open;
    }

    priv = malloc(sizeof(*priv));
    if (!priv) {
        perror("serve_files_init");
        goto out_malloc;
    }

    priv->root_path = canonical_root;
    priv->root_path_len = strlen(canonical_root);
    priv->root_fd = root_fd;
    pthread_mutex_init(&priv->cache_mutex, NULL);

    /* Make sure time stuff has been loaded */
    (void)gmtime((time_t[]){ time(NULL) });

    printf("Caching small files in \"%s\": ", canonical_root);
    fflush(stdout);
    _cache_small_files(priv);
    printf("done.\n");

    return priv;

out_malloc:
    close(root_fd);
out_open:
    free(canonical_root);
out_realpath:
    return NULL;
}

static void
serve_files_shutdown(void *data)
{
    struct serve_files_priv_t *priv = data;

    if (!priv)
        return;

    hash_free(priv->cache);
    close(priv->root_fd);
    free(priv->root_path);
    free(priv);
}

static ALWAYS_INLINE bool
_client_has_fresh_content(lwan_request_t *request, time_t mtime)
{
    return request->header.if_modified_since && mtime <= request->header.if_modified_since;
}

#define ADD_DATE_HEADER(d,b,n) \
    do { \
        if (LIKELY(_rfc_time((d), (b)))) { \
            hdr->key = (n); \
            hdr->value = (b); \
            ++hdr; \
        } \
    } while(0)

static size_t
_prepare_headers(lwan_request_t *request, lwan_http_status_t return_status,
                 struct stat *st, char *headers, size_t header_buf_size)
{
    lwan_key_value_t date_headers[4], *hdr = date_headers;
    char last_modified_buf[32], date_buf[32], expires_buf[32];

    ADD_DATE_HEADER(st->st_mtime, last_modified_buf, "Last-Modified");
    ADD_DATE_HEADER(NOW, date_buf, "Date");
    ADD_DATE_HEADER(ONE_WEEK, expires_buf, "Expires");

    if (LIKELY(date_headers != hdr)) {
        hdr->key = hdr->value = NULL;
        request->response.headers = date_headers;
    }

    request->response.content_length = st->st_size;

    return lwan_prepare_response_header(request, return_status, headers, header_buf_size);
}

#undef ADD_DATE_HEADER

static ALWAYS_INLINE bool
_compute_range(lwan_request_t *request, off_t *from, off_t *to, struct stat *st)
{
    off_t f, t;

    f = request->header.range.from;
    t = request->header.range.to;

    /*
     * No Range: header present: both t and f are -1
     */
    if (LIKELY(t <= 0 && f <= 0)) {
        *from = 0;
        *to = st->st_size;
        return true;
    }

    /*
     * To goes beyond from or To and From are the same: this is unsatisfiable.
     */
    if (UNLIKELY(t >= f))
        return false;

    /*
     * Range goes beyond the size of the file
     */
    if (UNLIKELY(f >= st->st_size || t >= st->st_size))
        return false;

    /*
     * t < 0 means ranges from f to the file size
     */
    if (t < 0)
        t = st->st_size - f;
    else
        t -= f;

    /*
     * If for some reason the previous calculations yields something
     * less than zero, the range is unsatisfiable.
     */
    if (UNLIKELY(t <= 0))
        return false;

    st->st_size = t;
    *from = f;
    *to = t;

    return true;
}

static lwan_http_status_t
_serve_file_stream(lwan_request_t *request, void *data)
{
    char headers[DEFAULT_HEADERS_SIZE];
    lwan_http_status_t return_status = HTTP_OK;
    struct stat st;
    size_t header_len;
    struct serve_files_priv_t *priv = request->response.stream.priv;
    char *path;
    off_t from, to;

    if (data != priv->root_path)
        path = (char *)data + priv->root_path_len + 1;
    else
        path = "index.html";

    if (UNLIKELY(fstatat(priv->root_fd, path, &st, 0) < 0)) {
        return_status = (errno == EACCES) ? HTTP_FORBIDDEN : HTTP_NOT_FOUND;
        goto end;
    }

    if (S_ISDIR(st.st_mode)) {
        char *index_file;

        if (asprintf(&index_file, "%s/index.html", (char *)data) < 0) {
            return_status = HTTP_INTERNAL_ERROR;
            goto end;
        }

        free(data);

        request->response.mime_type = "text/html";
        return _serve_file_stream(request, index_file);
    }

    if (UNLIKELY(!_compute_range(request, &from, &to, &st))) {
        return_status = HTTP_RANGE_UNSATISFIABLE;
        goto end;
    }

    if (_client_has_fresh_content(request, st.st_mtime))
        return_status = HTTP_NOT_MODIFIED;

    if (UNLIKELY(!(header_len = _prepare_headers(request, return_status, &st, headers, sizeof(headers))))) {
        return_status = HTTP_INTERNAL_ERROR;
        goto end;
    }

    if (request->method == HTTP_HEAD || return_status == HTTP_NOT_MODIFIED) {
        if (UNLIKELY(write(request->fd, headers, header_len) < 0))
            return_status = HTTP_INTERNAL_ERROR;
    } else {
        int file_fd = openat(priv->root_fd, path, O_RDONLY | O_NOATIME);

        if (UNLIKELY(file_fd < 0)) {
            return_status = (errno == EACCES) ? HTTP_FORBIDDEN : HTTP_NOT_FOUND;
            goto end;
        } else if (UNLIKELY(send(request->fd, headers, header_len, MSG_MORE) < 0)) {
            return_status = HTTP_INTERNAL_ERROR;
        } else if (UNLIKELY(lwan_sendfile(request, file_fd, from, to) < 0)) {
            return_status = HTTP_INTERNAL_ERROR;
        }

        close(file_fd);
    }

end:
    if (data != priv->root_path)
        free(data);

    return return_status;
}

static bool
_serve_cached_file(struct serve_files_priv_t *priv, lwan_request_t *request)
{
    struct cache_entry_t *cache_entry;
    const char *contents;
    size_t size;
    bool served;

    /*
     * The mutex will be locked while the cache is being updated. To be on
     * the safe side, just serve the file using regular disk I/O this time.
     */
    if (UNLIKELY(pthread_mutex_trylock(&priv->cache_mutex) < 0))
        return false;

    cache_entry = hash_find(priv->cache, request->url.value);
    if (!cache_entry) {
        served = false;
        goto end;
    }

    request->response.mime_type = (char *)cache_entry->mime_type;

    if (LIKELY(cache_entry->compressed.size)) {
        /*
         * TODO: check Accept-Encoding header
         * TODO: send Transfer-Encoding header
         * TODO: send date headers
         */
        contents = cache_entry->compressed.contents;
        size = cache_entry->compressed.size;
    } else {
        contents = cache_entry->uncompressed.contents;
        size = cache_entry->uncompressed.size;
    }

    strbuf_set_static(request->response.buffer, contents, size);
    served = true;

end:
    pthread_mutex_unlock(&priv->cache_mutex);
    return served;
}

static lwan_http_status_t
serve_files_handle_cb(lwan_request_t *request, lwan_response_t *response, void *data)
{
    lwan_http_status_t return_status = HTTP_OK;
    char *canonical_path;
    struct serve_files_priv_t *priv = data;

    if (UNLIKELY(!priv)) {
        return_status = HTTP_INTERNAL_ERROR;
        goto fail;
    }

    while (UNLIKELY(*request->url.value == '/' && request->url.len > 0)) {
        ++request->url.value;
        --request->url.len;
    }

    if (!request->url.len) {
        canonical_path = priv->root_path;
        response->mime_type = "text/html";
        goto serve;
    }

    if (_serve_cached_file(priv, request))
        return HTTP_OK;

    canonical_path = realpathat(priv->root_fd, priv->root_path, request->url.value, NULL);
    if (UNLIKELY(!canonical_path)) {
        switch (errno) {
        case EACCES:
            return_status = HTTP_FORBIDDEN;
            goto fail;
        case ENOENT:
        case ENOTDIR:
            return_status = HTTP_NOT_FOUND;
            goto fail;
        }
        return_status = HTTP_BAD_REQUEST;
        goto fail;
    }

    if (UNLIKELY(strncmp(canonical_path, priv->root_path, priv->root_path_len))) {
        free(canonical_path);
        /*
         * The reason a HTTP_NOT_FOUND is yielded here instead of a HTTP_FORBIDDEN
         * is that yielding HTTP_FORBIDDEN might lead to unwanted information
         * disclosure with malicious requests. For example, if the request:
         *     GET /../../../../../../../../../../etc/debian_version HTTP/1.0
         * Yields a different response from:
         *     GET /../../../../../../../../../../etc/something_else HTTP/1.0
         * Then an attacker might know that this system is probably Debian based.
         *
         * So just return HTTP_NOT_FOUND here -- which isn't wrong anyway, since
         * the requested resource is outside the root directory.
         */
        return_status = HTTP_NOT_FOUND;
        goto fail;
    }

    response->mime_type = (char*)lwan_determine_mime_type_for_file_name(request->url.value);
serve:
    response->stream.callback = _serve_file_stream;
    response->stream.data = canonical_path;
    response->stream.priv = priv;

    return return_status;

fail:
    response->stream.callback = NULL;
    return return_status;
}
