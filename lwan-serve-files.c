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
#include <assert.h>
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
#include "lwan-serve-files.h"
#include "lwan-sendfile.h"
#include "lwan-dir-watch.h"
#include "hash.h"
#include "realpathat.h"

#define NOW 0
#define ONE_HOUR 3600
#define ONE_DAY (ONE_HOUR * 24)
#define ONE_WEEK (ONE_DAY * 7)
#define ONE_MONTH (ONE_DAY * 31)

#define SET_NTH_HEADER(number_, key_, value_) \
    do { \
        headers[number_].key = (key_); \
        headers[number_].value = (value_); \
    } while(0)

#define ATOMIC_READ(V)		(*(volatile typeof(V) *)&(V))
#define ATOMIC_AAF(P, V) 	(__sync_add_and_fetch((P), (V)))

typedef struct serve_files_priv_t_	serve_files_priv_t;
typedef struct cache_entry_t_		cache_entry_t;
typedef struct cache_funcs_t_		cache_funcs_t;
typedef struct mmap_cache_data_t_	mmap_cache_data_t;
typedef struct sendfile_cache_data_t_	sendfile_cache_data_t;
typedef struct redir_cache_data_t_	redir_cache_data_t;

struct serve_files_priv_t_ {
    struct {
        char *path;
        size_t path_len;
        int fd;
    } root;

    int extra_modes;
    char *index_html;

    struct {
        struct hash *entries;
        pthread_rwlock_t lock;
    } cache;

    struct {
        char date[31];
        char expires[31];
        time_t last;
        pthread_rwlock_t lock;
    } date;
};

struct cache_funcs_t_ {
    bool (*init)(cache_entry_t *ce,
                 serve_files_priv_t *priv,
                 char *full_path,
                 struct stat *st);
    void (*free)(void *data);

    lwan_http_status_t (*serve)(cache_entry_t *ce,
                                serve_files_priv_t *priv,
                                lwan_request_t *request);
};

struct mmap_cache_data_t_ {
    struct {
        void *contents;
        /* zlib expects unsigned longs instead of size_t */
        unsigned long size;
    } compressed, uncompressed;
};

struct sendfile_cache_data_t_ {
    /*
     * FIXME Investigate if keeping files open and dup()ing them
     *       is faster than openat()ing. This won't scale as well,
     *       but might be a good alternative for popular files.
     */

    char *filename;
    size_t size;
};

struct redir_cache_data_t_ {
    char *redir_to;
};

struct cache_entry_t_ {
    struct {
        char string[31];
        time_t integer;
    } last_modified;

    const char *mime_type;

    unsigned int serving_count;
    unsigned int deleted;

    const cache_funcs_t *funcs;
};

static void _cache_files_recurse(serve_files_priv_t *priv,
                                 char *root, int levels);

static bool _mmap_init(cache_entry_t *ce, serve_files_priv_t *priv,
                       char *full_path, struct stat *st);
static void _mmap_free(void *data);
static lwan_http_status_t _mmap_serve(cache_entry_t *ce,
                                      serve_files_priv_t *priv,
                                      lwan_request_t *request);
static bool _sendfile_init(cache_entry_t *ce, serve_files_priv_t *priv,
                           char *full_path, struct stat *st);
static void _sendfile_free(void *data);
static lwan_http_status_t _sendfile_serve(cache_entry_t *ce,
                                          serve_files_priv_t *priv,
                                          lwan_request_t *request);

static void _redir_free(void *data);
static lwan_http_status_t _redir_serve(cache_entry_t *ce,
                                       serve_files_priv_t *priv,
                                       lwan_request_t *request);

static const cache_funcs_t mmap_funcs = {
    .init = _mmap_init,
    .free = _mmap_free,
    .serve = _mmap_serve
};

static const cache_funcs_t sendfile_funcs = {
    .init = _sendfile_init,
    .free = _sendfile_free,
    .serve = _sendfile_serve
};

static const cache_funcs_t redir_funcs = {
    .init = NULL,
    .free = _redir_free,
    .serve = _redir_serve
};

static char *index_html = "index.html";

static void
_compress_cached_entry(mmap_cache_data_t *md)
{
    static const size_t deflated_header_size = sizeof("Content-Encoding: deflate");

    md->compressed.size = compressBound(md->uncompressed.size);

    if (UNLIKELY(!(md->compressed.contents = malloc(md->compressed.size))))
        goto error_zero_out;

    if (UNLIKELY(compress(md->compressed.contents, &md->compressed.size,
                          md->uncompressed.contents, md->uncompressed.size) != Z_OK))
        goto error_free_compressed;

    if ((md->compressed.size + deflated_header_size) < md->uncompressed.size)
        return;

error_free_compressed:
    free(md->compressed.contents);
    md->compressed.contents = NULL;
error_zero_out:
    md->compressed.size = 0;
}

static bool
_mmap_init(cache_entry_t *ce,
           serve_files_priv_t *priv,
           char *full_path,
           struct stat *st)
{
    mmap_cache_data_t *md = (mmap_cache_data_t *)(ce + 1);
    int file_fd;
    bool success;

    file_fd = open(full_path, O_RDONLY | priv->extra_modes);
    if (UNLIKELY(file_fd < 0))
        return false;

    md->uncompressed.contents = mmap(NULL, st->st_size, PROT_READ,
                                     MAP_SHARED, file_fd, 0);
    if (UNLIKELY(md->uncompressed.contents == MAP_FAILED)) {
        success = false;
        goto close_file;
    }

    if (UNLIKELY(madvise(md->uncompressed.contents, st->st_size,
                         MADV_WILLNEED) < 0))
        perror("madvise");

    md->uncompressed.size = st->st_size;
    _compress_cached_entry(md);

    success = true;

close_file:
    close(file_fd);

    return success;
}

static bool
_sendfile_init(cache_entry_t *ce,
               serve_files_priv_t *priv,
               char *full_path,
               struct stat *st)
{
    sendfile_cache_data_t *sd = (sendfile_cache_data_t *)(ce + 1);

    sd->size = st->st_size;
    sd->filename = strdup(full_path + priv->root.path_len + 1);

    return !!sd->filename;
}

static ALWAYS_INLINE bool
_rfc_time(serve_files_priv_t *priv, time_t t, char buffer[32])
{
    bool ret;
    time_t tt;

    if (pthread_rwlock_rdlock(&priv->date.lock) < 0) {
        perror("pthread_wrlock_rdlock");
        return false;
    }

    tt = (t <= ONE_MONTH) ? priv->date.last + t : t;
    ret = !!strftime(buffer, 31, "%a, %d %b %Y %H:%M:%S GMT", gmtime(&tt));

    if (pthread_rwlock_unlock(&priv->date.lock) < 0) {
        perror("pthread_wrlock_unlock");
        return false;
    }

    return ret;
}

static void
_redir_free(void *data)
{
    redir_cache_data_t *rd = data;

    free(rd->redir_to);
}

static lwan_http_status_t
_redir_serve(cache_entry_t *ce, serve_files_priv_t *priv __attribute__((unused)), lwan_request_t *request)
{
    redir_cache_data_t *rd = (redir_cache_data_t *)(ce + 1);
    lwan_key_value_t headers[2];
    size_t header_len;
    char header_buf[DEFAULT_HEADERS_SIZE];

    strbuf_printf(request->response.buffer, "Redirecting to %s", rd->redir_to);
    request->response.content_length = strbuf_get_length(request->response.buffer);
    request->response.headers = headers;

    SET_NTH_HEADER(0, "Location", rd->redir_to);
    SET_NTH_HEADER(1, NULL, NULL);

    header_len = lwan_prepare_response_header(request,
            HTTP_MOVED_PERMANENTLY, header_buf, sizeof(header_buf));
    if (UNLIKELY(!header_len))
        return HTTP_INTERNAL_ERROR;

    struct iovec response_vec[] = {
        { .iov_base = header_buf, .iov_len = header_len },
        { .iov_base = strbuf_get_buffer(request->response.buffer), .iov_len = strbuf_get_length(request->response.buffer) }
    };

    if (UNLIKELY(writev(request->fd, response_vec, N_ELEMENTS(response_vec)) < 0))
        return HTTP_INTERNAL_ERROR;

    return HTTP_MOVED_PERMANENTLY;
}

static void
_cache_redir_to_directory(serve_files_priv_t *priv, char *dir)
{
    cache_entry_t *ce;
    redir_cache_data_t *rd;

    ce = malloc(sizeof(*ce) + sizeof(redir_cache_data_t));
    if (UNLIKELY(!ce))
        return;

    rd = (redir_cache_data_t *)(ce + 1);
    if (UNLIKELY(asprintf(&rd->redir_to, "%s/", dir) < 0)) {
        free(ce);
        return;
    }

    ce->funcs = &redir_funcs;

    hash_add(priv->cache.entries, strdup(dir), ce);
}

static void
_cache_one_file(serve_files_priv_t *priv, char *full_path, struct stat *st)
{
    /* Assumes priv->cache.lock locked */
    cache_entry_t *ce;
    struct stat dir_st;
    char *should_free = NULL;
    char *key = full_path + priv->root.path_len + 1;
    bool is_caching_directory;
    size_t data_size;
    const cache_funcs_t *funcs;

    if (!strcmp(full_path + priv->root.path_len, priv->root.path + priv->root.path_len))
        return;

    if (st) {
        is_caching_directory = false;
    } else {
        char *tmp;

        /*
         * FIXME Use the template engine to create a directory listing if
         *       index.html isn't available.
         */
        if (asprintf(&tmp, "%s/%s", full_path, priv->index_html) < 0)
            return;
        if (fstatat(priv->root.fd, tmp, &dir_st, 0) < 0) {
            free(tmp);
            return;
        }

        st = &dir_st;
        should_free = full_path = tmp;
        is_caching_directory = true;
    }

    if (st->st_size <= 16384) {
        data_size = sizeof(mmap_cache_data_t);
        funcs = &mmap_funcs;
    } else {
        data_size = sizeof(sendfile_cache_data_t);
        funcs = &sendfile_funcs;
    }

    ce = malloc(sizeof(*ce) + data_size);
    if (UNLIKELY(!ce))
        goto error;

    if (UNLIKELY(!funcs->init(ce, priv, full_path, st)))
        goto error;

    _rfc_time(priv, st->st_mtime, ce->last_modified.string);

    ce->mime_type = lwan_determine_mime_type_for_file_name(full_path + priv->root.path_len);
    ce->last_modified.integer = st->st_mtime;
    ce->deleted = false;
    ce->serving_count = 0;
    ce->funcs = funcs;

    if (!is_caching_directory) {
        char *tmp;

        hash_add(priv->cache.entries, strdup(key), ce);

        tmp = strrchr(key, '/');
        if (tmp && !strcmp(tmp + 1, priv->index_html)) {
            tmp[0] = '\0';
            _cache_redir_to_directory(priv, key);
        }
    } else {
        char *tmp;

        if (LIKELY(asprintf(&tmp, "%s/", key) > 0))
            hash_add(priv->cache.entries, tmp, ce);
    }

    free(should_free);
    return;

error:
    free(ce);
    free(should_free);
}

static bool
_key_match_prefix(const void *key, const size_t key_len, const void *data)
{
    return !strncmp(key, data, key_len);
}

static void
_watched_dir_changed(char *name, char *root, lwan_dir_watch_event_t event, void *data)
{
    serve_files_priv_t *priv = data;

    if (UNLIKELY(pthread_rwlock_wrlock(&priv->cache.lock) < 0)) {
        perror("pthread_rwlock_wrlock");
        return;
    }

    switch (event) {
    case DIR_WATCH_DEL_SELF:
        hash_del_predicate(priv->cache.entries, _key_match_prefix, name);
        break;
    case DIR_WATCH_MOD:
        hash_del(priv->cache.entries, name);
        /* Fallthrough */
    case DIR_WATCH_ADD: {
            char path[PATH_MAX];
            struct stat st;

            if (UNLIKELY(snprintf(path, PATH_MAX, "%s/%s", root, name) < 0))
                goto end;
            if (UNLIKELY(stat(path, &st) < 0))
                goto end;

            if (S_ISDIR(st.st_mode))
                _cache_files_recurse(priv, path, 0);
            else if (st.st_size)
                _cache_one_file(priv, path, &st);
        }
        break;
    case DIR_WATCH_DEL: {
            char name_with_slash[PATH_MAX];

            hash_del(priv->cache.entries, name);

            if (UNLIKELY(snprintf(name_with_slash, PATH_MAX, "%s/", name) < 0))
                goto end;

            hash_del(priv->cache.entries, name_with_slash);
        }
        break;
    }

end:
    if (UNLIKELY(pthread_rwlock_unlock(&priv->cache.lock) < 0))
        perror("pthread_rwlock_unlock");
}

static void
_cache_files_recurse(serve_files_priv_t *priv, char *root, int levels)
{
    /* Assumes priv->cache.lock locked */
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

        if (UNLIKELY(snprintf(full_path, PATH_MAX, "%s/%s", root, entry->d_name) < 0))
            continue;

        if (S_ISDIR(st.st_mode))
            _cache_files_recurse(priv, full_path, levels + 1);
        else
            _cache_one_file(priv, full_path, &st);
    }

    /* Cache the index for this directory as well. */
    _cache_one_file(priv, root, NULL);

    lwan_dir_watch_add(root, _watched_dir_changed, priv);

error:
    closedir(dir);
}

static void
_mmap_free(void *data)
{
    mmap_cache_data_t *md = data;

    munmap(md->uncompressed.contents, md->uncompressed.size);
    free(md->compressed.contents);
}

static void
_sendfile_free(void *data)
{
    sendfile_cache_data_t *sd = data;

    free(sd->filename);
}

static void
_free_cached_entry(void *data)
{
    cache_entry_t *ce = data;

    if (ATOMIC_READ(ce->serving_count) > 0) {
        /*
         * After this function returns, this cache entry has been removed
         * from the hash table.  Do not free it as someone is still using
         * it; just mark it as deleted, so when the last serving thread that
         * has a reference to this entry can actually free this.
         *
         * When this function is being called, the hash table is also
         * locked.  The reason atomic reads and writes is that the serving
         * threads do not lock the hash table: only the directory watcher
         * (while modifying it) and the request handler (while looking up).
         */
        ATOMIC_AAF(&ce->deleted, 1);

        /*
         * The serving count is read again to ensure that, if preemption
         * occurred before the ce->deleted increment, and the serving count
         * dropped to zero from another thread, this node still gets freed
         * if it's not being used anymore.
         */
        if (ATOMIC_READ(ce->serving_count) != 0)
            return;
    }

    assert(ATOMIC_READ(ce->serving_count) == 0);

    ce->funcs->free(ce + 1);
    free(ce);
}

static void
_cache_files(serve_files_priv_t *priv)
{
    priv->cache.entries = hash_str_new(256, free, _free_cached_entry);
    if (UNLIKELY(!priv->cache.entries))
        return;

    if (UNLIKELY(pthread_rwlock_wrlock(&priv->cache.lock) < 0))
        return;

    _cache_files_recurse(priv, priv->root.path, 0);

    if (UNLIKELY(pthread_rwlock_unlock(&priv->cache.lock) < 0))
        perror("pthread_mutex_unlock");
}

static void
_update_date_cache(serve_files_priv_t *priv)
{
    if (pthread_rwlock_trywrlock(&priv->date.lock) < 0)
        return;

    time_t now = time(NULL);

    if (now == priv->date.last)
        goto unlock;

    priv->date.last = now;
    _rfc_time(priv, NOW, priv->date.date);
    _rfc_time(priv, ONE_WEEK, priv->date.expires);

unlock:
    if (pthread_rwlock_unlock(&priv->date.lock) < 0)
        perror("pthread_rwlock_unlock");
}

static void *
serve_files_init(void *args)
{
    struct lwan_serve_files_settings_t *settings = args;
    char *canonical_root;
    int root_fd;
    serve_files_priv_t *priv;
    int extra_modes = O_NOATIME;

    canonical_root = realpath(settings->root_path, NULL);
    if (!canonical_root) {
        perror("serve_files_init");
        goto out_realpath;
    }

    root_fd = open(canonical_root, O_RDONLY | O_DIRECTORY | extra_modes);
    if (root_fd < 0) {
        root_fd = open(canonical_root, O_RDONLY | O_DIRECTORY);
        extra_modes &= ~O_NOATIME;
    }
    if (root_fd < 0) {
        perror("serve_files_init");
        goto out_open;
    }

    priv = malloc(sizeof(*priv));
    if (!priv) {
        perror("serve_files_init");
        goto out_malloc;
    }

    priv->root.path = canonical_root;
    priv->root.path_len = strlen(canonical_root);
    priv->root.fd = root_fd;
    priv->extra_modes = extra_modes;
    priv->index_html = settings->index_html ? settings->index_html : index_html;

    pthread_rwlock_init(&priv->date.lock, NULL);
    priv->date.last = 0;
    _update_date_cache(priv);

    printf("Caching files in \"%s\": ", canonical_root);
    fflush(stdout);
    pthread_rwlock_init(&priv->cache.lock, NULL);
    _cache_files(priv);
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
    serve_files_priv_t *priv = data;

    if (!priv)
        return;

    /* FIXME: Some thread might be holding the lock. Wait? */
    hash_free(priv->cache.entries);
    pthread_rwlock_destroy(&priv->cache.lock);
    pthread_rwlock_destroy(&priv->date.lock);
    close(priv->root.fd);
    free(priv->root.path);
    free(priv);
}

static ALWAYS_INLINE bool
_client_has_fresh_content(lwan_request_t *request, time_t mtime)
{
    return request->header.if_modified_since && mtime <= request->header.if_modified_since;
}

static size_t
_prepare_headers(serve_files_priv_t *priv,
                 lwan_request_t *request,
                 lwan_http_status_t return_status,
                 cache_entry_t *ce,
                 size_t size,
                 bool deflated,
                 char *header_buf,
                 size_t header_buf_size)
{
    lwan_key_value_t headers[5];
    size_t prepped_buffer_size;

    SET_NTH_HEADER(0, "Last-Modified", ce->last_modified.string);

    request->response.headers = headers;
    request->response.content_length = size;

    if (UNLIKELY(pthread_rwlock_rdlock(&priv->date.lock) < 0)) {
        perror("pthread_wrlock_rdlock");
        return 0;
    }

    SET_NTH_HEADER(1, "Date", priv->date.date);
    SET_NTH_HEADER(2, "Expires", priv->date.expires);

    if (deflated) {
        SET_NTH_HEADER(3, "Content-Encoding", "deflate");
        SET_NTH_HEADER(4, NULL, NULL);
    } else {
        SET_NTH_HEADER(3, NULL, NULL);
    }

    prepped_buffer_size = lwan_prepare_response_header(request, return_status, header_buf, header_buf_size);

    if (UNLIKELY(pthread_rwlock_unlock(&priv->date.lock) < 0))
        perror("pthread_wrlock_unlock");

    return prepped_buffer_size;
}

static ALWAYS_INLINE bool
_compute_range(lwan_request_t *request, off_t *from, off_t *to, off_t size)
{
    off_t f, t;

    f = request->header.range.from;
    t = request->header.range.to;

    /*
     * No Range: header present: both t and f are -1
     */
    if (LIKELY(t <= 0 && f <= 0)) {
        *from = 0;
        *to = size;
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
    if (UNLIKELY(f >= size || t >= size))
        return false;

    /*
     * t < 0 means ranges from f to the file size
     */
    if (t < 0)
        t = size - f;
    else
        t -= f;

    /*
     * If for some reason the previous calculations yields something
     * less than zero, the range is unsatisfiable.
     */
    if (UNLIKELY(t <= 0))
        return false;

    *from = f;
    *to = t;

    return true;
}

static lwan_http_status_t
_sendfile_serve(cache_entry_t *ce,
                serve_files_priv_t *priv,
                lwan_request_t *request)
{
    sendfile_cache_data_t *sd = (sendfile_cache_data_t *)(ce + 1);
    char *headers = request->buffer;
    size_t header_len;
    lwan_http_status_t return_status = HTTP_OK;
    off_t from, to;

    if (UNLIKELY(!_compute_range(request, &from, &to, sd->size)))
        return HTTP_RANGE_UNSATISFIABLE;

    if (_client_has_fresh_content(request, ce->last_modified.integer))
        return_status = HTTP_NOT_MODIFIED;

    header_len = _prepare_headers(priv, request, return_status,
                                  ce, sd->size, false,
                                  headers, DEFAULT_HEADERS_SIZE);
    if (UNLIKELY(!header_len))
        return HTTP_INTERNAL_ERROR;

    if (request->method == HTTP_HEAD || return_status == HTTP_NOT_MODIFIED) {
        if (UNLIKELY(write(request->fd, headers, header_len) < 0))
            return HTTP_INTERNAL_ERROR;
    } else {
        int file_fd = openat(priv->root.fd, sd->filename,
                             O_RDONLY | priv->extra_modes);

        if (UNLIKELY(file_fd < 0))
            return (errno == EACCES) ? HTTP_FORBIDDEN : HTTP_NOT_FOUND;

        if (UNLIKELY(send(request->fd, headers, header_len, MSG_MORE) < 0)) {
            return_status = HTTP_INTERNAL_ERROR;
        } else if (UNLIKELY(lwan_sendfile(request, file_fd, from, to) < 0)) {
            return_status = HTTP_INTERNAL_ERROR;
        }

        close(file_fd);
    }

    return return_status;
}

static lwan_http_status_t
_mmap_serve(cache_entry_t *ce,
            serve_files_priv_t *priv,
            lwan_request_t *request)
{
    mmap_cache_data_t *md = (mmap_cache_data_t *)(ce + 1);
    char *headers = request->buffer;
    size_t header_len;
    size_t size;
    void *contents;
    lwan_http_status_t return_status = HTTP_OK;
    bool deflated;

    if (_client_has_fresh_content(request, ce->last_modified.integer))
        return_status = HTTP_NOT_MODIFIED;

    deflated = request->header.accept_encoding.deflate && md->compressed.size;
    if (LIKELY(deflated)) {
        contents = md->compressed.contents;
        size = md->compressed.size;
    } else {
        contents = md->uncompressed.contents;
        size = md->uncompressed.size;
    }

    header_len = _prepare_headers(priv, request, return_status,
                                  ce, size, deflated,
                                  headers, DEFAULT_HEADERS_SIZE);
    if (UNLIKELY(!header_len))
        return HTTP_INTERNAL_ERROR;

    if (request->method == HTTP_HEAD || return_status == HTTP_NOT_MODIFIED) {
        if (UNLIKELY(write(request->fd, headers, header_len) < 0))
            return_status = HTTP_INTERNAL_ERROR;
    } else {
        struct iovec response_vec[] = {
            { .iov_base = headers, .iov_len = header_len },
            { .iov_base = contents, .iov_len = size }
        };

        if (UNLIKELY(writev(request->fd, response_vec, N_ELEMENTS(response_vec)) < 0))
            return_status = HTTP_INTERNAL_ERROR;
    }

    return return_status;
}

static cache_entry_t *
_create_temporary_cache_entry(serve_files_priv_t *priv, char *path)
{
    cache_entry_t *ce;
    sendfile_cache_data_t *sd;
    struct stat st;
    char *real;

    if (UNLIKELY(fstatat(priv->root.fd, path, &st, 0) < 0))
        return NULL;

    if (S_ISDIR(st.st_mode)) {
        char *tmp;

        if (UNLIKELY(asprintf(&tmp, "%s/%s", path, priv->index_html) < 0))
            return NULL;

        ce = _create_temporary_cache_entry(priv, tmp);
        free(tmp);

        return ce;
    }

    ce = malloc(sizeof(*ce) + sizeof(*sd));
    if (UNLIKELY(!ce))
        return NULL;

    sd = (sendfile_cache_data_t *)(ce + 1);
    sd->size = st.st_size;

    real = realpathat(priv->root.fd, priv->root.path, path, NULL);
    if (UNLIKELY(!real)) {
        free(ce);
        return NULL;
    }
    if (UNLIKELY(strncmp(real, priv->root.path, priv->root.path_len))) {
        free(real);
        free(ce);
        return NULL;
    }
    sd->filename = real;

    _rfc_time(priv, st.st_mtime, ce->last_modified.string);
    ce->last_modified.integer = st.st_mtime;
    ce->mime_type = lwan_determine_mime_type_for_file_name(path);
    ce->funcs = &sendfile_funcs;

    /*
     * This cache entry is temporary: the serving count begins at 1, so that
     * it will be unreffed after serving, and the entry freed because it is
     * also marked as deleted.
     */
    ce->serving_count = 1;
    ce->deleted = 1;

    return ce;
}

static cache_entry_t *
_fetch_from_cache_and_ref(serve_files_priv_t *priv, char *path)
{
    cache_entry_t *ce;

    /*
     * If the cache is locked, don't block waiting for it to be unlocked:
     * just serve the file using sendfile().
     */
    if (UNLIKELY(pthread_rwlock_tryrdlock(&priv->cache.lock) < 0))
        return _create_temporary_cache_entry(priv, path);

    ce = hash_find(priv->cache.entries, path);
    if (ce)
        ATOMIC_AAF(&ce->serving_count, 1);

    pthread_rwlock_unlock(&priv->cache.lock);
    return ce;
}

static lwan_http_status_t
_serve_cached_file_stream(lwan_request_t *request, void *data)
{
    cache_entry_t *ce = data;
    serve_files_priv_t *priv = request->response.stream.priv;
    lwan_http_status_t return_status;

    return_status = ce->funcs->serve(ce, priv, request);

    if (ATOMIC_AAF(&ce->serving_count, -1) == 0 && ATOMIC_READ(ce->deleted)) {
        /*
         * If ce->deleted, then it has been already removed from the hash
         * table -- this is just a dangling reference and at this point it
         * is safe to free it.
         */

        _free_cached_entry(ce);
    }

    return return_status;
}

static lwan_http_status_t
serve_files_handle_cb(lwan_request_t *request, lwan_response_t *response, void *data)
{
    lwan_http_status_t return_status = HTTP_OK;
    char *path;
    serve_files_priv_t *priv = data;
    cache_entry_t *ce;

    if (UNLIKELY(!priv)) {
        return_status = HTTP_INTERNAL_ERROR;
        goto fail;
    }

    while (*request->url.value == '/' && request->url.len > 0) {
        ++request->url.value;
        --request->url.len;
    }

    if (!request->url.len)
        path = priv->index_html;
    else
        path = request->url.value;

    ce = _fetch_from_cache_and_ref(priv, path);
    if (!ce) {
        char *tmp;

        if (!strstr(path, "/../")) {
            return_status = HTTP_NOT_FOUND;
            goto fail;
        }

        tmp = realpathat(priv->root.fd, priv->root.path, path, NULL);
        if (UNLIKELY(!tmp)) {
            return_status = HTTP_NOT_FOUND;
            goto fail;
        }
        if (LIKELY(!strncmp(tmp, priv->root.path, priv->root.path_len)))
            ce = _fetch_from_cache_and_ref(priv, tmp + priv->root.path_len + 1);

        free(tmp);

        if (UNLIKELY(!ce)) {
            return_status = HTTP_NOT_FOUND;
            goto fail;
        }
    }

    _update_date_cache(priv);

    response->mime_type = (char *)ce->mime_type;
    response->stream.callback = _serve_cached_file_stream;
    response->stream.data = ce;
    response->stream.priv = priv;

    return HTTP_OK;

fail:
    response->stream.callback = NULL;
    return return_status;
}

lwan_handler_t serve_files = {
    .init = serve_files_init,
    .shutdown = serve_files_shutdown,
    .handle = serve_files_handle_cb,
    .flags = HANDLER_PARSE_IF_MODIFIED_SINCE | HANDLER_PARSE_RANGE | HANDLER_PARSE_ACCEPT_ENCODING
};
