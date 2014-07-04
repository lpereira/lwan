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
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <zlib.h>

#include "lwan.h"
#include "lwan-cache.h"
#include "lwan-io-wrappers.h"
#include "lwan-serve-files.h"
#include "lwan-template.h"
#include "realpathat.h"
#include "hash.h"

#define SET_NTH_HEADER(number_, key_, value_) \
    do { \
        headers[number_].key = (key_); \
        headers[number_].value = (value_); \
    } while(0)

typedef struct serve_files_priv_t_	serve_files_priv_t;
typedef struct file_cache_entry_t_	file_cache_entry_t;
typedef struct cache_funcs_t_		cache_funcs_t;
typedef struct mmap_cache_data_t_	mmap_cache_data_t;
typedef struct sendfile_cache_data_t_	sendfile_cache_data_t;
typedef struct dir_list_cache_data_t_	dir_list_cache_data_t;
typedef struct redir_cache_data_t_	redir_cache_data_t;

struct serve_files_priv_t_ {
    struct {
        char *path;
        size_t path_len;
        int fd;
    } root;

    int open_mode;
    const char *index_html;

    struct cache_t *cache;
    lwan_tpl_t *directory_list_tpl;
};

struct cache_funcs_t_ {
    lwan_http_status_t (*serve)(lwan_request_t *request,
                                void *data);
    bool (*init)(file_cache_entry_t *ce,
                 serve_files_priv_t *priv,
                 const char *full_path,
                 struct stat *st);
    void (*free)(void *data);
    size_t struct_size;
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

struct dir_list_cache_data_t_ {
    strbuf_t *rendered;
};

struct redir_cache_data_t_ {
    char *redir_to;
};

struct file_cache_entry_t_ {
    struct cache_entry_t base;

    struct {
        char string[31];
        time_t integer;
    } last_modified;

    const char *mime_type;
    const cache_funcs_t *funcs;
};

struct file_list_t {
    const char *full_path;
    const char *rel_path;
    struct {
        lwan_tpl_list_generator_t generator;

        const char *icon;
        const char *icon_alt;
        const char *name;
        const char *type;

        int size;
        const char *unit;
    } file_list;
};

static int _directory_list_generator(coro_t *coro);

static bool _mmap_init(file_cache_entry_t *ce, serve_files_priv_t *priv,
                       const char *full_path, struct stat *st);
static void _mmap_free(void *data);
static lwan_http_status_t _mmap_serve(lwan_request_t *request, void *data);
static bool _sendfile_init(file_cache_entry_t *ce, serve_files_priv_t *priv,
                           const char *full_path, struct stat *st);
static void _sendfile_free(void *data);
static lwan_http_status_t _sendfile_serve(lwan_request_t *request, void *data);
static bool _dirlist_init(file_cache_entry_t *ce, serve_files_priv_t *priv,
                       const char *full_path, struct stat *st);
static void _dirlist_free(void *data);
static lwan_http_status_t _dirlist_serve(lwan_request_t *request, void *data);
static bool _redir_init(file_cache_entry_t *ce, serve_files_priv_t *priv,
                       const char *full_path, struct stat *st);
static void _redir_free(void *data);
static lwan_http_status_t _redir_serve(lwan_request_t *request, void *data);


static const cache_funcs_t mmap_funcs = {
    .init = _mmap_init,
    .free = _mmap_free,
    .serve = _mmap_serve,
    .struct_size = sizeof(mmap_cache_data_t)
};

static const cache_funcs_t sendfile_funcs = {
    .init = _sendfile_init,
    .free = _sendfile_free,
    .serve = _sendfile_serve,
    .struct_size = sizeof(sendfile_cache_data_t)
};

static const cache_funcs_t dirlist_funcs = {
    .init = _dirlist_init,
    .free = _dirlist_free,
    .serve = _dirlist_serve,
    .struct_size = sizeof(dir_list_cache_data_t)
};

static const cache_funcs_t redir_funcs = {
    .init = _redir_init,
    .free = _redir_free,
    .serve = _redir_serve,
    .struct_size = sizeof(redir_cache_data_t)
};

static const lwan_var_descriptor_t file_list_item_desc[] = {
    TPL_VAR_STR(struct file_list_t, file_list.icon),
    TPL_VAR_STR(struct file_list_t, file_list.icon_alt),
    TPL_VAR_STR(struct file_list_t, file_list.name),
    TPL_VAR_STR(struct file_list_t, file_list.type),
    TPL_VAR_INT(struct file_list_t, file_list.size),
    TPL_VAR_STR(struct file_list_t, file_list.unit),
    TPL_VAR_SENTINEL
};

static const lwan_var_descriptor_t file_list_desc[] = {
    TPL_VAR_STR(struct file_list_t, full_path),
    TPL_VAR_STR(struct file_list_t, rel_path),
    TPL_VAR_SEQUENCE(struct file_list_t, file_list,
                _directory_list_generator, file_list_item_desc),
    TPL_VAR_SENTINEL
};

static const char *directory_list_tpl_str = "<html>\n"
    "<head>\n"
    "  <title>Index of {{rel_path}}</title>\n"
    "</head>\n"
    "<body>\n"
    "  <h1>Index of {{rel_path}}</h1>\n"
    "  <table>\n"
    "    <tr>\n"
    "      <td>&nbsp;</td>\n"
    "      <td>File name</td>\n"
    "      <td>Type</td>\n"
    "      <td>Size</td>\n"
    "    </tr>\n"
    "    <tr>\n"
    "      <td><img src=\"/icons/back.png\"></td>\n"
    "      <td colspan=\"3\"><a href=\"..\">Parent directory</a></td>\n"
    "    </tr>\n"
    "{{#file_list}}"
    "    <tr>\n"
    "      <td><img src=\"/icons/{{file_list.icon}}.png\" alt=\"{{file_list.icon_alt}}\"></td>\n"
    "      <td><a href=\"{{rel_path}}/{{file_list.name}}\">{{file_list.name}}</a></td>\n"
    "      <td>{{file_list.type}}</td>\n"
    "      <td>{{file_list.size}}{{file_list.unit}}</td>\n"
    "    </tr>\n"
    "{{/file_list}}"
    "  </table>\n"
    "</body>\n"
    "</html>\n";

static int
_directory_list_generator(coro_t *coro)
{
    DIR *dir;
    struct dirent entry, *buffer;
    struct file_list_t *fl = coro_get_data(coro);
    int fd;

    dir = opendir(fl->full_path);
    if (!dir)
        return 0;

    fd = dirfd(dir);
    if (fd < 0)
        goto out;

    while (!readdir_r(dir, &entry, &buffer)) {
        struct stat st;

        if (!buffer)
            break;

        if (entry.d_name[0] == '.')
            continue;

        if (fstatat(fd, entry.d_name, &st, 0) < 0)
            continue;

        if (S_ISDIR(st.st_mode)) {
            fl->file_list.icon = "folder";
            fl->file_list.icon_alt = "DIR";
            fl->file_list.type = "directory";
        } else if (S_ISREG(st.st_mode)) {
            fl->file_list.icon = "file";
            fl->file_list.icon_alt = "FILE";
            fl->file_list.type = lwan_determine_mime_type_for_file_name(entry.d_name);
        } else {
            continue;
        }

        if (st.st_size < 1024) {
            fl->file_list.size = (int)st.st_size;
            fl->file_list.unit = "B";
        } else if (st.st_size < 1024 * 1024) {
            fl->file_list.size = (int)(st.st_size / 1024);
            fl->file_list.unit = "KiB";
        } else if (st.st_size < 1024 * 1024 * 1024) {
            fl->file_list.size = (int)(st.st_size / (1024 * 1024));
            fl->file_list.unit = "MiB";
        } else {
            fl->file_list.size = (int)(st.st_size / (1024 * 1024 * 1024));
            fl->file_list.unit = "GiB";
        }

        fl->file_list.name = entry.d_name;

        coro_yield(coro, 1);
    }

out:
    closedir(dir);
    return 0;
}

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
_mmap_init(file_cache_entry_t *ce,
           serve_files_priv_t *priv,
           const char *full_path,
           struct stat *st)
{
    mmap_cache_data_t *md = (mmap_cache_data_t *)(ce + 1);
    int file_fd;
    bool success;

    file_fd = openat(priv->root.fd, full_path + priv->root.path_len + 1,
                priv->open_mode);
    if (UNLIKELY(file_fd < 0))
        return false;

    md->uncompressed.contents = mmap(NULL, (size_t)st->st_size, PROT_READ,
                                     MAP_SHARED, file_fd, 0);
    if (UNLIKELY(md->uncompressed.contents == MAP_FAILED)) {
        success = false;
        goto close_file;
    }

    if (UNLIKELY(madvise(md->uncompressed.contents, (size_t)st->st_size,
                         MADV_WILLNEED) < 0))
        lwan_status_perror("madvise");

    md->uncompressed.size = (size_t)st->st_size;
    _compress_cached_entry(md);

    ce->mime_type = lwan_determine_mime_type_for_file_name(
                full_path + priv->root.path_len);

    success = true;

close_file:
    close(file_fd);

    return success;
}

static bool
_sendfile_init(file_cache_entry_t *ce,
               serve_files_priv_t *priv,
               const char *full_path,
               struct stat *st)
{
    sendfile_cache_data_t *sd = (sendfile_cache_data_t *)(ce + 1);

    sd->size = (size_t)st->st_size;
    sd->filename = strdup(full_path + priv->root.path_len + 1);

    ce->mime_type = lwan_determine_mime_type_for_file_name(
                full_path + priv->root.path_len);

    return !!sd->filename;
}

static bool
_dirlist_init(file_cache_entry_t *ce,
               serve_files_priv_t *priv,
               const char *full_path,
               struct stat *st __attribute__((unused)))
{
    dir_list_cache_data_t *dd = (dir_list_cache_data_t *)(ce + 1);
    struct file_list_t vars = {
        .full_path = full_path,
        .rel_path = full_path + priv->root.path_len
    };

    dd->rendered = lwan_tpl_apply(priv->directory_list_tpl, &vars);
    ce->mime_type = "text/html";

    return !!dd->rendered;
}

static bool
_redir_init(file_cache_entry_t *ce,
            serve_files_priv_t *priv,
            const char *full_path,
            struct stat *st __attribute__((unused)))
{
    redir_cache_data_t *rd = (redir_cache_data_t *)(ce + 1);

    if (asprintf(&rd->redir_to, "%s/", full_path + priv->root.path_len) < 0)
        return false;

    return true;
}

static const cache_funcs_t *
_get_funcs(serve_files_priv_t *priv, const char *key, char *full_path,
    struct stat *st)
{
    char index_html_path_buf[PATH_MAX];
    char *index_html_path = index_html_path_buf;

    if (S_ISDIR(st->st_mode)) {
        /* It is a directory. It might be the root directory (empty key), or
         * something else.  In either case, tack priv->index_html to the
         * path.  */
        if (*key == '\0') {
            index_html_path = (char *)priv->index_html;
        } else {
            /* Redirect /path to /path/. This is to help cases where there's
             * something like <img src="../foo.png">, so that actually
             * /path/../foo.png is served instead of /path../foo.png.  */
            const char *key_end = rawmemchr(key, '\0');
            if (*(key_end - 1) != '/')
                return &redir_funcs;

            if (UNLIKELY(snprintf(index_html_path, PATH_MAX, "%s%s",
                        key, priv->index_html) < 0))
                return NULL;
        }

        /* See if it exists. */
        if (fstatat(priv->root.fd, index_html_path, st, 0) < 0) {
            if (UNLIKELY(errno != ENOENT))
                return NULL;

            /* If it doesn't, we want to generate a directory list. */
            return &dirlist_funcs;
        }

        /* If it does, we want its full path. */

        /* FIXME: Use strlcpy() here instead of calling strlen()? */
        if (UNLIKELY(priv->root.path_len + 1 /* slash */ +
                            strlen(index_html_path) + 1 >= PATH_MAX))
            return NULL;

        full_path[priv->root.path_len] = '/';
        strncpy(full_path + priv->root.path_len + 1, index_html_path,
                    PATH_MAX - priv->root.path_len - 1);
    }

    /* It's not a directory: choose the fastest way to serve the file
     * judging by its size. */
    if (st->st_size < 16384)
        return &mmap_funcs;

    return &sendfile_funcs;
}

static file_cache_entry_t *
_create_cache_entry_from_funcs(serve_files_priv_t *priv, const char *full_path,
    struct stat *st, const cache_funcs_t *funcs)
{
    file_cache_entry_t *fce;

    fce = malloc(sizeof(*fce) + funcs->struct_size);
    if (UNLIKELY(!fce))
        return NULL;

    if (LIKELY(funcs->init(fce, priv, full_path, st)))
        return fce;

    free(fce);

    if (funcs != &mmap_funcs)
        return NULL;

    return _create_cache_entry_from_funcs(priv, full_path, st, &sendfile_funcs);
}

static struct cache_entry_t *
_create_cache_entry(const char *key, void *context)
{
    serve_files_priv_t *priv = context;
    file_cache_entry_t *fce;
    struct stat st;
    const cache_funcs_t *funcs;
    char full_path[PATH_MAX];

    if (UNLIKELY(!realpathat2(priv->root.fd, priv->root.path,
                key, full_path, &st)))
        return NULL;

    if (UNLIKELY(strncmp(full_path, priv->root.path, priv->root.path_len)))
        return NULL;

    funcs = _get_funcs(priv, key, full_path, &st);
    if (UNLIKELY(!funcs))
        return NULL;

    fce = _create_cache_entry_from_funcs(priv, full_path, &st, funcs);
    if (UNLIKELY(!fce))
        return NULL;

    lwan_format_rfc_time(st.st_mtime, fce->last_modified.string);

    fce->last_modified.integer = st.st_mtime;
    fce->funcs = funcs;

    return (struct cache_entry_t *)fce;
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
_dirlist_free(void *data)
{
    dir_list_cache_data_t *dd = data;

    strbuf_free(dd->rendered);
}

static void
_redir_free(void *data)
{
    redir_cache_data_t *rd = data;

    free(rd->redir_to);
}

static void
_destroy_cache_entry(struct cache_entry_t *entry, void *context __attribute__((unused)))
{
    file_cache_entry_t *fce = (file_cache_entry_t *)entry;

    fce->funcs->free(fce + 1);
    free(fce);
}

static void *
serve_files_init(void *args)
{
    struct lwan_serve_files_settings_t *settings = args;
    char *canonical_root;
    int root_fd;
    serve_files_priv_t *priv;
    int open_mode = O_RDONLY | O_NOATIME | O_NONBLOCK;

    if (!settings->root_path) {
        lwan_status_error("root_path not specified");
        return NULL;
    }

    canonical_root = realpath(settings->root_path, NULL);
    if (!canonical_root) {
        lwan_status_perror("Could not obtain real path of \"%s\"",
                           settings->root_path);
        goto out_realpath;
    }

    root_fd = open(canonical_root, O_DIRECTORY | open_mode);
    if (root_fd < 0) {
        root_fd = open(canonical_root, O_DIRECTORY);
        open_mode &= ~O_NOATIME;
    }
    if (root_fd < 0) {
        lwan_status_perror("Could not open directory \"%s\"",
                            canonical_root);
        goto out_open;
    }

    priv = malloc(sizeof(*priv));
    if (!priv) {
        lwan_status_perror("malloc");
        goto out_malloc;
    }

    priv->cache = cache_create(_create_cache_entry, _destroy_cache_entry,
                priv, 5);
    if (!priv->cache) {
        lwan_status_error("Couldn't create cache");
        goto out_cache_create;
    }

    priv->directory_list_tpl = lwan_tpl_compile_string(
                directory_list_tpl_str, file_list_desc);
    if (!priv->directory_list_tpl) {
        lwan_status_error("Could not compile directory list template");
        goto out_tpl_compile;
    }

    priv->root.path = canonical_root;
    priv->root.path_len = strlen(canonical_root);
    priv->root.fd = root_fd;
    priv->open_mode = open_mode;
    priv->index_html = settings->index_html ? settings->index_html : "index.html";

    return priv;

out_tpl_compile:
    cache_destroy(priv->cache);
out_cache_create:
    free(priv);
out_malloc:
    close(root_fd);
out_open:
    free(canonical_root);
out_realpath:
    return NULL;
}

static void *
serve_files_init_from_hash(const struct hash *hash)
{
    struct lwan_serve_files_settings_t settings = {
        .root_path = hash_find(hash, "path"),
        .index_html = hash_find(hash, "index_path")
    };
    return serve_files_init(&settings);
}

static void
serve_files_shutdown(void *data)
{
    serve_files_priv_t *priv = data;

    if (!priv) {
        lwan_status_warning("Nothing to shutdown");
        return;
    }

    lwan_tpl_free(priv->directory_list_tpl);
    cache_destroy(priv->cache);
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
_prepare_headers(lwan_request_t *request,
                 lwan_http_status_t return_status,
                 file_cache_entry_t *fce,
                 size_t size,
                 bool deflated,
                 char *header_buf,
                 size_t header_buf_size)
{
    lwan_key_value_t headers[3];

    request->response.headers = headers;
    request->response.content_length = size;

    SET_NTH_HEADER(0, "Last-Modified", fce->last_modified.string);

    if (deflated) {
        SET_NTH_HEADER(1, "Content-Encoding", "deflate");
        SET_NTH_HEADER(2, NULL, NULL);
    } else {
        SET_NTH_HEADER(1, NULL, NULL);
    }

    return lwan_prepare_response_header(request, return_status,
                                    header_buf, header_buf_size);
}

static ALWAYS_INLINE lwan_http_status_t
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
        return HTTP_OK;
    }

    /*
     * To goes beyond from or To and From are the same: this is unsatisfiable.
     */
    if (UNLIKELY(t >= f))
        return HTTP_RANGE_UNSATISFIABLE;

    /*
     * Range goes beyond the size of the file
     */
    if (UNLIKELY(f >= size || t >= size))
        return HTTP_RANGE_UNSATISFIABLE;

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
        return HTTP_RANGE_UNSATISFIABLE;

    *from = f;
    *to = t;

    return HTTP_PARTIAL_CONTENT;
}

static lwan_http_status_t
_sendfile_serve(lwan_request_t *request, void *data)
{
    file_cache_entry_t *fce = data;
    sendfile_cache_data_t *sd = (sendfile_cache_data_t *)(fce + 1);
    char headers[DEFAULT_BUFFER_SIZE];
    size_t header_len;
    lwan_http_status_t return_status;
    off_t from, to;

    return_status = _compute_range(request, &from, &to, (off_t)sd->size);
    if (UNLIKELY(return_status == HTTP_RANGE_UNSATISFIABLE))
        return HTTP_RANGE_UNSATISFIABLE;

    if (_client_has_fresh_content(request, fce->last_modified.integer))
        return_status = HTTP_NOT_MODIFIED;

    header_len = _prepare_headers(request, return_status,
                                  fce, sd->size, false,
                                  headers, DEFAULT_HEADERS_SIZE);
    if (UNLIKELY(!header_len))
        return HTTP_INTERNAL_ERROR;

    if (request->flags & REQUEST_METHOD_HEAD || return_status == HTTP_NOT_MODIFIED) {
        lwan_write(request, headers, header_len);
    } else {
        serve_files_priv_t *priv = request->response.stream.priv;
        /*
         * lwan_openat() will yield from the coroutine if openat()
         * can't open the file due to not having free file descriptors
         * around. This will happen just a handful of times.
         * The file will be automatically closed whenever this
         * coroutine is freed.
         */
        int file_fd = lwan_openat(request, priv->root.fd, sd->filename,
                                  priv->open_mode);
        if (UNLIKELY(file_fd < 0)) {
            switch (file_fd) {
            case -EACCES:
                return HTTP_FORBIDDEN;
            case -ENFILE:
                return HTTP_UNAVAILABLE;
            default:
                return HTTP_NOT_FOUND;
            }
        }

        lwan_send(request, headers, header_len, MSG_MORE);
        lwan_sendfile(request, file_fd, from, (size_t)to);
    }

    return return_status;
}

static lwan_http_status_t
_serve_contents_and_size(lwan_request_t *request, file_cache_entry_t *fce,
            bool deflated, void *contents, size_t size)
{
    char headers[DEFAULT_BUFFER_SIZE];
    size_t header_len;
    lwan_http_status_t return_status = HTTP_OK;

    if (_client_has_fresh_content(request, fce->last_modified.integer))
        return_status = HTTP_NOT_MODIFIED;

    header_len = _prepare_headers(request, return_status,
                                  fce, size, deflated,
                                  headers, DEFAULT_HEADERS_SIZE);
    if (UNLIKELY(!header_len))
        return HTTP_INTERNAL_ERROR;

    if (request->flags & REQUEST_METHOD_HEAD || return_status == HTTP_NOT_MODIFIED) {
        lwan_write(request, headers, header_len);
    } else {
        struct iovec response_vec[] = {
            { .iov_base = headers, .iov_len = header_len },
            { .iov_base = contents, .iov_len = size }
        };

        lwan_writev(request, response_vec, N_ELEMENTS(response_vec));
    }

    return return_status;
}

static lwan_http_status_t
_mmap_serve(lwan_request_t *request, void *data)
{
    file_cache_entry_t *fce = data;
    mmap_cache_data_t *md = (mmap_cache_data_t *)(fce + 1);

    if ((request->flags & REQUEST_ACCEPT_DEFLATE) && md->compressed.size)
        return _serve_contents_and_size(request, fce, true,
                    md->compressed.contents, md->compressed.size);

    return _serve_contents_and_size(request, fce, false,
                md->uncompressed.contents, md->uncompressed.size);
}

static lwan_http_status_t
_dirlist_serve(lwan_request_t *request, void *data)
{
    file_cache_entry_t *fce = data;
    dir_list_cache_data_t *dd = (dir_list_cache_data_t *)(fce + 1);

    return _serve_contents_and_size(request, fce, false,
            strbuf_get_buffer(dd->rendered), strbuf_get_length(dd->rendered));
}

static lwan_http_status_t
_redir_serve(lwan_request_t *request, void *data)
{
    file_cache_entry_t *fce = data;
    redir_cache_data_t *rd = (redir_cache_data_t *)(fce + 1);
    char header_buf[DEFAULT_BUFFER_SIZE];
    size_t header_buf_size;
    lwan_key_value_t headers[2];

    request->response.headers = headers;
    request->response.content_length = strlen(rd->redir_to);

    SET_NTH_HEADER(0, "Location", rd->redir_to);
    SET_NTH_HEADER(1, NULL, NULL);

    header_buf_size = lwan_prepare_response_header(request,
                HTTP_MOVED_PERMANENTLY, header_buf, DEFAULT_BUFFER_SIZE);
    if (UNLIKELY(!header_buf_size))
        return HTTP_INTERNAL_ERROR;

    struct iovec response_vec[] = {
        { .iov_base = header_buf, .iov_len = header_buf_size },
        { .iov_base = rd->redir_to, .iov_len = request->response.content_length },
    };

    lwan_writev(request, response_vec, N_ELEMENTS(response_vec));

    return HTTP_MOVED_PERMANENTLY;
}

static lwan_http_status_t
serve_files_handle_cb(lwan_request_t *request, lwan_response_t *response, void *data)
{
    lwan_http_status_t return_status = HTTP_NOT_FOUND;
    serve_files_priv_t *priv = data;
    struct cache_entry_t *ce;

    if (UNLIKELY(!priv)) {
        return_status = HTTP_INTERNAL_ERROR;
        goto fail;
    }

    ce = cache_coro_get_and_ref_entry(priv->cache, request->conn->coro,
                request->url.value);
    if (LIKELY(ce)) {
        file_cache_entry_t *fce = (file_cache_entry_t *)ce;
        response->mime_type = fce->mime_type;
        response->stream.callback = fce->funcs->serve;
        response->stream.data = ce;
        response->stream.priv = priv;

        return HTTP_OK;
    }

fail:
    response->stream.callback = NULL;
    return return_status;
}

lwan_handler_t serve_files = {
    .init = serve_files_init,
    .init_from_hash = serve_files_init_from_hash,
    .shutdown = serve_files_shutdown,
    .handle = serve_files_handle_cb,
    .flags = HANDLER_REMOVE_LEADING_SLASH | HANDLER_PARSE_IF_MODIFIED_SINCE | HANDLER_PARSE_RANGE | HANDLER_PARSE_ACCEPT_ENCODING
};
