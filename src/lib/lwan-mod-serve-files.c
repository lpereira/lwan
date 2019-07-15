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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <zlib.h>

#include "lwan-private.h"

#include "hash.h"
#include "realpathat.h"
#include "lwan-cache.h"
#include "lwan-config.h"
#include "lwan-io-wrappers.h"
#include "lwan-mod-serve-files.h"
#include "lwan-template.h"
#include "int-to-str.h"

#include "auto-index-icons.h"

#if defined(HAVE_BROTLI)
#include <brotli/encode.h>
#endif

static const struct lwan_key_value deflate_compression_hdr = {
    .key = "Content-Encoding",
    .value = "deflate",
};
static const struct lwan_key_value gzip_compression_hdr = {
    .key = "Content-Encoding",
    .value = "gzip",
};
#if defined(HAVE_BROTLI)
static const struct lwan_key_value br_compression_hdr = {
    .key = "Content-Encoding",
    .value = "br",
};
#endif

static const int open_mode = O_RDONLY | O_NONBLOCK | O_CLOEXEC;

struct file_cache_entry;

struct serve_files_priv {
    struct cache *cache;

    char *root_path;
    size_t root_path_len;
    int root_fd;

    const char *index_html;
    char *prefix;

    struct lwan_tpl *directory_list_tpl;

    size_t read_ahead;

    bool serve_precompressed_files;
    bool auto_index;
    bool auto_index_readme;
};

struct cache_funcs {
    enum lwan_http_status (*serve)(struct lwan_request *request, void *data);
    bool (*init)(struct file_cache_entry *ce,
                 struct serve_files_priv *priv,
                 const char *full_path,
                 struct stat *st);
    void (*free)(struct file_cache_entry *ce);
};

struct mmap_cache_data {
    struct lwan_value uncompressed;
    struct lwan_value deflated;
#if defined(HAVE_BROTLI)
    struct lwan_value brotli;
#endif
};

struct sendfile_cache_data {
    struct {
        int fd;
        size_t size;
    } compressed, uncompressed;
};

struct dir_list_cache_data {
    struct lwan_strbuf rendered;
    struct lwan_value deflated;
};

struct redir_cache_data {
    char *redir_to;
};

struct file_cache_entry {
    struct cache_entry base;

    struct {
        char string[30];
        time_t integer;
    } last_modified;

    const char *mime_type;
    const struct cache_funcs *funcs;

    union {
        struct mmap_cache_data mmap_cache_data;
        struct sendfile_cache_data sendfile_cache_data;
        struct dir_list_cache_data dir_list_cache_data;
        struct redir_cache_data redir_cache_data;
    };
};

struct file_list {
    const char *full_path;
    const char *rel_path;
    const char *readme;
    struct {
        coro_function_t generator;

        const char *icon;
        const char *icon_alt;
        const char *name;
        const char *type;

        int size;
        const char *unit;

        const char *zebra_class;
    } file_list;
};

static int directory_list_generator(struct coro *coro, void *data);

static bool mmap_init(struct file_cache_entry *ce,
                      struct serve_files_priv *priv,
                      const char *full_path,
                      struct stat *st);
static void mmap_free(struct file_cache_entry *ce);
static enum lwan_http_status mmap_serve(struct lwan_request *request,
                                        void *data);

static bool sendfile_init(struct file_cache_entry *ce,
                          struct serve_files_priv *priv,
                          const char *full_path,
                          struct stat *st);
static void sendfile_free(struct file_cache_entry *ce);
static enum lwan_http_status sendfile_serve(struct lwan_request *request,
                                            void *data);

static bool dirlist_init(struct file_cache_entry *ce,
                         struct serve_files_priv *priv,
                         const char *full_path,
                         struct stat *st);
static void dirlist_free(struct file_cache_entry *ce);
static enum lwan_http_status dirlist_serve(struct lwan_request *request,
                                           void *data);

static bool redir_init(struct file_cache_entry *ce,
                       struct serve_files_priv *priv,
                       const char *full_path,
                       struct stat *st);
static void redir_free(struct file_cache_entry *ce);
static enum lwan_http_status redir_serve(struct lwan_request *request,
                                         void *data);

static const struct cache_funcs mmap_funcs = {
    .init = mmap_init,
    .free = mmap_free,
    .serve = mmap_serve,
};

static const struct cache_funcs sendfile_funcs = {
    .init = sendfile_init,
    .free = sendfile_free,
    .serve = sendfile_serve,
};

static const struct cache_funcs dirlist_funcs = {
    .init = dirlist_init,
    .free = dirlist_free,
    .serve = dirlist_serve,
};

static const struct cache_funcs redir_funcs = {
    .init = redir_init,
    .free = redir_free,
    .serve = redir_serve,
};

#undef TPL_STRUCT
#define TPL_STRUCT struct file_list
static const struct lwan_var_descriptor file_list_desc[] = {
    TPL_VAR_STR_ESCAPE(full_path),
    TPL_VAR_STR_ESCAPE(rel_path),
    TPL_VAR_STR_ESCAPE(readme),
    TPL_VAR_SEQUENCE(file_list,
                     directory_list_generator,
                     ((const struct lwan_var_descriptor[]){
                         TPL_VAR_STR(file_list.icon),
                         TPL_VAR_STR(file_list.icon_alt),
                         TPL_VAR_STR(file_list.name),
                         TPL_VAR_STR(file_list.type),
                         TPL_VAR_INT(file_list.size),
                         TPL_VAR_STR(file_list.unit),
                         TPL_VAR_STR(file_list.zebra_class),
                         TPL_VAR_SENTINEL,
                     })),
    TPL_VAR_SENTINEL,
};


static const char *directory_list_tpl_str =
    "<html>\n"
    "<head>\n"
    "{{rel_path?}}  <title>Index of {{rel_path}}</title>{{/rel_path?}}\n"
    "{{^rel_path?}}  <title>Index of /</title>{{/rel_path?}}\n"
    "<style>\n"
    "  body { background: fff }\n"
    "  tr.odd>td { background: #fff }\n"
    "  tr.even>td { background: #eee }\n"
    "</style>\n"
    "</head>\n"
    "<body>\n"
    "{{rel_path?}}  <h1>Index of {{rel_path}}</h1>\n{{/rel_path?}}"
    "{{^rel_path?}}  <h1>Index of /</h1>\n{{/rel_path?}}"
    "{{readme?}}<pre>{{readme}}</pre>\n{{/readme?}}"
    "  <table>\n"
    "    <tr>\n"
    "      <td><img src=\"?icon=back\"></td>\n"
    "      <td colspan=\"3\"><a href=\"..\">Parent directory</a></td>\n"
    "    </tr>\n"
    "    <tr>\n"
    "      <td>&nbsp;</td>\n"
    "      <th>File name</th>\n"
    "      <th>Type</th>\n"
    "      <th>Size</th>\n"
    "    </tr>\n"
    "{{#file_list}}"
    "    <tr class=\"{{file_list.zebra_class}}\">\n"
    "      <td><img src=\"?icon={{file_list.icon}}\" "
    "alt=\"{{file_list.icon_alt}}\"></td>\n"
    "      <td><a "
    "href=\"{{rel_path}}/{{{file_list.name}}}\">{{{file_list.name}}}</a></td>\n"
    "      <td>{{file_list.type}}</td>\n"
    "      <td align=\"right\"><tt>{{file_list.size}}{{file_list.unit}}</tt></td>\n"
    "    </tr>\n"
    "{{/file_list}}"
    "{{^#file_list}}"
    "    <tr>\n"
    "      <td colspan=\"4\">Empty directory.</td>\n"
    "    </tr>\n"
    "{{/file_list}}"
    "  </table>\n"
    "</body>\n"
    "</html>\n";

static int directory_list_generator(struct coro *coro, void *data)
{
    static const char *zebra_classes[] = {"odd", "even"};
    struct file_list *fl = data;
    struct dirent *entry;
    int zebra_class = 0;
    DIR *dir;
    int fd;

    dir = opendir(fl->full_path);
    if (!dir)
        return 0;

    fd = dirfd(dir);
    if (fd < 0)
        goto out;

    while ((entry = readdir(dir))) {
        struct stat st;

        if (entry->d_name[0] == '.')
            continue;

        if (fstatat(fd, entry->d_name, &st, 0) < 0)
            continue;

        if (S_ISDIR(st.st_mode)) {
            fl->file_list.icon = "folder";
            fl->file_list.icon_alt = "DIR";
            fl->file_list.type = "directory";
        } else if (S_ISREG(st.st_mode)) {
            fl->file_list.icon = "file";
            fl->file_list.icon_alt = "FILE";
            fl->file_list.type =
                lwan_determine_mime_type_for_file_name(entry->d_name);
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

        fl->file_list.name = entry->d_name;
        fl->file_list.zebra_class = zebra_classes[zebra_class++ % 2];

        if (coro_yield(coro, 1))
            break;
    }

out:
    closedir(dir);
    return 0;
}

static ALWAYS_INLINE bool is_compression_worthy(const size_t compressed_sz,
                                                const size_t uncompressed_sz)
{
    /* FIXME: gzip encoding is also supported but not considered here */
    static const size_t deflated_header_size =
        sizeof("Content-Encoding: deflate\r\n") - 1;
    return ((compressed_sz + deflated_header_size) < uncompressed_sz);
}

static void realloc_if_needed(struct lwan_value *value, size_t needed_size)
{
    if (needed_size < value->len) {
        char *tmp = realloc(value->value, needed_size);

        if (tmp)
            value->value = tmp;
    }
}

static void deflate_value(const struct lwan_value *uncompressed,
                          struct lwan_value *compressed)
{
    const unsigned long bound = compressBound(uncompressed->len);

    compressed->len = bound;

    if (UNLIKELY(!(compressed->value = malloc(bound))))
        goto error_zero_out;

    if (UNLIKELY(compress((Bytef *)compressed->value, &compressed->len,
                          (Bytef *)uncompressed->value,
                          uncompressed->len) != Z_OK))
        goto error_free_compressed;

    if (is_compression_worthy(compressed->len, uncompressed->len))
        return realloc_if_needed(compressed, bound);

error_free_compressed:
    free(compressed->value);
    compressed->value = NULL;
error_zero_out:
    compressed->len = 0;
}

#if defined(HAVE_BROTLI)
static void brotli_value(const struct lwan_value *uncompressed,
                         struct lwan_value *brotli,
                         const struct lwan_value *deflated)
{
    const unsigned long bound =
        BrotliEncoderMaxCompressedSize(uncompressed->len);

    brotli->len = bound;

    if (UNLIKELY(!(brotli->value = malloc(brotli->len))))
        goto error_zero_out;

    if (UNLIKELY(
            BrotliEncoderCompress(BROTLI_DEFAULT_QUALITY, BROTLI_DEFAULT_WINDOW,
                                  BROTLI_DEFAULT_MODE, uncompressed->len,
                                  (uint8_t *)uncompressed->value, &brotli->len,
                                  (uint8_t *)brotli->value) != BROTLI_TRUE))
        goto error_free_compressed;

    /* is_compression_worthy() is already called for deflate-compressed data,
     * so only consider brotli-compressed data if it's worth it WRT deflate */
    if (LIKELY(brotli->len < deflated->len))
        return realloc_if_needed(brotli, bound);

error_free_compressed:
    free(brotli->value);
    brotli->value = NULL;
error_zero_out:
    brotli->len = 0;
}
#endif

static bool mmap_init(struct file_cache_entry *ce,
                      struct serve_files_priv *priv,
                      const char *full_path,
                      struct stat *st)
{
    struct mmap_cache_data *md = &ce->mmap_cache_data;
    const char *path = full_path + priv->root_path_len;
    int file_fd;
    bool success;

    path += *path == '/';

    file_fd = openat(priv->root_fd, path, open_mode);
    if (UNLIKELY(file_fd < 0))
        return false;

    md->uncompressed.value =
        mmap(NULL, (size_t)st->st_size, PROT_READ, MAP_SHARED, file_fd, 0);
    if (UNLIKELY(md->uncompressed.value == MAP_FAILED)) {
        success = false;
        goto close_file;
    }

    lwan_madvise_queue(md->uncompressed.value, (size_t)st->st_size);

    md->uncompressed.len = (size_t)st->st_size;
    deflate_value(&md->uncompressed, &md->deflated);
#if defined(HAVE_BROTLI)
    brotli_value(&md->uncompressed, &md->brotli, &md->deflated);
#endif

    ce->mime_type =
        lwan_determine_mime_type_for_file_name(full_path + priv->root_path_len);

    success = true;

close_file:
    close(file_fd);

    return success;
}

static bool is_world_readable(mode_t mode)
{
    const mode_t world_readable = S_IRUSR | S_IRGRP | S_IROTH;

    return (mode & world_readable) == world_readable;
}

static void
try_readahead(const struct serve_files_priv *priv, int fd, size_t size)
{
    if (size > priv->read_ahead)
        size = priv->read_ahead;

    if (LIKELY(size))
        lwan_readahead_queue(fd, 0, size);
}

static int try_open_compressed(const char *relpath,
                               const struct serve_files_priv *priv,
                               const struct stat *uncompressed,
                               size_t *compressed_sz)
{
    char gzpath[PATH_MAX];
    struct stat st;
    int ret, fd;

    /* Try to serve a compressed file using sendfile() if $FILENAME.gz exists */
    ret = snprintf(gzpath, PATH_MAX, "%s.gz", relpath + 1);
    if (UNLIKELY(ret < 0 || ret >= PATH_MAX))
        goto out;

    fd = openat(priv->root_fd, gzpath, open_mode);
    if (UNLIKELY(fd < 0))
        goto out;

    ret = fstat(fd, &st);
    if (UNLIKELY(ret < 0))
        goto close_and_out;

    if (UNLIKELY(st.st_mtime < uncompressed->st_mtime))
        goto close_and_out;

    if (UNLIKELY(!is_world_readable(st.st_mode)))
        goto close_and_out;

    if (LIKELY(is_compression_worthy((size_t)st.st_size,
                                     (size_t)uncompressed->st_size))) {
        *compressed_sz = (size_t)st.st_size;

        try_readahead(priv, fd, *compressed_sz);

        return fd;
    }

close_and_out:
    close(fd);
out:
    *compressed_sz = 0;
    return -ENOENT;
}

static bool sendfile_init(struct file_cache_entry *ce,
                          struct serve_files_priv *priv,
                          const char *full_path,
                          struct stat *st)
{
    struct sendfile_cache_data *sd = &ce->sendfile_cache_data;
    const char *relpath = full_path + priv->root_path_len;

    ce->mime_type = lwan_determine_mime_type_for_file_name(relpath);

    sd->uncompressed.fd = openat(priv->root_fd, relpath + 1, open_mode);
    if (UNLIKELY(sd->uncompressed.fd < 0)) {
        switch (errno) {
        case ENFILE:
        case EMFILE:
        case EACCES:
            /* These errors should produce responses other than 404, so
             * store errno as the file descriptor.  */
            sd->uncompressed.fd = sd->compressed.fd = -errno;
            sd->compressed.size = sd->uncompressed.size = 0;

            return true;
        }

        return false;
    }

    /* If precompressed files can be served, try opening it */
    if (LIKELY(priv->serve_precompressed_files)) {
        size_t compressed_sz;
        int fd = try_open_compressed(relpath, priv, st, &compressed_sz);

        sd->compressed.fd = fd;
        sd->compressed.size = compressed_sz;
    }

    sd->uncompressed.size = (size_t)st->st_size;
    try_readahead(priv, sd->uncompressed.fd, sd->uncompressed.size);

    return true;
}

static const char *get_rel_path(const char *full_path,
                                struct serve_files_priv *priv)
{
    const char *root_path = full_path + priv->root_path_len;

    if (priv->root_path_len == 1) {
        /* If root path length is 1, it's actually "/".   Don't skip
         * the first forward slash if serving from root directory. */
        root_path--;
    }

    if (*root_path)
        return root_path;

    if (streq(priv->prefix, "/"))
        return "";

    return priv->prefix;
}

static const char *dirlist_find_readme(struct lwan_strbuf *readme,
                                       struct serve_files_priv *priv,
                                       const char *full_path)
{
    static const char *candidates[] = {"readme", "readme.txt", "read.me",
                                       "README.TXT", "README"};
    int fd = -1;

    if (!priv->auto_index_readme)
        return NULL;

    for (size_t i = 0; i < N_ELEMENTS(candidates); i++) {
        char buffer[PATH_MAX];
        int r;

        r = snprintf(buffer, PATH_MAX, "%s/%s", full_path, candidates[i]);
        if (r < 0 || r >= PATH_MAX)
            continue;

        fd = open(buffer, O_RDONLY | O_CLOEXEC);
        if (fd < 0)
            continue;

        while (true) {
            ssize_t n = read(fd, buffer, sizeof(buffer));

            if (n < 0) {
                if (errno == EINTR)
                    continue;
                goto error;
            }
            if (!n)
                break;

            if (!lwan_strbuf_append_str(readme, buffer, (size_t)n))
                goto error;
        }

        close(fd);
        return lwan_strbuf_get_buffer(readme);
    }

error:
    if (fd >= 0)
        close(fd);
    return NULL;
}

static bool dirlist_init(struct file_cache_entry *ce,
                         struct serve_files_priv *priv,
                         const char *full_path,
                         struct stat *st __attribute__((unused)))
{
    struct dir_list_cache_data *dd = &ce->dir_list_cache_data;
    struct lwan_strbuf readme;
    bool ret = false;

    if (!lwan_strbuf_init(&readme))
        return false;
    if (!lwan_strbuf_init(&dd->rendered))
        goto out_free_readme;

    struct file_list vars = {
        .full_path = full_path,
        .rel_path = get_rel_path(full_path, priv),
        .readme = dirlist_find_readme(&readme, priv, full_path),
    };

    if (!lwan_tpl_apply_with_buffer(priv->directory_list_tpl, &dd->rendered,
                                    &vars))
        goto out_free_rendered;

    ce->mime_type = "text/html";

    struct lwan_value rendered = {
        .value = lwan_strbuf_get_buffer(&dd->rendered),
        .len = lwan_strbuf_get_length(&dd->rendered),
    };
    deflate_value(&rendered, &dd->deflated);

    ret = true;
    goto out_free_readme;

out_free_rendered:
    lwan_strbuf_free(&dd->rendered);
out_free_readme:
    lwan_strbuf_free(&readme);
    return ret;
}

static bool redir_init(struct file_cache_entry *ce,
                       struct serve_files_priv *priv,
                       const char *full_path,
                       struct stat *st __attribute__((unused)))
{
    struct redir_cache_data *rd = &ce->redir_cache_data;

    if (asprintf(&rd->redir_to, "%s/", full_path + priv->root_path_len) < 0)
        return false;

    ce->mime_type = "text/plain";
    return true;
}

static const struct cache_funcs *get_funcs(struct serve_files_priv *priv,
                                           const char *key,
                                           char *full_path,
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

            int ret = snprintf(index_html_path, PATH_MAX, "%s%s", key,
                               priv->index_html);
            if (UNLIKELY(ret < 0 || ret >= PATH_MAX))
                return NULL;
        }

        /* See if it exists. */
        if (fstatat(priv->root_fd, index_html_path, st, 0) < 0) {
            if (UNLIKELY(errno != ENOENT))
                return NULL;

            if (LIKELY(priv->auto_index)) {
                /* If it doesn't, we want to generate a directory list. */
                return &dirlist_funcs;
            }

            /* Auto index is disabled. */
            return NULL;
        }

        /* Only serve world-readable indexes. */
        if (UNLIKELY(!is_world_readable(st->st_mode)))
            return NULL;

        /* If it does, we want its full path. */

        /* FIXME: Use strlcpy() here instead of calling strlen()? */
        if (UNLIKELY(priv->root_path_len + 1 /* slash */ +
                         strlen(index_html_path) + 1 >=
                     PATH_MAX))
            return NULL;

        full_path[priv->root_path_len] = '/';
        strncpy(full_path + priv->root_path_len + 1, index_html_path,
                PATH_MAX - priv->root_path_len - 1);
    }

    /* Only serve regular files. */
    if (UNLIKELY(!S_ISREG(st->st_mode)))
        return NULL;

    /* It's not a directory: choose the fastest way to serve the file
     * judging by its size. */
    if (st->st_size < 16384)
        return &mmap_funcs;

    return &sendfile_funcs;
}

static struct file_cache_entry *
create_cache_entry_from_funcs(struct serve_files_priv *priv,
                              const char *full_path,
                              struct stat *st,
                              const struct cache_funcs *funcs)
{
    struct file_cache_entry *fce;

    fce = malloc(sizeof(*fce));
    if (UNLIKELY(!fce))
        return NULL;

    if (LIKELY(funcs->init(fce, priv, full_path, st))) {
        fce->funcs = funcs;
        return fce;
    }

    free(fce);

    if (funcs != &mmap_funcs)
        return NULL;

    return create_cache_entry_from_funcs(priv, full_path, st, &sendfile_funcs);
}

static void destroy_cache_entry(struct cache_entry *entry,
                                void *context __attribute__((unused)))
{
    struct file_cache_entry *fce = (struct file_cache_entry *)entry;

    fce->funcs->free(fce);
    free(fce);
}

static struct cache_entry *create_cache_entry(const char *key, void *context)
{
    struct serve_files_priv *priv = context;
    struct file_cache_entry *fce;
    struct stat st;
    const struct cache_funcs *funcs;
    char full_path[PATH_MAX];

    if (UNLIKELY(
            !realpathat2(priv->root_fd, priv->root_path, key, full_path, &st)))
        return NULL;

    if (UNLIKELY(!is_world_readable(st.st_mode)))
        return NULL;

    if (UNLIKELY(strncmp(full_path, priv->root_path, priv->root_path_len)))
        return NULL;

    funcs = get_funcs(priv, key, full_path, &st);
    if (UNLIKELY(!funcs))
        return NULL;

    fce = create_cache_entry_from_funcs(priv, full_path, &st, funcs);
    if (UNLIKELY(!fce))
        return NULL;

    if (UNLIKELY(lwan_format_rfc_time(st.st_mtime, fce->last_modified.string) <
                 0)) {
        destroy_cache_entry((struct cache_entry *)fce, NULL);
        return NULL;
    }
    fce->last_modified.integer = st.st_mtime;

    return (struct cache_entry *)fce;
}

static void mmap_free(struct file_cache_entry *fce)
{
    struct mmap_cache_data *md = &fce->mmap_cache_data;

    munmap(md->uncompressed.value, md->uncompressed.len);
    free(md->deflated.value);
#if defined(HAVE_BROTLI)
    free(md->brotli.value);
#endif
}

static void sendfile_free(struct file_cache_entry *fce)
{
    struct sendfile_cache_data *sd = &fce->sendfile_cache_data;

    if (sd->compressed.fd >= 0)
        close(sd->compressed.fd);
    if (sd->uncompressed.fd >= 0)
        close(sd->uncompressed.fd);
}

static void dirlist_free(struct file_cache_entry *fce)
{
    struct dir_list_cache_data *dd = &fce->dir_list_cache_data;

    lwan_strbuf_free(&dd->rendered);
    free(dd->deflated.value);
}

static void redir_free(struct file_cache_entry *fce)
{
    struct redir_cache_data *rd = &fce->redir_cache_data;

    free(rd->redir_to);
}

static void *serve_files_create(const char *prefix, void *args)
{
    struct lwan_serve_files_settings *settings = args;
    char *canonical_root;
    int root_fd;
    struct serve_files_priv *priv;

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

    root_fd = open(canonical_root, open_mode | O_DIRECTORY | O_PATH);
    if (root_fd < 0) {
        lwan_status_perror("Could not open directory \"%s\"", canonical_root);
        goto out_open;
    }

    priv = malloc(sizeof(*priv));
    if (!priv) {
        lwan_status_perror("malloc");
        goto out_malloc;
    }

    priv->cache =
        cache_create(create_cache_entry, destroy_cache_entry, priv, 5);
    if (!priv->cache) {
        lwan_status_error("Couldn't create cache");
        goto out_cache_create;
    }

    if (settings->directory_list_template) {
        priv->directory_list_tpl = lwan_tpl_compile_file(
            settings->directory_list_template, file_list_desc);
    } else {
        priv->directory_list_tpl =
            lwan_tpl_compile_string_full(directory_list_tpl_str, file_list_desc,
                                         LWAN_TPL_FLAG_CONST_TEMPLATE);
    }
    if (!priv->directory_list_tpl) {
        lwan_status_error("Could not compile directory list template");
        goto out_tpl_compile;
    }

    priv->prefix = strdup(prefix);
    if (!priv->prefix) {
        lwan_status_error("Could not copy prefix");
        goto out_tpl_prefix_copy;
    }

    priv->root_path = canonical_root;
    priv->root_path_len = strlen(canonical_root);
    priv->root_fd = root_fd;
    priv->index_html =
        settings->index_html ? settings->index_html : "index.html";
    priv->serve_precompressed_files = settings->serve_precompressed_files;
    priv->auto_index = settings->auto_index;
    priv->auto_index_readme = settings->auto_index_readme;
    priv->read_ahead = settings->read_ahead;

    return priv;

out_tpl_prefix_copy:
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

static void *serve_files_create_from_hash(const char *prefix,
                                          const struct hash *hash)
{
    struct lwan_serve_files_settings settings = {
        .root_path = hash_find(hash, "path"),
        .index_html = hash_find(hash, "index_path"),
        .serve_precompressed_files =
            parse_bool(hash_find(hash, "serve_precompressed_files"), true),
        .auto_index = parse_bool(hash_find(hash, "auto_index"), true),
        .directory_list_template = hash_find(hash, "directory_list_template"),
        .read_ahead =
            (size_t)parse_long("read_ahead", SERVE_FILES_READ_AHEAD_BYTES),
        .auto_index_readme =
            parse_bool(hash_find(hash, "auto_index_readme"), true),
    };

    return serve_files_create(prefix, &settings);
}

static void serve_files_destroy(void *data)
{
    struct serve_files_priv *priv = data;

    if (!priv) {
        lwan_status_warning("Nothing to shutdown");
        return;
    }

    lwan_tpl_free(priv->directory_list_tpl);
    cache_destroy(priv->cache);
    close(priv->root_fd);
    free(priv->root_path);
    free(priv->prefix);
    free(priv);
}

static ALWAYS_INLINE bool client_has_fresh_content(struct lwan_request *request,
                                                   time_t mtime)
{
    time_t header;
    int r = lwan_request_get_if_modified_since(request, &header);

    return LIKELY(!r) ? mtime <= header : false;
}

static size_t prepare_headers(struct lwan_request *request,
                              enum lwan_http_status return_status,
                              struct file_cache_entry *fce,
                              size_t size,
                              const struct lwan_key_value *user_hdr,
                              char header_buf[static DEFAULT_HEADERS_SIZE])
{
    char content_length[INT_TO_STR_BUFFER_SIZE];
    size_t discard;
    struct lwan_key_value additional_headers[4] = {
        {
            .key = "Last-Modified",
            .value = fce->last_modified.string,
        },
        {
            .key = "Content-Length",
            .value = uint_to_string(size, content_length, &discard),
        },
    };

    if (user_hdr)
        additional_headers[2] = *user_hdr;

    return lwan_prepare_response_header_full(request, return_status, header_buf,
                                             DEFAULT_HEADERS_SIZE,
                                             additional_headers);
}

static enum lwan_http_status
compute_range(struct lwan_request *request, off_t *from, off_t *to, off_t size)
{
    off_t f, t;
    int r = lwan_request_get_range(request, &f, &t);

    /* No Range: header present */
    if (LIKELY(r < 0 || (f < 0 && t < 0))) {
        *from = 0;
        *to = size;

        return HTTP_OK;
    }

    /* To must be greater than From; it doesn't make any sense to be
     * equal, either. */
    if (UNLIKELY(f >= t && t >= 0))
        return HTTP_RANGE_UNSATISFIABLE;

    /* Range goes beyond the size of the file */
    if (UNLIKELY(f >= size || t >= size))
        return HTTP_RANGE_UNSATISFIABLE;

    /* t < 0: ranges from f to the file size */
    if (t < 0) {
        *to = size;
    } else {
        if (UNLIKELY(__builtin_sub_overflow(t, f, to)))
            return HTTP_RANGE_UNSATISFIABLE;
    }

    *from = f;

    return HTTP_PARTIAL_CONTENT;
}

static enum lwan_http_status sendfile_serve(struct lwan_request *request,
                                            void *data)
{
    const struct lwan_key_value *compression_hdr;
    struct file_cache_entry *fce = data;
    struct sendfile_cache_data *sd = &fce->sendfile_cache_data;
    char headers[DEFAULT_HEADERS_SIZE];
    size_t header_len;
    enum lwan_http_status return_status;
    off_t from, to;
    size_t size;
    int fd;

    if (sd->compressed.size && (request->flags & REQUEST_ACCEPT_GZIP)) {
        from = 0;
        to = (off_t)sd->compressed.size;

        compression_hdr = &gzip_compression_hdr;
        fd = sd->compressed.fd;
        size = sd->compressed.size;

        return_status = HTTP_OK;
    } else {
        return_status =
            compute_range(request, &from, &to, (off_t)sd->uncompressed.size);
        if (UNLIKELY(return_status == HTTP_RANGE_UNSATISFIABLE))
            return HTTP_RANGE_UNSATISFIABLE;

        compression_hdr = NULL;
        fd = sd->uncompressed.fd;
        size = (size_t)(to - from);
    }
    if (UNLIKELY(fd < 0)) {
        switch (-fd) {
        case EACCES:
            return HTTP_FORBIDDEN;
        case EMFILE:
        case ENFILE:
            return HTTP_UNAVAILABLE;
        default:
            return HTTP_INTERNAL_ERROR;
        }
    }

    header_len = prepare_headers(request, return_status, fce, size,
                                 compression_hdr, headers);
    if (UNLIKELY(!header_len))
        return HTTP_INTERNAL_ERROR;

    if (lwan_request_get_method(request) == REQUEST_METHOD_HEAD) {
        lwan_send(request, headers, header_len, 0);
    } else {
        lwan_sendfile(request, fd, from, (size_t)to, headers, header_len);
    }

    return return_status;
}

static enum lwan_http_status
serve_buffer(struct lwan_request *request,
             struct file_cache_entry *fce,
             const struct lwan_key_value *additional_hdr,
             const void *contents,
             size_t size,
             enum lwan_http_status return_status)
{
    char headers[DEFAULT_HEADERS_SIZE];
    size_t header_len;

    header_len = prepare_headers(request, return_status, fce, size,
                                 additional_hdr, headers);
    if (UNLIKELY(!header_len))
        return HTTP_INTERNAL_ERROR;

    if (lwan_request_get_method(request) == REQUEST_METHOD_HEAD) {
        lwan_send(request, headers, header_len, 0);
    } else if (sizeof(headers) - header_len > size) {
        /* See comment in lwan_response() about avoiding writev(). */
        memcpy(headers + header_len, contents, size);
        lwan_send(request, headers, header_len + size, 0);
    } else {
        struct iovec response_vec[] = {
            {.iov_base = headers, .iov_len = header_len},
            {.iov_base = (void *)contents, .iov_len = size},
        };

        lwan_writev(request, response_vec, N_ELEMENTS(response_vec));
    }

    return return_status;
}

static enum lwan_http_status mmap_serve(struct lwan_request *request,
                                        void *data)
{
    const struct lwan_key_value *compressed;
    struct file_cache_entry *fce = data;
    struct mmap_cache_data *md = &fce->mmap_cache_data;
    void *contents;
    size_t size;
    enum lwan_http_status status;

#if defined(HAVE_BROTLI)
    if (md->brotli.len && (request->flags & REQUEST_ACCEPT_BROTLI)) {
        contents = md->brotli.value;
        size = md->brotli.len;
        compressed = &br_compression_hdr;

        status = HTTP_OK;
    } else
#endif
    if (md->deflated.len && (request->flags & REQUEST_ACCEPT_DEFLATE)) {
        contents = md->deflated.value;
        size = md->deflated.len;
        compressed = &deflate_compression_hdr;

        status = HTTP_OK;
    } else {
        off_t from, to;

        status =
            compute_range(request, &from, &to, (off_t)md->uncompressed.len);
        switch (status) {
        case HTTP_PARTIAL_CONTENT:
        case HTTP_OK:
            contents = (char *)md->uncompressed.value + from;
            size = (size_t)(to - from);
            compressed = NULL;
            break;

        default:
            return status;
        }
    }

    return serve_buffer(request, fce, compressed, contents, size, status);
}

static enum lwan_http_status dirlist_serve(struct lwan_request *request,
                                           void *data)
{
    const struct lwan_key_value *compressed = NULL;
    struct file_cache_entry *fce = data;
    struct dir_list_cache_data *dd = &fce->dir_list_cache_data;
    const char *icon;
    const void *contents;
    size_t size;

    icon = lwan_request_get_query_param(request, "icon");
    if (!icon) {
        if (dd->deflated.len && (request->flags & REQUEST_ACCEPT_DEFLATE)) {
            compressed = &deflate_compression_hdr;
            contents = dd->deflated.value;
            size = dd->deflated.len;
        } else {
            contents = lwan_strbuf_get_buffer(&dd->rendered);
            size = lwan_strbuf_get_length(&dd->rendered);
        }
    } else if (streq(icon, "back")) {
        contents = back_gif;
        size = sizeof(back_gif);
        request->response.mime_type = "image/gif";
    } else if (streq(icon, "file")) {
        contents = file_gif;
        size = sizeof(file_gif);
        request->response.mime_type = "image/gif";
    } else if (streq(icon, "folder")) {
        contents = folder_gif;
        size = sizeof(folder_gif);
        request->response.mime_type = "image/gif";
    } else {
        return HTTP_NOT_FOUND;
    }

    return serve_buffer(request, fce, compressed, contents, size, HTTP_OK);
}

static enum lwan_http_status redir_serve(struct lwan_request *request,
                                         void *data)
{
    struct file_cache_entry *fce = data;
    struct redir_cache_data *rd = &fce->redir_cache_data;
    const struct lwan_key_value headers = {.key = "Location",
                                           .value = rd->redir_to};

    return serve_buffer(request, fce, &headers, rd->redir_to,
                        strlen(rd->redir_to), HTTP_MOVED_PERMANENTLY);
}

static enum lwan_http_status
serve_files_handle_request(struct lwan_request *request,
                           struct lwan_response *response,
                           void *instance)
{
    struct serve_files_priv *priv = instance;
    enum lwan_http_status return_status;
    struct file_cache_entry *fce;
    struct cache_entry *ce;

    ce = cache_coro_get_and_ref_entry(priv->cache, request->conn->coro,
                                      request->url.value);
    if (UNLIKELY(!ce)) {
        return_status = HTTP_NOT_FOUND;
        goto out;
    }

    fce = (struct file_cache_entry *)ce;
    if (client_has_fresh_content(request, fce->last_modified.integer)) {
        return_status = HTTP_NOT_MODIFIED;
        goto out;
    }

    response->mime_type = fce->mime_type;
    response->stream.callback = fce->funcs->serve;
    response->stream.data = fce;

    request->flags |= RESPONSE_STREAM;

    return HTTP_OK;

out:
    response->stream.callback = NULL;
    return return_status;
}

static const struct lwan_module module = {
    .create = serve_files_create,
    .create_from_hash = serve_files_create_from_hash,
    .destroy = serve_files_destroy,
    .handle_request = serve_files_handle_request,
    .flags = HANDLER_PARSE_ACCEPT_ENCODING,
};

LWAN_REGISTER_MODULE(serve_files, &module);
