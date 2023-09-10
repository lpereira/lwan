/*
 * smolsite.zip
 * Copyright (c) 2023 L. A. F. Pereira <l@tia.mat.br>
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
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

#include "base64.h"
#include "hash.h"
#include "int-to-str.h"
#include "lwan.h"
#include "sha1.h"
#include "lwan-cache.h"
#include "lwan-private.h"
#include "lwan-template.h"

#include "junzip.h"

#include "smolsite.h"

#define CACHE_FOR_MINUTES 15

static struct cache *sites;

struct file {
    ptrdiff_t data_offset;
    size_t size_compressed;
    const char *mime_type;
    bool deflated;
};

struct site {
    struct cache_entry entry;
    struct lwan_value zipped;
    struct hash *files;
};

struct iframe_tpl_vars {
    const char *digest;
};

#undef TPL_STRUCT
#define TPL_STRUCT struct iframe_tpl_vars
static const struct lwan_var_descriptor iframe_tpl_desc[] = {
    TPL_VAR_STR(digest),
    TPL_VAR_SENTINEL,
};

static struct lwan_tpl *iframe_tpl;
static struct lwan_value smolsite_zip_base64;

static void calc_hash(struct lwan_value value,
                      char digest_str[static 41])
{
    /* FIXME: Is SHA-1 overkill? */
    sha1_context ctx;
    unsigned char digest[20];

    sha1_init(&ctx);
    sha1_update(&ctx, (const unsigned char *)value.value, value.len);
    sha1_finalize(&ctx, digest);

    snprintf(digest_str, 41,
             "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"
             "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
             digest[0], digest[1], digest[2], digest[3], digest[4], digest[5],
             digest[6], digest[7], digest[8], digest[9], digest[10], digest[11],
             digest[12], digest[13], digest[14], digest[15], digest[16],
             digest[17], digest[18], digest[19]);
}

static struct hash *pending_sites(void)
{
    /* This is kind of a hack: we can't have just a single thread-local
     * for the current thread's pending site because a coroutine might
     * yield while trying to obtain an item from the sites cache, which
     * would override that value.  Store these in a thread-local hash
     * table instead, which can be consulted by the create_site() function.
     * Items are removed from this table in a defer handler. */
    static __thread struct hash *pending_sites;

    if (!pending_sites) {
        pending_sites = hash_str_new(free, free);
        if (!pending_sites) {
            lwan_status_critical("Could not allocate pending sites hash table");
        }
    }

    return pending_sites;
}

static int file_cb(
    JZFile *zip, int idx, JZFileHeader *header, char *filename, void *user_data)
{
    struct site *site = user_data;
    char filename_buf[1024];
    ptrdiff_t data_offset;
    size_t cur_offset = zip->tell(zip);

    if (zip->seek(zip, header->offset, SEEK_SET))
        return 0;

    JZFileHeader local;
    if (jzReadLocalFileHeader(zip, &local, filename_buf, sizeof(filename_buf)))
        return 0;
    if (__builtin_add_overflow(zip->tell(zip), local.offset, &data_offset))
        return 0;
    if (data_offset < 0)
        return 0;
    if ((size_t)data_offset > site->zipped.len)
        return 0;

    uint32_t last_data_offset;
    if (__builtin_add_overflow(local.compressedSize, data_offset, &last_data_offset))
        return 0;
    if (last_data_offset > site->zipped.len)
        return 0;

    struct file *file = malloc(sizeof(*file));
    if (!file)
        return 0;

    file->data_offset = data_offset;
    file->deflated = local.compressionMethod == 8;
    file->size_compressed = local.compressedSize;
    file->mime_type = lwan_determine_mime_type_for_file_name(filename);

    char *key = strdup(filename);
    if (key) {
        if (!hash_add_unique(site->files, key, file)) {
            zip->seek(zip, cur_offset, SEEK_SET);
            return 1;
        }
    }

    free(key);
    free(file);
    return 0;
}

static struct cache_entry *create_site(const void *key, void *context)
{
    const struct lwan_value *zipped =
        hash_find(pending_sites(), (const void *)key);

    if (!zipped)
        return NULL;

    struct site *site = malloc(sizeof(*site));
    if (!site)
        goto no_site;

    site->zipped = *zipped;

    FILE *zip_mem = fmemopen(zipped->value, zipped->len, "rb");
    if (!zip_mem)
        goto no_file;

    JZFile *zip = jzfile_from_stdio_file(zip_mem);
    if (!zip) {
        fclose(zip_mem);
        goto no_file;
    }

    JZEndRecord end_record;
    if (jzReadEndRecord(zip, &end_record))
        goto no_end_record;

    site->files = hash_str_new(free, free);
    if (!site->files)
        goto no_hash;

    if (jzReadCentralDirectory(zip, &end_record, file_cb, site))
        goto no_central_dir;

    jzfile_free(zip);
    return (struct cache_entry *)site;

no_central_dir:
    hash_free(site->files);
no_hash:
no_end_record:
    jzfile_free(zip);
no_file:
    free(site);
no_site:
    free(zipped->value);
    return NULL;
}

static void destroy_site(struct cache_entry *entry, void *context)
{
    struct site *site = (struct site *)entry;
    hash_free(site->files);
    free(site->zipped.value);
    free(site);
}

static void remove_from_pending_defer(void *data)
{
    char *key = data;
    hash_del(pending_sites(), key);
}


LWAN_HANDLER_ROUTE(view_root, "/")
{
    char digest_str[41];
    struct site *site;

    if (!request->url.len) {
        const struct lwan_key_value redir_headers[] = {
            {"Location", smolsite_zip_base64.value},
            {"Cache-Control", "no-cache, max-age=0, private, no-transform"},
            {},
        };
        response->headers = coro_memdup(request->conn->coro,
                                        redir_headers,
                                        sizeof(redir_headers));
        return response->headers ? HTTP_TEMPORARY_REDIRECT : HTTP_INTERNAL_ERROR;
    }

    /* Lwan gives us a percent-decoded URL, but '+' is part of the Base64
     * alphabet */
    for (char *p = strchr(request->url.value, ' '); p; p = strchr(p + 1, ' '))
        *p = '+';

    calc_hash(request->url, digest_str);

    site = (struct site *)cache_coro_get_and_ref_entry(
        sites, request->conn->coro, digest_str);
    if (!site) {
        struct lwan_value *zip = malloc(sizeof(*zip));
        if (UNLIKELY(!zip))
            return HTTP_INTERNAL_ERROR;

        char *key = strdup(digest_str);
        if (UNLIKELY(!key))
            return HTTP_INTERNAL_ERROR;
        if (UNLIKELY(hash_add_unique(pending_sites(), key, zip))) {
            free(key);
            free(zip);
            return HTTP_INTERNAL_ERROR;
        }

        coro_defer(request->conn->coro, remove_from_pending_defer, key);

        /* This base64 decoding stuff could go to create_site(), but
         * then we'd need to allocate a new buffer, copy the encoded
         * ZIP into that buffer, and free it inside create_site(). It's
         * just more work than just decoding it.
         */
        unsigned char *decoded;
        size_t decoded_len;

        if (UNLIKELY(!base64_validate((unsigned char *)request->url.value,
                                      request->url.len))) {
            return HTTP_BAD_REQUEST;
        }

        decoded = base64_decode((unsigned char *)request->url.value,
                                request->url.len, &decoded_len);
        if (UNLIKELY(!decoded))
            return HTTP_BAD_REQUEST;

        zip->value = (char *)decoded;
        zip->len = decoded_len;

        site = (struct site *)cache_coro_get_and_ref_entry(
            sites, request->conn->coro, digest_str);
        if (UNLIKELY(!site))
            return HTTP_INTERNAL_ERROR;
    }

    response->mime_type = "text/html; charset=utf-8";

    struct iframe_tpl_vars vars = {.digest = digest_str};
    if (!lwan_tpl_apply_with_buffer(iframe_tpl, response->buffer, &vars))
        return HTTP_INTERNAL_ERROR;

    return HTTP_OK;
}

LWAN_HANDLER_ROUTE(view_site, "/s/")
{
    if (request->url.len < 40)
        return HTTP_NOT_FOUND;

    char *slash = memchr(request->url.value, '/', request->url.len);
    if (!slash)
        return HTTP_NOT_FOUND;
    if (slash - request->url.value < 40)
        return HTTP_NOT_FOUND;
    *slash = '\0';
    if (strcspn(request->url.value, "0123456789abcdefABCDEF"))
        return HTTP_NOT_FOUND;

    const char *file_name = slash + 1;

    struct site *site = (struct site *)cache_coro_get_and_ref_entry(
        sites, request->conn->coro, request->url.value);
    if (!site)
        return HTTP_NOT_FOUND;

    if (*file_name == '\0')
        file_name = "index.html";

    struct file *file = hash_find(site->files, file_name);
    if (!file)
        return HTTP_NOT_FOUND;

    if (file->deflated) {
        enum lwan_request_flags accept =
            lwan_request_get_accept_encoding(request);

        if (!(accept & REQUEST_ACCEPT_DEFLATE))
            return HTTP_NOT_ACCEPTABLE;

        static const struct lwan_key_value deflate_headers[] = {
            {"Content-Encoding", "deflate"},
            {},
        };
        response->headers = deflate_headers;
    }

    lwan_strbuf_set_static(response->buffer,
                           site->zipped.value + file->data_offset,
                           file->size_compressed);
    response->mime_type = file->mime_type;

    return HTTP_OK;
}

static struct lwan_value base64_encode_to_value(struct lwan_value input)
{
    size_t len;
    unsigned char *encoded =
        base64_encode((unsigned char *)input.value, input.len, &len);
    if (!encoded)
        lwan_status_critical("Could not base64-encode smolsite.zip!");
    return (struct lwan_value){.value = (char *)encoded, .len = len};
}

int main(void)
{
    struct lwan l;

    lwan_init(&l);
    lwan_detect_url_map(&l);

    smolsite_zip_base64 = base64_encode_to_value(smolsite_zip_value);

    iframe_tpl = lwan_tpl_compile_value_full(smolsite_html_value,
                                             iframe_tpl_desc,
                                             LWAN_TPL_FLAG_CONST_TEMPLATE);
    if (!iframe_tpl)
        lwan_status_critical("Could not compile template");

    sites = cache_create_full(create_site, destroy_site, hash_str_new, NULL,
                              CACHE_FOR_MINUTES * 60);
    if (!sites)
        lwan_status_critical("Could not create site cache");

    lwan_main_loop(&l);
    lwan_shutdown(&l);
    cache_destroy(sites);
    lwan_tpl_free(iframe_tpl);
    free(smolsite_zip_base64.value);

    return 0;
}
