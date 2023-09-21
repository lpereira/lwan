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
#include "qrcodegen.h"
#include "../clock/gifenc.h"

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
    struct lwan_strbuf qr_code;
    int has_qr_code;
};

struct iframe_tpl_vars {
    const char *digest;
    int has_qr_code;
};

#undef TPL_STRUCT
#define TPL_STRUCT struct iframe_tpl_vars
static const struct lwan_var_descriptor iframe_tpl_desc[] = {
    TPL_VAR_STR(digest),
    TPL_VAR_INT(has_qr_code),
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
        pending_sites = hash_str_new(free, NULL);
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

static bool generate_qr_code_gif(const char *b64, struct lwan_strbuf *output)
{
    uint8_t qrcode[qrcodegen_BUFFER_LEN_MAX];
    uint8_t tempBuffer[qrcodegen_BUFFER_LEN_MAX];
    char *url;
    bool ok;

    if (!lwan_strbuf_init(output))
        return false;

    if (asprintf(&url, "https://smolsite.zip/%s", b64) < 0)
        return false;

    ok = qrcodegen_encodeText(url, tempBuffer, qrcode, qrcodegen_Ecc_LOW,
                              qrcodegen_VERSION_MIN, qrcodegen_VERSION_MAX,
                              qrcodegen_Mask_AUTO, true);
    free(url);
    if (!ok)
        return false;

    int size = qrcodegen_getSize(qrcode);
    if ((int)(uint16_t)size != size)
        return false;

    ge_GIF *gif =
        ge_new_gif(output, (uint16_t)size, (uint16_t)size, NULL, 4, -1);
    if (!gif) {
        lwan_strbuf_free(output);
        return false;
    }

    for (int y = 0; y < size; y++) {
        for (int x = 0; x < size; x++) {
            gif->frame[y * size + x] = qrcodegen_getModule(qrcode, x, y) ? 0 : 15;
        }
    }
    ge_add_frame(gif, 0);
    ge_close_gif(gif);

    return true;
}

static struct cache_entry *create_site(const void *key, void *context)
{
    struct lwan_strbuf qr_code = LWAN_STRBUF_STATIC_INIT;
    const struct lwan_value *base64_encoded =
        hash_find(pending_sites(), (const void *)key);
    unsigned char *decoded = NULL;
    size_t decoded_len;

    if (!base64_encoded)
        return NULL;

    if (UNLIKELY(!base64_validate((unsigned char *)base64_encoded->value,
                                  base64_encoded->len))) {
        return NULL;
    }

    decoded = base64_decode((unsigned char *)base64_encoded->value,
                            base64_encoded->len, &decoded_len);
    if (UNLIKELY(!decoded))
        return NULL;

    struct site *site = malloc(sizeof(*site));
    if (!site)
        goto no_site;

    site->has_qr_code =
        generate_qr_code_gif((const char *)base64_encoded->value, &qr_code);

    site->qr_code = qr_code;
    site->zipped = (struct lwan_value) {.value = (char *)decoded, .len = decoded_len};

    FILE *zip_mem = fmemopen(decoded, decoded_len, "rb");
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
    free(decoded);
    lwan_strbuf_free(&qr_code);
    return NULL;
}

static void destroy_site(struct cache_entry *entry, void *context)
{
    struct site *site = (struct site *)entry;
    lwan_strbuf_free(&site->qr_code);
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
        char *key = strdup(digest_str);
        if (!key) {
        lwan_status_debug("a");
            return HTTP_INTERNAL_ERROR;
           }

        if (UNLIKELY(hash_add_unique(pending_sites(), key, &request->url))) {
        lwan_status_debug("b");
            return HTTP_INTERNAL_ERROR;
           }

        coro_defer(request->conn->coro, remove_from_pending_defer, key);

        site = (struct site *)cache_coro_get_and_ref_entry(
            sites, request->conn->coro, key);
        if (UNLIKELY(!site)) {
        lwan_status_debug("c");
            return HTTP_INTERNAL_ERROR;
}
    }

    response->mime_type = "text/html; charset=utf-8";

    struct iframe_tpl_vars vars = {
        .digest = digest_str,
        .has_qr_code = site->has_qr_code,
    };
    if (!lwan_tpl_apply_with_buffer(iframe_tpl, response->buffer, &vars))
        return HTTP_INTERNAL_ERROR;

    return HTTP_OK;
}

LWAN_HANDLER_ROUTE(qr_code, "/q/")
{
    struct site *site = (struct site *)cache_coro_get_and_ref_entry(
        sites, request->conn->coro, request->url.value);
    if (!site)
        return HTTP_NOT_FOUND;
    if (!site->has_qr_code)
        return HTTP_NOT_FOUND;

    lwan_strbuf_set_static(response->buffer,
                           lwan_strbuf_get_buffer(&site->qr_code),
                           lwan_strbuf_get_length(&site->qr_code));
    response->mime_type = "image/gif";
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
