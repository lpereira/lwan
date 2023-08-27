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

#include "junzip.h"

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

static void calc_hash(const struct lwan_request *request,
                      char digest_str[static 41])
{
    /* FIXME: Is SHA-1 overkill? */
    sha1_context ctx;
    unsigned char digest[20];

    sha1_init(&ctx);
    sha1_update(&ctx, (const unsigned char *)request->url.value,
                request->url.len);
    sha1_finalize(&ctx, digest);

    snprintf(digest_str, 41,
             "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"
             "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
             digest[0], digest[1], digest[2], digest[3], digest[4], digest[5],
             digest[6], digest[7], digest[8], digest[9], digest[10], digest[11],
             digest[12], digest[13], digest[14], digest[15], digest[16],
             digest[17], digest[18], digest[19]);
}

LWAN_HANDLER_ROUTE(view_root, "/")
{
    char digest_str[41];
    struct site *site;

    if (!request->url.len) {
        static const struct lwan_key_value redir_headers[] = {
            {"Refresh",
             "0; url=/"
             "UEsDBBQAAgAIAFsCG1c3MTWu6QMAAAoIAAAKABwAaW5kZXguaHRtbFVUCQAD3vjqZ"
             "OD46mR1eAsAAQToAwAABOgDAACtVW1v2zYQ/mz9iou3QA5qybJju/"
             "GLDCwvAwJ0WNFl+7BhQGnxLHGjSIGkrahb/"
             "vuOkoN6XbsV6CyYpu6Ozx0fPjyvC1dKEDztb/ubYF0g45u1dY3ETbDVvIE/"
             "gi3Lfs+"
             "N3iseZVpqs4Svdu1ndeoSJctxCXsjB33OHFu2hpE95C8eSzk8v7yhKdSCuyINx5MQ"
             "ChR54Wg+D+EgsL7Wj2mYQALjCXgbrVI2DQvnquVoVNd1XF/"
             "G2uSjSZIkHjc8v7wj2Iq5AngafjeFeLG4oXE6ncGUximBzSDJ4tls4nHJM/"
             "PjYnGYxsnkZg4zcs3acQ70BvMs6oKjcUTBflwsfqLvu3IOV1lC3uncI3s7tN5PgGc"
             "J+NjIB5Mtaj0fA7/y6CHshJRpeD655C/"
             "5jLPOEOmKZcI1xEs8PZrMXmIa4gGV5jwcdRx4OmjWv1gFO61ctGOlkM0SLFM2smgE"
             "nVXJTC7Ukui9qh5XwVOQoXJo6IB7FeNcqPzEVxn0jvfnS4c+SfyzCnrPKniZ+"
             "Gd1sn6S+OU9h4/"
             "uWSud6SlYjzpVrUetxoK1V5dX3Hhz70ILDGyppRUOzyhkvAmCdbV5KISFutASwXuI"
             "AWdBKCs4gisQfnzz6gweTAOFto4qAK0oSBto9N5YlLsh/"
             "La3DrhhOWX4+f61JxFJhqQZpmDt3EYojo+xvwbrEb2SLo0voeoq+"
             "N4MgUniSTEnDiibIextlzzTZclI+VIoEn61d0CnYhpX+EKEOsk3hGtGi+"
             "ZTQJVpql04QlUcHPFLL8B2/"
             "iT6XuuWxP7MRPxOVKP+8rkYQ3fyayAbRAuwusTnGHi/"
             "BygbqXMdVyqnWMwK3cF+iPo2Y+7vGH/"
             "CloqkGqOoNqyC5G2fDq1NGqxtZkTlNoFEB21bSIHrbF+"
             "ShOIc3Z1EP71u7vmAGgnJ0AfFJIs7Eqp7JaxDhWYQ+"
             "oNoZRcOYbdXmRNaDfDCaw1j63T12pDmc9baCYasVIHHuMUd20vXGrdxq6V4qw0n3l"
             "IIL0llVJFzyGEridWQNEcpmLT479VIZAf8n6tJPju7PnwZFZ+"
             "TRVdftD2xgwHGvqU/"
             "GGonOzSx17SNJaqcrlGaQtJi9phE4wb9W0Il8fugMy+F3hMglQj/"
             "BbSB8T9xtJJNd6s/"
             "hPORXo6G2klLu8IavqWoN62hrb3XOWNC0YxTjN9+"
             "umnXHjfmqC2ii31g84Nj1GRoQ5OukC7B8VqkcBJsiZ3YSpHh8d+"
             "OVRW9tVSO6DatukXD/nFzFy1aTfdU1zExH0vdBRPsJ649vDhm9vvoPdHwdLIj//"
             "ONvaXU1AM/Susvya8tW6caoSZ8vMg07RowTXzf2AR/"
             "AVBLAQIeAxQAAgAIAFsCG1c3MTWu6QMAAAoIAAAKABgAAAAAAAEAAACkgQAAAABpb"
             "mRleC5odG1sVVQFAAPe+"
             "OpkdXgLAAEE6AMAAAToAwAAUEsFBgAAAAABAAEAUAAAAC0EAAAAAA=="},
            {},
        };
        response->headers = redir_headers;
        return HTTP_TEMPORARY_REDIRECT;
    }

    /* Lwan gives us a percent-decoded URL, but '+' is part of the Base64
     * alphabet */
    for (char *p = request->url.value; *p; p++) {
        if (*p == ' ')
            *p = '+';
    }

    calc_hash(request, digest_str);

    site = (struct site *)cache_coro_get_and_ref_entry(
        sites, request->conn->coro, digest_str);
    if (!site) {
        struct lwan_value *zip = malloc(sizeof(*zip));
        if (UNLIKELY(!zip))
            return HTTP_INTERNAL_ERROR;

        char *key = strdup(digest_str);
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

    /* FIXME: this should really be a template! */
    lwan_strbuf_printf(
        response->buffer,
        "<html>\n"
        "<head><title>🗜 omg it's a smolsite</title>"
        "<style>"
        "body {"
        "font-family: sans-serif; margin: 0; padding: 0; "
        "              background-color: #4f2d51; color: #ddd; "
        "              background-image: url(\"data:image/svg+xml,%%3Csvg "
        "xmlns='http://www.w3.org/2000/svg' width='4' height='4' "
        "viewBox='0 0 4 4'%%3E%%3Cpath fill='%%23d7cbd9' "
        "fill-opacity='0.4' d='M1 "
        "3h1v1H1V3zm2-2h1v1H3V1z'%%3E%%3C/path%%3E%%3C/svg%%3E\")"
        "}"
        "</style>"
        "</head>"
        "<body id=\"b\">"
        "  <iframe allowfullscreen=\"false\" sandbox=\"allow-scripts\" "
        "   allowpaymentrequest=\"false\" "
        "   style=\"width: 100%%; height: calc(100%% - 32px); padding: 0; "
        "margin: 0; border: 0; border-bottom: 1px solid #170b19; "
        "background-color: white\" "
        "   src=\"/s/%s/\">\n"
        "  </iframe>\n"
        "  <p style=\"margin: 3px; margin-right: 6px; text-align: right; "
        "font-size: 16px; text-shadow: 0 0 16px black\">"
        "  Hosted in the URL by 🗜️<b>smolsite.zip</b>. Powered by the <a "
        "style=\"color: white\" href=\"https://lwan.ws\">Lwan</a> web server."
        "  </p>"
        "<script>"
        "let body = document.getElementById('b');"
        "body.addEventListener('dragenter', function(e) {"
        "        e.stopPropagation();"
        "        e.preventDefault();"
        "        b.style.border = '4px dotted black';"
        "}, false);"
        "body.addEventListener('dragleave', function(e) {"
        "        e.stopPropagation();"
        "        e.preventDefault();"
        "        b.style.border = '0';"
        "}, false);"
        "body.addEventListener('dragover', function(e) {"
        "        e.stopPropagation();"
        "        e.preventDefault();"
        "}, false);"
        "body.addEventListener('drop', function(e) {"
        "        e.stopPropagation();"
        "        e.preventDefault();"
        "        if (e.dataTransfer.files.length == 0) {"
        "                alert('Drop a file!');"
        "        } else if (e.dataTransfer.files.length > 1) {"
        "                alert('Drop only one file!');"
        "        } else {"
        "                let reader = new FileReader();"
        "                reader.onload = (e) => {"
        "                        if (e.target.readyState == 2) {"
        "                                let base64 = "
        "e.target.result.slice('data:application/zip;base64,'.length);"
        "                                window.top.location = "
        "'https://smolsite.zip/' + base64;"
        "                        }"
        "                };"
        "                reader.readAsDataURL(e.dataTransfer.files[0]);"
        "        }"
        "}, false);"
        "</script>"
        "</body>\n"
        "</html>",
        digest_str);
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
    for (const char *p = request->url.value; *p; p++) {
        if (!isxdigit(*p))
            return HTTP_NOT_FOUND;
    }

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

int main(void)
{
    struct lwan l;

    lwan_init(&l);
    lwan_detect_url_map(&l);

    sites = cache_create_full(create_site, destroy_site, hash_str_new, NULL,
                              CACHE_FOR_MINUTES * 60);
    if (!sites)
        lwan_status_critical("Could not create site cache");

    lwan_main_loop(&l);
    lwan_shutdown(&l);

    return 0;
}
