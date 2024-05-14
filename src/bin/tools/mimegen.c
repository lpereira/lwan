/*
 * lwan - web server
 * Copyright (c) 2016 L. A. F. Pereira <l@tia.mat.br>
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

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <endian.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(LWAN_HAVE_BROTLI)
#include <brotli/encode.h>
#elif defined(LWAN_HAVE_ZSTD)
#include <zstd.h>
#elif defined(LWAN_HAVE_ZOPFLI)
#include <zopfli/zopfli.h>
#else
#include <zlib.h>
#endif

#include "../../lib/hash.h"

struct output {
    char *ptr;
    size_t used, capacity;
};

static int
output_append_full(struct output *output, const char *str, size_t str_len)
{
    size_t total_size = output->used + str_len;

    if (total_size >= output->capacity) {
        char *tmp;

        while (total_size >= output->capacity)
            output->capacity *= 2;

        tmp = realloc(output->ptr, output->capacity);
        if (!tmp)
            return -errno;

        output->ptr = tmp;
    }

    memcpy(output->ptr + output->used, str, str_len);
    output->used = total_size;

    return 0;
}

static int output_append_u64(struct output *output, uint64_t value)
{
    return output_append_full(output, (char *)&value, 8);
}

static int output_append(struct output *output, const char *str)
{
    return output_append_full(output, str, strlen(str) + 1);
}

static int compare_ext(const void *a, const void *b)
{
    const char **exta = (const char **)a;
    const char **extb = (const char **)b;

    return strcasecmp(*exta, *extb);
}

static char *strend(char *str, char ch)
{
    str = strchr(str, ch);
    if (str) {
        *str = '\0';
        return str + 1;
    }
    return NULL;
}

static char *compress_output(const struct output *output, size_t *outlen)
{
    char *compressed;

#if defined(LWAN_HAVE_BROTLI)
    *outlen = BrotliEncoderMaxCompressedSize(output->used);

    compressed = malloc(*outlen);
    if (!compressed) {
        fprintf(stderr, "Could not allocate memory for compressed data\n");
        exit(1);
    }

    if (BrotliEncoderCompress(BROTLI_MAX_QUALITY, BROTLI_MAX_WINDOW_BITS,
                              BROTLI_MODE_TEXT, output->used,
                              (const unsigned char *)output->ptr, outlen,
                              (unsigned char *)compressed) != BROTLI_TRUE) {
        fprintf(stderr, "Could not compress mime type table with Brotli\n");
        exit(1);
    }
#elif defined(LWAN_HAVE_ZSTD)
    *outlen = ZSTD_compressBound(output->used);

    compressed = malloc(*outlen);
    if (!compressed) {
        fprintf(stderr, "Could not allocate memory for compressed data\n");
        exit(1);
    }

    *outlen = ZSTD_compress(compressed, *outlen, output->ptr, output->used,
                            ZSTD_maxCLevel());
    if (ZSTD_isError(*outlen)) {
        fprintf(stderr, "Could not compress mime type table with ZSTD\n");
        exit(1);
    }
#elif defined(LWAN_HAVE_ZOPFLI)
    ZopfliOptions opts;

    *outlen = 0;

    ZopfliInitOptions(&opts);
    ZopfliCompress(&opts, ZOPFLI_FORMAT_ZLIB,
                   (const unsigned char *)output->ptr, output->used,
                   (unsigned char **)&compressed, outlen);
#else
    *outlen = compressBound((uLong)output->used);
    compressed = malloc(*outlen);
    if (!compressed) {
        fprintf(stderr, "Could not allocate memory for compressed data\n");
        exit(1);
    }
    if (compress2((Bytef *)compressed, outlen, (const Bytef *)output->ptr,
                  output->used, 9) != Z_OK) {
        fprintf(stderr, "Could not compress data with zlib\n");
        exit(1);
    }
#endif
    if (!*outlen) {
        free(compressed);
        return NULL;
    }

    return compressed;
}

int main(int argc, char *argv[])
{
    /* 32k is sufficient for the provided mime.types, but we can reallocate
     * if necessary.  This is just to avoid unneccessary reallocs.  */
    struct output output = { .capacity = 32768 };
    FILE *fp;
    char buffer[256];
    size_t compressed_size;
    char *compressed, *ext;
    struct hash *ext_mime;
    struct hash_iter iter;
    const char **exts, *key;
    size_t i;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s /path/to/mime.types\n", argv[0]);
        return 1;
    }

    fp = fopen(argv[1], "re");
    if (!fp) {
        fprintf(stderr, "Could not open %s: %s\n", argv[1], strerror(errno));
        return 1;
    }

    ext_mime = hash_str_new(free, free);
    if (!ext_mime) {
        fprintf(stderr, "Could not allocate hash table\n");
        fclose(fp);
        return 1;
    }

    while (fgets(buffer, sizeof(buffer), fp)) {
        char *start = buffer, *end, *tab, *mime_type;

        while (*start && isspace(*start)) /* Strip spaces at the start. */
            start++;
        if (*start == '#') /* Ignore commented-out lines. */
            continue;

        strend(start, '\n'); /* Strip line endings. */
        strend(start, '#'); /* Strip comments from the middle. */
        tab = strend(start, '\t');
        if (!tab) /* Find mime-type/extension separator. */
            continue;

        mime_type = start;
        /* "application/octet-stream" is the fallback, so no need to store
         * it in the table.  It's just one line, though, so maybe not really
         * necessary? */
        if (streq(mime_type, "application/octet-stream"))
            continue;

        while (*tab && *tab == '\t') /* Find first extension. */
            tab++;

        for (ext = tab; *ext; ext += end - ext + 1) {
            char *k, *v;
            int r;

            end = strchr(ext, ' '); /* Stop at next extension. */
            if (!end)
                end = strchr(ext, '\0'); /* If not found, find last extension. */
            *end = '\0';

            /* Check if we have empty extensions. Shouldn't happen with the provided
             * mime.types file, but check on debug builds if this ever happens. */
            assert(end != ext);

            if (end - ext > 8) {
                /* Truncate extensions over 8 characters.  See commit 2050759297. */
                ext[8] = '\0';
            }

            k = strdup(ext);
            v = strdup(mime_type);

            if (!k || !v) {
                fprintf(stderr, "Could not allocate memory\n");
                fclose(fp);
                return 1;
            }

            r = hash_add_unique(ext_mime, k, v);
            if (r < 0) {
                free(k);
                free(v);

                if (r != -EEXIST) {
                    fprintf(stderr, "Could not add extension to hash table\n");
                    fclose(fp);
                    return 1;
                }
            }
        }
    }

    {
        char *k = strdup("bin");
        char *v = strdup("application/octet-stream");
        if (!k || !v) {
            fprintf(stderr, "Could not allocate memory\n");
            fclose(fp);
            return 1;
        }
        int r = hash_add_unique(ext_mime, k, v);
        if (r != 0 && r != -EEXIST) {
            fprintf(stderr, "Could not add fallback mime entry\n");
            fclose(fp);
            return 1;
        }
    }

    /* Get sorted list of extensions. */
    exts = calloc(hash_get_count(ext_mime), sizeof(char *));
    if (!exts) {
        fprintf(stderr, "Could not allocate extension array\n");
        fclose(fp);
        return 1;
    }
    hash_iter_init(ext_mime, &iter);
    for (i = 0; hash_iter_next(&iter, (const void **)&key, NULL); i++)
        exts[i] = key;
    qsort(exts, hash_get_count(ext_mime), sizeof(char *), compare_ext);

    /* Generate uncompressed blob. */
    output.ptr = malloc(output.capacity);
    if (!output.ptr) {
        fprintf(stderr, "Could not allocate temporary memory\n");
        fclose(fp);
        return 1;
    }
    ssize_t bin_index = -1;
    for (i = 0; i < hash_get_count(ext_mime); i++) {
        uint64_t ext_lower = 0;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstringop-truncation"
        /* See lwan_determine_mime_type_for_file_name() in lwan-tables.c */
        strncpy((char *)&ext_lower, exts[i], 8);
#pragma GCC diagnostic pop

        ext_lower &= ~0x2020202020202020ull;
        ext_lower = htobe64(ext_lower);

        if (output_append_u64(&output, ext_lower) < 0) {
            fprintf(stderr, "Could not append to output\n");
            fclose(fp);
            return 1;
        }

        if (bin_index < 0 && streq(exts[i], "bin"))
            bin_index = (ssize_t)i;
    }
    for (i = 0; i < hash_get_count(ext_mime); i++) {
        if (output_append(&output, hash_find(ext_mime, exts[i])) < 0) {
            fprintf(stderr, "Could not append to output\n");
            fclose(fp);
            return 1;
        }
    }

    if (bin_index < 0) {
        fprintf(stderr, "Could not find fallback item after sorting!\n");
        fclose(fp);
        return 1;
    }

    /* Compress blob. */
    compressed = compress_output(&output, &compressed_size);
    if (!compressed) {
        fprintf(stderr, "Could not compress data\n");
        fclose(fp);
        return 1;
    }

    /* Print output. */
#if defined(LWAN_HAVE_BROTLI)
    printf("/* Compressed with brotli */\n");
#elif defined(LWAN_HAVE_ZSTD)
    printf("/* Compressed with zstd */\n");
#elif defined(LWAN_HAVE_ZOPFLI)
    printf("/* Compressed with zopfli (deflate) */\n");
#else
    printf("/* Compressed with zlib (deflate) */\n");
#endif

    unsigned int entries_floor = 1u << (31 - __builtin_clz(hash_get_count(ext_mime)));

    printf("#pragma once\n");
    printf("#define MIME_UNCOMPRESSED_LEN %zu\n", output.used);
    printf("#define MIME_COMPRESSED_LEN %lu\n", compressed_size);
    printf("#define MIME_ENTRIES %d\n", hash_get_count(ext_mime));
    printf("#define MIME_ENTRIES_FLOOR %d\n", entries_floor);
    printf("#define MIME_ENTRY_FALLBACK %ld\n", bin_index);
    printf("static const unsigned char mime_entries_compressed[] = {\n");
    for (i = 1; compressed_size; compressed_size--, i++)
        printf("0x%02x,%c", compressed[i - 1] & 0xff, " \n"[i % 13 == 0]);
    printf("};\n");

    free(compressed);
    free(output.ptr);
    free(exts);
    hash_unref(ext_mime);
    fclose(fp);

    return 0;
}
