/*
 * lwan - simple web server
 * Copyright (c) 2012, 2013 Leandro A. F. Pereira <leandro@hardinfo.org>
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
#include <string.h>
#include <stdlib.h>

#if defined(HAVE_BROTLI)
#include <brotli/decode.h>
#elif defined(HAVE_ZSTD)
#include <zstd.h>
#else
#include <zlib.h>
#endif

#include "lwan-private.h"

#include "mime-types.h"

static unsigned char uncompressed_mime_entries[MIME_UNCOMPRESSED_LEN];
static char *mime_types[MIME_ENTRIES];
static bool mime_entries_initialized = false;

void lwan_tables_init(void)
{
    if (mime_entries_initialized)
        return;

    lwan_status_debug("Uncompressing MIME type table: %u->%u bytes, %d entries",
                      MIME_COMPRESSED_LEN, MIME_UNCOMPRESSED_LEN, MIME_ENTRIES);

#if defined(HAVE_BROTLI)
    size_t uncompressed_length = MIME_UNCOMPRESSED_LEN;
    BrotliDecoderResult ret;

    ret = BrotliDecoderDecompress(MIME_COMPRESSED_LEN, mime_entries_compressed,
                                  &uncompressed_length,
                                  uncompressed_mime_entries);
    if (ret != BROTLI_DECODER_RESULT_SUCCESS)
        lwan_status_critical("Error while uncompressing table with Brotli");
#elif defined(HAVE_ZSTD)
    size_t uncompressed_length =
        ZSTD_decompress(uncompressed_mime_entries, MIME_UNCOMPRESSED_LEN,
                        mime_entries_compressed, MIME_COMPRESSED_LEN);
    if (ZSTD_isError(uncompressed_length))
        lwan_status_critical("Error while uncompressing table with Zstd");
#else
    uLongf uncompressed_length = MIME_UNCOMPRESSED_LEN;
    int ret =
        uncompress((Bytef *)uncompressed_mime_entries, &uncompressed_length,
                   (const Bytef *)mime_entries_compressed, MIME_COMPRESSED_LEN);
    if (ret != Z_OK) {
        lwan_status_critical("Error while uncompressing table: zlib error %d",
                             ret);
    }
#endif

    if (uncompressed_length != MIME_UNCOMPRESSED_LEN) {
        lwan_status_critical("Expected uncompressed length %d, got %ld",
                             MIME_UNCOMPRESSED_LEN, uncompressed_length);
    }

    unsigned char *ptr = uncompressed_mime_entries + 8 * MIME_ENTRIES;
    for (size_t i = 0; i < MIME_ENTRIES; i++) {
        mime_types[i] = (char *)ptr;
        ptr = rawmemchr(ptr + 1, '\0') + 1;
    }

    mime_entries_initialized = true;

    assert(streq(lwan_determine_mime_type_for_file_name(".mkv"),
                 "video/x-matroska"));
    assert(streq(lwan_determine_mime_type_for_file_name(".xml"),
                 "application/xml"));
    assert(streq(lwan_determine_mime_type_for_file_name(".nosuchext"),
                 "application/octet-stream"));
    assert(streq(lwan_determine_mime_type_for_file_name(".gif"),
                 "image/gif"));
    assert(streq(lwan_determine_mime_type_for_file_name(".JS"),
                 "application/javascript"));
    assert(streq(lwan_determine_mime_type_for_file_name(".BZ2"),
                 "application/x-bzip2"));
}

void
lwan_tables_shutdown(void)
{
}

static int
compare_mime_entry(const void *a, const void *b)
{
    const char *exta = (const char *)a;
    const char *extb = (const char *)b;

    return strncmp(exta, extb, 8);
}

const char *
lwan_determine_mime_type_for_file_name(const char *file_name)
{
    char *last_dot = strrchr(file_name, '.');
    if (UNLIKELY(!last_dot))
        goto fallback;

    STRING_SWITCH_L(last_dot) {
    case STR4_INT_L('.','g','i','f'): return "image/gif";
    case STR4_INT_L('.','j','p','g'): return "image/jpeg";
    case STR4_INT_L('.','p','n','g'): return "image/png";
    case STR4_INT_L('.','h','t','m'): return "text/html";
    case STR4_INT_L('.','c','s','s'): return "text/css";
    case STR4_INT_L('.','t','x','t'): return "text/plain";
    case STR4_INT_L('.','j','s',' '): return "application/javascript";
    }

    if (LIKELY(*last_dot)) {
        char key[9];
        char *extension;

        strncpy(key, last_dot + 1, 8);
        key[8] = '\0';
        for (char *p = key; *p; p++)
            *p |= 0x20;

        extension = bsearch(key, uncompressed_mime_entries, MIME_ENTRIES, 8,
                            compare_mime_entry);
        if (LIKELY(extension))
            return mime_types[(extension - (char*)uncompressed_mime_entries) / 8];
    }

fallback:
    return "application/octet-stream";
}

#define GENERATE_ENTRY(id, code, short, long)                                  \
    [HTTP_ ## id] = {.status = #code " " short, .description = long},
static const struct {
    const char *status;
    const char *description;
} status_table[] = {
    FOR_EACH_HTTP_STATUS(GENERATE_ENTRY)
};
#undef GENERATE_ENTRY

const char *
lwan_http_status_as_string_with_code(enum lwan_http_status status)
{
    if (LIKELY(status < N_ELEMENTS(status_table))) {
        const char *ret = status_table[status].status;

        if (LIKELY(ret))
            return ret;
    }

    return "999 Invalid";
}

ALWAYS_INLINE const char *
lwan_http_status_as_string(enum lwan_http_status status)
{
    return lwan_http_status_as_string_with_code(status) + 4;
}

const char *
lwan_http_status_as_descriptive_string(enum lwan_http_status status)
{
    if (LIKELY(status < N_ELEMENTS(status_table))) {
        const char *ret = status_table[status].description;

        if (LIKELY(ret))
            return ret;
    }

    return "Invalid";
}

enum {
    CHAR_PROP_SPACE = 1<<0,
    CHAR_PROP_HEX = 1<<1,
    CHAR_PROP_DIG = 1<<2,
};

static const uint8_t char_prop_tbl[256] = {
    [' '] = CHAR_PROP_SPACE,
    ['\t'] = CHAR_PROP_SPACE,
    ['\n'] = CHAR_PROP_SPACE,
    ['\r'] = CHAR_PROP_SPACE,
    ['0'] = CHAR_PROP_HEX | CHAR_PROP_DIG,
    ['1'] = CHAR_PROP_HEX | CHAR_PROP_DIG,
    ['2'] = CHAR_PROP_HEX | CHAR_PROP_DIG,
    ['3'] = CHAR_PROP_HEX | CHAR_PROP_DIG,
    ['4'] = CHAR_PROP_HEX | CHAR_PROP_DIG,
    ['5'] = CHAR_PROP_HEX | CHAR_PROP_DIG,
    ['6'] = CHAR_PROP_HEX | CHAR_PROP_DIG,
    ['7'] = CHAR_PROP_HEX | CHAR_PROP_DIG,
    ['8'] = CHAR_PROP_HEX | CHAR_PROP_DIG,
    ['9'] = CHAR_PROP_HEX | CHAR_PROP_DIG,
    ['a'] = CHAR_PROP_HEX,
    ['b'] = CHAR_PROP_HEX,
    ['c'] = CHAR_PROP_HEX,
    ['d'] = CHAR_PROP_HEX,
    ['e'] = CHAR_PROP_HEX,
    ['f'] = CHAR_PROP_HEX,
    ['A'] = CHAR_PROP_HEX,
    ['B'] = CHAR_PROP_HEX,
    ['C'] = CHAR_PROP_HEX,
    ['D'] = CHAR_PROP_HEX,
    ['E'] = CHAR_PROP_HEX,
    ['F'] = CHAR_PROP_HEX,
};

ALWAYS_INLINE uint8_t lwan_char_isspace(char ch)
{
    return char_prop_tbl[(unsigned char)ch] & CHAR_PROP_SPACE;
}

ALWAYS_INLINE uint8_t lwan_char_isxdigit(char ch)
{
    return char_prop_tbl[(unsigned char)ch] & CHAR_PROP_HEX;
}

ALWAYS_INLINE uint8_t lwan_char_isdigit(char ch)
{
    return char_prop_tbl[(unsigned char)ch] & CHAR_PROP_DIG;
}
