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
#else
#include <zlib.h>
#endif

#include "lwan-private.h"

#include "mime-types.h"

static unsigned char uncompressed_mime_entries[MIME_UNCOMPRESSED_LEN];
static struct mime_entry mime_entries[MIME_ENTRIES];
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

    unsigned char *ptr = uncompressed_mime_entries;
    for (size_t i = 0; i < MIME_ENTRIES; i++) {
        mime_entries[i].extension = (char *)ptr;
        ptr = rawmemchr(ptr + 1, '\0') + 1;
        mime_entries[i].type = (char *)ptr;
        ptr = rawmemchr(ptr + 1, '\0') + 1;
    }

    mime_entries_initialized = true;
}

void
lwan_tables_shutdown(void)
{
}

static int
compare_mime_entry(const void *a, const void *b)
{
    const struct mime_entry *me1 = a;
    const struct mime_entry *me2 = b;
    return strcmp(me1->extension, me2->extension);
}

const char *
lwan_determine_mime_type_for_file_name(const char *file_name)
{
    char *last_dot = strrchr(file_name, '.');
    if (UNLIKELY(!last_dot))
        goto fallback;

    STRING_SWITCH_L(last_dot) {
    case MULTICHAR_CONSTANT_L('.','j','p','g'):
        return "image/jpeg";
    case MULTICHAR_CONSTANT_L('.','p','n','g'):
        return "image/png";
    case MULTICHAR_CONSTANT_L('.','h','t','m'):
        return "text/html";
    case MULTICHAR_CONSTANT_L('.','c','s','s'):
        return "text/css";
    case MULTICHAR_CONSTANT_L('.','t','x','t'):
        return "text/plain";
    case MULTICHAR_CONSTANT_L('.','j','s',0x20):
        return "application/javascript";
    }

    if (LIKELY(*last_dot)) {
        struct mime_entry *entry, key = { .extension = last_dot + 1 };

        entry = bsearch(&key, mime_entries, MIME_ENTRIES,
                       sizeof(struct mime_entry), compare_mime_entry);
        if (LIKELY(entry))
            return entry->type;
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
