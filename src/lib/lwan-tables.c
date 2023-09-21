/*
 * lwan - web server
 * Copyright (c) 2012, 2013 L. A. F. Pereira <l@tia.mat.br>
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

#if defined(LWAN_HAVE_BROTLI)
#include <brotli/decode.h>
#elif defined(LWAN_HAVE_ZSTD)
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

#if defined(LWAN_HAVE_BROTLI)
    size_t uncompressed_length = MIME_UNCOMPRESSED_LEN;
    BrotliDecoderResult ret;

    ret = BrotliDecoderDecompress(MIME_COMPRESSED_LEN, mime_entries_compressed,
                                  &uncompressed_length,
                                  uncompressed_mime_entries);
    if (ret != BROTLI_DECODER_RESULT_SUCCESS)
        lwan_status_critical("Error while uncompressing table with Brotli");
#elif defined(LWAN_HAVE_ZSTD)
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
        ptr += strlen((const char *)ptr) + 1;
    }

    mime_entries_initialized = true;

    assert(streq(lwan_determine_mime_type_for_file_name(".mkv"),
                 "video/x-matroska"));
    assert(streq(lwan_determine_mime_type_for_file_name(".xml"),
                 "application/xml"));
    assert(streq(lwan_determine_mime_type_for_file_name(".nosuchext"),
                 "application/octet-stream"));
    assert(streq(lwan_determine_mime_type_for_file_name("nodotinfilename"),
                 "application/octet-stream"));
    assert(streq(lwan_determine_mime_type_for_file_name(""),
                 "application/octet-stream"));
    assert(streq(lwan_determine_mime_type_for_file_name(".gif"),
                 "image/gif"));
    assert(streq(lwan_determine_mime_type_for_file_name(".JS"),
                 "text/javascript"));
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
    case STR4_INT_L('.','c','s','s'): return "text/css";
    case STR4_INT_L('.','g','i','f'): return "image/gif";
    case STR4_INT_L('.','h','t','m'): return "text/html";
    case STR4_INT_L('.','j','p','g'): return "image/jpeg";
    case STR4_INT_L('.','j','s',' '): return "text/javascript";
    case STR4_INT_L('.','p','n','g'): return "image/png";
    case STR4_INT_L('.','t','x','t'): return "text/plain";
    }

    if (LIKELY(*last_dot)) {
        uint64_t key;
        const unsigned char *extension;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstringop-truncation"
        /* Data is stored with NULs on strings up to 7 chars, and no NULs
         * for 8-char strings, because that's implicit.  So truncation is
         * intentional here: comparison in compare_mime_entry() uses
         * strncmp(..., 8), so even if NUL isn't present, it'll stop at the
         * right place.  */
        strncpy((char *)&key, last_dot + 1, 8);
#pragma GCC diagnostic pop
        key &= ~0x2020202020202020ull;

        extension = bsearch(&key, uncompressed_mime_entries, MIME_ENTRIES, 8,
                            compare_mime_entry);
        if (LIKELY(extension))
            return mime_types[(extension - uncompressed_mime_entries) / 8];
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
    CHAR_PROP_SPACE = 1 << 0,
    CHAR_PROP_HEX = 1 << 1,
    CHAR_PROP_DIG = 1 << 2,
    CHAR_PROP_ALPHA = 1 << 3,
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
    ['a'] = CHAR_PROP_HEX | CHAR_PROP_ALPHA,
    ['b'] = CHAR_PROP_HEX | CHAR_PROP_ALPHA,
    ['c'] = CHAR_PROP_HEX | CHAR_PROP_ALPHA,
    ['d'] = CHAR_PROP_HEX | CHAR_PROP_ALPHA,
    ['e'] = CHAR_PROP_HEX | CHAR_PROP_ALPHA,
    ['f'] = CHAR_PROP_HEX | CHAR_PROP_ALPHA,
    ['g'] = CHAR_PROP_ALPHA,
    ['h'] = CHAR_PROP_ALPHA,
    ['i'] = CHAR_PROP_ALPHA,
    ['j'] = CHAR_PROP_ALPHA,
    ['k'] = CHAR_PROP_ALPHA,
    ['l'] = CHAR_PROP_ALPHA,
    ['m'] = CHAR_PROP_ALPHA,
    ['n'] = CHAR_PROP_ALPHA,
    ['o'] = CHAR_PROP_ALPHA,
    ['p'] = CHAR_PROP_ALPHA,
    ['q'] = CHAR_PROP_ALPHA,
    ['r'] = CHAR_PROP_ALPHA,
    ['s'] = CHAR_PROP_ALPHA,
    ['t'] = CHAR_PROP_ALPHA,
    ['u'] = CHAR_PROP_ALPHA,
    ['v'] = CHAR_PROP_ALPHA,
    ['w'] = CHAR_PROP_ALPHA,
    ['x'] = CHAR_PROP_ALPHA,
    ['y'] = CHAR_PROP_ALPHA,
    ['z'] = CHAR_PROP_ALPHA,
    ['A'] = CHAR_PROP_HEX | CHAR_PROP_ALPHA,
    ['B'] = CHAR_PROP_HEX | CHAR_PROP_ALPHA,
    ['C'] = CHAR_PROP_HEX | CHAR_PROP_ALPHA,
    ['D'] = CHAR_PROP_HEX | CHAR_PROP_ALPHA,
    ['E'] = CHAR_PROP_HEX | CHAR_PROP_ALPHA,
    ['F'] = CHAR_PROP_HEX | CHAR_PROP_ALPHA,
    ['G'] = CHAR_PROP_ALPHA,
    ['H'] = CHAR_PROP_ALPHA,
    ['I'] = CHAR_PROP_ALPHA,
    ['J'] = CHAR_PROP_ALPHA,
    ['K'] = CHAR_PROP_ALPHA,
    ['L'] = CHAR_PROP_ALPHA,
    ['M'] = CHAR_PROP_ALPHA,
    ['N'] = CHAR_PROP_ALPHA,
    ['O'] = CHAR_PROP_ALPHA,
    ['P'] = CHAR_PROP_ALPHA,
    ['Q'] = CHAR_PROP_ALPHA,
    ['R'] = CHAR_PROP_ALPHA,
    ['S'] = CHAR_PROP_ALPHA,
    ['T'] = CHAR_PROP_ALPHA,
    ['U'] = CHAR_PROP_ALPHA,
    ['V'] = CHAR_PROP_ALPHA,
    ['W'] = CHAR_PROP_ALPHA,
    ['X'] = CHAR_PROP_ALPHA,
    ['Y'] = CHAR_PROP_ALPHA,
    ['Z'] = CHAR_PROP_ALPHA,
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

ALWAYS_INLINE uint8_t lwan_char_isalpha(char ch)
{
    return char_prop_tbl[(unsigned char)ch] & CHAR_PROP_ALPHA;
}

ALWAYS_INLINE uint8_t lwan_char_isalnum(char ch)
{
    return char_prop_tbl[(unsigned char)ch] & (CHAR_PROP_ALPHA | CHAR_PROP_DIG);
}
