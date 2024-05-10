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

void lwan_tables_shutdown(void)
{
}

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
    assert(streq(lwan_determine_mime_type_for_file_name(".gif"), "image/gif"));
    assert(streq(lwan_determine_mime_type_for_file_name(".JS"),
                 "text/javascript"));
    assert(streq(lwan_determine_mime_type_for_file_name(".BZ2"),
                 "application/x-bzip2"));
}

LWAN_SELF_TEST(status_codes)
{
#define ASSERT_STATUS(id, code, short, long)                                   \
    do {                                                                       \
        assert(!strncmp(lwan_http_status_as_string_with_code(HTTP_##id),       \
                        #code, 3));                                            \
        assert(!strcmp(lwan_http_status_as_string(HTTP_##id), short));         \
        assert(                                                                \
            !strcmp(lwan_http_status_as_descriptive_string(HTTP_##id), long)); \
    } while (0);
    FOR_EACH_HTTP_STATUS(ASSERT_STATUS)
#undef ASSERT_STATUS
}

static int compare_mime_entry(const void *a, const void *b)
{
    static const uintptr_t begin = (uintptr_t)uncompressed_mime_entries;
    static const uintptr_t end = begin + 8 * MIME_ENTRIES;
    const uintptr_t pa = (uintptr_t)a;
    const uintptr_t pb = (uintptr_t)b;
    uint64_t exta;
    uint64_t extb;

    if (end - pa >= begin && end - pb >= begin) {
        /* If both keys are within the uncompressed mime entries range, then
         * we don't need to load from memory, just compare the pointers: they're
         * all stored sequentially in memory by construction. */
        exta = pa;
        extb = pb;
    } else {
        /* These are stored in big-endian so the comparison below works
         * as expected. */
        exta = string_as_uint64((const char *)a);
        extb = string_as_uint64((const char *)b);
    }

    return (exta > extb) - (exta < extb);
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
        uint64_t key = 0;
        const unsigned char *extension;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstringop-truncation"
        /* Data is stored with NULs on strings up to 7 chars, and no NULs
         * for 8-char strings, because that's implicit.  So truncation is
         * intentional here: comparison in compare_mime_entry() always loads
         * 8 bytes per extension. */
        strncpy((char *)&key, last_dot + 1, 8);
#pragma GCC diagnostic pop
        key &= ~0x2020202020202020ull;
        key = htobe64(key);

        extension = bsearch(&key, uncompressed_mime_entries, MIME_ENTRIES, 8,
                            compare_mime_entry);
        if (LIKELY(extension))
            return mime_types[(extension - uncompressed_mime_entries) / 8];
    }

fallback:
    return "application/octet-stream";
}

#include "lookup-http-status.h" /* genrated by statuslookupgen */

ALWAYS_INLINE const char *
lwan_http_status_as_string_with_code(const enum lwan_http_status status)
{
    return lwan_lookup_http_status_impl(status);
}

const char *
lwan_http_status_as_string(const enum lwan_http_status status)
{
    return lwan_http_status_as_string_with_code(status) + 4;
}

const char *lwan_http_status_as_descriptive_string(const enum lwan_http_status status)
{
    const char *str = lwan_lookup_http_status_impl(status);
    return str + strlen(str) + 1;
}

enum {
    CHAR_PROP_SPACE = 1 << 0,
    CHAR_PROP_HEX = 1 << 1,
    CHAR_PROP_DIG = 1 << 2,
    CHAR_PROP_ALPHA = 1 << 3,
    CHAR_PROP_CGI_HEADER = 1 << 4,
};

static const uint8_t char_prop_tbl[256] = {
    [' '] = CHAR_PROP_SPACE,
    ['\t'] = CHAR_PROP_SPACE,
    ['\n'] = CHAR_PROP_SPACE,
    ['\r'] = CHAR_PROP_SPACE,
    ['0'] = CHAR_PROP_HEX | CHAR_PROP_DIG | CHAR_PROP_CGI_HEADER,
    ['1'] = CHAR_PROP_HEX | CHAR_PROP_DIG | CHAR_PROP_CGI_HEADER,
    ['2'] = CHAR_PROP_HEX | CHAR_PROP_DIG | CHAR_PROP_CGI_HEADER,
    ['3'] = CHAR_PROP_HEX | CHAR_PROP_DIG | CHAR_PROP_CGI_HEADER,
    ['4'] = CHAR_PROP_HEX | CHAR_PROP_DIG | CHAR_PROP_CGI_HEADER,
    ['5'] = CHAR_PROP_HEX | CHAR_PROP_DIG | CHAR_PROP_CGI_HEADER,
    ['6'] = CHAR_PROP_HEX | CHAR_PROP_DIG | CHAR_PROP_CGI_HEADER,
    ['7'] = CHAR_PROP_HEX | CHAR_PROP_DIG | CHAR_PROP_CGI_HEADER,
    ['8'] = CHAR_PROP_HEX | CHAR_PROP_DIG | CHAR_PROP_CGI_HEADER,
    ['9'] = CHAR_PROP_HEX | CHAR_PROP_DIG | CHAR_PROP_CGI_HEADER,
    ['a'] = CHAR_PROP_HEX | CHAR_PROP_ALPHA | CHAR_PROP_CGI_HEADER,
    ['b'] = CHAR_PROP_HEX | CHAR_PROP_ALPHA | CHAR_PROP_CGI_HEADER,
    ['c'] = CHAR_PROP_HEX | CHAR_PROP_ALPHA | CHAR_PROP_CGI_HEADER,
    ['d'] = CHAR_PROP_HEX | CHAR_PROP_ALPHA | CHAR_PROP_CGI_HEADER,
    ['e'] = CHAR_PROP_HEX | CHAR_PROP_ALPHA | CHAR_PROP_CGI_HEADER,
    ['f'] = CHAR_PROP_HEX | CHAR_PROP_ALPHA | CHAR_PROP_CGI_HEADER,
    ['g'] = CHAR_PROP_ALPHA | CHAR_PROP_CGI_HEADER,
    ['h'] = CHAR_PROP_ALPHA | CHAR_PROP_CGI_HEADER,
    ['i'] = CHAR_PROP_ALPHA | CHAR_PROP_CGI_HEADER,
    ['j'] = CHAR_PROP_ALPHA | CHAR_PROP_CGI_HEADER,
    ['k'] = CHAR_PROP_ALPHA | CHAR_PROP_CGI_HEADER,
    ['l'] = CHAR_PROP_ALPHA | CHAR_PROP_CGI_HEADER,
    ['m'] = CHAR_PROP_ALPHA | CHAR_PROP_CGI_HEADER,
    ['n'] = CHAR_PROP_ALPHA | CHAR_PROP_CGI_HEADER,
    ['o'] = CHAR_PROP_ALPHA | CHAR_PROP_CGI_HEADER,
    ['p'] = CHAR_PROP_ALPHA | CHAR_PROP_CGI_HEADER,
    ['q'] = CHAR_PROP_ALPHA | CHAR_PROP_CGI_HEADER,
    ['r'] = CHAR_PROP_ALPHA | CHAR_PROP_CGI_HEADER,
    ['s'] = CHAR_PROP_ALPHA | CHAR_PROP_CGI_HEADER,
    ['t'] = CHAR_PROP_ALPHA | CHAR_PROP_CGI_HEADER,
    ['u'] = CHAR_PROP_ALPHA | CHAR_PROP_CGI_HEADER,
    ['v'] = CHAR_PROP_ALPHA | CHAR_PROP_CGI_HEADER,
    ['w'] = CHAR_PROP_ALPHA | CHAR_PROP_CGI_HEADER,
    ['x'] = CHAR_PROP_ALPHA | CHAR_PROP_CGI_HEADER,
    ['y'] = CHAR_PROP_ALPHA | CHAR_PROP_CGI_HEADER,
    ['z'] = CHAR_PROP_ALPHA | CHAR_PROP_CGI_HEADER,
    ['A'] = CHAR_PROP_HEX | CHAR_PROP_ALPHA | CHAR_PROP_CGI_HEADER,
    ['B'] = CHAR_PROP_HEX | CHAR_PROP_ALPHA | CHAR_PROP_CGI_HEADER,
    ['C'] = CHAR_PROP_HEX | CHAR_PROP_ALPHA | CHAR_PROP_CGI_HEADER,
    ['D'] = CHAR_PROP_HEX | CHAR_PROP_ALPHA | CHAR_PROP_CGI_HEADER,
    ['E'] = CHAR_PROP_HEX | CHAR_PROP_ALPHA | CHAR_PROP_CGI_HEADER,
    ['F'] = CHAR_PROP_HEX | CHAR_PROP_ALPHA | CHAR_PROP_CGI_HEADER,
    ['G'] = CHAR_PROP_ALPHA | CHAR_PROP_CGI_HEADER,
    ['H'] = CHAR_PROP_ALPHA | CHAR_PROP_CGI_HEADER,
    ['I'] = CHAR_PROP_ALPHA | CHAR_PROP_CGI_HEADER,
    ['J'] = CHAR_PROP_ALPHA | CHAR_PROP_CGI_HEADER,
    ['K'] = CHAR_PROP_ALPHA | CHAR_PROP_CGI_HEADER,
    ['L'] = CHAR_PROP_ALPHA | CHAR_PROP_CGI_HEADER,
    ['M'] = CHAR_PROP_ALPHA | CHAR_PROP_CGI_HEADER,
    ['N'] = CHAR_PROP_ALPHA | CHAR_PROP_CGI_HEADER,
    ['O'] = CHAR_PROP_ALPHA | CHAR_PROP_CGI_HEADER,
    ['P'] = CHAR_PROP_ALPHA | CHAR_PROP_CGI_HEADER,
    ['Q'] = CHAR_PROP_ALPHA | CHAR_PROP_CGI_HEADER,
    ['R'] = CHAR_PROP_ALPHA | CHAR_PROP_CGI_HEADER,
    ['S'] = CHAR_PROP_ALPHA | CHAR_PROP_CGI_HEADER,
    ['T'] = CHAR_PROP_ALPHA | CHAR_PROP_CGI_HEADER,
    ['U'] = CHAR_PROP_ALPHA | CHAR_PROP_CGI_HEADER,
    ['V'] = CHAR_PROP_ALPHA | CHAR_PROP_CGI_HEADER,
    ['W'] = CHAR_PROP_ALPHA | CHAR_PROP_CGI_HEADER,
    ['X'] = CHAR_PROP_ALPHA | CHAR_PROP_CGI_HEADER,
    ['Y'] = CHAR_PROP_ALPHA | CHAR_PROP_CGI_HEADER,
    ['Z'] = CHAR_PROP_ALPHA | CHAR_PROP_CGI_HEADER,
    ['!'] = CHAR_PROP_CGI_HEADER,
    ['#'] = CHAR_PROP_CGI_HEADER,
    ['$'] = CHAR_PROP_CGI_HEADER,
    ['%'] = CHAR_PROP_CGI_HEADER,
    ['&'] = CHAR_PROP_CGI_HEADER,
    ['\''] = CHAR_PROP_CGI_HEADER,
    ['*'] = CHAR_PROP_CGI_HEADER,
    ['+'] = CHAR_PROP_CGI_HEADER,
    ['.'] = CHAR_PROP_CGI_HEADER,
    ['^'] = CHAR_PROP_CGI_HEADER,
    ['_'] = CHAR_PROP_CGI_HEADER,
    ['`'] = CHAR_PROP_CGI_HEADER,
    ['|'] = CHAR_PROP_CGI_HEADER,
    ['~'] = CHAR_PROP_CGI_HEADER,
};

ALWAYS_INLINE uint8_t lwan_char_isspace(char ch)
{
    return char_prop_tbl[(unsigned char)ch] & CHAR_PROP_SPACE;
}

ALWAYS_INLINE uint8_t lwan_char_iscgiheader(char ch)
{
    return char_prop_tbl[(unsigned char)ch] & CHAR_PROP_CGI_HEADER;
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

#include <ctype.h>
LWAN_SELF_TEST(compare_with_ctype)
{
    for (int i = 0; i < 256; i++) {
        assert(!!isxdigit((char)i) == !!lwan_char_isxdigit((char)i));
        assert(!!isdigit((char)i) == !!lwan_char_isdigit((char)i));
        assert(!!isalpha((char)i) == !!lwan_char_isalpha((char)i));
        assert(!!isalnum((char)i) == !!lwan_char_isalnum((char)i));

        /* isspace() and lwan_char_isspace() differs on purpose */
    }
}
