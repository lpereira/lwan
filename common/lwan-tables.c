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
#include <zlib.h>

#include "lwan-private.h"

#include "mime-types.h"

static unsigned char uncompressed_mime_entries[MIME_UNCOMPRESSED_LEN];
static struct mime_entry mime_entries[MIME_ENTRIES];
static bool mime_entries_initialized = false;

void
lwan_tables_init(void)
{
    if (mime_entries_initialized)
        return;

    lwan_status_debug("Uncompressing MIME type table");
    uLongf uncompressed_length = MIME_UNCOMPRESSED_LEN;
    int ret = uncompress((Bytef*)uncompressed_mime_entries,
            &uncompressed_length, (const Bytef*)mime_entries_compressed,
            MIME_COMPRESSED_LEN);
    if (ret != Z_OK)
        lwan_status_critical(
            "Error while uncompressing table: zlib error %d", ret);

    if (uncompressed_length != MIME_UNCOMPRESSED_LEN)
        lwan_status_critical("Expected uncompressed length %d, got %ld",
            MIME_UNCOMPRESSED_LEN, uncompressed_length);

    unsigned char *ptr = uncompressed_mime_entries;
    for (size_t i = 0; i < MIME_ENTRIES; i++) {
        mime_entries[i].extension = (char*)ptr;
        ptr = rawmemchr(ptr + 1, '\0') + 1;
        mime_entries[i].type = (char*)ptr;
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

    enum {
        EXT_JPG = MULTICHAR_CONSTANT_L('.','j','p','g'),
        EXT_PNG = MULTICHAR_CONSTANT_L('.','p','n','g'),
        EXT_HTM = MULTICHAR_CONSTANT_L('.','h','t','m'),
        EXT_CSS = MULTICHAR_CONSTANT_L('.','c','s','s'),
        EXT_TXT = MULTICHAR_CONSTANT_L('.','t','x','t'),
        EXT_JS  = MULTICHAR_CONSTANT_L('.','j','s',0x20),
    };

    STRING_SWITCH_L(last_dot) {
    case EXT_CSS:
        return "text/css";
    case EXT_HTM:
        return "text/html";
    case EXT_JPG:
        return "image/jpeg";
    case EXT_JS:
        return "application/javascript";
    case EXT_PNG:
        return "image/png";
    case EXT_TXT:
        return "text/plain";
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

const char *
lwan_http_status_as_string_with_code(enum lwan_http_status status)
{
    const char *ret;

#define RESP(code,description)		[code] = #code " " description
    static const char *responses[] = {
        RESP(200, "OK"),
        RESP(206, "Partial content"),
        RESP(301, "Moved permanently"),
        RESP(304, "Not modified"),
        RESP(400, "Bad request"),
        RESP(401, "Not authorized"),
        RESP(403, "Forbidden"),
        RESP(404, "Not found"),
        RESP(405, "Not allowed"),
        RESP(408, "Request timeout"),
        RESP(413, "Request too large"),
        RESP(416, "Requested range unsatisfiable"),
        RESP(418, "I'm a teapot"),
        RESP(420, "Client too high"),
        RESP(500, "Internal server error"),
        RESP(501, "Not implemented"),
        RESP(503, "Service unavailable"),
        RESP(520, "Server too high"),
    };
#undef RESP

    ret = LIKELY(status < N_ELEMENTS(responses)) ? responses[status] : NULL;
    return LIKELY(ret) ? ret : "999 Invalid";
}

ALWAYS_INLINE const char *
lwan_http_status_as_string(enum lwan_http_status status)
{
    return lwan_http_status_as_string_with_code(status) + 4;
}

const char *
lwan_http_status_as_descriptive_string(enum lwan_http_status status)
{
    switch (status) {
    case HTTP_OK:
        return "Success!";
    case HTTP_PARTIAL_CONTENT:
        return "Delivering part of requested resource.";
    case HTTP_MOVED_PERMANENTLY:
        return "This content has moved to another place.";
    case HTTP_NOT_MODIFIED:
        return "The content has not changed since previous request.";
    case HTTP_BAD_REQUEST:
        return "The client has issued a bad request.";
    case HTTP_NOT_AUTHORIZED:
        return "Client has no authorization to access this resource.";
    case HTTP_FORBIDDEN:
        return "Access to this resource has been denied.";
    case HTTP_NOT_FOUND:
        return "The requested resource could not be found on this server.";
    case HTTP_NOT_ALLOWED:
        return "The requested method is not allowed by this server.";
    case HTTP_TIMEOUT:
        return "Client did not produce a request within expected timeframe.";
    case HTTP_TOO_LARGE:
        return "The request entity is too large.";
    case HTTP_RANGE_UNSATISFIABLE:
        return "The server can't supply the requested portion of the requested resource.";
    case HTTP_I_AM_A_TEAPOT:
        return "Client requested to brew coffee but device is a teapot.";
    case HTTP_CLIENT_TOO_HIGH:
        return "Client is too high to make a request.";
    case HTTP_INTERNAL_ERROR:
        return "The server encountered an internal error that couldn't be recovered from.";
    case HTTP_NOT_IMPLEMENTED:
        return "Server lacks the ability to fulfil the request.";
    case HTTP_UNAVAILABLE:
        return "The server is either overloaded or down for maintenance.";
    case HTTP_SERVER_TOO_HIGH:
        return "The server is too high to answer the request.";
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
    return char_prop_tbl[(int)ch] & CHAR_PROP_SPACE;
}

ALWAYS_INLINE uint8_t lwan_char_isxdigit(char ch)
{
    return char_prop_tbl[(int)ch] & CHAR_PROP_HEX;
}

ALWAYS_INLINE uint8_t lwan_char_isdigit(char ch)
{
    return char_prop_tbl[(int)ch] & CHAR_PROP_DIG;
}
