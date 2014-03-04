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

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <zlib.h>

#include "lwan.h"
#include "mime-types.h"

enum {
    EXT_JPG = MULTICHAR_CONSTANT_L('.','j','p','g'),
    EXT_PNG = MULTICHAR_CONSTANT_L('.','p','n','g'),
    EXT_HTM = MULTICHAR_CONSTANT_L('.','h','t','m'),
    EXT_CSS = MULTICHAR_CONSTANT_L('.','c','s','s'),
    EXT_TXT = MULTICHAR_CONSTANT_L('.','t','x','t'),
    EXT_JS  = MULTICHAR_CONSTANT_L('.','j','s',0),
} lwan_mime_ext_t;

static struct mime_entry mime_entries[MIME_ENTRIES];
static bool mime_entries_uncompressed = false;

void
lwan_tables_init(void)
{
    if (mime_entries_uncompressed)
        return;

    assert(sizeof(mime_entries) == MIME_UNCOMPRESSED_LEN);

    lwan_status_debug("Uncompressing MIME type table");
    uLongf uncompressed_length = sizeof(mime_entries);
    int ret = uncompress((Bytef*)mime_entries, &uncompressed_length,
            (const Bytef*)mime_entries_compressed, MIME_COMPRESSED_LEN);
    if (ret != Z_OK)
        lwan_status_critical(
            "Error while uncompressing table: zlib error %d", ret);

    if (uncompressed_length != MIME_UNCOMPRESSED_LEN)
        lwan_status_critical("Expected uncompressed length %d, got %ld",
            MIME_UNCOMPRESSED_LEN, uncompressed_length);

    mime_entries_uncompressed = true;
}

void
lwan_tables_shutdown(void)
{
}

static int
_compare_mime_entry(const void *a, const void *b)
{
    const struct mime_entry *me1 = a;
    const struct mime_entry *me2 = b;
    return strncmp(me1->extension, me2->extension, sizeof(me1->extension));
}

const char *
lwan_determine_mime_type_for_file_name(const char *file_name)
{
    char *last_dot = strrchr(file_name, '.');
    if (UNLIKELY(!last_dot))
        goto fallback;

    STRING_SWITCH_L(last_dot) {
    case EXT_CSS: return "text/css";
    case EXT_HTM: return "text/html";
    case EXT_JPG: return "image/jpeg";
    case EXT_JS:  return "application/javascript";
    case EXT_PNG: return "image/png";
    case EXT_TXT: return "text/plain";
    }

    if (LIKELY(*last_dot)) {
        struct mime_entry *entry, key;

        strncpy(key.extension, (const char *)last_dot + 1,
                                            sizeof(key.extension) - 1);
        entry = bsearch(&key, mime_entries, MIME_ENTRIES,
                       sizeof(struct mime_entry), _compare_mime_entry);
        if (LIKELY(entry))
            return entry->type;
    }

fallback:
    return "application/octet-stream";
}

const char *
lwan_http_status_as_string(lwan_http_status_t status)
{
    switch (status) {
    case HTTP_OK: return "OK";
    case HTTP_PARTIAL_CONTENT: return "Partial content";
    case HTTP_MOVED_PERMANENTLY: return "Moved permanently";
    case HTTP_NOT_MODIFIED: return "Not modified";
    case HTTP_BAD_REQUEST: return "Bad request";
    case HTTP_NOT_AUTHORIZED: return "Not authorized";
    case HTTP_NOT_FOUND: return "Not found";
    case HTTP_FORBIDDEN: return "Forbidden";
    case HTTP_NOT_ALLOWED: return "Not allowed";
    case HTTP_TOO_LARGE: return "Request too large";
    case HTTP_RANGE_UNSATISFIABLE: return "Requested range unsatisfiable";
    case HTTP_INTERNAL_ERROR: return "Internal server error";
    case HTTP_UNAVAILABLE: return "Service unavailable";
    }
    return "Invalid";
}

const char *
lwan_http_status_as_descriptive_string(lwan_http_status_t status)
{
    switch (status) {
    case HTTP_OK: return "Success!";
    case HTTP_PARTIAL_CONTENT: return "Delivering part of requested resource.";
    case HTTP_MOVED_PERMANENTLY: return "This content has moved to another place.";
    case HTTP_NOT_MODIFIED: return "The content has not changed since previous request.";
    case HTTP_BAD_REQUEST: return "The client has issued a bad request.";
    case HTTP_NOT_AUTHORIZED: return "Client has no authorization to access this resource.";
    case HTTP_NOT_FOUND: return "The requested resource could not be found on this server.";
    case HTTP_FORBIDDEN: return "Access to this resource has been denied.";
    case HTTP_NOT_ALLOWED: return "The requested method is not allowed by this server.";
    case HTTP_TOO_LARGE: return "The request entity is too large.";
    case HTTP_RANGE_UNSATISFIABLE: return "The server can't supply the requested portion of the requested resource.";
    case HTTP_INTERNAL_ERROR: return "The server encountered an internal error that couldn't be recovered from.";
    case HTTP_UNAVAILABLE: return "The server is either overloaded or down for maintenance.";
    }
    return "Invalid";
}
