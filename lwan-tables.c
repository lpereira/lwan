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

#include <string.h>
#include "lwan.h"

const char *
lwan_determine_mime_type_for_file_name(char *file_name)
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

fallback:
    return "application/octet-stream";
}

const char *
lwan_http_status_as_string(lwan_http_status_t status)
{
    switch (status) {
    case HTTP_OK: return "OK";
    case HTTP_MOVED_PERMANENTLY: return "Moved permanently";
    case HTTP_NOT_MODIFIED: return "Not modified";
    case HTTP_BAD_REQUEST: return "Bad request";
    case HTTP_NOT_FOUND: return "Not found";
    case HTTP_FORBIDDEN: return "Forbidden";
    case HTTP_NOT_ALLOWED: return "Not allowed";
    case HTTP_TOO_LARGE: return "Request too large";
    case HTTP_RANGE_UNSATISFIABLE: return "Requested range unsatisfiable";
    case HTTP_INTERNAL_ERROR: return "Internal server error";
    }
    return "Invalid";
}

const char *
lwan_http_status_as_descriptive_string(lwan_http_status_t status)
{
    switch (status) {
    case HTTP_OK: return "Success!";
    case HTTP_MOVED_PERMANENTLY: return "This content has moved to another place.";
    case HTTP_NOT_MODIFIED: return "The content has not changed since previous request.";
    case HTTP_BAD_REQUEST: return "The client has issued a bad request.";
    case HTTP_NOT_FOUND: return "The requested resource could not be found on this server.";
    case HTTP_FORBIDDEN: return "Access to this resource has been denied.";
    case HTTP_NOT_ALLOWED: return "The requested method is not allowed by this server.";
    case HTTP_TOO_LARGE: return "The request entity is too large.";
    case HTTP_RANGE_UNSATISFIABLE: return "The server can't supply the requested portion of the requested resource.";
    case HTTP_INTERNAL_ERROR: return "The server encountered an internal error that couldn't be recovered from.";
    }
    return "Invalid";
}
