/*
 * lwan - simple web server
 * Copyright (c) 2012 Leandro A. F. Pereira <leandro@hardinfo.org>
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
#include "int-to-str.h"

ALWAYS_INLINE char *
uint_to_string(size_t value,
               char buffer[INT_TO_STR_BUFFER_SIZE],
               size_t *len)
{
    char *p = buffer + INT_TO_STR_BUFFER_SIZE;

    assert(len);

    *p = '\0';
    do {
        *--p = (char)('0' + value % 10);
    } while (value /= 10);

    *len = (size_t)(INT_TO_STR_BUFFER_SIZE - (size_t)(p - buffer));

    return p;
}

ALWAYS_INLINE char *
int_to_string(ssize_t value,
              char buffer[INT_TO_STR_BUFFER_SIZE],
              size_t *len)
{
    if (value < 0) {
        char *p = uint_to_string((size_t) -value, buffer, len);
        *--p = '-';
        ++*len;

        return p;
    }

    return uint_to_string((size_t) value, buffer, len);
}
