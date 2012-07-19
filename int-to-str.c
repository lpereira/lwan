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

#include "int-to-str.h"

ALWAYS_INLINE char *
int_to_string(int32_t value, char *buf16, int32_t *len)
{
    bool negative;

    if (value < 0) {
        negative = true;
        value = -value;
    } else
        negative = false;

    char *p = buf16 + 15;
    *p = '\0';
    do {
        *--p = '0' + (value % 10);
    } while (value /= 10);

    if (negative)
        *--p = '-';

    if (len)
        *len = 15 - (p - buf16);

    return p;
}
