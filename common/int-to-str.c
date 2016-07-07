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
#include "lwan-private.h"

ALWAYS_INLINE char *
uint_to_string(size_t value,
               char dst[static INT_TO_STR_BUFFER_SIZE],
               size_t *length_out)
{
    /*
     * Based on routine by A. Alexandrescu, licensed under CC0
     * https://creativecommons.org/publicdomain/zero/1.0/legalcode
     */
    static const size_t length = INT_TO_STR_BUFFER_SIZE;
    size_t next = length - 1;
    static const char digits[201] =
	"0001020304050607080910111213141516171819"
	"2021222324252627282930313233343536373839"
	"4041424344454647484950515253545556575859"
	"6061626364656667686970717273747576777879"
	"8081828384858687888990919293949596979899";
    dst[next--] = '\0';
    while (value >= 100) {
	const uint32_t i = (uint32_t)((value % 100) * 2);
	value /= 100;
	dst[next] = digits[i + 1];
	dst[next - 1] = digits[i];
	next -= 2;
    }
    // Handle last 1-2 digits
    if (value < 10) {
	dst[next] = (char)('0' + (uint32_t)value);
	*length_out = length - next - 1;
	return dst + next;
    }
    uint32_t i = (uint32_t)value * 2;
    dst[next] = digits[i + 1];
    dst[next - 1] = digits[i];
    *length_out = length - next;
    return dst + next - 1;
}

ALWAYS_INLINE char *
int_to_string(ssize_t value,
              char dst[static INT_TO_STR_BUFFER_SIZE],
              size_t *length_out)
{
    if (value < 0) {
        char *p = uint_to_string((size_t) -value, dst, length_out);
        *--p = '-';
        ++*length_out;

        return p;
    }

    return uint_to_string((size_t) value, dst, length_out);
}
