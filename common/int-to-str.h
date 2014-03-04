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
#ifndef __INT_TO_STR_H__
#define __INT_TO_STR_H__

#include "lwan.h"

#define INT_TO_STR_BUFFER_SIZE (3 * sizeof(size_t) + 1)

char *int_to_string(ssize_t value,
                    char buffer[static INT_TO_STR_BUFFER_SIZE],
                    size_t *len);
char *uint_to_string(size_t value,
                     char buffer[static INT_TO_STR_BUFFER_SIZE],
                     size_t *len);

#endif /* __INT_TO_STR_H__ */

