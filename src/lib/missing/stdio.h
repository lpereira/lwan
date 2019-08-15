/*
 * lwan - simple web server
 * Copyright (c) 2019 Leandro A. F. Pereira <leandro@hardinfo.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#include_next <stdio.h>

#ifndef MISSING_STDIO_H
#define MISSING_STDIO_H

#if !defined(HAVE_FWRITE_UNLOCKED)
size_t fwrite_unlocked(const void *ptr, size_t size, size_t n, FILE *stream);
#endif

#endif /* MISSING_STDIO_H */
