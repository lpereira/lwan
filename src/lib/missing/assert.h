/*
 * lwan - simple web server
 * Copyright (c) 2012 L. A. F. Pereira <l@tia.mat.br>
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

#include_next <assert.h>

#ifndef MISSING_ASSERT_H
#define MISSING_ASSERT_H

#undef static_assert
#if defined(HAVE_STATIC_ASSERT)
# define static_assert(expr, msg)	_Static_assert(expr, msg)
#else
# define static_assert(expr, msg)
#endif

/* Use assertions as optimization hints */
#ifndef NDEBUG
#undef assert
#ifdef __clang__
#define assert(expr) __builtin_assume(expr)
#else
#define assert(expr)                                                           \
    do {                                                                       \
        if (!(expr))                                                           \
            __builtin_unreachable();                                           \
    } while (0)
#endif
#endif

#endif /* MISSING_ASSERT_H */
