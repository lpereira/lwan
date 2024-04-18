/*
 * lwan - web server
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
#if defined(LWAN_HAVE_STATIC_ASSERT)
# define static_assert(expr, msg)	_Static_assert(expr, msg)
#else
# define static_assert(expr, msg)
#endif

/* Macro to enable self-test on startup in debug builds.
 * Details: https://tia.mat.br/posts/2023/12/11/self-test.html */
#if defined(NDEBUG)
#define LWAN_SELF_TEST(name)                                                   \
    __attribute__((unused)) static void self_test_##name(void)
#else
#define LWAN_SELF_TEST(name)                                                   \
    __attribute__((constructor)) static void self_test_##name(void)
#endif

#endif /* MISSING_ASSERT_H */
