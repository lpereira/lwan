/*
 * lwan - simple web server
 * Copyright (c) 2016 Leandro A. F. Pereira <leandro@hardinfo.org>
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

#pragma once

/* API available in Glibc/Linux, but possibly not elsewhere */
#cmakedefine HAVE_ACCEPT4
#cmakedefine HAVE_ALLOCA_H
#cmakedefine HAVE_CLOCK_GETTIME
#cmakedefine HAVE_GET_CURRENT_DIR_NAME
#cmakedefine HAVE_GETAUXVAL
#cmakedefine HAVE_MEMPCPY
#cmakedefine HAVE_MEMRCHR
#cmakedefine HAVE_MKOSTEMP
#cmakedefine HAVE_PIPE2
#cmakedefine HAVE_PTHREADBARRIER
#cmakedefine HAVE_RAWMEMCHR
#cmakedefine HAVE_READAHEAD
#cmakedefine HAVE_REALLOCARRAY

/* Compiler builtins for specific CPU instruction support */
#cmakedefine HAVE_BUILTIN_CLZLL
#cmakedefine HAVE_BUILTIN_CPU_INIT
#cmakedefine HAVE_BUILTIN_IA32_CRC32
#cmakedefine HAVE_BUILTIN_MUL_OVERFLOW
#cmakedefine HAVE_BUILTIN_ADD_OVERFLOW
#cmakedefine HAVE_BUILTIN_FPCLASSIFY

/* C11 _Static_assert() */
#cmakedefine HAVE_STATIC_ASSERT

/* Libraries */
#cmakedefine HAVE_LUA

/* Valgrind support for coroutines */
#cmakedefine HAVE_VALGRIND

