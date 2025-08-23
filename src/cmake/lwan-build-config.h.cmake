/*
 * lwan - web server
 * Copyright (c) 2016 L. A. F. Pereira <l@tia.mat.br>
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

#cmakedefine LWAN_VERSION "@LWAN_VERSION@"

/* API available in Glibc/Linux, but possibly not elsewhere */
#cmakedefine LWAN_HAVE_ACCEPT4
#cmakedefine LWAN_HAVE_ALLOCA_H
#cmakedefine LWAN_HAVE_CLOCK_GETTIME
#cmakedefine LWAN_HAVE_GET_CURRENT_DIR_NAME
#cmakedefine LWAN_HAVE_GETAUXVAL
#cmakedefine LWAN_HAVE_MEMPCPY
#cmakedefine LWAN_HAVE_MEMRCHR
#cmakedefine LWAN_HAVE_MKOSTEMP
#cmakedefine LWAN_HAVE_PIPE2
#cmakedefine LWAN_HAVE_PTHREADBARRIER
#cmakedefine LWAN_HAVE_READAHEAD
#cmakedefine LWAN_HAVE_REALLOCARRAY
#cmakedefine LWAN_HAVE_EPOLL
#cmakedefine LWAN_HAVE_KQUEUE
#cmakedefine LWAN_HAVE_KQUEUE1
#cmakedefine LWAN_HAVE_DLADDR
#cmakedefine LWAN_HAVE_POSIX_FADVISE
#cmakedefine LWAN_HAVE_LINUX_CAPABILITY
#cmakedefine LWAN_HAVE_PTHREAD_SET_NAME_NP
#cmakedefine LWAN_HAVE_GETENTROPY
#cmakedefine LWAN_HAVE_FWRITE_UNLOCKED
#cmakedefine LWAN_HAVE_GETTID
#cmakedefine LWAN_HAVE_SECURE_GETENV
#cmakedefine LWAN_HAVE_STATFS
#cmakedefine LWAN_HAVE_SO_ATTACH_REUSEPORT_CBPF
#cmakedefine LWAN_HAVE_SO_INCOMING_CPU
#cmakedefine LWAN_HAVE_SYSLOG
#cmakedefine LWAN_HAVE_STPCPY
#cmakedefine LWAN_HAVE_EVENTFD
#cmakedefine LWAN_HAVE_MINCORE
#cmakedefine LWAN_HAVE_STATFS_F_TYPE

/* Compiler builtins for specific CPU instruction support */
#cmakedefine LWAN_HAVE_BUILTIN_CPU_INIT
#cmakedefine LWAN_HAVE_BUILTIN_IA32_CRC32
#cmakedefine LWAN_HAVE_BUILTIN_MUL_OVERFLOW
#cmakedefine LWAN_HAVE_BUILTIN_ADD_OVERFLOW
#cmakedefine LWAN_HAVE_BUILTIN_FPCLASSIFY
#cmakedefine LWAN_HAVE_BUILTIN_EXPECT_PROBABILITY

/* GCC extensions */
#cmakedefine LWAN_HAVE_ACCESS_ATTRIBUTE

/* C11 _Static_assert() */
#cmakedefine LWAN_HAVE_STATIC_ASSERT

/* Libraries */
#cmakedefine LWAN_HAVE_LUA
#cmakedefine LWAN_HAVE_LUA_JIT
#cmakedefine LWAN_HAVE_BROTLI
#cmakedefine LWAN_HAVE_ZSTD
#cmakedefine LWAN_HAVE_LIBUCONTEXT
#cmakedefine LWAN_HAVE_MBEDTLS

/* Valgrind support for coroutines */
#cmakedefine LWAN_HAVE_VALGRIND

/* Sanitizer */
#cmakedefine LWAN_HAVE_UNDEFINED_SANITIZER
#cmakedefine LWAN_HAVE_ADDRESS_SANITIZER
#cmakedefine LWAN_HAVE_THREAD_SANITIZER
