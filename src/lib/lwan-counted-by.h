/*
 * lwan - web server
 * Copyright (c) 2026 L. A. F. Pereira <l@tia.mat.br>
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

#if 0
/* As of GCC 16.1.1, bad code seems to be generated if
 * attribute(counted_by) is used. Disabling this attribute for now.
 * Reproducer: https://gcc.godbolt.org/z/M3heT1Gd7
 */

#if defined __has_attribute
#  if __has_attribute (__counted_by__)
#    define LWAN_COUNTED_BY(member_) __attribute__((__counted_by__(member_)))
#  else
#    define LWAN_COUNTED_BY(member_)
#  endif
#endif

#else

#  define LWAN_COUNTED_BY(member_)

#endif
