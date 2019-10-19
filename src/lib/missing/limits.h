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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#include_next <limits.h>

#ifndef MISSING_LIMITS_H
#define MISSING_LIMITS_H

#ifndef PATH_MAX
# define PATH_MAX 4096
#endif

#ifndef OPEN_MAX
# include <sys/param.h>
# ifdef NOFILE
#  define OPEN_MAX NOFILE
# else
#  define OPEN_MAX 65535
# endif
#endif

#ifndef OFF_MAX
# include <sys/types.h>
# define OFF_MAX ~((off_t)1 << (sizeof(off_t) * CHAR_BIT - 1))
#endif

#ifndef PAGE_SIZE
# include <sys/param.h>
# ifndef PAGE_SIZE
#  ifdef EXEC_PAGESIZE
#   define PAGE_SIZE EXEC_PAGESIZE
#  else
#   define PAGE_SIZE 4096
#  endif
# endif
#endif

#endif /* MISSING_LIMITS_H */
