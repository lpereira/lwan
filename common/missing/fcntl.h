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

#include_next <fcntl.h>

#ifndef MISSING_FCNTL_H
#define MISSING_FCNTL_H

#ifndef O_NOATIME
# define O_NOATIME 0
#endif

#ifndef O_PATH
# define O_PATH 0
#endif

#if defined(__linux__)

/* Definitions for O_TMPFILE obtained from glibc/Linux kernel. */
# if !defined(__O_TMPFILE)
#  if defined(__alpha__)
#   define __O_TMPFILE 0100000000
#  elif defined(__sparc__) || defined(__sparc64__)
#   define __O_TMPFILE 0200000000
#  elif defined(__parisc__) || defined(__hppa__)
#   define __O_TMPFILE 0400000000
#  else
#   define __O_TMPFILE 020000000
#  endif
# endif

/* a horrid kludge trying to make sure that this will fail on old kernels */
#ifndef O_TMPFILE
# define O_TMPFILE (__O_TMPFILE | O_DIRECTORY)
#endif

#endif /* __linux__ */

#ifndef HAS_READAHEAD
#include <sys/types.h>

ssize_t readahead(int fd, off_t offset, size_t count);
#endif

#endif /* MISSING_FCNTL_H */
