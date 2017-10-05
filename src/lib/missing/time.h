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

#include_next <time.h>

#ifndef MISSING_TIME_H
#define MISSING_TIME_H

#ifndef HAS_CLOCK_GETTIME
typedef int clockid_t;
int clock_gettime(clockid_t clk_id, struct timespec *ts);

# ifndef CLOCK_MONOTONIC_COARSE
#  define CLOCK_MONOTONIC_COARSE 0
# endif

# ifndef CLOCK_MONOTONIC
#  define CLOCK_MONOTONIC 1
# endif
#endif

#endif /* MISSING_TIME_H */
