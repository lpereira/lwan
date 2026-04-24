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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#if defined(LWAN_HAVE_LANDLOCK)
#include_next <linux/landlock.h>

#if !defined(MISSING_LINUX_LANDLOCK_H)
#define MISSING_LINUX_LANDLOCK_H

#if !defined(LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF)
#define LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF (1U << 0)
#endif
#if !defined(LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON)
#define LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON (1U << 1)
#endif
#if !defined(LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF)
#define LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF (1U << 2)
#endif
#if !defined(LANDLOCK_RESTRICT_SELF_TSYNC)
#define LANDLOCK_RESTRICT_SELF_TSYNC (1U << 3)
#endif

#endif /* MISSING_LINUX_LANDLOCK_H */

#endif /* LWAN_HAVE_LANDLOCK */
