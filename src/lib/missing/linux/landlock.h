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

#if !defined(LANDLOCK_ACCESS_FS_EXECUTE)
#define LANDLOCK_ACCESS_FS_EXECUTE (1ULL << 0)
#endif
#if !defined(LANDLOCK_ACCESS_FS_WRITE_FILE)
#define LANDLOCK_ACCESS_FS_WRITE_FILE (1ULL << 1)
#endif
#if !defined(LANDLOCK_ACCESS_FS_READ_FILE)
#define LANDLOCK_ACCESS_FS_READ_FILE (1ULL << 2)
#endif
#if !defined(LANDLOCK_ACCESS_FS_READ_DIR)
#define LANDLOCK_ACCESS_FS_READ_DIR (1ULL << 3)
#endif
#if !defined(LANDLOCK_ACCESS_FS_REMOVE_DIR)
#define LANDLOCK_ACCESS_FS_REMOVE_DIR (1ULL << 4)
#endif
#if !defined(LANDLOCK_ACCESS_FS_REMOVE_FILE)
#define LANDLOCK_ACCESS_FS_REMOVE_FILE (1ULL << 5)
#endif
#if !defined(LANDLOCK_ACCESS_FS_MAKE_CHAR)
#define LANDLOCK_ACCESS_FS_MAKE_CHAR (1ULL << 6)
#endif
#if !defined(LANDLOCK_ACCESS_FS_MAKE_DIR)
#define LANDLOCK_ACCESS_FS_MAKE_DIR (1ULL << 7)
#endif
#if !defined(LANDLOCK_ACCESS_FS_MAKE_REG)
#define LANDLOCK_ACCESS_FS_MAKE_REG (1ULL << 8)
#endif
#if !defined(LANDLOCK_ACCESS_FS_MAKE_SOCK)
#define LANDLOCK_ACCESS_FS_MAKE_SOCK (1ULL << 9)
#endif
#if !defined(LANDLOCK_ACCESS_FS_MAKE_FIFO)
#define LANDLOCK_ACCESS_FS_MAKE_FIFO (1ULL << 10)
#endif
#if !defined(LANDLOCK_ACCESS_FS_MAKE_BLOCK)
#define LANDLOCK_ACCESS_FS_MAKE_BLOCK (1ULL << 11)
#endif
#if !defined(LANDLOCK_ACCESS_FS_MAKE_SYM)
#define LANDLOCK_ACCESS_FS_MAKE_SYM (1ULL << 12)
#endif
#if !defined(LANDLOCK_ACCESS_FS_REFER)
#define LANDLOCK_ACCESS_FS_REFER (1ULL << 13)
#endif
#if !defined(LANDLOCK_ACCESS_FS_TRUNCATE)
#define LANDLOCK_ACCESS_FS_TRUNCATE (1ULL << 14)
#endif
#if !defined(LANDLOCK_ACCESS_FS_IOCTL_DEV)
#define LANDLOCK_ACCESS_FS_IOCTL_DEV (1ULL << 15)
#endif

#if !defined(LANDLOCK_ACCESS_NET_BIND_TCP)
#define LANDLOCK_ACCESS_NET_BIND_TCP (1ULL << 0)
#endif
#if !defined(LANDLOCK_ACCESS_NET_CONNECT_TCP)
#define LANDLOCK_ACCESS_NET_CONNECT_TCP (1ULL << 1)
#endif

#if !defined(LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET)
#define LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET (1ULL << 0)
#endif
#if !defined(LANDLOCK_SCOPE_SIGNAL)
#define LANDLOCK_SCOPE_SIGNAL (1ULL << 1)
#endif

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
