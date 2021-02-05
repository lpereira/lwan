/*
 * lwan - simple web server
 * Copyright (c) 2020 Leandro A. F. Pereira <leandro@hardinfo.org>
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

#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__APPLE__)
#include <sys/mount.h>
#include <sys/param.h>
#elif defined(__linux__)
#include_next <sys/vfs.h>
#include <linux/magic.h>
#endif

#ifndef _MISSING_VFS_H_
#define _MISSING_VFS_H_

#if !defined(HAVE_STATFS)
struct statfs {
    int f_type;
};

int statfs(const char *path, struct statfs *buf);
#endif

#ifndef TMPFS_MAGIC
#define TMPFS_MAGIC 0xbebacafe
#endif

#endif /* _MISSING_VFS_H_ */
