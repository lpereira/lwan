/*
 * lwan - web server
 * Copyright (c) 2018 L. A. F. Pereira <l@tia.mat.br>
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

#ifndef __MISSING_CAPABILITY_H__
#define __MISSING_CAPABILITY_H__

#if defined(__linux__) && defined(LWAN_HAVE_LINUX_CAPABILITY)

#include_next <linux/capability.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

static inline int capset(struct __user_cap_header_struct *header,
                         struct __user_cap_data_struct *data)
{
#if defined(SYS_capset)
    return (int)syscall(SYS_capset, header, data);
#else
    return 0;
#endif
}

#else
struct __user_cap_data_struct {
    unsigned int effective, permitted, inheritable;
};

struct __user_cap_header_struct {
#define _LINUX_CAPABILITY_VERSION_1 0
    unsigned int version;
    int pid;
};

int capset(struct __user_cap_header_struct *header,
           struct __user_cap_data_struct *data);

#endif

#endif /* __MISSING_CAPABILITY_H__ */
