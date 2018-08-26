/*
 * lwan - simple web server
 * Copyright (c) 2018 Leandro A. F. Pereira <leandro@hardinfo.org>
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

#include <unistd.h>
#include <sys/syscall.h>

#if defined(__linux__) && defined(SYS_ioprio_set)

#define IOPRIO_WHO_PROCESS 1
#define IOPRIO_CLASS_IDLE 3
#define IOPRIO_PRIO_VALUE(class, data) (((class) << 13) | (data))

static inline int ioprio_set(int which, int who, int ioprio)
{
    return (int)syscall(SYS_ioprio_set, which, who, ioprio);
}

#else

#define IOPRIO_WHO_PROCESS 0
#define IOPRIO_PRIO_VALUE(arg1, arg2) 0
#define IOPRIO_CLASS_IDLE 0

static inline int ioprio_set(int which __attribute__((unused),
                             int who __attribute__((unused)),
                             int ioprio __attribute__((unused)))
{
    return 0;
}

#endif
