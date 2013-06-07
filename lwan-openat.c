/*
 * lwan - simple web server
 * Copyright (c) 2013 Leandro A. F. Pereira <leandro@hardinfo.org>
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

#include <fcntl.h>
#include <errno.h>

#include "lwan.h"

#define OPEN_FILE_TRIES 5

int
lwan_openat(lwan_request_t *request,
            int dirfd, const char *pathname, int flags)
{
    int fd;
    int tries;

    for (tries = OPEN_FILE_TRIES; tries; tries--) {
        fd = openat(dirfd, pathname, flags);

        if (LIKELY(fd >= 0))
            return fd;

        switch (errno) {
        case EMFILE:
        case ENFILE:
        case ENOMEM:
            coro_yield(request->coro, 1);
            break;
        default:
            return -errno;
        }
    }

    return -ENFILE;
}
