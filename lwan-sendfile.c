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

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/sendfile.h>
#endif /* __linux__ */

#include "lwan.h"
#include "lwan-sendfile.h"

ssize_t
lwan_sendfile(int out_fd, int in_fd, off_t *offset, size_t count)
{
#ifdef __linux__
    return sendfile(out_fd, in_fd, offset, count);
#endif /* __linux__ */
#ifdef __FreeBSD__
    return sendfile(in_fd, out_fd, offset ? *offset : 0, count, NULL, NULL, 0);
#endif /* __FreeBSD__ */
    size_t total_bytes_written = 0;
    char buffer[512];

    if (offset) {
        if ((*offset = lseek(in_fd, *offset, SEEK_SET)) < 0) {
            perror("lseek");
            return -1;
        }
    }

    while (total_bytes_written < count) {
        ssize_t read_bytes = read(in_fd, buffer, sizeof(buffer));
        if (read_bytes < 0) {
            perror("read");
            return -1;
        }

        ssize_t bytes_written = write(out_fd, buffer, read_bytes);
        if (bytes_written < 0) {
            perror("write");
            return -1;
        }

        total_bytes_written += bytes_written;
    }

    if (offset)
        *offset += total_bytes_written;

    return total_bytes_written;
}
