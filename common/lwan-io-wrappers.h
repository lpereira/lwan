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

#pragma once

#include <unistd.h>
#include <sys/uio.h>

#include "lwan.h"

int lwan_openat(lwan_request_t *request, int dirfd, const char *pathname,
                int flags);
ssize_t lwan_writev(lwan_request_t *request, struct iovec *iov,
                    int iovcnt);
ssize_t lwan_write(lwan_request_t *request, const void *buffer,
                   size_t count);
ssize_t lwan_send(lwan_request_t *request, const void *buf, size_t count,
                  int flags);
void lwan_sendfile(lwan_request_t *request, int in_fd,
                    off_t offset, size_t count,
                    const char *header, size_t header_len);

