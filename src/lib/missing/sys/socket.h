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

#include_next <sys/socket.h>

#ifndef MISSING_SYS_SOCKET_H
#define MISSING_SYS_SOCKET_H

#ifndef MSG_MORE
# define MSG_MORE 0
#endif

#ifndef SOCK_CLOEXEC
# define SOCK_CLOEXEC 0
#endif

#ifndef SOCK_NONBLOCK
# define SOCK_NONBLOCK 00004000
#endif

#ifndef HAS_ACCEPT4
int accept4(int sock, struct sockaddr *addr, socklen_t *addrlen, int flags);
#endif

#endif /* MISSING_SYS_SOCKET_H */
