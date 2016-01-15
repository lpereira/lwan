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

#pragma once

#include "lwan.h"

void lwan_response_init(lwan_t *l);
void lwan_response_shutdown(lwan_t *l);

void lwan_socket_init(lwan_t *l);
void lwan_socket_shutdown(lwan_t *l);

void lwan_thread_init(lwan_t *l);
void lwan_thread_shutdown(lwan_t *l);
void lwan_thread_add_client(lwan_thread_t *t, int fd);

void lwan_status_init(lwan_t *l);
void lwan_status_shutdown(lwan_t *l);

void lwan_job_thread_init(void);
void lwan_job_thread_shutdown(void);
void lwan_job_add(bool (*cb)(void *data), void *data);
void lwan_job_del(bool (*cb)(void *data), void *data);

void lwan_tables_init(void);
void lwan_tables_shutdown(void);

char *lwan_process_request(lwan_t *l, lwan_request_t *request,
                           lwan_value_t *buffer, char *next_request);

void lwan_straitjacket_enforce(config_t *c, config_line_t *l);

#undef static_assert
#if HAVE_STATIC_ASSERT
#define static_assert(expr, msg)	_Static_assert(expr, msg)
#else
#define static_assert(expr, msg)
#endif

#define strndupa_impl(s, l) ({ \
   char *strndupa_tmp_s = alloca(l + 1); \
   strndupa_tmp_s[l] = '\0'; \
   memcpy(strndupa_tmp_s, s, l); \
})

#ifndef strndupa
#define strndupa(s, l) strndupa_impl((s), strnlen((s), (l)))
#endif

#ifndef strdupa
#define strdupa(s) strndupa((s), strlen(s))
#endif

#ifndef HAS_RAWMEMCHR
#define rawmemchr(s, c) memchr((s), (c), SIZE_MAX)
#endif

#ifndef HAS_MEMPCPY
static inline void *
mempcpy(void *dest, const void *src, size_t len)
{
   char *p = memcpy(dest, src, len);
   return p + len;
}
#endif

#ifndef MSG_MORE
#define MSG_MORE 0
#endif

#ifndef O_NOATIME
#define O_NOATIME 0
#endif

#ifndef O_PATH
#define O_PATH 0
#endif

#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 0
#endif
