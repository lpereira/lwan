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

#ifndef __LWAN_PRIVATE_H__
#define __LWAN_PRIVATE_H__

#include "lwan.h"

void lwan_response_init(void);
void lwan_response_shutdown(void);

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

static unsigned long lwan_long_has_zero_byte(unsigned long n) __attribute__((pure));
static unsigned long lwan_chr_is_space(char ch) __attribute__((pure));

static ALWAYS_INLINE unsigned long
lwan_long_has_zero_byte(const unsigned long n)
{
    return ((n - 0x01010101UL) & ~n) & 0x80808080UL;
}

static ALWAYS_INLINE unsigned long
lwan_chr_is_space(const char ch)
{
    return lwan_long_has_zero_byte((0x1010101UL * (unsigned long)ch) ^ 0x090a0d20UL);
}

#endif /* __LWAN_PRIVATE_H__ */
