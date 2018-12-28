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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#pragma once

#include <stdbool.h>
#include <stdio.h>

struct lwan_strbuf {
    union {
        char *buffer;
        const char *static_buffer;
    } value;
    size_t used;
    unsigned int flags;
};

bool lwan_strbuf_init_with_size(struct lwan_strbuf *buf, size_t size);
bool lwan_strbuf_init(struct lwan_strbuf *buf);
struct lwan_strbuf *lwan_strbuf_new_static(const char *str, size_t size);
struct lwan_strbuf *lwan_strbuf_new_with_size(size_t size);
struct lwan_strbuf *lwan_strbuf_new(void);
void lwan_strbuf_free(struct lwan_strbuf *s);

void lwan_strbuf_reset(struct lwan_strbuf *s);

bool lwan_strbuf_append_char(struct lwan_strbuf *s, const char c);
bool lwan_strbuf_append_str(struct lwan_strbuf *s1, const char *s2, size_t sz);
bool lwan_strbuf_append_printf(struct lwan_strbuf *s, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

bool lwan_strbuf_set_static(struct lwan_strbuf *s1, const char *s2, size_t sz);
bool lwan_strbuf_set(struct lwan_strbuf *s1, const char *s2, size_t sz);
bool lwan_strbuf_printf(struct lwan_strbuf *s1, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

bool lwan_strbuf_grow_to(struct lwan_strbuf *s, size_t new_size);
bool lwan_strbuf_grow_by(struct lwan_strbuf *s, size_t offset);

#define lwan_strbuf_get_length(s) (((struct lwan_strbuf *)(s))->used)
#define lwan_strbuf_get_buffer(s) (((struct lwan_strbuf *)(s))->value.buffer)
