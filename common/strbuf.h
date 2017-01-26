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

#include <stdbool.h>
#include <stdio.h>

struct strbuf {
    union {
        char *buffer;
        const char *static_buffer;
    } value;
    struct {
        size_t allocated, buffer;
    } len;
    unsigned int flags;
};

bool		 strbuf_init_with_size(struct strbuf *buf, size_t size);
bool		 strbuf_init(struct strbuf *buf);
struct strbuf	*strbuf_new_static(const char *str, size_t size);
struct strbuf	*strbuf_new_with_size(size_t size);
struct strbuf	*strbuf_new(void);
void		 strbuf_free(struct strbuf *s);
bool		 strbuf_append_char(struct strbuf *s, const char c);
bool		 strbuf_append_str(struct strbuf *s1, const char *s2, size_t sz);
bool		 strbuf_set_static(struct strbuf *s1, const char *s2, size_t sz);
bool		 strbuf_set(struct strbuf *s1, const char *s2, size_t sz);
int		 strbuf_cmp(struct strbuf *s1, struct strbuf *s2);
bool		 strbuf_append_printf(struct strbuf *s, const char *fmt, ...);
bool		 strbuf_printf(struct strbuf *s1, const char *fmt, ...);
bool		 strbuf_shrink_to(struct strbuf *s, size_t new_size);
bool		 strbuf_shrink_to_default(struct strbuf *s);
bool		 strbuf_grow_to(struct strbuf *s, size_t new_size);
bool		 strbuf_reset(struct strbuf *s);
bool		 strbuf_reset_length(struct strbuf *s);

#define strbuf_get_length(s)	(((struct strbuf *)(s))->len.buffer)
#define strbuf_get_buffer(s)	(((struct strbuf *)(s))->value.buffer)

