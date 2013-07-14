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

#ifndef __STRBUF_H__
#define __STRBUF_H__

#include <stdbool.h>
#include <stdio.h>

typedef struct strbuf_t_		strbuf_t;

struct strbuf_t_ {
    struct {
        size_t allocated, buffer;
    } len;
    union {
        char *buffer;
        const char *static_buffer;
    } value;
    unsigned char is_static : 1;
};

strbuf_t	*strbuf_new_with_size(size_t size);
strbuf_t	*strbuf_new(void);
void		 strbuf_free(strbuf_t *s);
bool		 strbuf_append_char(strbuf_t *s, char c);
bool		 strbuf_append_str(strbuf_t *s1, char *s2, size_t sz);
bool		 strbuf_set_static(strbuf_t *s1, const char *s2, size_t sz);
bool		 strbuf_set(strbuf_t *s1, char *s2, size_t sz);
int		 strbuf_cmp(strbuf_t *s1, strbuf_t *s2);
bool		 strbuf_append_printf(strbuf_t *s, const char *fmt, ...);
bool		 strbuf_printf(strbuf_t *s1, const char *fmt, ...);
int		 strbuf_get_length(strbuf_t *s);
char		*strbuf_get_buffer(strbuf_t *s);
bool		 strbuf_shrink_to(strbuf_t *s, size_t new_size);
bool		 strbuf_shrink_to_default(strbuf_t *s);
bool		 strbuf_grow_to(strbuf_t *s, size_t new_size);
bool		 strbuf_reset(strbuf_t *s);
bool		 strbuf_reset_length(strbuf_t *s);

#endif /* __STRBUF_H__ */
