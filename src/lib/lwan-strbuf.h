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
#include <string.h>

struct lwan_strbuf {
    char *buffer;

    /* `capacity` used to be derived from `used` by aligning it to the next
     * power of two, but this resulted in re-allocations after this strbuf
     * been reset between requests.  It now always contains the capacity
     * allocated by `buffer`; resetting essentially only resets `used` and
     * writes `\0` to buffer[0]. */
    size_t capacity, used;

    unsigned int flags;
};

#define LWAN_STRBUF_STATIC_INIT                                                \
    (struct lwan_strbuf) { .buffer = "" }

bool lwan_strbuf_init_with_size(struct lwan_strbuf *buf, size_t size);
bool lwan_strbuf_init(struct lwan_strbuf *buf);
struct lwan_strbuf *lwan_strbuf_new_static(const char *str, size_t size);
struct lwan_strbuf *lwan_strbuf_new_with_size(size_t size);
struct lwan_strbuf *lwan_strbuf_new(void);
void lwan_strbuf_free(struct lwan_strbuf *s);

void lwan_strbuf_reset(struct lwan_strbuf *s);
void lwan_strbuf_reset_trim(struct lwan_strbuf *s, size_t trim_thresh);

bool lwan_strbuf_append_char(struct lwan_strbuf *s, const char c);

bool lwan_strbuf_append_str(struct lwan_strbuf *s1, const char *s2, size_t sz);
static inline bool lwan_strbuf_append_strz(struct lwan_strbuf *s1,
                                           const char *s2)
{
    return lwan_strbuf_append_str(s1, s2, strlen(s2));
}

bool lwan_strbuf_set_static(struct lwan_strbuf *s1, const char *s2, size_t sz);
static inline bool lwan_strbuf_set_staticz(struct lwan_strbuf *s1,
                                           const char *s2)
{
    return lwan_strbuf_set_static(s1, s2, strlen(s2));
}

bool lwan_strbuf_set(struct lwan_strbuf *s1, const char *s2, size_t sz);
static inline bool lwan_strbuf_setz(struct lwan_strbuf *s1, const char *s2)
{
    return lwan_strbuf_set(s1, s2, strlen(s2));
}

bool lwan_strbuf_append_printf(struct lwan_strbuf *s, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

bool lwan_strbuf_printf(struct lwan_strbuf *s1, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

bool lwan_strbuf_grow_to(struct lwan_strbuf *s, size_t new_size);
bool lwan_strbuf_grow_by(struct lwan_strbuf *s, size_t offset);

static inline size_t lwan_strbuf_get_length(const struct lwan_strbuf *s)
{
    return s->used;
}

static inline char *lwan_strbuf_get_buffer(const struct lwan_strbuf *s)
{
    return s->buffer;
}
