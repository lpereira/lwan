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

#define _GNU_SOURCE
#include <limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "lwan-private.h"

static const unsigned int STATIC = 1 << 0;
static const unsigned int DYNAMICALLY_ALLOCATED = 1 << 1;
static const size_t DEFAULT_BUF_SIZE = 64;

static inline size_t align_size(size_t unaligned_size)
{
    const size_t aligned_size = lwan_nextpow2(unaligned_size);

    if (UNLIKELY(unaligned_size >= aligned_size))
        return 0;

    return aligned_size;
}

static ALWAYS_INLINE size_t max(size_t one, size_t another)
{
    return (one > another) ? one : another;
}

static bool grow_buffer_if_needed(struct lwan_strbuf *s, size_t size)
{
    if (s->flags & STATIC) {
        const size_t aligned_size = align_size(max(size + 1, s->used));
        if (UNLIKELY(!aligned_size))
            return false;

        char *buffer = malloc(aligned_size);
        if (UNLIKELY(!buffer))
            return false;

        memcpy(buffer, s->value.static_buffer, s->used);
        buffer[s->used + 1] = '\0';

        s->flags &= ~STATIC;
        s->value.buffer = buffer;

        return true;
    }

    if (UNLIKELY(!s->used || lwan_nextpow2(s->used) < size)) {
        const size_t aligned_size = align_size(size + 1);
        if (UNLIKELY(!aligned_size))
            return false;

        char *buffer = realloc(s->value.buffer, aligned_size);
        if (UNLIKELY(!buffer))
            return false;
        s->value.buffer = buffer;
    }

    return true;
}

bool lwan_strbuf_init_with_size(struct lwan_strbuf *s, size_t size)
{
    if (UNLIKELY(!s))
        return false;

    memset(s, 0, sizeof(*s));

    if (UNLIKELY(!grow_buffer_if_needed(s, size)))
        return false;

    s->used = 0;
    s->value.buffer[0] = '\0';

    return true;
}

ALWAYS_INLINE bool lwan_strbuf_init(struct lwan_strbuf *s)
{
    return lwan_strbuf_init_with_size(s, DEFAULT_BUF_SIZE);
}

struct lwan_strbuf *lwan_strbuf_new_with_size(size_t size)
{
    struct lwan_strbuf *s = malloc(sizeof(*s));

    if (UNLIKELY(!s))
        return NULL;

    if (UNLIKELY(!lwan_strbuf_init_with_size(s, size))) {
        free(s);
        s = NULL;
    } else {
        s->flags |= DYNAMICALLY_ALLOCATED;
    }
    return s;
}

ALWAYS_INLINE struct lwan_strbuf *lwan_strbuf_new(void)
{
    return lwan_strbuf_new_with_size(DEFAULT_BUF_SIZE);
}

ALWAYS_INLINE struct lwan_strbuf *lwan_strbuf_new_static(const char *str,
                                                         size_t size)
{
    struct lwan_strbuf *s = malloc(sizeof(*s));

    if (!s)
        return NULL;

    s->flags = STATIC | DYNAMICALLY_ALLOCATED;
    s->value.static_buffer = str;
    s->used = size;

    return s;
}

void lwan_strbuf_free(struct lwan_strbuf *s)
{
    if (UNLIKELY(!s))
        return;
    if (!(s->flags & STATIC))
        free(s->value.buffer);
    if (s->flags & DYNAMICALLY_ALLOCATED)
        free(s);
}

bool lwan_strbuf_append_char(struct lwan_strbuf *s, const char c)
{
    if (UNLIKELY(!grow_buffer_if_needed(s, s->used + 2)))
        return false;

    s->value.buffer[s->used++] = c;
    s->value.buffer[s->used] = '\0';

    return true;
}

bool lwan_strbuf_append_str(struct lwan_strbuf *s1, const char *s2, size_t sz)
{
    if (!sz)
        sz = strlen(s2);

    if (UNLIKELY(!grow_buffer_if_needed(s1, s1->used + sz + 2)))
        return false;

    memcpy(s1->value.buffer + s1->used, s2, sz);
    s1->used += sz;
    s1->value.buffer[s1->used] = '\0';

    return true;
}

bool lwan_strbuf_set_static(struct lwan_strbuf *s1, const char *s2, size_t sz)
{
    if (!sz)
        sz = strlen(s2);

    if (!(s1->flags & STATIC))
        free(s1->value.buffer);

    s1->value.static_buffer = s2;
    s1->used = sz;
    s1->flags |= STATIC;

    return true;
}

bool lwan_strbuf_set(struct lwan_strbuf *s1, const char *s2, size_t sz)
{
    if (!sz)
        sz = strlen(s2);

    if (UNLIKELY(!grow_buffer_if_needed(s1, sz + 1)))
        return false;

    memcpy(s1->value.buffer, s2, sz);
    s1->used = sz;
    s1->value.buffer[sz] = '\0';

    return true;
}

static ALWAYS_INLINE bool
internal_printf(struct lwan_strbuf *s1,
                bool (*save_str)(struct lwan_strbuf *, const char *, size_t),
                const char *fmt,
                va_list values)
{
    char *s2;
    int len;

    if (UNLIKELY((len = vasprintf(&s2, fmt, values)) < 0))
        return false;

    bool success = save_str(s1, s2, (size_t)len);
    free(s2);

    return success;
}

bool lwan_strbuf_printf(struct lwan_strbuf *s, const char *fmt, ...)
{
    bool could_printf;
    va_list values;

    va_start(values, fmt);
    could_printf = internal_printf(s, lwan_strbuf_set, fmt, values);
    va_end(values);

    return could_printf;
}

bool lwan_strbuf_append_printf(struct lwan_strbuf *s, const char *fmt, ...)
{
    bool could_printf;
    va_list values;

    va_start(values, fmt);
    could_printf = internal_printf(s, lwan_strbuf_append_str, fmt, values);
    va_end(values);

    return could_printf;
}

bool lwan_strbuf_grow_to(struct lwan_strbuf *s, size_t new_size)
{
    return grow_buffer_if_needed(s, new_size + 1);
}

bool lwan_strbuf_grow_by(struct lwan_strbuf *s, size_t offset)
{
    size_t new_size;

    if (__builtin_add_overflow(offset, s->used, &new_size))
        return false;

    return lwan_strbuf_grow_to(s, new_size);
}

void lwan_strbuf_reset(struct lwan_strbuf *s)
{
    if (s->flags & STATIC) {
        s->value.buffer = "";
    } else {
        s->value.buffer[0] = '\0';
    }

    s->used = 0;
}
