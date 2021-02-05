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

static const unsigned int BUFFER_MALLOCD = 1 << 0;
static const unsigned int STRBUF_MALLOCD = 1 << 1;

static inline size_t align_size(size_t unaligned_size)
{
    const size_t aligned_size = lwan_nextpow2(unaligned_size);

    if (UNLIKELY(unaligned_size >= aligned_size))
        return 0;

    return aligned_size;
}

static bool grow_buffer_if_needed(struct lwan_strbuf *s, size_t size)
{
    if (!(s->flags & BUFFER_MALLOCD)) {
        const size_t aligned_size = align_size(LWAN_MAX(size + 1, s->used));
        if (UNLIKELY(!aligned_size))
            return false;

        char *buffer = malloc(aligned_size);
        if (UNLIKELY(!buffer))
            return false;

        memcpy(buffer, s->buffer, s->used);
        buffer[s->used + 1] = '\0';

        s->flags |= BUFFER_MALLOCD;
        s->buffer = buffer;
        s->capacity = aligned_size;

        return true;
    }

    if (UNLIKELY(s->capacity < size)) {
        const size_t aligned_size = align_size(size + 1);
        if (UNLIKELY(!aligned_size))
            return false;

        char *buffer = realloc(s->buffer, aligned_size);
        if (UNLIKELY(!buffer))
            return false;

        s->buffer = buffer;
        s->capacity = aligned_size;
    }

    return true;
}

bool lwan_strbuf_init_with_size(struct lwan_strbuf *s, size_t size)
{
    if (UNLIKELY(!s))
        return false;

    *s = LWAN_STRBUF_STATIC_INIT;

    if (size) {
        if (UNLIKELY(!grow_buffer_if_needed(s, size)))
            return false;

        s->buffer[0] = '\0';
    }

    return true;
}

ALWAYS_INLINE bool lwan_strbuf_init(struct lwan_strbuf *s)
{
    return lwan_strbuf_init_with_size(s, 0);
}

struct lwan_strbuf *lwan_strbuf_new_with_size(size_t size)
{
    struct lwan_strbuf *s = malloc(sizeof(*s));

    if (UNLIKELY(!lwan_strbuf_init_with_size(s, size))) {
        free(s);

        return NULL;
    }

    s->flags |= STRBUF_MALLOCD;

    return s;
}

ALWAYS_INLINE struct lwan_strbuf *lwan_strbuf_new(void)
{
    return lwan_strbuf_new_with_size(0);
}

ALWAYS_INLINE struct lwan_strbuf *lwan_strbuf_new_static(const char *str,
                                                         size_t size)
{
    struct lwan_strbuf *s = malloc(sizeof(*s));

    if (UNLIKELY(!s))
        return NULL;

    *s = (struct lwan_strbuf) {
        .flags = STRBUF_MALLOCD,
        .buffer = (char *)str,
        .used = size,
        .capacity = size,
    };

    return s;
}

void lwan_strbuf_free(struct lwan_strbuf *s)
{
    if (UNLIKELY(!s))
        return;
    if (s->flags & BUFFER_MALLOCD)
        free(s->buffer);
    if (s->flags & STRBUF_MALLOCD)
        free(s);
}

bool lwan_strbuf_append_char(struct lwan_strbuf *s, const char c)
{
    if (UNLIKELY(!grow_buffer_if_needed(s, s->used + 2)))
        return false;

    s->buffer[s->used++] = c;
    s->buffer[s->used] = '\0';

    return true;
}

bool lwan_strbuf_append_str(struct lwan_strbuf *s1, const char *s2, size_t sz)
{
    if (UNLIKELY(!grow_buffer_if_needed(s1, s1->used + sz + 2)))
        return false;

    memcpy(s1->buffer + s1->used, s2, sz);
    s1->used += sz;
    s1->buffer[s1->used] = '\0';

    return true;
}

bool lwan_strbuf_set_static(struct lwan_strbuf *s1, const char *s2, size_t sz)
{
    if (s1->flags & BUFFER_MALLOCD)
        free(s1->buffer);

    s1->buffer = (char *)s2;
    s1->used = s1->capacity = sz;
    s1->flags &= ~BUFFER_MALLOCD;

    return true;
}

bool lwan_strbuf_set(struct lwan_strbuf *s1, const char *s2, size_t sz)
{
    if (UNLIKELY(!grow_buffer_if_needed(s1, sz + 1)))
        return false;

    memcpy(s1->buffer, s2, sz);
    s1->used = sz;
    s1->buffer[sz] = '\0';

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
    if (s->flags & BUFFER_MALLOCD) {
        s->buffer[0] = '\0';
    } else {
        s->buffer = "";
        s->capacity = 0;
    }

    s->used = 0;
}

void lwan_strbuf_reset_trim(struct lwan_strbuf *s, size_t trim_thresh)
{
    if (s->flags & BUFFER_MALLOCD && s->capacity > trim_thresh) {
        /* Not using realloc() here because we don't care about the contents
         * of this buffer after reset is called, but we want to maintain a
         * buffer already allocated of up to trim_thresh bytes. */
        void *tmp = malloc(trim_thresh);

        if (tmp) {
            free(s->buffer);
            s->buffer = tmp;
            s->capacity = trim_thresh;
        }
    }

    return lwan_strbuf_reset(s);
}

/* This function is quite dangerous, so the prototype is only in lwan-private.h */
char *lwan_strbuf_extend_unsafe(struct lwan_strbuf *s, size_t by)
{
    if (!lwan_strbuf_grow_by(s, by))
        return NULL;

    size_t prev_used = s->used;
    s->used += by;

    return s->buffer + prev_used;
}
