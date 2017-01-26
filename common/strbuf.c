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

#define _GNU_SOURCE
#include <limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "lwan.h"
#include "strbuf.h"

static const unsigned int STATIC = 1<<0;
static const unsigned int DYNAMICALLY_ALLOCATED = 1<<1;
static const size_t DEFAULT_BUF_SIZE = 64;

static size_t
find_next_power_of_two(size_t number)
{
#if defined(HAVE_BUILTIN_CLZLL)
    static const int size_bits = (int)sizeof(number) * CHAR_BIT;

    if (sizeof(size_t) == sizeof(unsigned int)) {
        return (size_t)1 << (size_bits - __builtin_clz((unsigned int)number));
    } else if (sizeof(size_t) == sizeof(unsigned long)) {
        return (size_t)1 << (size_bits - __builtin_clzl((unsigned long)number));
    } else if (sizeof(size_t) == sizeof(unsigned long long)) {
        return (size_t)1 << (size_bits - __builtin_clzll((unsigned long long)number));
    } else {
        (void)size_bits;
    }
#endif

    number--;
    number |= number >> 1;
    number |= number >> 2;
    number |= number >> 4;
    number |= number >> 8;
    number |= number >> 16;

    return number + 1;
}

static inline size_t align_size(size_t unaligned_size)
{
    const size_t aligned_size = find_next_power_of_two(unaligned_size);

    if (UNLIKELY(unaligned_size >= aligned_size))
        return 0;

    return aligned_size;
}


static ALWAYS_INLINE size_t
max(size_t one, size_t another)
{
    return (one > another) ? one : another;
}

static bool
grow_buffer_if_needed(struct strbuf *s, size_t size)
{
    if (s->flags & STATIC) {
        const size_t aligned_size = align_size(max(size + 1, s->len.buffer));
        if (UNLIKELY(!aligned_size))
            return false;

        char *buffer = malloc(aligned_size);
        if (UNLIKELY(!buffer))
            return false;

        memcpy(buffer, s->value.static_buffer, s->len.buffer);
        buffer[s->len.buffer + 1] = '\0';

        s->flags &= ~STATIC;
        s->len.allocated = aligned_size;
        s->value.buffer = buffer;

        return true;
    }

    if (UNLIKELY(s->len.allocated < size)) {
        const size_t aligned_size = align_size(size + 1);
        if (UNLIKELY(!aligned_size))
            return false;

        char *buffer = realloc(s->value.buffer, aligned_size);
        if (UNLIKELY(!buffer))
            return false;
        s->len.allocated = aligned_size;
        s->value.buffer = buffer;
    }

    return true;
}

bool
strbuf_init_with_size(struct strbuf *s, size_t size)
{
    if (UNLIKELY(!s))
        return false;

    memset(s, 0, sizeof(*s));

    if (UNLIKELY(!grow_buffer_if_needed(s, size)))
        return false;

    s->len.buffer = 0;
    s->value.buffer[0] = '\0';

    return true;
}

ALWAYS_INLINE bool
strbuf_init(struct strbuf *s)
{
    return strbuf_init_with_size(s, DEFAULT_BUF_SIZE);
}

struct strbuf *
strbuf_new_with_size(size_t size)
{
    struct strbuf *s = malloc(sizeof(*s));
    if (UNLIKELY(!strbuf_init_with_size(s, size))) {
        free(s);
        s = NULL;
    } else {
        s->flags |= DYNAMICALLY_ALLOCATED;
    }
    return s;
}

ALWAYS_INLINE struct strbuf *
strbuf_new(void)
{
    return strbuf_new_with_size(DEFAULT_BUF_SIZE);
}

ALWAYS_INLINE struct strbuf *
strbuf_new_static(const char *str, size_t size)
{
    struct strbuf *s = malloc(sizeof(*s));

    if (!s)
        return NULL;

    s->flags = STATIC | DYNAMICALLY_ALLOCATED;
    s->value.static_buffer = str;
    s->len.buffer = s->len.allocated = size;

    return s;
}

void
strbuf_free(struct strbuf *s)
{
    if (UNLIKELY(!s))
        return;
    if (!(s->flags & STATIC))
        free(s->value.buffer);
    if (s->flags & DYNAMICALLY_ALLOCATED)
        free(s);
}

bool
strbuf_append_char(struct strbuf *s, const char c)
{
    if (UNLIKELY(!grow_buffer_if_needed(s, s->len.buffer + 2)))
        return false;

    *(s->value.buffer + s->len.buffer++) = c;
    *(s->value.buffer + s->len.buffer) = '\0';

    return true;
}

bool
strbuf_append_str(struct strbuf *s1, const char *s2, size_t sz)
{
    if (!sz)
        sz = strlen(s2);

    if (UNLIKELY(!grow_buffer_if_needed(s1, s1->len.buffer + sz + 2)))
        return false;

    memcpy(s1->value.buffer + s1->len.buffer, s2, sz);
    s1->len.buffer += sz;
    s1->value.buffer[s1->len.buffer] = '\0';

    return true;
}

bool
strbuf_set_static(struct strbuf *s1, const char *s2, size_t sz)
{
    if (!sz)
        sz = strlen(s2);

    if (!(s1->flags & STATIC))
        free(s1->value.buffer);
    s1->value.static_buffer = s2;
    s1->len.allocated = s1->len.buffer = sz;
    s1->flags |= STATIC;

    return true;
}

bool
strbuf_set(struct strbuf *s1, const char *s2, size_t sz)
{
    if (!sz)
        sz = strlen(s2);

    if (UNLIKELY(!grow_buffer_if_needed(s1, sz + 1)))
        return false;

    memcpy(s1->value.buffer, s2, sz);
    s1->len.buffer = sz;
    s1->value.buffer[sz] = '\0';

    return true;
}

ALWAYS_INLINE int
strbuf_cmp(struct strbuf *s1, struct strbuf *s2)
{
    if (s1 == s2)
        return 0;
    int result = memcmp(s1->value.buffer, s2->value.buffer, s1->len.buffer < s2->len.buffer ? s1->len.buffer : s2->len.buffer);
    if (!result)
        return (int)(s1->len.buffer - s2->len.buffer);
    return result;
}

static ALWAYS_INLINE bool
internal_printf(struct strbuf *s1, bool (*save_str)(struct strbuf *, const char *, size_t), const char *fmt, va_list values)
{
    char *s2;
    int len;

    if (UNLIKELY((len = vasprintf(&s2, fmt, values)) < 0))
        return false;

    bool success = save_str(s1, s2, (size_t)len);
    free(s2);

    return success;
}

bool
strbuf_printf(struct strbuf *s, const char *fmt, ...)
{
    bool could_printf;
    va_list values;

    va_start(values, fmt);
    could_printf = internal_printf(s, strbuf_set, fmt, values);
    va_end(values);

    return could_printf;
}

bool
strbuf_append_printf(struct strbuf *s, const char *fmt, ...)
{
    bool could_printf;
    va_list values;

    va_start(values, fmt);
    could_printf = internal_printf(s, strbuf_append_str, fmt, values);
    va_end(values);

    return could_printf;
}

bool
strbuf_shrink_to(struct strbuf *s, size_t new_size)
{
    if (s->len.allocated <= new_size)
        return true;

    if (s->flags & STATIC)
        return true;

    size_t aligned_size = align_size(new_size + 1);
    if (UNLIKELY(!aligned_size))
        return false;

    char *buffer = realloc(s->value.buffer, aligned_size);
    if (UNLIKELY(!buffer))
        return false;

    s->value.buffer = buffer;
    s->len.allocated = aligned_size;
    if (s->len.buffer > aligned_size) {
        s->len.buffer = aligned_size - 1;
        s->value.buffer[s->len.buffer + 1] = '\0';
    }

    return true;
}

ALWAYS_INLINE bool
strbuf_shrink_to_default(struct strbuf *s)
{
    return strbuf_shrink_to(s, DEFAULT_BUF_SIZE);
}

ALWAYS_INLINE bool
strbuf_reset(struct strbuf *s)
{
    if (LIKELY(strbuf_shrink_to_default(s))) {
        s->len.buffer = 0;
        return true;
    }
    return false;
}

bool
strbuf_grow_to(struct strbuf *s, size_t new_size)
{
    return grow_buffer_if_needed(s, new_size + 1);
}

bool
strbuf_reset_length(struct strbuf *s)
{
    if (s->flags & STATIC) {
        s->flags &= ~STATIC;
        s->value.buffer = malloc(s->len.allocated);
        if (UNLIKELY(!s->value.buffer))
            return false;
    }

    s->len.buffer = 0;
    s->value.buffer[0] = '\0';

    return true;
}
