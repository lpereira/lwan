/*
 * lwan - web server
 * Copyright (c) 2012 L. A. F. Pereira <l@tia.mat.br>
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
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "lwan-private.h"

static const unsigned int BUFFER_MALLOCD = 1 << 0;
static const unsigned int STRBUF_MALLOCD = 1 << 1;
static const unsigned int BUFFER_FIXED = 1 << 2;
static const unsigned int GROW_BUFFER_FAILED = 1 << 3;

bool lwan_strbuf_has_grow_buffer_failed_flag(const struct lwan_strbuf *s)
{
    return s->flags & GROW_BUFFER_FAILED;
}

static inline size_t align_size(size_t unaligned_size)
{
    const size_t aligned_size = lwan_nextpow2(unaligned_size);

    if (UNLIKELY(unaligned_size >= aligned_size))
        return 0;

    return aligned_size;
}

static ALWAYS_INLINE
bool grow_buffer_if_needed_internal(struct lwan_strbuf *s, size_t size)
{
    if (s->flags & BUFFER_FIXED)
        return size < s->capacity;

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
        char *buffer;
        const size_t aligned_size = align_size(size + 1);

        if (UNLIKELY(!aligned_size))
            return false;

        if (s->used == 0) {
            /* Avoid memcpy() inside realloc() if we were not using the
             * allocated buffer at this point.  */
            buffer = malloc(aligned_size);

            if (UNLIKELY(!buffer))
                return false;

            free(s->buffer);
            buffer[0] = '\0';
        } else {
            buffer = realloc(s->buffer, aligned_size);

            if (UNLIKELY(!buffer))
                return false;
        }

        s->buffer = buffer;
        s->capacity = aligned_size;
    }

    return true;
}

static bool grow_buffer_if_needed(struct lwan_strbuf *s, size_t size)
{
    if (UNLIKELY(!grow_buffer_if_needed_internal(s, size))) {
        s->flags |= GROW_BUFFER_FAILED;
        return false;
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

bool lwan_strbuf_init_with_fixed_buffer(struct lwan_strbuf *s,
                                        void *buffer,
                                        size_t size)
{
    if (UNLIKELY(!s))
        return false;

    *s = (struct lwan_strbuf) {
        .capacity = size,
        .used = 0,
        .buffer = buffer,
        .flags = BUFFER_FIXED,
    };

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

struct lwan_strbuf *lwan_strbuf_new_with_fixed_buffer(size_t size)
{
    struct lwan_strbuf *s = malloc(sizeof(*s) + size + 1);

    if (UNLIKELY(!lwan_strbuf_init_with_fixed_buffer(s, s + 1, size))) {
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
    if (s->flags & BUFFER_MALLOCD) {
        assert(!(s->flags & BUFFER_FIXED));
        free(s->buffer);
    }
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
    s1->flags &= ~(BUFFER_MALLOCD | BUFFER_FIXED);

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

bool lwan_strbuf_vprintf(struct lwan_strbuf *s, const char *fmt, va_list ap)
{
    return internal_printf(s, lwan_strbuf_set, fmt, ap);
}

bool lwan_strbuf_printf(struct lwan_strbuf *s, const char *fmt, ...)
{
    bool could_printf;
    va_list values;

    va_start(values, fmt);
    could_printf = lwan_strbuf_vprintf(s, fmt, values);
    va_end(values);

    return could_printf;
}

bool lwan_strbuf_append_vprintf(struct lwan_strbuf *s, const char *fmt, va_list ap)
{
    return internal_printf(s, lwan_strbuf_append_str, fmt, ap);
}

bool lwan_strbuf_append_printf(struct lwan_strbuf *s, const char *fmt, ...)
{
    bool could_printf;
    va_list values;

    va_start(values, fmt);
    could_printf = lwan_strbuf_append_vprintf(s, fmt, values);
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
        free(s->buffer);
        s->flags &= ~BUFFER_MALLOCD;
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

bool lwan_strbuf_init_from_file(struct lwan_strbuf *s, const char *path)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    struct stat st;

    if (UNLIKELY(fd < 0))
        return false;

    if (UNLIKELY(fstat(fd, &st) < 0))
        goto error_close;

    size_t min_buf_size;
    if (UNLIKELY(__builtin_add_overflow(st.st_size, 1, &min_buf_size)))
        goto error_close;
    if (UNLIKELY(!lwan_strbuf_init_with_size(s, min_buf_size)))
        goto error_close;

    s->used = (size_t)st.st_size;

    for (char *buffer = s->buffer; st.st_size; ) {
        ssize_t n_read = read(fd, buffer, (size_t)st.st_size);

        if (UNLIKELY(n_read < 0)) {
            if (errno == EINTR)
                continue;
            goto error;
        }

        buffer += n_read;
        *buffer = '\0';
        st.st_size -= (off_t)n_read;
    }

    close(fd);
    return true;

error:
    lwan_strbuf_free(s);
error_close:
    close(fd);
    return false;
}

struct lwan_strbuf *lwan_strbuf_new_from_file(const char *path)
{
    struct lwan_strbuf *strbuf = malloc(sizeof(*strbuf));

    if (!strbuf)
        return NULL;

    if (lwan_strbuf_init_from_file(strbuf, path)) {
        strbuf->flags |= STRBUF_MALLOCD;
        return strbuf;
    }

    free(strbuf);
    return NULL;
}
