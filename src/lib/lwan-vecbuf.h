/*
 * lwan - simple web server
 * Copyright (c) 2018 Leandro A. F. Pereira <leandro@hardinfo.org>
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

#include <errno.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/uio.h>

#define DEFINE_VECBUF_TYPE(type_name_, vec_n_, buf_n_)                         \
    struct type_name_ {                                                        \
        struct iovec iovec[vec_n_];                                            \
        char buffer[buf_n_];                                                   \
        char *ptr;                                                             \
        int n;                                                                 \
    };                                                                         \
                                                                               \
    static ALWAYS_INLINE size_t type_name_##_buflen(                           \
        const struct type_name_ *vb)                                           \
    {                                                                          \
        return (size_t)(vb->ptr - vb->buffer) + (buf_n_);                      \
    }                                                                          \
                                                                               \
    static ALWAYS_INLINE void type_name_##_init(struct type_name_ *vb)         \
    {                                                                          \
        vb->ptr = vb->buffer;                                                  \
        vb->n = 0;                                                             \
    }                                                                          \
                                                                               \
    static int type_name_##_append_str_len(struct type_name_ *vb,              \
                                           const char *s, size_t len)          \
    {                                                                          \
        if (UNLIKELY(vb->n >= (vec_n_)))                                       \
            return -ENOSPC;                                                    \
                                                                               \
        vb->iovec[vb->n++] =                                                   \
            (struct iovec){.iov_base = (void *)s, .iov_len = len};             \
                                                                               \
        return 0;                                                              \
    }                                                                          \
                                                                               \
    static ALWAYS_INLINE int type_name_##_append_str(struct type_name_ *vb,    \
                                                     const char *s)            \
    {                                                                          \
        return type_name_##_append_str_len(vb, s, strlen(s));                  \
    }                                                                          \
                                                                               \
    static int type_name_##_append_printf(struct type_name_ *vb,               \
                                          const char *fmt, ...)                \
    {                                                                          \
        size_t bl = type_name_##_buflen(vb);                                   \
        va_list v;                                                             \
        int len;                                                               \
                                                                               \
        va_start(v, fmt);                                                      \
        len = vsnprintf(vb->ptr, bl, fmt, v);                                  \
        va_end(v);                                                             \
                                                                               \
        if (UNLIKELY(len < 0))                                                 \
            return -errno;                                                     \
        if (UNLIKELY(len >= (int)bl))                                          \
            return -ENOSPC;                                                    \
                                                                               \
        int ret = type_name_##_append_str_len(vb, vb->ptr, (size_t)len);       \
        if (LIKELY(!ret))                                                      \
            vb->ptr += len; /* No +1 for \0: iov_len takes care of it */       \
                                                                               \
        return ret;                                                            \
    }
