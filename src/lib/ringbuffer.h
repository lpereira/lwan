/*
 * lwan - simple web server
 * Copyright (c) 2018 L. A. F. Pereira <l@tia.mat.br>
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

/*
 * Inspired by blog post by Juho Snellman
 * https://www.snellman.net/blog/archive/2016-12-13-ring-buffers/
 */

#pragma once

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define DEFINE_RING_BUFFER_TYPE(type_name_, element_type_, size_)              \
    static_assert((size_) && !((size_) & ((size_)-1)),                         \
                  "size is a power of two");                                   \
                                                                               \
    struct type_name_ {                                                        \
        uint32_t read, write;                                                  \
        element_type_ array[size_];                                            \
    };                                                                         \
                                                                               \
    __attribute__((unused)) static inline uint32_t type_name_##_mask(          \
        uint32_t value)                                                        \
    {                                                                          \
        return value & ((size_)-1);                                            \
    }                                                                          \
                                                                               \
    __attribute__((unused)) static inline uint32_t type_name_##_size(          \
        const struct type_name_ *rb)                                           \
    {                                                                          \
        return rb->write - rb->read;                                           \
    }                                                                          \
                                                                               \
    __attribute__((unused)) static inline bool type_name_##_full(              \
        const struct type_name_ *rb)                                           \
    {                                                                          \
        return type_name_##_size(rb) == (size_);                               \
    }                                                                          \
                                                                               \
    __attribute__((unused)) static inline bool type_name_##_empty(             \
        const struct type_name_ *rb)                                           \
    {                                                                          \
        return rb->write == rb->read;                                          \
    }                                                                          \
                                                                               \
    __attribute__((unused)) static inline void type_name_##_init(              \
        struct type_name_ *rb)                                                 \
    {                                                                          \
        rb->write = rb->read = 0;                                              \
    }                                                                          \
                                                                               \
    __attribute__((unused)) static inline void type_name_##_put(               \
        struct type_name_ *rb, const element_type_ *e)                         \
    {                                                                          \
        assert(!type_name_##_full(rb));                                        \
        memcpy(&rb->array[type_name_##_mask(rb->write++)], e, sizeof(*e));     \
    }                                                                          \
                                                                               \
    __attribute__((unused)) static inline bool type_name_##_try_put(           \
        struct type_name_ *rb, const element_type_ *e)                         \
    {                                                                          \
        if (type_name_##_full(rb))                                             \
            return false;                                                      \
                                                                               \
        memcpy(&rb->array[type_name_##_mask(rb->write++)], e, sizeof(*e));     \
        return true;                                                           \
    }                                                                          \
                                                                               \
    __attribute__((unused)) static inline element_type_ type_name_##_get(      \
        struct type_name_ *rb)                                                 \
    {                                                                          \
        assert(!type_name_##_empty(rb));                                       \
        return rb->array[type_name_##_mask(rb->read++)];                       \
    }                                                                          \
                                                                               \
    __attribute__((unused)) static inline element_type_ *type_name_##_get_ptr( \
        struct type_name_ *rb)                                                 \
    {                                                                          \
        assert(!type_name_##_empty(rb));                                       \
        return &rb->array[type_name_##_mask(rb->read++)];                      \
    }                                                                          \
                                                                               \
    __attribute__((unused)) static inline element_type_                        \
        *type_name_##_get_ptr_or_null(struct type_name_ *rb)                   \
    {                                                                          \
        return type_name_##_empty(rb)                                          \
                   ? NULL                                                      \
                   : &rb->array[type_name_##_mask(rb->read++)];                \
    }
