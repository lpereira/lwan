/*
 * lwan - simple web server
 * Copyright (c) 2017 Leandro A. F. Pereira <leandro@hardinfo.org>
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

#include <stdint.h>

#include "lwan-coro.h"

struct lwan_array {
    void *base;
    size_t elements;
};

int lwan_array_init(struct lwan_array *a);
int lwan_array_reset(struct lwan_array *a);
void *lwan_array_append(struct lwan_array *a, size_t element_size);
void lwan_array_sort(struct lwan_array *a, size_t element_size, int (*cmp)(const void *a, const void *b));
struct lwan_array *coro_lwan_array_new(struct coro *coro);

#define DEFINE_ARRAY_TYPE(array_type_, element_type_) \
    struct array_type_ { \
        struct lwan_array base; \
    }; \
    __attribute__((unused)) \
    static inline int array_type_ ## _init(struct array_type_ *array) \
    { \
        return lwan_array_init((struct lwan_array *)array); \
    } \
    __attribute__((unused)) \
    static inline int array_type_ ## _reset(struct array_type_ *array) \
    { \
        return lwan_array_reset((struct lwan_array *)array); \
    } \
    __attribute__((unused)) \
    static inline element_type_ * array_type_ ## _append(struct array_type_ *array) \
    { \
        return (element_type_ *)lwan_array_append((struct lwan_array *)array, sizeof(element_type_)); \
    } \
    __attribute__((unused)) \
    static inline void array_type_ ## _sort(struct array_type_ *array, int (*cmp)(const void *a, const void *b)) \
    { \
        lwan_array_sort((struct lwan_array *)array, sizeof(element_type_), cmp); \
    } \
    __attribute__((unused)) \
    static inline struct array_type_ *coro_ ## array_type_ ## _new(struct coro *coro) \
    { \
        return (struct array_type_ *)coro_lwan_array_new(coro); \
    }
