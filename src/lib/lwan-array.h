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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#pragma once

#include <assert.h>
#include <stdint.h>

#include "lwan-coro.h"

#define LWAN_ARRAY_INCREMENT 16

struct lwan_array {
    void *base;
    size_t elements;
};

int lwan_array_reset(struct lwan_array *a, void *inline_storage);
void *lwan_array_append_heap(struct lwan_array *a, size_t element_size);
void *lwan_array_append_inline(struct lwan_array *a,
                               size_t element_size,
                               void *inline_storage);
void lwan_array_sort(struct lwan_array *a,
                     size_t element_size,
                     int (*cmp)(const void *a, const void *b));
struct lwan_array *coro_lwan_array_new(struct coro *coro, bool inline_first);

#define LWAN_ARRAY_FOREACH(array_, iter_)                                      \
    for (iter_ = (array_)->base.base;                                          \
         iter_ <                                                               \
         ((typeof(iter_))(array_)->base.base + (array_)->base.elements);       \
         iter_++)

#define LWAN_ARRAY_FOREACH_REVERSE(array_, iter_)                              \
    if ((array_)->base.elements)                                               \
        for (iter_ = ((typeof(iter_))(array_)->base.base +                     \
                      (array_)->base.elements - 1);                            \
             iter_ >= (typeof(iter_))(array_)->base.base; iter_--)

#define LWAN_ARRAY_STATIC_INIT                                                 \
    {                                                                          \
    }

#define DEFINE_ARRAY_TYPE(array_type_, element_type_)                          \
    struct array_type_ {                                                       \
        struct lwan_array base;                                                \
    };                                                                         \
    __attribute__((unused)) static inline element_type_ *array_type_##_append( \
        struct array_type_ *array)                                             \
    {                                                                          \
        return (element_type_ *)lwan_array_append_heap(&array->base,           \
                                                       sizeof(element_type_)); \
    }                                                                          \
    __attribute__((unused)) static inline struct array_type_                   \
        *coro_##array_type_##_new(struct coro *coro)                           \
    {                                                                          \
        return (struct array_type_ *)coro_lwan_array_new(coro, false);         \
    }                                                                          \
    DEFINE_ARRAY_TYPE_FUNCS(array_type_, element_type_, NULL)

#define DEFINE_ARRAY_TYPE_INLINEFIRST(array_type_, element_type_)              \
    struct array_type_ {                                                       \
        struct lwan_array base;                                                \
        element_type_ storage[LWAN_ARRAY_INCREMENT];                           \
    };                                                                         \
    __attribute__((unused)) static inline element_type_ *array_type_##_append( \
        struct array_type_ *array)                                             \
    {                                                                          \
        return (element_type_ *)lwan_array_append_inline(                      \
            &array->base, sizeof(element_type_), &array->storage);             \
    }                                                                          \
    __attribute__((unused)) static inline struct array_type_                   \
        *coro_##array_type_##_new(struct coro *coro)                           \
    {                                                                          \
        return (struct array_type_ *)coro_lwan_array_new(coro, true);          \
    }                                                                          \
    DEFINE_ARRAY_TYPE_FUNCS(array_type_, element_type_, &array->storage)

#define DEFINE_ARRAY_TYPE_FUNCS(array_type_, element_type_, inline_storage_)   \
    __attribute__((unused)) static inline element_type_                        \
        *array_type_##_get_array(struct array_type_ *array)                    \
    {                                                                          \
        return (element_type_ *)array->base.base;                              \
    }                                                                          \
    __attribute__((unused))                                                    \
        __attribute__((nonnull(1))) static inline void array_type_##_init(     \
            struct array_type_ *array)                                         \
    {                                                                          \
        array->base = (struct lwan_array) LWAN_ARRAY_STATIC_INIT;              \
    }                                                                          \
    __attribute__((unused)) static inline int array_type_##_reset(             \
        struct array_type_ *array)                                             \
    {                                                                          \
        return lwan_array_reset(&array->base, inline_storage_);                \
    }                                                                          \
    __attribute__((unused)) static inline element_type_                        \
        *array_type_##_append0(struct array_type_ *array)                      \
    {                                                                          \
        element_type_ *element = array_type_##_append(array);                  \
                                                                               \
        if (element)                                                           \
            memset(element, 0, sizeof(*element));                              \
                                                                               \
        return element;                                                        \
    }                                                                          \
    __attribute__((unused)) static inline void array_type_##_sort(             \
        struct array_type_ *array, int (*cmp)(const void *a, const void *b))   \
    {                                                                          \
        lwan_array_sort(&array->base, sizeof(element_type_), cmp);             \
    }                                                                          \
    __attribute__((unused)) static inline size_t array_type_##_get_elem_index( \
        const struct array_type_ *array, element_type_ *elem)                  \
    {                                                                          \
        assert(elem >= (element_type_ *)array->base.base);                     \
        assert(elem <                                                          \
               (element_type_ *)array->base.base + array->base.elements);      \
        return (size_t)(elem - (element_type_ *)array->base.base);             \
    }                                                                          \
    __attribute__((unused)) static inline element_type_                        \
        *array_type_##_get_elem(const struct array_type_ *array, size_t index) \
    {                                                                          \
        assert(index <= /* Legal to have a ptr to 1 past end */                \
               array->base.elements);                                          \
        return &((element_type_ *)array->base.base)[index];                    \
    }                                                                          \
    __attribute__((unused)) static inline size_t array_type_##_len(            \
        const struct array_type_ *array)                                       \
    {                                                                          \
        return array->base.elements;                                           \
    }
