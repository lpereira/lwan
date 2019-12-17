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

#define _DEFAULT_SOURCE
#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>

#include "lwan.h"
#include "lwan-array.h"

int lwan_array_init(struct lwan_array *a)
{
    if (UNLIKELY(!a))
        return -EINVAL;

    a->base = NULL;
    a->elements = 0;

    return 0;
}

int lwan_array_reset(struct lwan_array *a, void *inline_storage)
{
    if (UNLIKELY(!a))
        return -EINVAL;

    if (a->base != inline_storage)
        free(a->base);

    a->base = NULL;
    a->elements = 0;

    return 0;
}

#if !defined(HAVE_BUILTIN_ADD_OVERFLOW)
static inline bool add_overflow(size_t a, size_t b, size_t *out)
{
    if (UNLIKELY(a > 0 && b > SIZE_MAX - a))
        return true;

    *out = a + b;
    return false;
}
#else
#define add_overflow __builtin_add_overflow
#endif

void *lwan_array_append_heap(struct lwan_array *a, size_t element_size)
{
    if (!(a->elements % LWAN_ARRAY_INCREMENT)) {
        void *new_base;
        size_t new_cap;

        if (UNLIKELY(
                add_overflow(a->elements, LWAN_ARRAY_INCREMENT, &new_cap))) {
            errno = EOVERFLOW;
            return NULL;
        }

        new_base = reallocarray(a->base, new_cap, element_size);
        if (UNLIKELY(!new_base))
            return NULL;

        a->base = new_base;
    }

    return ((char *)a->base) + a->elements++ * element_size;
}

void *lwan_array_append_inline(struct lwan_array *a,
                               size_t element_size,
                               void *inline_storage)
{
    if (!a->base)
        a->base = inline_storage;
    else if (UNLIKELY(a->base != inline_storage))
        return lwan_array_append_heap(a, element_size);

    assert(a->elements <= LWAN_ARRAY_INCREMENT);

    if (a->elements == LWAN_ARRAY_INCREMENT) {
        void *new_base = calloc(2 * LWAN_ARRAY_INCREMENT, element_size);
        if (UNLIKELY(!new_base))
            return NULL;

        a->base = memcpy(new_base, inline_storage,
                         LWAN_ARRAY_INCREMENT * element_size);
    }

    return ((char *)a->base) + a->elements++ * element_size;
}

void lwan_array_sort(struct lwan_array *a,
                     size_t element_size,
                     int (*cmp)(const void *a, const void *b))
{
    if (LIKELY(a->elements))
        qsort(a->base, a->elements, element_size, cmp);
}

static void coro_lwan_array_free_heap(void *data)
{
    struct lwan_array *array = data;

    lwan_array_reset(array, NULL);
    free(array);
}

static void coro_lwan_array_free_inline(void *data)
{
    struct lwan_array *array = data;

    lwan_array_reset(array, array + 1);
    free(array);
}

struct lwan_array *coro_lwan_array_new(struct coro *coro, bool inline_first)
{
    struct lwan_array *array;

    array = coro_malloc_full(coro, sizeof(*array),
                             inline_first ? coro_lwan_array_free_inline
                                          : coro_lwan_array_free_heap);
    if (LIKELY(array))
        lwan_array_init(array);

    return array;
}
