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

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>

#include "lwan.h"
#include "lwan-array.h"
#include "reallocarray.h"

#define INCREMENT 16

int
lwan_array_init(struct lwan_array *a, size_t element_size)
{
    if (UNLIKELY(!a))
        return -EINVAL;

    a->base = NULL;
    a->element_size = element_size;
    a->elements = 0;

    return 0;
}

int
lwan_array_reset(struct lwan_array *a)
{
    if (UNLIKELY(!a))
        return -EINVAL;

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

    *out = a + INCREMENT;
    return false;
}
#else
#define add_overflow __builtin_add_overflow
#endif

void *
lwan_array_append(struct lwan_array *a)
{
    if (!(a->elements % INCREMENT)) {
        void *new_base;
        size_t new_cap;

        if (UNLIKELY(add_overflow(a->elements, INCREMENT, &new_cap))) {
            errno = EOVERFLOW;
            return NULL;
        }

        new_base = reallocarray(a->base, new_cap, a->element_size);
        if (UNLIKELY(!new_base))
            return NULL;

        a->base = new_base;
    }

    return ((unsigned char *)a->base) + (a->elements++) * a->element_size;
}
