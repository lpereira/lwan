/*
 * lwan - web server
 * Copyright (c) 2024 L. A. F. Pereira <l@tia.mat.br>
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

#include "lwan-private.h"
#include "lwan-arena.h"

void arena_init(struct arena *a)
{
    ptr_array_init(&a->ptrs);
    a->bump_ptr_alloc.ptr = NULL;
    a->bump_ptr_alloc.remaining = 0;
}

void arena_destroy(struct arena *a)
{
    void **iter;

    LWAN_ARRAY_FOREACH(&a->ptrs, iter) {
        free(*iter);
    }

    arena_init(a);
}

static void *arena_bump_ptr(struct arena *a, size_t sz)
{
    void *ptr = a->bump_ptr_alloc.ptr;

    assert(a->bump_ptr_alloc.remaining >= sz);

    a->bump_ptr_alloc.remaining -= sz;
    a->bump_ptr_alloc.ptr = (char *)a->bump_ptr_alloc.ptr + sz;

    return ptr;
}

void *arena_alloc(struct arena *a, size_t sz)
{
    sz = (sz + sizeof(void *) - 1ul) & ~(sizeof(void *) - 1ul);

    if (a->bump_ptr_alloc.remaining < sz) {
        void *ptr = malloc(LWAN_MAX((size_t)PAGE_SIZE, sz));

        if (UNLIKELY(!ptr))
            return NULL;

        void **saved_ptr = ptr_array_append(&a->ptrs);
        if (UNLIKELY(!saved_ptr)) {
            free(ptr);
            return NULL;
        }

        *saved_ptr = ptr;

        a->bump_ptr_alloc.ptr = ptr;
        a->bump_ptr_alloc.remaining = PAGE_SIZE;
    }

    return arena_bump_ptr(a, sz);
}

static void destroy_arena(void *data)
{
    struct arena *arena = data;
    arena_destroy(arena);
}

struct arena *coro_arena_new(struct coro *coro)
{
    struct arena *arena = coro_malloc(coro, sizeof(*arena));

    if (LIKELY(arena)) {
        arena_init(arena);
        coro_defer(coro, destroy_arena, arena);
    }

    return arena;
}
