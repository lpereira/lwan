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

#if !defined(NDEBUG) && defined(LWAN_HAVE_VALGRIND)
#define INSTRUMENT_FOR_VALGRIND
#include <valgrind.h>
#include <memcheck.h>
#endif

#if defined(__clang__)
# if defined(__has_feature) && __has_feature(address_sanitizer)
#  define __SANITIZE_ADDRESS__
# endif
#endif
#if defined(__SANITIZE_ADDRESS__)
#define INSTRUMENT_FOR_ASAN
void __asan_poison_memory_region(void const volatile *addr, size_t size);
void __asan_unpoison_memory_region(void const volatile *addr, size_t size);
#endif

void arena_init(struct arena *a)
{
    ptr_array_init(&a->ptrs);
    a->bump_ptr_alloc.ptr = NULL;
    a->bump_ptr_alloc.remaining = 0;
}

void arena_reset(struct arena *a)
{
    void **iter;

    LWAN_ARRAY_FOREACH(&a->ptrs, iter) {
        free(*iter);
    }

    arena_init(a);
}

void *arena_alloc(struct arena *a, const size_t sz)
{
    const size_t aligned_sz = (sz + sizeof(void *) - 1ul) & ~(sizeof(void *) - 1ul);

    if (a->bump_ptr_alloc.remaining < aligned_sz) {
        const size_t alloc_sz = LWAN_MAX((size_t)PAGE_SIZE, aligned_sz);
        void *ptr = malloc(alloc_sz);

        if (UNLIKELY(!ptr))
            return NULL;

        void **saved_ptr = ptr_array_append(&a->ptrs);
        if (UNLIKELY(!saved_ptr)) {
            free(ptr);
            return NULL;
        }

        *saved_ptr = ptr;

        a->bump_ptr_alloc.ptr = ptr;
        a->bump_ptr_alloc.remaining = alloc_sz;

#if defined(INSTRUMENT_FOR_ASAN)
        __asan_poison_memory_region(ptr, alloc_sz);
#endif
#if defined(INSTRUMENT_FOR_VALGRIND)
        VALGRIND_MAKE_MEM_NOACCESS(ptr, alloc_sz);
#endif
    }

    void *ptr = a->bump_ptr_alloc.ptr;

#if defined(INSTRUMENT_FOR_VALGRIND)
    VALGRIND_MAKE_MEM_UNDEFINED(ptr, sz);
#endif
#if defined(INSTRUMENT_FOR_ASAN)
    __asan_unpoison_memory_region(ptr, sz);
#endif

    a->bump_ptr_alloc.remaining -= aligned_sz;
    a->bump_ptr_alloc.ptr = (char *)ptr + aligned_sz;

    return ptr;
}

static void reset_arena(void *data)
{
    struct arena *arena = data;
    arena_reset(arena);
}

struct arena *coro_arena_new(struct coro *coro)
{
    struct arena *arena = coro_malloc(coro, sizeof(*arena));

    if (LIKELY(arena)) {
        arena_init(arena);
        coro_defer(coro, reset_arena, arena);
    }

    return arena;
}
