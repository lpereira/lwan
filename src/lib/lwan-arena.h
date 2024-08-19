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

#pragma once

#include "lwan-array.h"
#include "lwan-coro.h"

DEFINE_ARRAY_TYPE_INLINEFIRST(ptr_array, void *)

struct arena {
    struct ptr_array ptrs;

    struct {
        void *ptr;
        size_t remaining;
    } bump_ptr_alloc;
};

void arena_init(struct arena *a);
struct arena *coro_arena_new(struct coro *coro);
void arena_destroy(struct arena *a);

void *arena_alloc(struct arena *a, size_t sz);
