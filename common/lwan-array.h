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

struct lwan_array {
    void *base;
    size_t element_size;
    size_t elements;
};

#define ARRAY_INITIALIZER(element_size_) \
    { .base = NULL, .element_size = (element_size_), .elements = 0 }

int lwan_array_init(struct lwan_array *a, size_t element_size);
int lwan_array_reset(struct lwan_array *a);
void *lwan_array_append(struct lwan_array *a);

