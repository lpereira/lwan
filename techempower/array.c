/*
 * libkmod - interface to kernel module operations
 *
 * Copyright (C) 2011-2013  ProFUSION embedded systems
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "array.h"
#include "reallocarray.h"

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* basic pointer array growing in steps */


static int array_realloc(struct array *array, size_t new_total)
{
	void *tmp = reallocarray(array->array, sizeof(void *), new_total);
	if (tmp == NULL)
		return -ENOMEM;
	array->array = tmp;
	array->total = new_total;
	return 0;
}

void array_init(struct array *array, size_t step)
{
	assert(step > 0);
	array->array = NULL;
	array->count = 0;
	array->total = 0;
	array->step = step;
}

int array_append(struct array *array, const void *element)
{
	size_t idx;

	if (array->count + 1 >= array->total) {
		int r = array_realloc(array, array->total + array->step);
		if (r < 0)
			return r;
	}
	idx = array->count;
	array->array[idx] = (void *)element;
	array->count++;
	return (int)idx;
}

int array_append_unique(struct array *array, const void *element)
{
	void **itr = array->array;
	void **itr_end = itr + array->count;
	for (; itr < itr_end; itr++)
		if (*itr == element)
			return -EEXIST;
	return array_append(array, element);
}

void array_pop(struct array *array) {
	array->count--;
	if (array->count + array->step < array->total) {
		int r = array_realloc(array, array->total - array->step);
		if (r < 0)
			return;
	}
}

void array_free_array(struct array *array) {
	free(array->array);
	array->count = 0;
	array->total = 0;
}


void array_sort(struct array *array, int (*cmp)(const void *a, const void *b))
{
	qsort(array->array, array->count, sizeof(void *), cmp);
}

int array_remove_at(struct array *array, unsigned int pos)
{
	if (array->count <= pos)
		return -ENOENT;

	array->count--;
	if (pos < array->count)
		memmove(array->array + pos, array->array + pos + 1,
			sizeof(void *) * (array->count - pos));

	if (array->count + array->step < array->total) {
		int r = array_realloc(array, array->total - array->step);
		/* ignore error */
		if (r < 0)
			return 0;
	}

	return 0;
}
