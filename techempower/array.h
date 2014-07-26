#pragma once

#include <stddef.h>

/*
 * Declaration of struct array is in header because we may want to embed the
 * structure into another, so we need to know its size
 */
struct array {
	void **array;
	size_t count;
	size_t total;
	size_t step;
};

void array_init(struct array *array, size_t step);
int array_append(struct array *array, const void *element);
int array_append_unique(struct array *array, const void *element);
void array_pop(struct array *array);
void array_free_array(struct array *array);
void array_sort(struct array *array, int (*cmp)(const void *a, const void *b));
int array_remove_at(struct array *array, unsigned int pos);
