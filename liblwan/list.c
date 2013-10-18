/*
 * list - double linked list routines
 * Author: Rusty Russell <rusty@rustcorp.com.au>
 *
 * The list header contains routines for manipulating double linked lists.
 * It defines two types: struct list_head used for anchoring lists, and
 * struct list_node which is usually embedded in the structure which is placed
 * in the list.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to permit
 * persons to whom the Software is furnished to do so, subject to the
 * following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT
 * OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR
 * THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include "list.h"

static void *corrupt(const char *abortstr,
		     const struct list_node *head,
		     const struct list_node *node,
		     unsigned int count)
{
	if (abortstr) {
		fprintf(stderr,
			"%s: prev corrupt in node %p (%u) of %p\n",
			abortstr, node, count, head);
		abort();
	}
	return NULL;
}

struct list_node *list_check_node(const struct list_node *node,
				  const char *abortstr)
{
	const struct list_node *p, *n;
	int count = 0;

	for (p = node, n = node->next; n != node; p = n, n = n->next) {
		count++;
		if (n->prev != p)
			return corrupt(abortstr, node, n, count);
	}
	/* Check prev on head node. */
	if (node->prev != p)
		return corrupt(abortstr, node, node, 0);

	return (struct list_node *)node;
}

struct list_head *list_check(const struct list_head *h, const char *abortstr)
{
	if (!list_check_node(&h->n, abortstr))
		return NULL;
	return (struct list_head *)h;
}
