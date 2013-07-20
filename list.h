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

#ifndef _LIST_H
#define _LIST_H
#include <stdbool.h>
#include <stddef.h>
#include <assert.h>

/**
 * check_type - issue a warning or build failure if type is not correct.
 * @expr: the expression whose type we should check (not evaluated).
 * @type: the exact type we expect the expression to be.
 *
 * This macro is usually used within other macros to try to ensure that a macro
 * argument is of the expected type.  No type promotion of the expression is
 * done: an unsigned int is not the same as an int!
 *
 * check_type() always evaluates to 0.
 *
 * If your compiler does not support typeof, then the best we can do is fail
 * to compile if the sizes of the types are unequal (a less complete check).
 *
 * Example:
 *      // They should always pass a 64-bit value to _set_some_value!
 *      #define set_some_value(expr)                    \
 *              _set_some_value((check_type((expr), uint64_t), (expr)))
 */
#define check_type(expr, type)                  \
        ((typeof(expr) *)0 != (type *)0)

/**
 * check_types_match - issue a warning or build failure if types are not same.
 * @expr1: the first expression (not evaluated).
 * @expr2: the second expression (not evaluated).
 *
 * This macro is usually used within other macros to try to ensure that
 * arguments are of identical types.  No type promotion of the expressions is
 * done: an unsigned int is not the same as an int!
 *
 * check_types_match() always evaluates to 0.
 *
 * If your compiler does not support typeof, then the best we can do is fail
 * to compile if the sizes of the types are unequal (a less complete check).
 *
 * Example:
 *      // Do subtraction to get to enclosing type, but make sure that
 *      // pointer is of correct type for that member.
 *      #define container_of(mbr_ptr, encl_type, mbr)                   \
 *              (check_types_match((mbr_ptr), &((encl_type *)0)->mbr),  \
 *               ((encl_type *)                                         \
 *                ((char *)(mbr_ptr) - offsetof(enclosing_type, mbr))))
 */

#define check_types_match(expr1, expr2)         \
        ((typeof(expr1) *)0 != (typeof(expr2) *)0)

/**
 * container_of - get pointer to enclosing structure
 * @member_ptr: pointer to the structure member
 * @containing_type: the type this member is within
 * @member: the name of this member within the structure.
 *
 * Given a pointer to a member of a structure, this macro does pointer
 * subtraction to return the pointer to the enclosing type.
 *
 * Example:
 *      struct foo {
 *              int fielda, fieldb;
 *              // ...
 *      };
 *      struct info {
 *              int some_other_field;
 *              struct foo my_foo;
 *      };
 *
 *      static struct info *foo_to_info(struct foo *foo)
 *      {
 *              return container_of(foo, struct info, my_foo);
 *      }
 */
#define container_of(member_ptr, containing_type, member)               \
         ((containing_type *)                                           \
          ((char *)(member_ptr)                                         \
           - container_off(containing_type, member))                    \
          + check_types_match(*(member_ptr), ((containing_type *)0)->member))

/**
 * container_off - get offset to enclosing structure
 * @containing_type: the type this member is within
 * @member: the name of this member within the structure.
 *
 * Given a pointer to a member of a structure, this macro does
 * typechecking and figures out the offset to the enclosing type.
 *
 * Example:
 *      struct foo {
 *              int fielda, fieldb;
 *              // ...
 *      };
 *      struct info {
 *              int some_other_field;
 *              struct foo my_foo;
 *      };
 *
 *      static struct info *foo_to_info(struct foo *foo)
 *      {
 *              size_t off = container_off(struct info, my_foo);
 *              return (void *)((char *)foo - off);
 *      }
 */
#define container_off(containing_type, member)  \
        offsetof(containing_type, member)

/**
 * container_off_var - get offset of a field in enclosing structure
 * @container_var: a pointer to a container structure
 * @member: the name of a member within the structure.
 *
 * Given (any) pointer to a structure and a its member name, this
 * macro does pointer subtraction to return offset of member in a
 * structure memory layout.
 *
 */
#define container_off_var(var, member)          \
        container_off(typeof(*var), member)

/**
 * struct list_node - an entry in a doubly-linked list
 * @next: next entry (self if empty)
 * @prev: previous entry (self if empty)
 *
 * This is used as an entry in a linked list.
 * Example:
 *	struct child {
 *		const char *name;
 *		// Linked list of all us children.
 *		struct list_node list;
 *	};
 */
struct list_node
{
	struct list_node *next, *prev;
};

/**
 * struct list_head - the head of a doubly-linked list
 * @h: the list_head (containing next and prev pointers)
 *
 * This is used as the head of a linked list.
 * Example:
 *	struct parent {
 *		const char *name;
 *		struct list_head children;
 *		unsigned int num_children;
 *	};
 */
struct list_head
{
	struct list_node n;
};

/**
 * list_check - check head of a list for consistency
 * @h: the list_head
 * @abortstr: the location to print on aborting, or NULL.
 *
 * Because list_nodes have redundant information, consistency checking between
 * the back and forward links can be done.  This is useful as a debugging check.
 * If @abortstr is non-NULL, that will be printed in a diagnostic if the list
 * is inconsistent, and the function will abort.
 *
 * Returns the list head if the list is consistent, NULL if not (it
 * can never return NULL if @abortstr is set).
 *
 * See also: list_check_node()
 *
 * Example:
 *	static void dump_parent(struct parent *p)
 *	{
 *		struct child *c;
 *
 *		printf("%s (%u children):\n", p->name, p->num_children);
 *		list_check(&p->children, "bad child list");
 *		list_for_each(&p->children, c, list)
 *			printf(" -> %s\n", c->name);
 *	}
 */
struct list_head *list_check(const struct list_head *h, const char *abortstr);

/**
 * list_check_node - check node of a list for consistency
 * @n: the list_node
 * @abortstr: the location to print on aborting, or NULL.
 *
 * Check consistency of the list node is in (it must be in one).
 *
 * See also: list_check()
 *
 * Example:
 *	static void dump_child(const struct child *c)
 *	{
 *		list_check_node(&c->list, "bad child list");
 *		printf("%s\n", c->name);
 *	}
 */
struct list_node *list_check_node(const struct list_node *n,
				  const char *abortstr);

#ifdef _LIST_DEBUG
#define list_debug(h) list_check((h), __func__)
#define list_debug_node(n) list_check_node((n), __func__)
#else
#define list_debug(h) (h)
#define list_debug_node(n) (n)
#endif

/**
 * LIST_HEAD_INIT - initializer for an empty list_head
 * @name: the name of the list.
 *
 * Explicit initializer for an empty list.
 *
 * See also:
 *	LIST_HEAD, list_head_init()
 *
 * Example:
 *	static struct list_head my_list = LIST_HEAD_INIT(my_list);
 */
#define LIST_HEAD_INIT(name) { { &name.n, &name.n } }

/**
 * LIST_HEAD - define and initialize an empty list_head
 * @name: the name of the list.
 *
 * The LIST_HEAD macro defines a list_head and initializes it to an empty
 * list.  It can be prepended by "static" to define a static list_head.
 *
 * See also:
 *	LIST_HEAD_INIT, list_head_init()
 *
 * Example:
 *	static LIST_HEAD(my_global_list);
 */
#define LIST_HEAD(name) \
	struct list_head name = LIST_HEAD_INIT(name)

/**
 * list_head_init - initialize a list_head
 * @h: the list_head to set to the empty list
 *
 * Example:
 *	...
 *	struct parent *parent = malloc(sizeof(*parent));
 *
 *	list_head_init(&parent->children);
 *	parent->num_children = 0;
 */
static inline void list_head_init(struct list_head *h)
{
	h->n.next = h->n.prev = &h->n;
}

/**
 * list_add - add an entry at the start of a linked list.
 * @h: the list_head to add the node to
 * @n: the list_node to add to the list.
 *
 * The list_node does not need to be initialized; it will be overwritten.
 * Example:
 *	struct child *child = malloc(sizeof(*child));
 *
 *	child->name = "marvin";
 *	list_add(&parent->children, &child->list);
 *	parent->num_children++;
 */
static inline void list_add(struct list_head *h, struct list_node *n)
{
	n->next = h->n.next;
	n->prev = &h->n;
	h->n.next->prev = n;
	h->n.next = n;
	(void)list_debug(h);
}

/**
 * list_add_tail - add an entry at the end of a linked list.
 * @h: the list_head to add the node to
 * @n: the list_node to add to the list.
 *
 * The list_node does not need to be initialized; it will be overwritten.
 * Example:
 *	list_add_tail(&parent->children, &child->list);
 *	parent->num_children++;
 */
static inline void list_add_tail(struct list_head *h, struct list_node *n)
{
	n->next = &h->n;
	n->prev = h->n.prev;
	h->n.prev->next = n;
	h->n.prev = n;
	(void)list_debug(h);
}

/**
 * list_empty - is a list empty?
 * @h: the list_head
 *
 * If the list is empty, returns true.
 *
 * Example:
 *	assert(list_empty(&parent->children) == (parent->num_children == 0));
 */
static inline bool list_empty(const struct list_head *h)
{
	(void)list_debug(h);
	return h->n.next == &h->n;
}

/**
 * list_del - delete an entry from an (unknown) linked list.
 * @n: the list_node to delete from the list.
 *
 * Note that this leaves @n in an undefined state; it can be added to
 * another list, but not deleted again.
 *
 * See also:
 *	list_del_from()
 *
 * Example:
 *	list_del(&child->list);
 *	parent->num_children--;
 */
static inline void list_del(struct list_node *n)
{
	(void)list_debug_node(n);
	n->next->prev = n->prev;
	n->prev->next = n->next;
#ifdef _LIST_DEBUG
	/* Catch use-after-del. */
	n->next = n->prev = NULL;
#endif
}

/**
 * list_del_from - delete an entry from a known linked list.
 * @h: the list_head the node is in.
 * @n: the list_node to delete from the list.
 *
 * This explicitly indicates which list a node is expected to be in,
 * which is better documentation and can catch more bugs.
 *
 * See also: list_del()
 *
 * Example:
 *	list_del_from(&parent->children, &child->list);
 *	parent->num_children--;
 */
static inline void list_del_from(struct list_head *h, struct list_node *n)
{
#ifdef _LIST_DEBUG
	{
		/* Thorough check: make sure it was in list! */
		struct list_node *i;
		for (i = h->n.next; i != n; i = i->next)
			assert(i != &h->n);
	}
#else
        (void)h;
#endif /* _LIST_DEBUG */

	/* Quick test that catches a surprising number of bugs. */
	assert(!list_empty(h));
	list_del(n);
}

/**
 * list_entry - convert a list_node back into the structure containing it.
 * @n: the list_node
 * @type: the type of the entry
 * @member: the list_node member of the type
 *
 * Example:
 *	// First list entry is children.next; convert back to child.
 *	child = list_entry(parent->children.n.next, struct child, list);
 *
 * See Also:
 *	list_top(), list_for_each()
 */
#define list_entry(n, type, member) container_of(n, type, member)

/**
 * list_top - get the first entry in a list
 * @h: the list_head
 * @type: the type of the entry
 * @member: the list_node member of the type
 *
 * If the list is empty, returns NULL.
 *
 * Example:
 *	struct child *first;
 *	first = list_top(&parent->children, struct child, list);
 *	if (!first)
 *		printf("Empty list!\n");
 */
#define list_top(h, type, member)					\
	((type *)list_top_((h), list_off_(type, member)))

static inline const void *list_top_(const struct list_head *h, size_t off)
{
	if (list_empty(h))
		return NULL;
	return (const char *)h->n.next - off;
}

/**
 * list_pop - remove the first entry in a list
 * @h: the list_head
 * @type: the type of the entry
 * @member: the list_node member of the type
 *
 * If the list is empty, returns NULL.
 *
 * Example:
 *	struct child *one;
 *	one = list_pop(&parent->children, struct child, list);
 *	if (!one)
 *		printf("Empty list!\n");
 */
#define list_pop(h, type, member)					\
	((type *)list_pop_((h), list_off_(type, member)))

static inline const void *list_pop_(const struct list_head *h, size_t off)
{
	struct list_node *n;

	if (list_empty(h))
		return NULL;
	n = h->n.next;
	list_del(n);
	return (const char *)n - off;
}

/**
 * list_tail - get the last entry in a list
 * @h: the list_head
 * @type: the type of the entry
 * @member: the list_node member of the type
 *
 * If the list is empty, returns NULL.
 *
 * Example:
 *	struct child *last;
 *	last = list_tail(&parent->children, struct child, list);
 *	if (!last)
 *		printf("Empty list!\n");
 */
#define list_tail(h, type, member) \
	((type *)list_tail_((h), list_off_(type, member)))

static inline const void *list_tail_(const struct list_head *h, size_t off)
{
	if (list_empty(h))
		return NULL;
	return (const char *)h->n.prev - off;
}

/**
 * list_for_each - iterate through a list.
 * @h: the list_head (warning: evaluated multiple times!)
 * @i: the structure containing the list_node
 * @member: the list_node member of the structure
 *
 * This is a convenient wrapper to iterate @i over the entire list.  It's
 * a for loop, so you can break and continue as normal.
 *
 * Example:
 *	list_for_each(&parent->children, child, list)
 *		printf("Name: %s\n", child->name);
 */
#define list_for_each(h, i, member)					\
	list_for_each_off(h, i, list_off_var_(i, member))

/**
 * list_for_each_rev - iterate through a list backwards.
 * @h: the list_head
 * @i: the structure containing the list_node
 * @member: the list_node member of the structure
 *
 * This is a convenient wrapper to iterate @i over the entire list.  It's
 * a for loop, so you can break and continue as normal.
 *
 * Example:
 *	list_for_each_rev(&parent->children, child, list)
 *		printf("Name: %s\n", child->name);
 */
#define list_for_each_rev(h, i, member)					\
	for (i = container_of_var(list_debug(h)->n.prev, i, member);	\
	     &i->member != &(h)->n;					\
	     i = container_of_var(i->member.prev, i, member))

/**
 * list_for_each_safe - iterate through a list, maybe during deletion
 * @h: the list_head
 * @i: the structure containing the list_node
 * @nxt: the structure containing the list_node
 * @member: the list_node member of the structure
 *
 * This is a convenient wrapper to iterate @i over the entire list.  It's
 * a for loop, so you can break and continue as normal.  The extra variable
 * @nxt is used to hold the next element, so you can delete @i from the list.
 *
 * Example:
 *	struct child *next;
 *	list_for_each_safe(&parent->children, child, next, list) {
 *		list_del(&child->list);
 *		parent->num_children--;
 *	}
 */
#define list_for_each_safe(h, i, nxt, member)				\
	list_for_each_safe_off(h, i, nxt, list_off_var_(i, member))

/**
 * list_append_list - empty one list onto the end of another.
 * @to: the list to append into
 * @from: the list to empty.
 *
 * This takes the entire contents of @from and moves it to the end of
 * @to.  After this @from will be empty.
 *
 * Example:
 *	struct list_head adopter;
 *
 *	list_append_list(&adopter, &parent->children);
 *	assert(list_empty(&parent->children));
 *	parent->num_children = 0;
 */
static inline void list_append_list(struct list_head *to,
				    struct list_head *from)
{
	struct list_node *from_tail = list_debug(from)->n.prev;
	struct list_node *to_tail = list_debug(to)->n.prev;

	/* Sew in head and entire list. */
	to->n.prev = from_tail;
	from_tail->next = &to->n;
	to_tail->next = &from->n;
	from->n.prev = to_tail;

	/* Now remove head. */
	list_del(&from->n);
	list_head_init(from);
}

/**
 * list_prepend_list - empty one list into the start of another.
 * @to: the list to prepend into
 * @from: the list to empty.
 *
 * This takes the entire contents of @from and moves it to the start
 * of @to.  After this @from will be empty.
 *
 * Example:
 *	list_prepend_list(&adopter, &parent->children);
 *	assert(list_empty(&parent->children));
 *	parent->num_children = 0;
 */
static inline void list_prepend_list(struct list_head *to,
				     struct list_head *from)
{
	struct list_node *from_tail = list_debug(from)->n.prev;
	struct list_node *to_head = list_debug(to)->n.next;

	/* Sew in head and entire list. */
	to->n.next = &from->n;
	from->n.prev = &to->n;
	to_head->prev = from_tail;
	from_tail->next = to_head;

	/* Now remove head. */
	list_del(&from->n);
	list_head_init(from);
}

/**
 * list_for_each_off - iterate through a list of memory regions.
 * @h: the list_head
 * @i: the pointer to a memory region wich contains list node data.
 * @off: offset(relative to @i) at which list node data resides.
 *
 * This is a low-level wrapper to iterate @i over the entire list, used to
 * implement all oher, more high-level, for-each constructs. It's a for loop,
 * so you can break and continue as normal.
 *
 * WARNING! Being the low-level macro that it is, this wrapper doesn't know
 * nor care about the type of @i. The only assumtion made is that @i points
 * to a chunk of memory that at some @offset, relative to @i, contains a
 * properly filled `struct node_list' which in turn contains pointers to
 * memory chunks and it's turtles all the way down. Whith all that in mind
 * remember that given the wrong pointer/offset couple this macro will
 * happilly churn all you memory untill SEGFAULT stops it, in other words
 * caveat emptor.
 *
 * It is worth mentioning that one of legitimate use-cases for that wrapper
 * is operation on opaque types with known offset for `struct list_node'
 * member(preferably 0), because it allows you not to disclose the type of
 * @i.
 *
 * Example:
 *	list_for_each_off(&parent->children, child,
 *				offsetof(struct child, list))
 *		printf("Name: %s\n", child->name);
 */
#define list_for_each_off(h, i, off)                                    \
  for (i = list_node_to_off_(list_debug(h)->n.next, (off));             \
       list_node_from_off_((void *)i, (off)) != &(h)->n;                \
       i = list_node_to_off_(list_node_from_off_((void *)i, (off))->next, \
                             (off)))

/**
 * list_for_each_safe_off - iterate through a list of memory regions, maybe
 * during deletion
 * @h: the list_head
 * @i: the pointer to a memory region wich contains list node data.
 * @nxt: the structure containing the list_node
 * @off: offset(relative to @i) at which list node data resides.
 *
 * For details see `list_for_each_off' and `list_for_each_safe'
 * descriptions.
 *
 * Example:
 *	list_for_each_safe_off(&parent->children, child,
 *		next, offsetof(struct child, list))
 *		printf("Name: %s\n", child->name);
 */
#define list_for_each_safe_off(h, i, nxt, off)                          \
  for (i = list_node_to_off_(list_debug(h)->n.next, (off)),             \
         nxt = list_node_to_off_(list_node_from_off_(i, (off))->next,   \
                                 (off));                                \
       list_node_from_off_(i, (off)) != &(h)->n;                        \
       i = nxt,                                                         \
         nxt = list_node_to_off_(list_node_from_off_(i, (off))->next,   \
                                 (off)))


/* Other -off variants. */
#define list_entry_off(n, type, off)		\
	((type *)list_node_from_off_((n), (off)))

#define list_head_off(h, type, off)		\
	((type *)list_head_off((h), (off)))

#define list_tail_off(h, type, off)		\
	((type *)list_tail_((h), (off)))

#define list_add_off(h, n, off)                 \
	list_add((h), list_node_from_off_((n), (off)))

#define list_del_off(n, off)                    \
	list_del(list_node_from_off_((n), (off)))

#define list_del_from_off(h, n, off)			\
	list_del_from(h, list_node_from_off_((n), (off)))

/* Offset helper functions so we only single-evaluate. */
static inline void *list_node_to_off_(struct list_node *node, size_t off)
{
	return (void *)((char *)node - off);
}
static inline struct list_node *list_node_from_off_(void *ptr, size_t off)
{
	return (struct list_node *)((char *)ptr + off);
}

/* Get the offset of the member, but make sure it's a list_node. */
#define list_off_(type, member)					\
	(container_off(type, member) +				\
	 check_type(((type *)0)->member, struct list_node))

#define list_off_var_(var, member)			\
	(container_off_var(var, member) +		\
	 check_type(var->member, struct list_node))

#endif /* _LIST_H */
