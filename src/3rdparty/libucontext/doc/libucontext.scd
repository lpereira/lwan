libucontext(3)

# NAME

libucontext - a library for userspace context swapping

# SYNOPSIS

*#include <libucontext/libucontext.h>*

```
typedef struct {
  /* depends on target architecture */
} libucontext_mcontext_t;

typedef struct {
  void *ss_sp;
  int ss_flags;
  size_t ss_size;
} libucontext_stack_t;

typedef struct libucontext_ucontext {
  unsigned int uc_flags;
  struct libucontext_ucontext *uc_link;
  libucontext_stack_t uc_stack;
  libucontext_mcontext_t uc_mcontext;
} libucontext_ucontext_t;
```

*int libucontext_getcontext(libucontext_ucontext_t* \*_ucp_*);*

*int libucontext_setcontext(const libucontext_ucontext_t* \*_ucp_*);*

*void libucontext_makecontext(libucontext_ucontext_t* \*_ucp_*, void* _(\*func)()_*, int* _argc_*,* _..._*);*

*int libucontext_swapcontext(libucontext_ucontext_t* \*_oucp_*, const libucontext_ucontext_t* \*_ucp_*);*

# DESCRIPTION

The *libucontext* library provides an implementation of the SysV ucontext functions.  These
are traditionally used to implement user-space context swapping.  This is achieved by using
the *libucontext_getcontext*, *libucontext_setcontext*, *libucontext_makecontext* and
*libucontext_swapcontext* functions as appropriate.

The *libucontext_getcontext* function initializes a structure pointed to by _ucp_ with the
current user context.

The *libucontext_setcontext* function sets the current user context to the structure pointed
to by _ucp_.  It discards the current user context.

The *libucontext_swapcontext* function saves the current user context in a structure pointed
to by _oucp_ and then sets the current user context to the new context in a structure pointed
to by _ucp_.

The *libucontext_makecontext* function modifies a user context in a structure pointed to by
_ucp_ to run a function pointed to by _func_ and sets up an argument list of _argc_ values.

# CAVEATS

In SysV, the ucontext functions save and restore signal masks.  The *libucontext* library,
however, does not.  In practice, this does not usually matter, as users of these functions
rarely change the signal mask between contexts.

Other implementations may or may not save and restore additional processor registers that
this implementation does not.  The *libucontext* library only saves and restores the general
purpose registers.  In practice, this has proven sufficient.

# EXAMPLE

A practical example showing cooperative multithreading.  This program is intended for
illustrative purpose only and has been written in a way favoring simplicity over performance
and robustness:

```
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <libucontext/libucontext.h>

libucontext_ucontext_t mainctx = {};
libucontext_ucontext_t *curthr = &mainctx;
libucontext_ucontext_t *threads = NULL;
size_t thrcount = 0;

void
yieldto(libucontext_ucontext_t *target)
{
	libucontext_ucontext_t *oldthr = curthr;
	curthr = target;

	libucontext_swapcontext(oldthr, curthr);
}

void
yield(void)
{
	libucontext_ucontext_t *newthr;

	/* we set uc_flags to non-zero to signal thread completion. */
	do
		newthr = &threads[random() % thrcount];
	while (newthr == curthr || newthr->uc_flags);

	srandom(time(NULL));

	yieldto(newthr);
}

void
worker(size_t multiple)
{
	size_t accum = 1;

	for (size_t i = 0; i < 10; i++)
	{
		accum += (multiple * i);

		printf("[%p] accumulated %zu\n", curthr, accum);
		yield();
	}

	/* mark thread as completed, so we don't return here */
	curthr->uc_flags = 1;
}

void
create(size_t multiple)
{
	libucontext_ucontext_t *cursor;

	thrcount += 1;
	threads = realloc(threads, sizeof(*threads) * thrcount);

	cursor = &threads[thrcount - 1];
	memset(cursor, '\0', sizeof *cursor);

	/* initialize the new thread's values to our current context */
	libucontext_getcontext(cursor);

	/* set up uc_link */
	cursor->uc_link = thrcount > 1 ? &threads[thrcount - 2] : &mainctx;

	/* set up a stack */
	cursor->uc_stack.ss_size = 8192;
	cursor->uc_stack.ss_sp = calloc(1, cursor->uc_stack.ss_size);

	/* set up the function call */
	libucontext_makecontext(cursor, worker, 1, multiple);
}

int
main(int argc, const char *argv[])
{
	srandom(time(NULL));

	libucontext_getcontext(&mainctx);

	for (size_t i = 1; i < 4; i++)
		create(i);

	/* start the threads off by yielding to the last one */
	yieldto(&threads[thrcount - 1]);

	return EXIT_SUCCESS;
}
```

# AUTHORS

Ariadne Conill <ariadne@dereferenced.org>

