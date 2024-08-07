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
