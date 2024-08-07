/*
 * libucontext test program based on POSIX example program.
 * Public domain.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ucontext.h>

static ucontext_t ctx[3];


static void check_arg(int actual, int expected) {
	if (actual == expected) return;
	fprintf(stderr, "argument has wrong value.  got %d, expected %d.\n", actual, expected);
	abort();
}


static void f1 (int a, int b, int c, int d, int e, int f, int g, int h, int i, int j) {
	printf("start f1\n");

	printf("checking provided arguments to function f1\n");
	check_arg(a, 1);
	check_arg(b, 2);
	check_arg(c, 3);
	check_arg(d, 4);
	check_arg(e, 5);
	check_arg(f, 6);
	check_arg(g, 7);
	check_arg(h, 8);
	check_arg(i, 9);
	check_arg(j, 10);
	printf("looks like all arguments are passed correctly\n");

	printf("swap back to f2\n");
	swapcontext(&ctx[1], &ctx[2]);
	printf("finish f1\n");
}


static void f2 (void) {
	printf("start f2\n");
	printf("swap to f1\n");
	swapcontext(&ctx[2], &ctx[1]);
	printf("finish f2, should swap to f1\n");
}


int main (int argc, const char *argv[]) {
	char st1[8192];
	char st2[8192];
	volatile int done = 0;


	/* poison each coroutine's stack memory for debugging purposes */
	memset(st1, 'A', sizeof st1);
	memset(st2, 'B', sizeof st2);


	printf("setting up context 1\n");


	getcontext(&ctx[1]);
	ctx[1].uc_stack.ss_sp = st1;
	ctx[1].uc_stack.ss_size = sizeof st1;
	ctx[1].uc_link = &ctx[0];
	makecontext(&ctx[1], f1, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10);


	printf("setting up context 2\n");


	getcontext(&ctx[2]);
	ctx[2].uc_stack.ss_sp = st2;
	ctx[2].uc_stack.ss_size = sizeof st2;
	ctx[2].uc_link = &ctx[1];
	makecontext(&ctx[2], f2, 0);


	printf("doing initial swapcontext\n");


	swapcontext(&ctx[0], &ctx[2]);


	printf("returned from initial swapcontext\n");


	/* test ability to use getcontext/setcontext without makecontext */
	getcontext(&ctx[1]);
	printf("done = %d\n", done);
	if (done++ == 0) setcontext(&ctx[1]);
	if (done != 2) {
		fprintf(stderr, "wrong value for done.  got %d, expected 2\n", done);
		abort();
	}

	return 0;
}
