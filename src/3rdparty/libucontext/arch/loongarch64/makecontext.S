/*
 * Copyright (c) 2021 Peng Fan <fanpeng@loongson.cn>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * This software is provided 'as is' and without any warranty, express or
 * implied.  In no event shall the authors be liable for any damages arising
 * from the use of this software.
 */

#include "defs.h"

#define LOCALSZ (6)

#define A3_OFF (FRAMESZ - (5 * REG_SZ))
#define A4_OFF (FRAMESZ - (4 * REG_SZ))
#define A5_OFF (FRAMESZ - (3 * REG_SZ))
#define A6_OFF (FRAMESZ - (2 * REG_SZ))
#define A7_OFF (FRAMESZ - (1 * REG_SZ))

ALIAS(makecontext, libucontext_makecontext)

FUNC(libucontext_makecontext)
	PUSH_FRAME(libucontext_makecontext)

	move	$t5, $a0
	move	$t4, $a1

	/* store $a3 through $a7 to the stack frame. */
	st.d	$a3, $sp, A3_OFF
	st.d	$a4, $sp, A4_OFF
	st.d	$a5, $sp, A5_OFF
	st.d	$a6, $sp, A6_OFF
	st.d	$a7, $sp, A7_OFF

	/* set $zero in the mcontext to 1. */
	addi.d	$v0, $zero, 1
	st.d	$v0, $t5, REG_OFFSET(0)

	/* ensure the stack is aligned on a quad-word boundary. */
	ld.d	$t0, $t5, UCONTEXT_STACK_PTR
	ld.d	$t2, $t5, UCONTEXT_STACK_SIZE
	/* the third argument(from zero), that's the first argument of func() */
	addi.d	$t1, $sp, A3_OFF
	add.d	$t0, $t0, $t2

	addi.d	$t7, $zero, ALMASK
	and	$t0, $t0, $t7

	/* number of args */
	beq	$a2, $zero, no_more_arguments
	bltu	$a2, $zero, no_more_arguments

	/* store register arguments. */
	addi.d	$t2, $t5, MCONTEXT_GREGS + (4 * REG_SZ)
	move	$t3, $zero

store_register_arg:
	addi.d	$t3, $t3, 1
	ld.d	$v1, $t1, 0
	addi.d	$t1, $t1, REG_SZ
	st.d	$v1, $t2, 0
	addi.d	$t2, $t2, REG_SZ
	addi.d	$t6, $zero, 8
	bltu	$t3, $t6, store_register_arg
	bgeu	$t3, $a2, no_more_arguments

	/* make room for stack arguments. */
	sub.d	$t2, $a2, $t3

	addi.d	$t6, $zero, 3
	sll.d	$t2, $t2, $t6

	sub.d	$t0, $t0, $t2

	addi.d	$t6, $zero, ALMASK
	and	$t0, $t0, $t6

	/* store stack arguments. */
	move	$t2, $t0

store_stack_arg:
	addi.d	$t3, $t3, 1
	ld.d	$v1, $t1, 0
	addi.d	$t1, $t1, REG_SZ
	st.d	$v1, $t2, 0
	addi.d	$t2, $t2, REG_SZ
	bltu	$t3, $a2, store_stack_arg

no_more_arguments:
	/* trampoline setup. */
	la.got	$t8, libucontext_trampoline

	ld.d	$v1, $t5, UCONTEXT_UC_LINK
	st.d	$v1, $t5, REG_OFFSET(23)

	st.d	$t0, $t5, REG_OFFSET(3)

	st.d	$t8, $t5, REG_OFFSET(1)

	st.d	$t4, $t5, MCONTEXT_PC

	POP_FRAME(libucontext_makecontext)

	jr	$ra
END(libucontext_makecontext)
