/*
 * Copyright (c) 2020 Ariadne Conill <ariadne@dereferenced.org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * This software is provided 'as is' and without any warranty, express or
 * implied.  In no event shall the authors be liable for any damages arising
 * from the use of this software.
 */

LOCALSZ = 2

#include "defs.h"

A3_OFF = FRAMESZ + (3 * REG_SZ)

/*
 * Because we have to fiddle with $gp, we have to implement this in
 * assembly rather than C.  Annoying, that...
 */

ALIAS(makecontext, libucontext_makecontext)
ALIAS(__makecontext, libucontext_makecontext)

FUNC(libucontext_makecontext)
	PUSH_FRAME(libucontext_makecontext)

	/* store $a3 through $a7 to the stack frame. */
	sw	$a3, A3_OFF($sp)

	/* set $zero in the mcontext to 1. */
	li	$v0, 1
	sw	$v0, REG_OFFSET(0)($a0)

	/* ensure the stack is aligned on a quad-word boundary. */
	lw	$t0, UCONTEXT_STACK_PTR($a0)
	lw	$t2, UCONTEXT_STACK_SIZE($a0)
	addiu	$t1, $sp, A3_OFF
	addu	$t0, $t2
	and	$t0, ALMASK
	blez	$a2, no_more_arguments

	/* store register arguments. */
	addiu	$t2, $a0, MCONTEXT_GREGS + (4 * REG_SZ)
	move	$t3, $zero

store_register_arg:
	addiu	$t3, 1
	lw	$v1, ($t1)
	addiu	$t1, REG_SZ
	sw	$v1, ($t2)
	addiu	$t2, REG_SZ
	bgeu	$t3, $a2, no_more_arguments
	bltu	$t3, 4, store_register_arg

	/* make room for stack arguments. */
	subu	$t2, $a2, $t3
	sll	$t2, 3
	subu	$t0, $t2
	and	$t0, ALMASK

	/* store stack arguments. */
	move	$t2, $t0

store_stack_arg:
	addiu	$t3, 1
	lw	$v1, ($t1)
	addiu	$t1, REG_SZ
	sw	$v1, ($t2)
	addiu	$t2, REG_SZ
	bltu	$t3, $a2, store_stack_arg

no_more_arguments:
	/* make room for $a0-$a3 storage */
	addiu	$t0, -(4 * REG_SZ)

	/* trampoline setup. */
	la	$t9, libucontext_trampoline

	/* copy link pointer as $s0... */
	lw	$v1, UCONTEXT_UC_LINK($a0)
	sw	$v1, REG_OFFSET(16)($a0)

	/* set our $sp */
	sw	$t0, REG_OFFSET(29)($a0)

	/* $gp is copied as $s1 */
	sw	$gp, REG_OFFSET(17)($a0)

	/* set our $ra */
	sw	$t9, REG_OFFSET(31)($a0)

	/* set our $pc */
	sw	$a1, MCONTEXT_PC($a0)

	POP_FRAME(libucontext_makecontext)

	jr	$ra
END(libucontext_makecontext)
