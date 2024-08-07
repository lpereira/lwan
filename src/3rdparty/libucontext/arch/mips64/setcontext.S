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

LOCALSZ = 1

#include "defs.h"

ALIAS(setcontext, libucontext_setcontext)
ALIAS(__setcontext, libucontext_setcontext)

FUNC(libucontext_setcontext)
	PUSH_FRAME(libucontext_setcontext)

	/* move the context to $v0 */	
	move	$v0, $a0

	/* load the registers */
	ld	$a0, REG_OFFSET(4)($v0)
	ld	$a1, REG_OFFSET(5)($v0)
	ld	$a2, REG_OFFSET(6)($v0)
	ld	$a3, REG_OFFSET(7)($v0)
	ld	$a4, REG_OFFSET(8)($v0)
	ld	$a5, REG_OFFSET(9)($v0)
	ld	$a6, REG_OFFSET(10)($v0)
	ld	$a7, REG_OFFSET(11)($v0)

	ld	$s0, REG_OFFSET(16)($v0)
	ld	$s1, REG_OFFSET(17)($v0)
	ld	$s2, REG_OFFSET(18)($v0)
	ld	$s3, REG_OFFSET(19)($v0)
	ld	$s4, REG_OFFSET(20)($v0)
	ld	$s5, REG_OFFSET(21)($v0)
	ld	$s6, REG_OFFSET(22)($v0)
	ld	$s7, REG_OFFSET(23)($v0)

	ld	$gp, REG_OFFSET(28)($v0)
	ld	$sp, REG_OFFSET(29)($v0)
	ld	$fp, REG_OFFSET(30)($v0)
	ld	$ra, REG_OFFSET(31)($v0)
	ld	$t9, (MCONTEXT_PC)($v0)

	move	$v0, $zero
	jr	$t9

	POP_FRAME(libucontext_setcontext)
END(libucontext_setcontext)
