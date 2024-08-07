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

A1_OFFSET = FRAMESZ - (1 * REG_SZ)

ALIAS(swapcontext, libucontext_swapcontext)
ALIAS(__swapcontext, libucontext_swapcontext)

FUNC(libucontext_swapcontext)
	/* copy $gp, $sp, $fp to temporary registers so we don't clobber them */
	move	$a2, $gp
	move	$a3, $sp

	PUSH_FRAME(libucontext_swapcontext)

	/* set registers */
	sd	$s0, REG_OFFSET(16)($a0)
	sd	$s1, REG_OFFSET(17)($a0)
	sd	$s2, REG_OFFSET(18)($a0)
	sd	$s3, REG_OFFSET(19)($a0)
	sd	$s4, REG_OFFSET(20)($a0)
	sd	$s5, REG_OFFSET(21)($a0)
	sd	$s6, REG_OFFSET(22)($a0)
	sd	$s7, REG_OFFSET(23)($a0)

	sd	$a2, REG_OFFSET(28)($a0)
	sd	$a3, REG_OFFSET(29)($a0)
	sd	$fp, REG_OFFSET(30)($a0)
	sd	$ra, REG_OFFSET(31)($a0)
	sd	$ra, (MCONTEXT_PC)($a0)

	/* copy new context address in $a1 to stack */
	sd	$a1, A1_OFFSET($sp)

	/* load new context address into $v0 */
	ld	$v0, A1_OFFSET($sp)

	/* load the registers */
	ld	$a0, REG_OFFSET(4)($v0)
	ld	$a1, REG_OFFSET(5)($v0)
	ld	$a2, REG_OFFSET(6)($v0)
	ld	$a3, REG_OFFSET(7)($v0)

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

fail:
	la	$t9, exit

	POP_FRAME(libucontext_swapcontext)

	move	$v0, $zero
	jalr	$t9
END(libucontext_swapcontext)
