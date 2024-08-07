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

ALIAS(getcontext, libucontext_getcontext)
ALIAS(__getcontext, libucontext_getcontext)

FUNC(libucontext_getcontext)
	/* copy $gp, $sp, $fp to temporary registers so we don't clobber them */
	move	$a2, $gp
	move	$a3, $sp
	move	$a1, $fp

	PUSH_FRAME(libucontext_getcontext)

	/* set registers */
	sw	$s0, REG_OFFSET(16)($a0)
	sw	$s1, REG_OFFSET(17)($a0)
	sw	$s2, REG_OFFSET(18)($a0)
	sw	$s3, REG_OFFSET(19)($a0)
	sw	$s4, REG_OFFSET(20)($a0)
	sw	$s5, REG_OFFSET(21)($a0)
	sw	$s6, REG_OFFSET(22)($a0)
	sw	$s7, REG_OFFSET(23)($a0)

	sw	$a2, REG_OFFSET(28)($a0)
	sw	$a3, REG_OFFSET(29)($a0)
	sw	$a1, REG_OFFSET(30)($a0)
	sw	$ra, REG_OFFSET(31)($a0)
	sw	$ra, (MCONTEXT_PC)($a0)

	POP_FRAME(libucontext_getcontext)

	jr	$ra
END(libucontext_getcontext)
