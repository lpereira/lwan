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

#define LOCALSZ (1)

#include "defs.h"

ALIAS(setcontext, libucontext_setcontext)

FUNC(libucontext_setcontext)
	PUSH_FRAME(libucontext_setcontext)

	/* move the context to $v0, in LA, $v0 = $a0 = $4 */
	move	$t5, $a0

	/* load the registers */
	ld.d	$a0, $t5, REG_OFFSET(4)
	ld.d	$a1, $t5, REG_OFFSET(5)
	ld.d	$a2, $t5, REG_OFFSET(6)
	ld.d	$a3, $t5, REG_OFFSET(7)
	ld.d	$a4, $t5, REG_OFFSET(8)
	ld.d	$a5, $t5, REG_OFFSET(9)
	ld.d	$a6, $t5, REG_OFFSET(10)
	ld.d	$a7, $t5, REG_OFFSET(11)

	ld.d	$s0, $t5, REG_OFFSET(23)
	ld.d	$s1, $t5, REG_OFFSET(24)
	ld.d	$s2, $t5, REG_OFFSET(25)
	ld.d	$s3, $t5, REG_OFFSET(26)
	ld.d	$s4, $t5, REG_OFFSET(27)
	ld.d	$s5, $t5, REG_OFFSET(28)
	ld.d	$s6, $t5, REG_OFFSET(29)
	ld.d	$s7, $t5, REG_OFFSET(30)
	ld.d	$s8, $t5, REG_OFFSET(31)

	ld.d	$sp, $t5, REG_OFFSET(3)
	ld.d	$fp, $t5, REG_OFFSET(22)
	ld.d	$ra, $t5, REG_OFFSET(1)

	ld.d	$t8, $t5, (MCONTEXT_PC)

	jr	$t8
	move	$v0, $zero

	POP_FRAME(libucontext_setcontext)
END(libucontext_setcontext)
