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

ALIAS(getcontext, libucontext_getcontext)

FUNC(libucontext_getcontext)
	/* copy $sp, $fp to temporary registers so we don't clobber them */
	move	$a2, $sp
	move	$a3, $fp

	PUSH_FRAME(libucontext_getcontext)

	/* set registers */
	st.d	$s0, $a0, REG_OFFSET(23)
	st.d	$s1, $a0, REG_OFFSET(24)
	st.d	$s2, $a0, REG_OFFSET(25)
	st.d	$s3, $a0, REG_OFFSET(26)
	st.d	$s4, $a0, REG_OFFSET(27)
	st.d	$s5, $a0, REG_OFFSET(28)
	st.d	$s6, $a0, REG_OFFSET(29)
	st.d	$s7, $a0, REG_OFFSET(30)
	st.d	$s8, $a0, REG_OFFSET(31)

	st.d	$a2, $a0, REG_OFFSET(3)
	st.d	$a3, $a0, REG_OFFSET(22)
	st.d	$ra, $a0, REG_OFFSET(1)

	st.d	$ra, $a0, (MCONTEXT_PC)

	POP_FRAME(libucontext_getcontext)

	jr	$ra
END(libucontext_getcontext)
