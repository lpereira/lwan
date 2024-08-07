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

#include "defs.h"

ALIAS(getcontext, libucontext_getcontext)
ALIAS(__getcontext, libucontext_getcontext)

FUNC(libucontext_getcontext)
	sd ra, REG_OFFSET(REG_PC)(a0)
	sd ra, REG_OFFSET(REG_RA)(a0)
	sd sp, REG_OFFSET(REG_SP)(a0)

	/* first saved register block */
	sd s0, REG_OFFSET(REG_S0)(a0)
	sd s1, REG_OFFSET(REG_S1)(a0)

	/* return register block */
	sd a0, REG_OFFSET(REG_A0)(a0)
	sd a1, REG_OFFSET(REG_A1)(a0)

	/* second saved register block */
	sd s2, REG_OFFSET(REG_S2)(a0)
	sd s3, REG_OFFSET(REG_S3)(a0)
	sd s4, REG_OFFSET(REG_S4)(a0)
	sd s5, REG_OFFSET(REG_S5)(a0)
	sd s6, REG_OFFSET(REG_S6)(a0)
	sd s7, REG_OFFSET(REG_S7)(a0)
	sd s8, REG_OFFSET(REG_S8)(a0)
	sd s9, REG_OFFSET(REG_S9)(a0)
	sd s10, REG_OFFSET(REG_S10)(a0)
	sd s11, REG_OFFSET(REG_S11)(a0)

	/* done saving, return */
	ret
END(libucontext_getcontext)
