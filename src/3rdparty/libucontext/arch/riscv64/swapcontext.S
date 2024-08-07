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

ALIAS(swapcontext, libucontext_swapcontext)
ALIAS(__swapcontext, libucontext_swapcontext)

FUNC(libucontext_swapcontext)
	/* move $a1 to $t0 to avoid clobbering. */
	mv t0, a1

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

	/* restore the other context from $t0. */
	ld t1, REG_OFFSET(REG_PC)(t0)
	ld ra, REG_OFFSET(REG_RA)(t0)
	ld sp, REG_OFFSET(REG_SP)(t0)

	/* first saved register block */
	ld s0, REG_OFFSET(REG_S0)(t0)
	ld s1, REG_OFFSET(REG_S1)(t0)

	/* return register block */
	ld a0, REG_OFFSET(REG_A0)(t0)
	ld a1, REG_OFFSET(REG_A1)(t0)

	/* argument register block */
	ld a2, REG_OFFSET(REG_A2)(t0)
	ld a3, REG_OFFSET(REG_A3)(t0)
	ld a4, REG_OFFSET(REG_A4)(t0)
	ld a5, REG_OFFSET(REG_A5)(t0)
	ld a6, REG_OFFSET(REG_A6)(t0)
	ld a7, REG_OFFSET(REG_A7)(t0)

	/* second saved register block */
	ld s2, REG_OFFSET(REG_S2)(t0)
	ld s3, REG_OFFSET(REG_S3)(t0)
	ld s4, REG_OFFSET(REG_S4)(t0)
	ld s5, REG_OFFSET(REG_S5)(t0)
	ld s6, REG_OFFSET(REG_S6)(t0)
	ld s7, REG_OFFSET(REG_S7)(t0)
	ld s8, REG_OFFSET(REG_S8)(t0)
	ld s9, REG_OFFSET(REG_S9)(t0)
	ld s10, REG_OFFSET(REG_S10)(t0)
	ld s11, REG_OFFSET(REG_S11)(t0)

	/* done swapping, jump to new PC in S1 */
	jr t1
END(libucontext_swapcontext)
