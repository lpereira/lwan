/*
 * Copyright (c) 2022 Ariadne Conill <ariadne@dereferenced.org>
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
	/* copy context into r3 like getcontext */
	l.sw		REG_OFFSET(1)(r3), r1			/* store r1 and r2 */
	l.sw		REG_OFFSET(2)(r3), r2

	l.sw		REG_OFFSET(9)(r3), r9			/* store r9 to both r9 and r11 in the context */
	l.sw		REG_OFFSET(11)(r3), r9

	l.sw		REG_OFFSET(10)(r3), r10			/* store r10 for TLS */

	l.sw		REG_OFFSET(14)(r3), r14			/* store r14 through r30 even */
	l.sw		REG_OFFSET(16)(r3), r16
	l.sw		REG_OFFSET(18)(r3), r18
	l.sw		REG_OFFSET(20)(r3), r20
	l.sw		REG_OFFSET(22)(r3), r22
	l.sw		REG_OFFSET(24)(r3), r24
	l.sw		REG_OFFSET(26)(r3), r26
	l.sw		REG_OFFSET(28)(r3), r28
	l.sw		REG_OFFSET(30)(r3), r30

	/* set the new context from r4 */
	l.ori		r30, r4, 0				/* copy r4 to r30 to avoid clobbering */

	l.lwz		r3, REG_OFFSET(3)(r30)			/* restore r3-r8 (argument registers) */
	l.lwz		r4, REG_OFFSET(4)(r30)
	l.lwz		r5, REG_OFFSET(5)(r30)
	l.lwz		r6, REG_OFFSET(6)(r30)
	l.lwz		r7, REG_OFFSET(7)(r30)
	l.lwz		r8, REG_OFFSET(8)(r30)

	l.lwz		r1, REG_OFFSET(1)(r30)			/* restore stack/frame pointers */
	l.lwz		r2, REG_OFFSET(2)(r30)

	l.lwz		r9, REG_OFFSET(9)(r30)			/* restore link register and starting address register */
	l.lwz		r11, REG_OFFSET(11)(r30)

	l.lwz		r10, REG_OFFSET(10)(r30)		/* restore TLS register */

	l.lwz		r14, REG_OFFSET(14)(r30)		/* restore r14-r30, even only */
	l.lwz		r16, REG_OFFSET(16)(r30)
	l.lwz		r18, REG_OFFSET(18)(r30)
	l.lwz		r20, REG_OFFSET(20)(r30)
	l.lwz		r22, REG_OFFSET(22)(r30)
	l.lwz		r24, REG_OFFSET(24)(r30)
	l.lwz		r26, REG_OFFSET(26)(r30)
	l.lwz		r28, REG_OFFSET(28)(r30)
	l.lwz		r30, REG_OFFSET(30)(r30)

	l.jr		r11					/* jump to new starting address */
	l.ori		r11, r0, 0
END(libucontext_swapcontext)
