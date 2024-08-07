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

ALIAS(setcontext, libucontext_setcontext)
ALIAS(__setcontext, libucontext_setcontext)

FUNC(libucontext_setcontext)
	l.ori		r30, r3, 0				/* avoid clobbering r3 by copying to r30 */

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
END(libucontext_setcontext)
