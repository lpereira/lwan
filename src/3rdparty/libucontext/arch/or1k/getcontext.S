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

ALIAS(getcontext, libucontext_getcontext)
ALIAS(__getcontext, libucontext_getcontext)

FUNC(libucontext_getcontext)
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

	l.jr		r9
	l.ori		r11, r0, 0
END(libucontext_getcontext)
