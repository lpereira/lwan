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
	mov	r4, r0						/* move r4 to r0, and increment by REG_OFFSET(REG_MACL) + REG_SZ. */
	add	#(REG_OFFSET(REG_MACL + 1)), r0

	sts.l	macl, @-r0					/* save macl/mach registers */
	sts.l	mach, @-r0

	stc.l	gbr, @-r0					/* save gbr register */

	movt	r1						/* load T-flag into r1 */
	mov.l	r1, @-r0					/* save T-flag as SR register */

	sts.l	pr, @-r0					/* save current PR */
	sts.l	pr, @-r0					/* save current PR as PC as well */

	mov.l	r15, @-r0					/* preserve registers backwards, from r15 to r1 */
	mov.l	r14, @-r0
	mov.l	r13, @-r0
	mov.l	r12, @-r0
	mov.l	r11, @-r0
	mov.l	r10, @-r0
	mov.l	r9, @-r0
	mov.l	r8, @-r0
	mov.l	r7, @-r0
	mov.l	r6, @-r0
	mov.l	r5, @-r0
	mov.l	r4, @-r0
	mov.l	r3, @-r0
	mov.l	r2, @-r0
	mov.l	r1, @-r0

	mov	r0, r1
	mov	#0, r0

	mov.l	r0, @-r1					/* preserve r0 as explicit zero */

	mov	#0, r0						/* set return value as zero */
	rts
END(libucontext_getcontext)
