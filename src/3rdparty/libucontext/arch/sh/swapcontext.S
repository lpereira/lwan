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

	mov	r5, r0						/* now restore the new context */

	add	#(REG_OFFSET(6)), r0				/* restore GPRs r6-15 */
	mov.l	@r0+, r6
	mov.l	@r0+, r7
	mov.l	@r0+, r8
	mov.l	@r0+, r9
	mov.l	@r0+, r10
	mov.l	@r0+, r11
	mov.l	@r0+, r12
	mov.l	@r0+, r13
	mov.l	@r0+, r14
	mov.l	@r0+, r15

	mov.l	@r0+, r2					/* restore PR */
	lds.l	@r0+, pr

	mov.l	@r0+, r1					/* restore T-flag */
	shlr	r1

	add	#REG_SZ, r0					/* skip GBR (used for TLS) */

	lds.l	@r0+, mach					/* load mach/macl registers */
	lds.l	@r0+, macl

	mov	r5, r0						/* bring r0 back to the top of the context */
	add	#(REG_OFFSET(0)), r1				/* restore r0 into r1 (temporarily) */
	mov.l	r1, @-r15					/* push to stack from r1 */
	mov.l	r2, @-r15					/* push PC to stack */

	mov.l	@(REG_OFFSET(1), r0), r1			/* restore real r1 */
	mov.l	@(REG_OFFSET(2), r0), r2			/* restore real r2 */
	mov.l	@(REG_OFFSET(3), r0), r3			/* restore real r3 */
	mov.l	@(REG_OFFSET(4), r0), r4			/* restore real r4 */
	mov.l	@(REG_OFFSET(5), r0), r5			/* restore real r5 */

	mov.l	@r15+, r0					/* pop PC from stack */

	jmp	@r0						/* jump to new PC */

	mov.l	@r15+, r0					/* pop original r0 from stack */
END(libucontext_swapcontext)
