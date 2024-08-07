/*
 * Copyright (c) 2018 Ariadne Conill <ariadne@dereferenced.org>
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

	.global PROC_NAME(libucontext_swapcontext);
	.align  2;
	TYPE(libucontext_swapcontext)
	ENT(libucontext_swapcontext)
PROC_NAME(libucontext_swapcontext):
	str	xzr, [x0, #REG_OFFSET(0)]

	/* save GPRs */
	stp	x2, x3,   [x0, #REG_OFFSET(2)]
	stp	x4, x5,   [x0, #REG_OFFSET(4)]
	stp	x6, x7,   [x0, #REG_OFFSET(6)]
	stp	x8, x9,   [x0, #REG_OFFSET(8)]
	stp	x10, x11, [x0, #REG_OFFSET(10)]
	stp	x12, x13, [x0, #REG_OFFSET(12)]
	stp	x14, x15, [x0, #REG_OFFSET(14)]
	stp	x16, x17, [x0, #REG_OFFSET(16)]
	stp	x18, x19, [x0, #REG_OFFSET(18)]
	stp	x20, x21, [x0, #REG_OFFSET(20)]
	stp	x22, x23, [x0, #REG_OFFSET(22)]
	stp	x24, x25, [x0, #REG_OFFSET(24)]
	stp	x26, x27, [x0, #REG_OFFSET(26)]
	stp	x28, x29, [x0, #REG_OFFSET(28)]
	str	x30,      [x0, #REG_OFFSET(30)]

	/* save current program counter in link register */
	str	x30, [x0, #PC_OFFSET]

	/* save current stack pointer */
	mov	x2, sp
	str	x2, [x0, #SP_OFFSET]

	/* save pstate */
	str	xzr, [x0, #PSTATE_OFFSET]

	add x2, x0, #FPSIMD_CONTEXT_OFFSET
	stp q8, q9,   [x2, #144]
	stp q10, q11, [x2, #176]
	stp q12, q13, [x2, #208]
	stp q14, q15, [x2, #240]

	/* context to swap to is in x1 so... we move to x0 and call setcontext */
	/* store our link register in x28 */
	mov	x28, x30

	/* move x1 to x0 and call setcontext */
	mov	x0, x1
	bl	PROC_NAME(libucontext_setcontext)

	/* hmm, we came back here try to return */
	mov	x30, x28
	ret
END(libucontext_swapcontext)
