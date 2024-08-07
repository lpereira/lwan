/*
 * Copyright (c) 2018, 2020 Ariadne Conill <ariadne@dereferenced.org>
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

	.global PROC_NAME(libucontext_setcontext);
	.align  2;
	TYPE(libucontext_setcontext)
	ENT(libucontext_setcontext)
PROC_NAME(libucontext_setcontext):
	/* restore GPRs */
	ldp	x18, x19, [x0, #REG_OFFSET(18)]
	ldp	x20, x21, [x0, #REG_OFFSET(20)]
	ldp	x22, x23, [x0, #REG_OFFSET(22)]
	ldp	x24, x25, [x0, #REG_OFFSET(24)]
	ldp	x26, x27, [x0, #REG_OFFSET(26)]
	ldp	x28, x29, [x0, #REG_OFFSET(28)]
	ldr	x30,      [x0, #REG_OFFSET(30)]

	/* save current stack pointer */
	ldr	x2, [x0, #SP_OFFSET]
	mov	sp, x2

	add x2, x0, #FPSIMD_CONTEXT_OFFSET
	ldp q8, q9,   [x2, #144]
	ldp q10, q11, [x2, #176]
	ldp q12, q13, [x2, #208]
	ldp q14, q15, [x2, #240]

	/* save current program counter in link register */
	ldr	x16, [x0, #PC_OFFSET]

	/* restore args */
	ldp	x2, x3, [x0, #REG_OFFSET(2)]
	ldp	x4, x5, [x0, #REG_OFFSET(4)]
	ldp	x6, x7, [x0, #REG_OFFSET(6)]
	ldp	x0, x1, [x0, #REG_OFFSET(0)]

	/* jump to new PC */
	br	x16
END(libucontext_setcontext)
