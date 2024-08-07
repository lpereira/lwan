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

ALIAS(swapcontext, libucontext_swapcontext)
ALIAS(__swapcontext, libucontext_swapcontext)

FUNC(libucontext_swapcontext)
	/* copy all of the current registers into the ucontext structure */
	add	r2, r0, #REG_OFFSET(0)
	stmia	r2, {r0-r12}
	str	r13, [r0,#REG_OFFSET(13)]
	str	r14, [r0,#REG_OFFSET(15)]

#ifndef FORCE_SOFT_FLOAT
#ifndef FORCE_HARD_FLOAT
	/* test for vfp magic number, copy to other ucontext */
	ldr	r3, [r1, #VFP_MAGIC_OFFSET]
	ldr	r4, =#0x56465001
	str	r3, [r0, #VFP_MAGIC_OFFSET]
	cmp	r3, r4
	bne	1f
#endif
	/* if vfp in use, save and restore d8-d15 */
	.fpu	vfp
	add	r2, r0, #VFP_D8_OFFSET
	vstmia	r2, {d8-d15}

	add	r14, r1, #VFP_D8_OFFSET
	vldmia	r14, {d8-d15}
	.fpu	softvfp
1:
#endif

	/* load new registers from the second ucontext structure */
	add	r14, r1, #REG_OFFSET(0)
	ldmia	r14, {r0-r12}
	ldr	r13, [r14, #52]
	add	r14, r14, #56
	ldmia	r14, {r14, pc}
END(libucontext_swapcontext)
