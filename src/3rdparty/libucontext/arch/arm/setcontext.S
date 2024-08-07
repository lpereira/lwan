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

FUNC(libucontext_setcontext)
#ifndef FORCE_SOFT_FLOAT
#ifndef FORCE_HARD_FLOAT
	/* test for vfp magic number set by getcontext */
	ldr	r2, [r0, #VFP_MAGIC_OFFSET]
	ldr	r3, =#0x56465001
	cmp	r2, r3
        bne     1f
#endif
	/* if vfp in use, restore d8-d15 from uc_regspace */
	.fpu	vfp
	add	r14, r0, #VFP_D8_OFFSET
	vldmia	r14, {d8-d15}
	.fpu 	softvfp
1:
#endif

	/* copy all of the current registers into the ucontext structure */
	add	r14, r0, #REG_OFFSET(0)
	ldmia	r14, {r0-r12}
	ldr	r13, [r14, #52]
	add	r14, r14, #56

	/* load link register and jump to new context */
	ldmia	r14, {r14, pc}
END(libucontext_setcontext)
