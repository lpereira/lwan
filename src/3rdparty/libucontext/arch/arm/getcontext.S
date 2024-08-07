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

ALIAS(getcontext, libucontext_getcontext)
ALIAS(__getcontext, libucontext_getcontext)

FUNC(libucontext_getcontext)
	/* copy all of the current registers into the ucontext structure */
	add	r1, r0, #REG_OFFSET(4)
	stmia	r1, {r4-r12}
	str	r13, [r0, #REG_OFFSET(13)]
	str	r14, [r0, #REG_OFFSET(15)]

#ifndef FORCE_SOFT_FLOAT
#ifndef FORCE_HARD_FLOAT
        /* test for vfp, set kernel-defined magic number in uc_regspace */
        push    {r0-r1,fp,lr}
        mov     r0, #16
        bl      getauxval
        tst     r0, #64
        pop     {r0-r1,fp,lr}
	moveq	r2, #0
	ldrne	r2, =#0x56465001
	str	r2, [r0, #VFP_MAGIC_OFFSET]
        beq     1f
#endif
	/* if vfp detected, save d8-d15 */
	.fpu	vfp
	add	r1, r0, #VFP_D8_OFFSET
	vstmia	r1, {d8-d15}
	.fpu	softvfp
1:
#endif

	/* return 0 */
	mov	r0, #0
	mov	pc, lr
END(libucontext_getcontext)
