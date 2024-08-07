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
	lgr	%r1, %r2			/* use %r1 as our working register */

	lam	%a2, %a15, AREG_OFFSET(2)(%r1)	/* load access registers, but skip %a0 and %a1 which are for TLS */
	lmg	%r0, %r15, REG_OFFSET(0)(%r1)	/* store general-purpose registers */

	br	%r14				/* return to new link register address */
END(libucontext_setcontext)
