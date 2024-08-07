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
	lgr	%r1, %r2			/* use %r1 as our working register */
	la	%r2, 0				/* we will return 0 */

	stam	%a0, %a15, AREG_OFFSET(0)(%r1)	/* store access registers */
	stmg	%r0, %r15, REG_OFFSET(0)(%r1)	/* store general-purpose registers */

	br	%r14				/* return to where we came from */
END(libucontext_getcontext)
