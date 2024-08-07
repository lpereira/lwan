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
	move.l		4(%sp), %a0				/* load ucontext_t pointer from stack */

	movem.l		%d2-%d7, REG_OFFSET(REG_D2)(%a0)	/* preserve $d2 through $d7 */
	movem.l		%a2-%a6, REG_OFFSET(REG_A2)(%a0)	/* preserve $a2 through $a6 */

	lea		4(%sp), %a1				/* load stack pointer into $a1 */
	move.l		%a1, REG_OFFSET(REG_SP)(%a0)		/* store $a1 in ucontext */
	move.l		(%sp), REG_OFFSET(REG_PC)(%a0)		/* store return address in ucontext's PC register */

	clr.l		%d0					/* return 0 */
	rts
END(libucontext_getcontext)
