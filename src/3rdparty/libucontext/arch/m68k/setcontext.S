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

ALIAS(setcontext, libucontext_setcontext)
ALIAS(__setcontext, libucontext_setcontext)

FUNC(libucontext_setcontext)
	move.l		4(%sp), %a0				/* load ucontext_t pointer from stack */

	move.l		REG_OFFSET(REG_SP)(%a0), %sp		/* load new stack pointer */

	movem.l		REG_OFFSET(REG_D2)(%a0), %d2-%d7	/* load $d2 through $d7 */
	movem.l		REG_OFFSET(REG_A2)(%a0), %a2-%a6	/* load $a2 through $a6 */

	clr.l		%d0					/* clear $d0 */

	move.l		REG_OFFSET(REG_PC)(%a0), %a1		/* load jump target */

	jmp		(%a1)					/* jump to *$a1 */
END(libucontext_setcontext)
