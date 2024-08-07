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

#include "common-defs.h"

.hidden libucontext_trampoline
FUNC(libucontext_trampoline)
	cmpdi	31,0			/* test if ucontext link pointer is null */
	beq	no_linked_context	/* if it is, exit */

	/* now, call SYS_swapcontext */
	mr      4,31			/* ucp is in r31 */
	li      3,0			/* don't care about restoring, set oucp to NULL */
	li      5,1696			/* sizeof(ucontext_t) */
	li      0,249			/* SYS_swapcontext */
	sc

	/* we should not wind back up here, if we do, exit with -1 */
	li	3,-1

no_linked_context:
	b	exit@GOT
	nop
END(libucontext_trampoline)
