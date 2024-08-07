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

.hidden libucontext_trampoline
FUNC(libucontext_trampoline)
	basr	%r14, %r7			/* run function pointer (%r7) and return here */
	ltgr	%r8, %r8			/* check to see if uc_link (%r8) is null */

	jz	no_linked_context		/* if we have no linked context, prepare to exit */

	lgr	%r2, %r8			/* copy the uc_link structure address to %r2 */
	br	%r9				/* call setcontext */

no_linked_context:
	la	%r2, 0				/* return 0 */
	brasl	%r14, exit@plt			/* call exit */

	j	.+2				/* crash if exit returns */
END(libucontext_trampoline)
