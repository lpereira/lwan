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
	/* get the proper context into position and test for NULL */
	mr.	3,31

	/* if we have no linked context, lets get out of here */
	beq	no_linked_context

	/* jump to setcontext */
	bl	libucontext_setcontext@local

no_linked_context:
	b	exit@GOT
END(libucontext_trampoline)
