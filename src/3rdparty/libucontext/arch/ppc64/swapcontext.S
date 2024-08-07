/*
 * Copyright (c) 2019 Bobby Bingham <koorogi@koorogi.info>
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

ALIAS(swapcontext, __libucontext_swapcontext)
ALIAS(__swapcontext, __libucontext_swapcontext)

/* make sure this is visible regardless of EXPORT_UNPREFIXED */
.weak libucontext_swapcontext
libucontext_swapcontext = __libucontext_swapcontext

FUNC(__libucontext_swapcontext)
	addis 2, 12, .TOC.-__libucontext_swapcontext@ha
	addi  2, 12, .TOC.-__libucontext_swapcontext@l

	.localentry __libucontext_swapcontext,.-__libucontext_swapcontext

	li 0, 249     # SYS_swapcontext
	li 5, 1696    # sizeof(ucontext_t)
	sc

.hidden __retfromsyscall
	b __retfromsyscall
END(__libucontext_swapcontext)
