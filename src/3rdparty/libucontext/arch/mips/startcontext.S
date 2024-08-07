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

LOCALSZ = 1

#include "defs.h"

.hidden libucontext_trampoline
FUNC(libucontext_trampoline)
	move	$gp, $s1

	/* we receive our initial ucontext in $s0, so if $s0 is nil, bail */
	beqz	$s0, no_linked_context

	/* call setcontext */
	move	$a0, $s0
	la	$t9, PROC_NAME(libucontext_setcontext)

	jr	$t9

no_linked_context:
	move	$a0, $zero
	la	$t9, exit
	jalr	$t9
	nop
END(libucontext_trampoline)
