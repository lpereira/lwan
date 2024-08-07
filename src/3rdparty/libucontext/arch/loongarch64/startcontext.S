/*
 * Copyright (c) 2021 Peng Fan <fanpeng@loongson.cn>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * This software is provided 'as is' and without any warranty, express or
 * implied.  In no event shall the authors be liable for any damages arising
 * from the use of this software.
 */

#define LOCALSZ (4)

#include "defs.h"

FUNC(libucontext_trampoline)

	/* call setcontext */
	move	$a0, $s0
	/* we receive our initial ucontext in $s0, so if $s0 is nil, bail */
	beqz	$s0, no_linked_context

	la.got	$t8, libucontext_setcontext

	jr	$t8

no_linked_context:
	move	$a0, $zero
	la.global	$t8, exit
	jr	$t8

END(libucontext_trampoline)
