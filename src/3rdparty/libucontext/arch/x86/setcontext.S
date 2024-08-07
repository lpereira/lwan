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
	/* load address of the ucontext structure */
	movl	4(%esp), %eax

	/* set up the FS segment register */
	movl	REG_OFFSET(REG_FS)(%eax), %ecx
	movw	%cx, %fs

	/* fetch the new EIP */
	movl	REG_OFFSET(REG_EIP)(%eax), %ecx

	/* set up the new stack pointer */
	movl	REG_OFFSET(REG_ESP)(%eax), %esp

	/* push the return address onto the stack */
	pushl	%ecx

	/* set all of the registers */
	movl	REG_OFFSET(REG_EBX)(%eax), %ebx
	movl	REG_OFFSET(REG_ECX)(%eax), %ecx
	movl	REG_OFFSET(REG_EDX)(%eax), %edx
	movl	REG_OFFSET(REG_EBP)(%eax), %ebp
	movl	REG_OFFSET(REG_EDI)(%eax), %edi
	movl	REG_OFFSET(REG_ESI)(%eax), %esi
	movl	REG_OFFSET(REG_EAX)(%eax), %eax

	ret
END(libucontext_setcontext)
