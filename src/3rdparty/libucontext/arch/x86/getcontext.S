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
	/* load address of the ucontext structure */
	movl	4(%esp), %eax

	/* EAX is not a preserved register */
	movl	$0, REG_OFFSET(REG_EAX)(%eax)

	/* copy all of the current registers into the ucontext structure */
	movl	%ecx, REG_OFFSET(REG_ECX)(%eax)
	movl	%ebx, REG_OFFSET(REG_EBX)(%eax)
	movl	%edx, REG_OFFSET(REG_EDX)(%eax)
	movl	%edi, REG_OFFSET(REG_EDI)(%eax)
	movl	%esi, REG_OFFSET(REG_ESI)(%eax)
	movl	%ebp, REG_OFFSET(REG_EBP)(%eax)

	/* the first argument on the stack is the jump target (%eip), so we store it in the EIP
	   register in the ucontext structure. */
	movl	(%esp), %ecx
	movl	%ecx, REG_OFFSET(REG_EIP)(%eax)

	/* take the stack pointer address (%esp) offsetting by 4 to skip over the jump target. */
	leal	4(%esp), %ecx
	movl	%ecx, REG_OFFSET(REG_ESP)(%eax)

	/* finally, save the FS segment register */
	xorl	%ecx, %ecx
	movw	%fs, %cx
	movl	%ecx, REG_OFFSET(REG_FS)(%eax)

	/* we're all done here, return 0 */
	xorl	%eax, %eax
	ret
END(libucontext_getcontext)
