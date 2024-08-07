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
	/* set all of the registers */
	movq	REG_OFFSET(REG_R8)(%rdi), %r8
	movq	REG_OFFSET(REG_R9)(%rdi), %r9
	movq	REG_OFFSET(REG_R10)(%rdi), %r10
	movq	REG_OFFSET(REG_R11)(%rdi), %r11
	movq	REG_OFFSET(REG_R12)(%rdi), %r12
	movq	REG_OFFSET(REG_R13)(%rdi), %r13
	movq	REG_OFFSET(REG_R14)(%rdi), %r14
	movq	REG_OFFSET(REG_R15)(%rdi), %r15
	movq	REG_OFFSET(REG_RSI)(%rdi), %rsi
	movq	REG_OFFSET(REG_RBP)(%rdi), %rbp
	movq	REG_OFFSET(REG_RBX)(%rdi), %rbx
	movq	REG_OFFSET(REG_RDX)(%rdi), %rdx
	movq	REG_OFFSET(REG_RAX)(%rdi), %rax
	movq	REG_OFFSET(REG_RCX)(%rdi), %rcx
	movq	REG_OFFSET(REG_RSP)(%rdi), %rsp

	/* set the jump target by pushing it to the stack.
	   ret will pop the new %rip from the stack, causing us to jump there. */
	pushq	REG_OFFSET(REG_RIP)(%rdi)

	/* finally, set %rdi correctly. */
	movq	REG_OFFSET(REG_RDI)(%rdi), %rdi

	/* we're all done here, return 0 */
	xorl	%eax, %eax
	ret
END(libucontext_setcontext)
