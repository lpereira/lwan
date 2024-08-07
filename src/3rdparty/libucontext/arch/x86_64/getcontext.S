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
	/* copy all of the current registers into the ucontext structure */
	movq	%r8, REG_OFFSET(REG_R8)(%rdi)
	movq	%r9, REG_OFFSET(REG_R9)(%rdi)
	movq	%r10, REG_OFFSET(REG_R10)(%rdi)
	movq	%r11, REG_OFFSET(REG_R11)(%rdi)
	movq	%r12, REG_OFFSET(REG_R12)(%rdi)
	movq	%r13, REG_OFFSET(REG_R13)(%rdi)
	movq	%r14, REG_OFFSET(REG_R14)(%rdi)
	movq	%r15, REG_OFFSET(REG_R15)(%rdi)
	movq	%rdi, REG_OFFSET(REG_RDI)(%rdi)
	movq	%rsi, REG_OFFSET(REG_RSI)(%rdi)
	movq	%rbp, REG_OFFSET(REG_RBP)(%rdi)
	movq	%rbx, REG_OFFSET(REG_RBX)(%rdi)
	movq	%rdx, REG_OFFSET(REG_RDX)(%rdi)
	movq	%rax, REG_OFFSET(REG_RAX)(%rdi)
	movq	%rcx, REG_OFFSET(REG_RCX)(%rdi)

	/* the first argument on the stack is the jump target (%rip), so we store it in the RIP
	   register in the ucontext structure. */
	movq	(%rsp), %rcx
	movq	%rcx, REG_OFFSET(REG_RIP)(%rdi)

	/* finally take the stack pointer address (%rsp) offsetting by 8 to skip over the jump
	   target. */
	leaq	8(%rsp), %rcx
	movq	%rcx, REG_OFFSET(REG_RSP)(%rdi)

	/* we're all done here, return 0 */
	xorl	%eax, %eax
	ret
END(libucontext_getcontext)
