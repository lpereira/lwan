/*
 * Copyright (c) 2022 Ariadne Conill <ariadne@dereferenced.org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * This software is provided 'as is' and without any warranty, express or
 * implied.  In no event shall the authors be liable for any damages arising
 * from the use of this software.
 */

#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include "defs.h"
#include <libucontext/libucontext.h>


extern void libucontext_trampoline(void);


void
libucontext_makecontext(libucontext_ucontext_t *ucp, void (*func)(void), int argc, ...)
{
	libucontext_greg_t *sp;
	va_list va;
	int i;

	/* set up and align the stack. */
	sp = (libucontext_greg_t *) ((uintptr_t) ucp->uc_stack.ss_sp + ucp->uc_stack.ss_size);
	sp -= argc < 6 ? 0 : (argc - 6);
	sp = (libucontext_greg_t *) (((uintptr_t) sp & ~0x3));

	/* set up the ucontext structure */
	ucp->uc_mcontext.regs.gpr[REG_SP] = (libucontext_greg_t) sp;
	ucp->uc_mcontext.regs.gpr[REG_RA] = (libucontext_greg_t) &libucontext_trampoline;
	ucp->uc_mcontext.regs.gpr[REG_FP] = 0;
	ucp->uc_mcontext.regs.gpr[REG_SA] = (libucontext_greg_t) func;
	ucp->uc_mcontext.regs.gpr[REG_LR] = (libucontext_greg_t) ucp->uc_link;

	va_start(va, argc);

	/* args less than argv[6] have dedicated registers, else they overflow onto stack */
	for (i = 0; i < argc; i++)
	{
		if (i < 6)
			ucp->uc_mcontext.regs.gpr[i + 3] = va_arg (va, libucontext_greg_t);
		else
			sp[i - 6] = va_arg (va, libucontext_greg_t);
	}

	va_end(va);
}

#ifdef EXPORT_UNPREFIXED
extern __typeof(libucontext_makecontext) makecontext __attribute__((weak, __alias__("libucontext_makecontext")));
extern __typeof(libucontext_makecontext) __makecontext __attribute__((weak, __alias__("libucontext_makecontext")));
#endif
