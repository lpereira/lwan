/*
 * Copyright (c) 2018 Ariadne Conill <ariadne@dereferenced.org>
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

#include <stdarg.h>
#include <stdint.h>


#include "defs.h"
#include <libucontext/libucontext.h>


extern void libucontext_trampoline(void);


void
libucontext_makecontext(libucontext_ucontext_t *ucp, void (*func)(), int argc, ...)
{
	libucontext_greg_t *sp;
	va_list va;
	int i;
	unsigned int stack_args;

	stack_args = argc > 8 ? argc : 0;

	sp = (libucontext_greg_t *) ((uintptr_t) ucp->uc_stack.ss_sp + ucp->uc_stack.ss_size);
	sp -= stack_args + 4;
	sp = (libucontext_greg_t *) ((uintptr_t) sp & -16L);

	ucp->uc_mcontext.gp_regs[REG_NIP]   = (uintptr_t) func;
	ucp->uc_mcontext.gp_regs[REG_LNK]   = (uintptr_t) &libucontext_trampoline;
	ucp->uc_mcontext.gp_regs[REG_SP]    = (uintptr_t) sp;
	ucp->uc_mcontext.gp_regs[REG_ENTRY] = (uintptr_t) func;
	ucp->uc_mcontext.gp_regs[REG_R31]   = (uintptr_t) ucp->uc_link;

	sp[0] = 0;

	va_start(va, argc);

	for (i = 0; i < argc; i++) {
		if (i < 8)
			ucp->uc_mcontext.gp_regs[i + 3] = va_arg (va, libucontext_greg_t);
		else
			sp[i + 4] = va_arg (va, libucontext_greg_t);
	}

	va_end(va);
}

#ifdef EXPORT_UNPREFIXED
extern __typeof(libucontext_makecontext) makecontext __attribute__((weak, __alias__("libucontext_makecontext")));
extern __typeof(libucontext_makecontext) __makecontext __attribute__((weak, __alias__("libucontext_makecontext")));
#endif
