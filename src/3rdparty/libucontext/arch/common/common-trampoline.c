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

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

__attribute__ ((visibility ("hidden")))
void
libucontext_trampoline(void)
{
	register libucontext_ucontext_t *uc_link = NULL;

	FETCH_LINKPTR(uc_link);

	if (uc_link == NULL)
		exit(0);

	libucontext_setcontext(uc_link);
}
