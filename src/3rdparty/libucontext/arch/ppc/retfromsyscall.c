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

#include <errno.h>

__attribute__ ((visibility ("hidden")))
int __retfromsyscall(long retval)
{
	if (retval < 0) {
		errno = -retval;
		return -1;
	}
	return 0;
}

