#ifndef __ARCH_SH4_DEFS_H
#define __ARCH_SH4_DEFS_H

#define REG_SZ			(4)
#define MCONTEXT_GREGS		(24)

#define REG_SP			(15)
#define REG_PC			(16)
#define REG_PR			(17)
#define REG_SR			(18)
#define REG_GBR			(19)
#define REG_MACH		(20)
#define REG_MACL		(21)

#define FETCH_LINKPTR(dest)	\
	asm("mov r8, %0" : "=r" (dest));

#include "common-defs.h"

#endif
