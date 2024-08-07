#ifndef __ARCH_OR1K_DEFS_H
#define __ARCH_OR1K_DEFS_H

#define REG_SZ		(4)
#define MCONTEXT_GREGS	(20)

#define REG_SP		(1)
#define REG_FP		(2)
#define REG_RA		(9)
#define REG_SA		(11)
#define REG_LR		(14)
#define REG_PC		(33)
#define REG_SR		(34)

#define PC_OFFSET	REG_OFFSET(REG_PC)

#define FETCH_LINKPTR(dest) \
	asm("l.ori %0, r14, 0" :: "r" ((dest)))

#include "common-defs.h"

#endif
