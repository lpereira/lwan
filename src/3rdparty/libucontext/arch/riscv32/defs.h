#ifndef __ARCH_RISCV64_DEFS_H
#define __ARCH_RISCV64_DEFS_H

#define REG_SZ		(4)
#define MCONTEXT_GREGS	(160)

/* program counter is saved in x0 as well as x1, similar to mips */
#ifndef REG_PC
#define REG_PC		(0)
#endif

#ifndef REG_RA
#define REG_RA		(1)
#endif

#ifndef REG_SP
#define REG_SP		(2)
#endif

#ifndef REG_S0
#define REG_S0		(8)
#endif

#define REG_S1		(9)

#ifndef REG_A0
#define REG_A0		(10)
#endif

#define REG_A1		(11)
#define REG_A2		(12)
#define REG_A3		(13)
#define REG_A4		(14)
#define REG_A5		(15)
#define REG_A6		(16)
#define REG_A7		(17)
#define REG_S2		(18)
#define REG_S3		(19)
#define REG_S4		(20)
#define REG_S5		(21)
#define REG_S6		(22)
#define REG_S7		(23)
#define REG_S8		(24)
#define REG_S9		(25)
#define REG_S10		(26)
#define REG_S11		(27)

#define PC_OFFSET	REG_OFFSET(REG_PC)

#define FETCH_LINKPTR(dest) \
	asm("mv	%0, s1" : "=r" ((dest)))

#include "common-defs.h"

#endif
