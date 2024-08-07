#ifndef __ARCH_M68K_DEFS_H
#define __ARCH_M68K_DEFS_H

#define REG_SZ		(4)
#define MCONTEXT_GREGS	(24)

#define REG_D0		(0)
#define REG_D1		(1)
#define REG_D2		(2)
#define REG_D3		(3)
#define REG_D4		(4)
#define REG_D5		(5)
#define REG_D6		(6)
#define REG_D7		(7)
#define REG_A0		(8)
#define REG_A1		(9)
#define REG_A2		(10)
#define REG_A3		(11)
#define REG_A4		(12)
#define REG_A5		(13)
#define REG_A6		(14)
#define REG_A7		(15)
#define REG_SP		(15)
#define REG_PC		(16)
#define REG_PS		(17)

#define PC_OFFSET	REG_OFFSET(REG_PC)

#define FETCH_LINKPTR(dest) \
	asm("mov.l (%%sp, %%d7.l * 4), %0" :: "r" ((dest)))

#include "common-defs.h"

#endif
