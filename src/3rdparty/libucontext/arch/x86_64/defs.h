#ifndef __ARCH_X86_64_DEFS_H
#define __ARCH_X86_64_DEFS_H

#ifndef REG_R8
# define REG_R8		(0)
#endif

#ifndef REG_R9
# define REG_R9		(1)
#endif

#ifndef REG_R10
# define REG_R10	(2)
#endif

#ifndef REG_R11
# define REG_R11	(3)
#endif

#ifndef REG_R12
# define REG_R12	(4)
#endif

#ifndef REG_R13
# define REG_R13	(5)
#endif

#ifndef REG_R14
# define REG_R14	(6)
#endif

#ifndef REG_R15
# define REG_R15	(7)
#endif

#ifndef REG_RDI
# define REG_RDI	(8)
#endif

#ifndef REG_RSI
# define REG_RSI	(9)
#endif

#ifndef REG_RBP
# define REG_RBP	(10)
#endif

#ifndef REG_RBX
# define REG_RBX	(11)
#endif

#ifndef REG_RDX
# define REG_RDX	(12)
#endif

#ifndef REG_RAX
# define REG_RAX	(13)
#endif

#ifndef REG_RCX
# define REG_RCX	(14)
#endif

#ifndef REG_RSP
# define REG_RSP	(15)
#endif

#ifndef REG_RIP
# define REG_RIP	(16)
#endif

#ifndef REG_EFL
# define REG_EFL	(17)
#endif

#ifndef REG_CSGSFS
# define REG_CSGSFS	(18)
#endif

#ifndef REG_ERR
# define REG_ERR	(19)
#endif

#ifndef REG_TRAPNO
# define REG_TRAPNO	(20)
#endif

#ifndef REG_OLDMASK
# define REG_OLDMASK	(21)
#endif

#ifndef REG_CR2
# define REG_CR2	(22)
#endif

#define MCONTEXT_GREGS	(40)

#define REG_SZ		(8)

#define FETCH_LINKPTR(dest) \
	asm("movq (%%rbx), %0" : "=r" ((dest)));

#include "common-defs.h"

#endif
