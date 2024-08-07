#ifndef __ARCH_X86_DEFS_H
#define __ARCH_X86_DEFS_H

#ifndef REG_GS
# define REG_GS		(0)
#endif

#ifndef REG_FS
# define REG_FS		(1)
#endif

#ifndef REG_ES
# define REG_ES		(2)
#endif

#ifndef REG_DS
# define REG_DS		(3)
#endif

#ifndef REG_EDI
# define REG_EDI	(4)
#endif

#ifndef REG_ESI
# define REG_ESI	(5)
#endif

#ifndef REG_EBP
# define REG_EBP	(6)
#endif

#ifndef REG_ESP
# define REG_ESP	(7)
#endif

#ifndef REG_EBX
# define REG_EBX	(8)
#endif

#ifndef REG_EDX
# define REG_EDX	(9)
#endif

#ifndef REG_ECX
# define REG_ECX	(10)
#endif

#ifndef REG_EAX
# define REG_EAX	(11)
#endif

#ifndef REG_EIP
# define REG_EIP	(14)
#endif

#define REG_SZ		(4)

#define MCONTEXT_GREGS	(20)

#define FETCH_LINKPTR(dest) \
	asm("movl (%%esp, %%ebx, 4), %0" : "=r" ((dest)));

#include "common-defs.h"

#endif
