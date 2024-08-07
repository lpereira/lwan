#ifndef __ARCH_MIPS64_DEFS_H
#define __ARCH_MIPS64_DEFS_H

#define REG_SZ		(8)

#define REG_R0		(0)
#define REG_R1		(1)
#define REG_R2		(2)
#define REG_R3		(3)
#define REG_R4		(4)
#define REG_R5		(5)
#define REG_R6		(6)
#define REG_R7		(7)
#define REG_R8		(8)
#define REG_R9		(9)
#define REG_R10		(10)
#define REG_R11		(11)
#define REG_R12		(12)
#define REG_R13		(13)
#define REG_R14		(14)
#define REG_R15		(15)
#define REG_R16		(16)
#define REG_R17		(17)
#define REG_R18		(18)
#define REG_R19		(19)
#define REG_R20		(20)
#define REG_R21		(21)
#define REG_R22		(22)
#define REG_R23		(23)
#define REG_R24		(24)
#define REG_R25		(25)
#define REG_R26		(26)
#define REG_R27		(27)
#define REG_R28		(28)
#define REG_R29		(29)
#define REG_R30		(30)
#define REG_R31		(31)

/* $a0 is $4 */
#define REG_A0		(4)

/* stack pointer is actually $29 */
#define REG_SP		(29)

/* frame pointer is actually $30 */
#define REG_FP		(30)

/* $s0 ($16) is used as link register */
#define REG_LNK		(16)

/* $t9 ($25) is used as entry */
#define REG_ENTRY	(25)

/* offset to mc_gregs in ucontext_t */
#define MCONTEXT_GREGS	(40)

/* offset to PC in ucontext_t */
#define MCONTEXT_PC	(MCONTEXT_GREGS + 576)

/* offset to uc_link in ucontext_t */
#define UCONTEXT_UC_LINK	(8)

/* offset to uc_stack.ss_sp in ucontext_t */
#define UCONTEXT_STACK_PTR	(16)

/* offset to uc_stack.ss_size in ucontext_t */
#define UCONTEXT_STACK_SIZE	(24)

/* setup frame, from MIPS N32/N64 calling convention manual */
#define ALSZ		15
#define ALMASK		~15
#define FRAMESZ		(((LOCALSZ * REG_SZ) + ALSZ) & ALMASK)		// 16
#define GPOFF		(FRAMESZ - (LOCALSZ * REG_SZ))			// [16 - 16]

#define SETUP_FRAME(__proc)				\
	.frame		$sp, FRAMESZ, $ra;		\
	.mask		0x10000000, 0;			\
	.fmask		0x00000000, 0;

#define PUSH_FRAME(__proc)				\
	daddiu		$sp, -FRAMESZ;			\
	.cpsetup	$25, GPOFF, __proc;

#define POP_FRAME(__proc)				\
	.cpreturn;					\
	daddiu		$sp, FRAMESZ

#define ENT(__proc)	.ent    __proc, 0;

#include <common-defs.h>

#endif
