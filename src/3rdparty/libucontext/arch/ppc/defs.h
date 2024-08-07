#ifndef __ARCH_PPC_DEFS_H
#define __ARCH_PPC_DEFS_H

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
#define REG_R32		(32)
#define REG_R33		(33)
#define REG_R34		(34)
#define REG_R35		(35)
#define REG_R36		(36)
#define REG_R37		(37)
#define REG_R38		(38)
#define REG_R39		(39)
#define REG_R40		(40)
#define REG_R41		(41)
#define REG_R42		(42)
#define REG_R43		(43)
#define REG_R44		(44)
#define REG_R45		(45)
#define REG_R46		(46)
#define REG_R47		(47)

/* sp register is actually %r1 */
#define REG_SP		REG_R1

/* nip register is actually %srr0 (r32) */
#define REG_NIP		REG_R32

/* lnk register is actually r32 */
#define REG_LNK		REG_R36

#include "common-defs.h"

#endif
