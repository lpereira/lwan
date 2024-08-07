#ifndef LIBUCONTEXT_BITS_H
#define LIBUCONTEXT_BITS_H

#define REG_GS		(0)
#define REG_FS		(1)
#define REG_ES		(2)
#define REG_DS		(3)
#define REG_EDI		(4)
#define REG_ESI		(5)
#define REG_EBP		(6)
#define REG_ESP		(7)
#define REG_EBX		(8)
#define REG_EDX		(9)
#define REG_ECX		(10)
#define REG_EAX		(11)
#define REG_EIP		(14)

typedef int libucontext_greg_t, libucontext_gregset_t[19];

typedef struct libucontext_fpstate {
	unsigned long cw, sw, tag, ipoff, cssel, dataoff, datasel;
	struct {
		unsigned short significand[4], exponent;
	} _st[8];
	unsigned long status;
} *libucontext_fpregset_t;

typedef struct {
	libucontext_gregset_t gregs;
	libucontext_fpregset_t fpregs;
	unsigned long oldmask, cr2;
} libucontext_mcontext_t;

typedef struct {
	void *ss_sp;
	int ss_flags;
	size_t ss_size;
} libucontext_stack_t;

typedef struct libucontext_ucontext {
	unsigned long uc_flags;
	struct libucontext_ucontext *uc_link;
	libucontext_stack_t uc_stack;
	libucontext_mcontext_t uc_mcontext;
} libucontext_ucontext_t;

#endif

