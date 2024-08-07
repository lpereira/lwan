#ifndef LIBUCONTEXT_BITS_H
#define LIBUCONTEXT_BITS_H

typedef unsigned long libucontext_greg_t;
typedef unsigned long libucontext_gregset_t[34];

typedef struct {
	__uint128_t vregs[32];
	unsigned int fpsr;
	unsigned int fpcr;
} libucontext_fpregset_t;

typedef struct sigcontext {
	unsigned long fault_address;
	unsigned long regs[31];
	unsigned long sp, pc, pstate;
	long double __reserved[256];
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
	unsigned char __pad[136];
	libucontext_mcontext_t uc_mcontext;
} libucontext_ucontext_t;

#endif
