#ifndef LIBUCONTEXT_BITS_H
#define LIBUCONTEXT_BITS_H

typedef unsigned long long libucontext_greg_t, libucontext_gregset_t[32];

typedef struct {
	unsigned regmask, status;
	unsigned long long pc, gregs[32], fpregs[32];
	unsigned ownedfp, fpc_csr, fpc_eir, used_math, dsp;
	unsigned long long mdhi, mdlo;
	unsigned long hi1, lo1, hi2, lo2, hi3, lo3;
} libucontext_mcontext_t;

typedef struct {
	void *ss_sp;
	size_t ss_size;
	int ss_flags;
} libucontext_stack_t;

typedef struct libucontext_ucontext {
	unsigned long uc_flags;
	struct libucontext_ucontext *uc_link;
	libucontext_stack_t uc_stack;
	libucontext_mcontext_t uc_mcontext;
} libucontext_ucontext_t;

#endif
