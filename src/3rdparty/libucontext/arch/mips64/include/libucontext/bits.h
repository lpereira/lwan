#ifndef LIBUCONTEXT_BITS_H
#define LIBUCONTEXT_BITS_H

typedef unsigned long long libucontext_greg_t, libucontext_gregset_t[32];

typedef struct {
	union {
		double fp_dregs[32];
		struct {
			float _fp_fregs;
			unsigned _fp_pad;
		} fp_fregs[32];
	} fp_r;
} libucontext_fpregset_t;

typedef struct {
	libucontext_gregset_t gregs;
	libucontext_fpregset_t fpregs;
	libucontext_greg_t mdhi;
	libucontext_greg_t hi1;
	libucontext_greg_t hi2;
	libucontext_greg_t hi3;
	libucontext_greg_t mdlo;
	libucontext_greg_t lo1;
	libucontext_greg_t lo2;
	libucontext_greg_t lo3;
	libucontext_greg_t pc;
	unsigned int fpc_csr;
	unsigned int used_math;
	unsigned int dsp;
	unsigned int reserved;
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
