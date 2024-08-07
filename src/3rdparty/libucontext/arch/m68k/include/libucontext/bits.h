#ifndef LIBUCONTEXT_BITS_H
#define LIBUCONTEXT_BITS_H

typedef struct sigaltstack {
	void *ss_sp;
	int ss_flags;
	size_t ss_size;
} libucontext_stack_t;

typedef int libucontext_greg_t, libucontext_gregset_t[18];
typedef struct {
	int f_pcr, f_psr, f_fpiaddr, f_fpregs[8][3];
} libucontext_fpregset_t;

typedef struct {
	int version;
	libucontext_gregset_t gregs;
	libucontext_fpregset_t fpregs;
} libucontext_mcontext_t;

typedef struct libucontext_ucontext {
	unsigned long uc_flags;
	struct libucontext_ucontext *uc_link;
	libucontext_stack_t uc_stack;
	libucontext_mcontext_t uc_mcontext;
} libucontext_ucontext_t;

#endif
