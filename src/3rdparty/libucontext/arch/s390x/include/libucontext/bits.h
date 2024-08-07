#ifndef LIBUCONTEXT_BITS_H
#define LIBUCONTEXT_BITS_H

typedef unsigned long libucontext_greg_t, libucontext_gregset_t[27];

typedef struct {
	unsigned long mask;
	unsigned long addr;
} libucontext_psw_t;

typedef union {
	double d;
	float f;
} libucontext_fpreg_t;

typedef struct {
	unsigned fpc;
	libucontext_fpreg_t fprs[16];
} libucontext_fpregset_t;

typedef struct {
	libucontext_psw_t psw;
	unsigned long gregs[16];
	unsigned aregs[16];
	libucontext_fpregset_t fpregs;
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
