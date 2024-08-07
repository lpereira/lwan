#ifndef LIBUCONTEXT_BITS_H
#define LIBUCONTEXT_BITS_H

typedef unsigned long libucontext_greg_t;
typedef unsigned long libucontext__riscv_mc_gp_state[32];

struct libucontext__riscv_mc_f_ext_state {
	unsigned int __f[32];
	unsigned int __fcsr;
};

struct libucontext__riscv_mc_d_ext_state {
	unsigned long long __f[32];
	unsigned int __fcsr;
};

struct libucontext__riscv_mc_q_ext_state {
	unsigned long long __f[64] __attribute__((aligned(16)));
	unsigned int __fcsr;
	unsigned int __reserved[3];
};

union libucontext__riscv_mc_fp_state {
	struct libucontext__riscv_mc_f_ext_state __f;
	struct libucontext__riscv_mc_d_ext_state __d;
	struct libucontext__riscv_mc_q_ext_state __q;
};

typedef struct libucontext_mcontext {
	libucontext__riscv_mc_gp_state __gregs;
	union libucontext__riscv_mc_fp_state __fpregs;
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
	unsigned char __pad[128];
	libucontext_mcontext_t uc_mcontext;
} libucontext_ucontext_t;

#endif
