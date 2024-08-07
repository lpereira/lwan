#ifndef LIBUCONTEXT_BITS_H
#define LIBUCONTEXT_BITS_H

typedef unsigned long long libucontext_greg_t, libucontext_gregset_t[32];

/* Container for all general registers.  */
typedef __loongarch_mc_gp_state gregset_t;

/* Container for floating-point state.  */
typedef union __loongarch_mc_fp_state fpregset_t;

union __loongarch_mc_fp_state {
    unsigned int   __val32[256 / 32];
    unsigned long long   __val64[256 / 64];
};

typedef struct mcontext_t {
    unsigned long long   __pc;
    unsigned long long   __gregs[32];
    unsigned int   __flags;

    unsigned int   __fcsr;
    unsigned int   __vcsr;
    unsigned long long   __fcc;
    union __loongarch_mc_fp_state    __fpregs[32] __attribute__((__aligned__ (32)));

    unsigned int   __reserved;
} mcontext_t;

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
