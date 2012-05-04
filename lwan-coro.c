/*
 * lwan - simple web server
 * Copyright (c) 2012 Leandro A. F. Pereira <leandro@hardinfo.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <ucontext.h>
#include <unistd.h>

#include "lwan.h"
#include "lwan-coro.h"

#ifdef USE_VALGRIND
#include <valgrind/valgrind.h>
#endif

#ifdef __x86_64__
static const int const default_stack_size = 16 * 1024;
#else
static const int const default_stack_size = 12 * 1024;
#endif

#ifdef __x86_64__
union ptr_splitter {
    void *ptr;
    uint32_t part[sizeof(void *) / sizeof(uint32_t)];
};
#endif

struct coro_t_ {
    coro_state_t state;
    coro_function_t function;
    coro_switcher_t *switcher;
    void *data;

    ucontext_t context;
    int yield_value;

#ifdef USE_VALGRIND
    int vg_stack_id;
#endif

    char stack[1];
};

/*
 * These swapcontext() implementations were obtained from glibc and
 * modified slightly to not save/restore the floating point registers
 * and signal mask. They're Copyright (C) 2001, 2002, 2003 Free Software
 * Foundation, Inc and are distributed under GNU LGPL version 2.1 (or
 * later). I'm not sure if I can distribute them inside a GPL program;
 * they're straightforward so I'm assuming there won't be any problem;
 * if there is, I'll just roll my own.
 *     -- Leandro
 */
void _coro_swapcontext(ucontext_t *current, ucontext_t *other);
#ifdef __x86_64__
    asm(
    ".text\n\t"
    ".p2align 4,,15\n\t"
    ".globl _coro_swapcontext\n\t"
    ".globl __coro_swapcontext\n\t"
    "_coro_swapcontext:\n\t"
    "__coro_swapcontext:\n\t"
    "mov    %rbx,0x80(%rdi)\n\t"
    "mov    %rbp,0x78(%rdi)\n\t"
    "mov    %r12,0x48(%rdi)\n\t"
    "mov    %r13,0x50(%rdi)\n\t"
    "mov    %r14,0x58(%rdi)\n\t"
    "mov    %r15,0x60(%rdi)\n\t"
    "mov    %rdi,0x68(%rdi)\n\t"
    "mov    %rsi,0x70(%rdi)\n\t"
    "mov    %rdx,0x88(%rdi)\n\t"
    "mov    %rcx,0x98(%rdi)\n\t"
    "mov    %r8,0x28(%rdi)\n\t"
    "mov    %r9,0x30(%rdi)\n\t"
    "mov    (%rsp),%rcx\n\t"
    "mov    %rcx,0xa8(%rdi)\n\t"
    "lea    0x8(%rsp),%rcx\n\t"
    "mov    %rcx,0xa0(%rdi)\n\t"
    "mov    0xa0(%rsi),%rsp\n\t"
    "mov    0x80(%rsi),%rbx\n\t"
    "mov    0x78(%rsi),%rbp\n\t"
    "mov    0x48(%rsi),%r12\n\t"
    "mov    0x50(%rsi),%r13\n\t"
    "mov    0x58(%rsi),%r14\n\t"
    "mov    0x60(%rsi),%r15\n\t"
    "mov    0xa8(%rsi),%rcx\n\t"
    "push   %rcx\n\t"
    "mov    0x68(%rsi),%rdi\n\t"
    "mov    0x88(%rsi),%rdx\n\t"
    "mov    0x98(%rsi),%rcx\n\t"
    "mov    0x28(%rsi),%r8\n\t"
    "mov    0x30(%rsi),%r9\n\t"
    "mov    0x70(%rsi),%rsi\n\t"
    "retq\n\t");
#elif __i386__
    asm(
    ".text\n\t"
    ".p2align 2,,3\n\t"
    ".globl _coro_swapcontext\n\t"
    ".globl __coro_swapcontext\n\t"
    "_coro_swapcontext:\n\t"
    "__coro_swapcontext:\n\t"
    "mov    0x4(%esp),%eax\n\t"
    "movl   $0x0,0x40(%eax)\n\t"
    "mov    %ecx,0x3c(%eax)\n\t"
    "mov    %edx,0x38(%eax)\n\t"
    "mov    %edi,0x24(%eax)\n\t"
    "mov    %esi,0x28(%eax)\n\t"
    "mov    %ebp,0x2c(%eax)\n\t"
    "mov    (%esp),%ecx\n\t"
    "mov    %ecx,0x4c(%eax)\n\t"
    "lea    0x4(%esp),%ecx\n\t"
    "mov    %ecx,0x30(%eax)\n\t"
    "mov    %ebx,0x34(%eax)\n\t"
    "xor    %edx,%edx\n\t"
    "mov    %fs,%dx\n\t"
    "mov    %edx,0x18(%eax)\n\t"
    "mov    0x18(%eax),%edx\n\t"
    "mov    %edx,%fs\n\t"
    "mov    0x4c(%eax),%ecx\n\t"
    "mov    0x30(%eax),%esp\n\t"
    "push   %ecx\n\t"
    "mov    0x24(%eax),%edi\n\t"
    "mov    0x28(%eax),%esi\n\t"
    "mov    0x2c(%eax),%ebp\n\t"
    "mov    0x34(%eax),%ebx\n\t"
    "mov    0x38(%eax),%edx\n\t"
    "mov    0x3c(%eax),%ecx\n\t"
    "mov    0x40(%eax),%eax\n\t"
    "ret    \n\t");
#else
static ALWAYS_INLINE void
_coro_swapcontext(ucontext_t *current, ucontext_t *other)
{
    swapcontext(current, other);
}
#endif

#ifdef __x86_64__
static void
_coro_entry_point(uint32_t part0, uint32_t part1)
{
    union ptr_splitter p;
    p.part[0] = part0;
    p.part[1] = part1;
    coro_t *coro = p.ptr;
    int return_value = coro->function(coro);
    coro->state = CORO_FINISHED;
    coro_yield(coro, return_value);
}
#else
static void
_coro_entry_point(coro_t *coro)
{
    int return_value = coro->function(coro);
    coro->state = CORO_FINISHED;
    coro_yield(coro, return_value);
}
#endif

coro_t *
coro_new_full(coro_switcher_t *switcher, ssize_t stack_size, coro_function_t function, void *data)
{
    coro_t *coro = malloc(sizeof(*coro) + stack_size);

#ifdef USE_VALGRIND
    coro->vg_stack_id = VALGRIND_STACK_REGISTER(coro->stack, coro->stack + stack_size);
#endif

    coro->state = CORO_NEW;
    coro->switcher = switcher;
    coro->function = function;
    coro->data = data;

    getcontext(&coro->context);
    coro->context.uc_stack.ss_sp = coro->stack;
    coro->context.uc_stack.ss_size = stack_size;
    coro->context.uc_stack.ss_flags = 0;
    coro->context.uc_link = NULL;

#ifdef __x86_64__
    union ptr_splitter p;
    p.ptr = coro;
    makecontext(&coro->context, (void (*)())_coro_entry_point, 2, p.part[0], p.part[1]);
#else
    makecontext(&coro->context, (void (*)())_coro_entry_point, 1, coro);
#endif

    return coro;
}

ALWAYS_INLINE coro_t *
coro_new(coro_switcher_t *switcher, coro_function_t function, void *data)
{
    return coro_new_full(switcher, default_stack_size, function, data);
}

ALWAYS_INLINE void *
coro_get_data(coro_t *coro)
{
    return LIKELY(coro) ? coro->data : NULL;
}

ALWAYS_INLINE coro_state_t
coro_get_state(coro_t *coro)
{
    return LIKELY(coro) ? coro->state : CORO_FINISHED;
}

ALWAYS_INLINE int
coro_resume(coro_t *coro)
{
    if (UNLIKELY(!coro))
        return 0;
    if (coro->state == CORO_NEW)
        coro->state = CORO_RUNNING;
    else if (coro->state == CORO_FINISHED)
        return 0;

    ucontext_t prev_caller = coro->switcher->caller;
    _coro_swapcontext(&coro->switcher->caller, &coro->context);
    coro->context = coro->switcher->callee;
    coro->switcher->caller = prev_caller;

    return coro->yield_value;
}

ALWAYS_INLINE void
coro_yield(coro_t *coro, int value)
{
    if (UNLIKELY(!coro))
        return;
    coro->yield_value = value;
    _coro_swapcontext(&coro->switcher->callee, &coro->switcher->caller);
}

void
coro_free(coro_t *coro)
{
    if (UNLIKELY(!coro))
        return;
#ifdef USE_VALGRIND
    VALGRIND_STACK_DEREGISTER(coro->vg_stack_id);
#endif
    // FIXME: Deallocate stuff allocated inside a coroutine
    free(coro);
}
