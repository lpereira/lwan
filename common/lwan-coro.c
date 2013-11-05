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

#include <assert.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "lwan.h"
#include "lwan-coro.h"

#ifdef USE_VALGRIND
#include <valgrind/valgrind.h>
#endif

#define CORO_STACK_MIN		(3 * (PTHREAD_STACK_MIN)) / 2

typedef struct coro_defer_t_	coro_defer_t;

struct coro_defer_t_ {
    coro_defer_t *next;
    void (*func)();
    void *data1;
    void *data2;
};

struct coro_t_ {
    coro_switcher_t *switcher;
    coro_context_t context;
    int yield_value;

    coro_defer_t *defer;
    void *data;

    bool ended;

#if !defined(NDEBUG) && defined(USE_VALGRIND)
    int vg_stack_id;
#endif
};

static void _coro_entry_point(coro_t *data, coro_function_t func);

/*
 * This swapcontext() implementation was obtained from glibc and modified
 * slightly to not save/restore the floating point registers, unneeded
 * registers, and signal mask.  It is Copyright (C) 2001, 2002, 2003 Free
 * Software Foundation, Inc and are distributed under GNU LGPL version 2.1
 * (or later).  I'm not sure if I can distribute them inside a GPL program;
 * they're straightforward so I'm assuming there won't be any problem; if
 * there is, I'll just roll my own.
 *     -- Leandro
 */
#ifdef __x86_64__
void _coro_swapcontext(coro_context_t *current, coro_context_t *other)
                __attribute__((noinline));
    asm(
    ".text\n\t"
    ".p2align 4\n\t"
    ".globl _coro_swapcontext\n\t"
    "_coro_swapcontext:\n\t"
    "mov    %rbx,0(%rdi)\n\t"
    "mov    %rbp,8(%rdi)\n\t"
    "mov    %r12,16(%rdi)\n\t"
    "mov    %r13,24(%rdi)\n\t"
    "mov    %r14,32(%rdi)\n\t"
    "mov    %r15,40(%rdi)\n\t"
    "mov    %rdi,48(%rdi)\n\t"
    "mov    %rsi,56(%rdi)\n\t"
    "mov    (%rsp),%rcx\n\t"
    "mov    %rcx,64(%rdi)\n\t"
    "lea    0x8(%rsp),%rcx\n\t"
    "mov    %rcx,72(%rdi)\n\t"
    "mov    72(%rsi),%rsp\n\t"
    "mov    0(%rsi),%rbx\n\t"
    "mov    8(%rsi),%rbp\n\t"
    "mov    16(%rsi),%r12\n\t"
    "mov    24(%rsi),%r13\n\t"
    "mov    32(%rsi),%r14\n\t"
    "mov    40(%rsi),%r15\n\t"
    "mov    64(%rsi),%rcx\n\t"
    "push   %rcx\n\t"
    "mov    48(%rsi),%rdi\n\t"
    "mov    56(%rsi),%rsi\n\t"
    "retq\n\t");
#else
#define _coro_swapcontext(cur,oth) swapcontext(cur, oth)
#endif

#ifdef __x86_64__
static ALWAYS_INLINE void
_coro_makecontext(coro_t *coro, void *stack, size_t stack_size, coro_function_t func)
{
    coro->context[6 /* RDI */] = (uintptr_t) coro;
    coro->context[7 /* RSI */] = (uintptr_t) func;
    coro->context[8 /* RIP */] = (uintptr_t) _coro_entry_point;
    coro->context[9 /* RSP */] = (uintptr_t) stack + stack_size;
}
#else
#define _coro_makecontext(ctx, fun, args, ...) makecontext(ctx, fun, args, __VA_ARGS__)
#endif

static void
_coro_entry_point(coro_t *coro, coro_function_t func)
{
    int return_value = func(coro);
    coro->ended = true;
    coro_yield(coro, return_value);
}

coro_t *
coro_new_full(coro_switcher_t *switcher, ssize_t stack_size, coro_function_t func, void *data)
{
    coro_t *coro = malloc(sizeof(*coro) + stack_size);
    void *stack = (coro_t *)coro + 1;

    coro->ended = false;
    coro->switcher = switcher;
    coro->data = data;
    coro->defer = NULL;

#if !defined(NDEBUG) && defined(USE_VALGRIND)
    coro->vg_stack_id = VALGRIND_STACK_REGISTER(stack, stack + stack_size);
#endif

#ifdef __x86_64__
    _coro_makecontext(coro, stack, stack_size, func);
#else
    getcontext(&coro->context);

    coro->context.uc_stack.ss_sp = stack;
    coro->context.uc_stack.ss_size = stack_size;
    coro->context.uc_stack.ss_flags = 0;
    coro->context.uc_link = NULL;

    _coro_makecontext(&coro->context, (void (*)())_coro_entry_point,
                2, coro, func);
#endif

    return coro;
}

ALWAYS_INLINE coro_t *
coro_new(coro_switcher_t *switcher, coro_function_t function, void *data)
{
    return coro_new_full(switcher, CORO_STACK_MIN, function, data);
}

ALWAYS_INLINE void *
coro_get_data(coro_t *coro)
{
    return LIKELY(coro) ? coro->data : NULL;
}

ALWAYS_INLINE int
coro_resume(coro_t *coro)
{
    assert(coro);
    assert(coro->ended == false);

#ifdef __x86_64__
    _coro_swapcontext(&coro->switcher->caller, &coro->context);
    if (!coro->ended)
        memcpy(&coro->context, &coro->switcher->callee,
                    sizeof(coro->context));
#else
    coro_context_t prev_caller;

    memcpy(&prev_caller, &coro->switcher->caller, sizeof(prev_caller));
    _coro_swapcontext(&coro->switcher->caller, &coro->context);
    if (!coro->ended) {
        memcpy(&coro->context, &coro->switcher->callee,
                    sizeof(coro->context));
        memcpy(&coro->switcher->caller, &prev_caller,
                    sizeof(coro->switcher->caller));
    }
#endif

    return coro->yield_value;
}

ALWAYS_INLINE void
coro_yield(coro_t *coro, int value)
{
    assert(coro);
    coro->yield_value = value;
    _coro_swapcontext(&coro->switcher->callee, &coro->switcher->caller);
}

void
coro_free(coro_t *coro)
{
    assert(coro);
#if !defined(NDEBUG) && defined(USE_VALGRIND)
    VALGRIND_STACK_DEREGISTER(coro->vg_stack_id);
#endif
    coro_defer_t *defer;
    for (defer = coro->defer; defer;) {
        coro_defer_t *tmp = defer;
        defer->func(defer->data1, defer->data2);
        defer = tmp->next;
        free(tmp);
    }
    free(coro);
}

static void
_coro_defer_any(coro_t *coro, void (*func)(), void *data1, void *data2)
{
    coro_defer_t *defer = malloc(sizeof(*defer));
    if (UNLIKELY(!defer))
        return;

    assert(func);

    defer->next = coro->defer;
    defer->func = func;
    defer->data1 = data1;
    defer->data2 = data2;
    coro->defer = defer;
}

ALWAYS_INLINE void
coro_defer(coro_t *coro, void (*func)(void *data), void *data)
{
    _coro_defer_any(coro, func, data, NULL);
}

ALWAYS_INLINE void
coro_defer2(coro_t *coro, void (*func)(void *data1, void *data2),
            void *data1, void *data2)
{
    _coro_defer_any(coro, func, data1, data2);
}

static void nothing()
{
}

void *
coro_malloc(coro_t *coro, size_t size)
{
    coro_defer_t *defer = malloc(sizeof(*defer) + size);
    if (UNLIKELY(!defer))
        return NULL;

    defer->next = coro->defer;
    defer->func = nothing;
    coro->defer = defer;

    return defer + 1;
}
