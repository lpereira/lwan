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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "lwan.h"
#include "lwan-coro.h"

#ifdef USE_VALGRIND
#include <valgrind/valgrind.h>
#endif

typedef struct coro_defer_t_	coro_defer_t;

struct coro_defer_t_ {
    coro_defer_t *next;
    void (*func)();
    void *data1;
    void *data2;
};

typedef enum {
    CORO_NEW,
    CORO_RUNNING,
    CORO_FINISHED
} coro_state_t;

struct coro_t_ {
    coro_switcher_t *switcher;
    coro_function_t function;
    coro_defer_t *defer;
    void *data;

    coro_context_t context;
    int yield_value;

#ifndef NDEBUG
#ifdef USE_VALGRIND
    int vg_stack_id;
#endif
    coro_state_t state;
#endif
};

static void _coro_entry_point(coro_t *data);

/*
 * These swapcontext()/getcontext()/makecontext() implementations were
 * obtained from glibc and modified slightly to not save/restore the
 * floating point registers and signal mask.  They're Copyright (C) 2001,
 * 2002, 2003 Free Software Foundation, Inc and are distributed under GNU
 * LGPL version 2.1 (or later).  I'm not sure if I can distribute them
 * inside a GPL program; they're straightforward so I'm assuming there won't
 * be any problem; if there is, I'll just roll my own.
 *     -- Leandro
 */
void _coro_swapcontext(coro_context_t *current, coro_context_t *other);
#ifdef __x86_64__
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
static void
_coro_makecontext(coro_t *coro, size_t stack_size)
{
    void *stack = coro + 1;

    /* Setup context ucp */
    coro->context[8 /* RIP */] = (uintptr_t) _coro_entry_point;
    coro->context[9 /* RSP */] = (uintptr_t) stack + stack_size;

    /* Function data */
    coro->context[6 /* RDI */] = (uintptr_t) coro;
}
#else
#define _coro_makecontext(ctx, fun, args, ...) makecontext(ctx, fun, args, __VA_ARGS__)
#endif

int _coro_getcontext(coro_context_t *current);
#ifdef __x86_64__
    asm(
    ".text\n\t"
    ".p2align 4\n\t"
    ".globl _coro_getcontext\n\t"
    "_coro_getcontext:\n\t"
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
    "retq\n\t");
#else
#define _coro_getcontext(cur) getcontext(cur)
#endif

static void
_coro_entry_point(coro_t *coro)
{
    int return_value = coro->function(coro);
#ifndef NDEBUG
    coro->state = CORO_FINISHED;
#endif
    coro_yield(coro, return_value);
}

coro_t *
coro_new_full(coro_switcher_t *switcher, ssize_t stack_size, coro_function_t function, void *data)
{
    coro_t *coro = malloc(sizeof(*coro) + stack_size);
    void *stack = (coro_t *)coro + 1;

#ifndef NDEBUG
    coro->state = CORO_NEW;
#endif
    coro->switcher = switcher;
    coro->function = function;
    coro->data = data;
    coro->defer = NULL;

#if !defined(NDEBUG) && defined(USE_VALGRIND)
    coro->vg_stack_id = VALGRIND_STACK_REGISTER(stack, stack + stack_size);
#endif

    _coro_getcontext(&coro->context);

#ifdef __x86_64__
    _coro_makecontext(coro, stack_size);
    (void) stack;
#else
    coro->context.uc_stack.ss_sp = stack;
    coro->context.uc_stack.ss_size = stack_size;
    coro->context.uc_stack.ss_flags = 0;
    coro->context.uc_link = NULL;

    _coro_makecontext(&coro->context, (void (*)())_coro_entry_point, 1, coro);
#endif

    return coro;
}

ALWAYS_INLINE coro_t *
coro_new(coro_switcher_t *switcher, coro_function_t function, void *data)
{
    return coro_new_full(switcher, PTHREAD_STACK_MIN, function, data);
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
    assert(coro->state != CORO_FINISHED);

    coro_context_t prev_caller;

    memcpy(&prev_caller, &coro->switcher->caller, sizeof(prev_caller));
    _coro_swapcontext(&coro->switcher->caller, &coro->context);
    memcpy(&coro->context, &coro->switcher->callee, sizeof(prev_caller));
    memcpy(&coro->switcher->caller, &prev_caller, sizeof(prev_caller));

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
