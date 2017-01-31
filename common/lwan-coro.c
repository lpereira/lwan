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

#define _GNU_SOURCE
#include <assert.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lwan-private.h"

#include "lwan-array.h"
#include "lwan-coro.h"

#ifdef USE_VALGRIND
#include <valgrind/valgrind.h>
#endif

#ifdef __GLIBC__
#define CORO_STACK_MIN         ((3 * (PTHREAD_STACK_MIN)) / 2)
#else
#define CORO_STACK_MIN         (5 * (PTHREAD_STACK_MIN))
#endif

static_assert(DEFAULT_BUFFER_SIZE < (CORO_STACK_MIN + PTHREAD_STACK_MIN),
    "Request buffer fits inside coroutine stack");

typedef void (*defer_func)();

struct coro_defer {
    defer_func func;
    void *data1;
    void *data2;
};

DEFINE_ARRAY_TYPE(coro_defer_array, struct coro_defer)

struct coro {
    struct coro_switcher *switcher;
    coro_context context;
    int yield_value;

#if !defined(NDEBUG) && defined(USE_VALGRIND)
    unsigned int vg_stack_id;
#endif

    struct coro_defer_array defer;
    void *data;

    bool ended;
};

static void coro_entry_point(struct coro *data, coro_function_t func);

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
#if defined(__x86_64__)
void __attribute__((noinline))
coro_swapcontext(coro_context *current, coro_context *other);
    asm(
    ".text\n\t"
    ".p2align 4\n\t"
#if defined(__APPLE__)
    ".globl _coro_swapcontext\n\t"
    "_coro_swapcontext:\n\t"
#else
    ".globl coro_swapcontext\n\t"
    "coro_swapcontext:\n\t"
#endif
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
    "mov    48(%rsi),%rdi\n\t"
    "mov    64(%rsi),%rcx\n\t"
    "mov    56(%rsi),%rsi\n\t"
    "jmp    *%rcx\n\t");
#elif defined(__i386__)
void __attribute__((noinline))
coro_swapcontext(coro_context *current, coro_context *other);
    asm(
    ".text\n\t"
    ".p2align 16\n\t"
#if defined(__APPLE__)
    ".globl _coro_swapcontext\n\t"
    "_coro_swapcontext:\n\t"
#else
    ".globl coro_swapcontext\n\t"
    "coro_swapcontext:\n\t"
#endif
    "movl   0x4(%esp),%eax\n\t"
    "movl   %ecx,0x1c(%eax)\n\t" /* ECX */
    "movl   %ebx,0x0(%eax)\n\t"  /* EBX */
    "movl   %esi,0x4(%eax)\n\t"  /* ESI */
    "movl   %edi,0x8(%eax)\n\t"  /* EDI */
    "movl   %ebp,0xc(%eax)\n\t"  /* EBP */
    "movl   (%esp),%ecx\n\t"
    "movl   %ecx,0x14(%eax)\n\t" /* EIP */
    "leal   0x4(%esp),%ecx\n\t"
    "movl   %ecx,0x18(%eax)\n\t" /* ESP */
    "movl   8(%esp),%eax\n\t"
    "movl   0x14(%eax),%ecx\n\t" /* EIP (1) */
    "movl   0x18(%eax),%esp\n\t" /* ESP */
    "pushl  %ecx\n\t"            /* EIP (2) */
    "movl   0x0(%eax),%ebx\n\t"  /* EBX */
    "movl   0x4(%eax),%esi\n\t"  /* ESI */
    "movl   0x8(%eax),%edi\n\t"  /* EDI */
    "movl   0xc(%eax),%ebp\n\t"  /* EBP */
    "movl   0x1c(%eax),%ecx\n\t" /* ECX */
    "ret\n\t");
#else
#define coro_swapcontext(cur,oth) swapcontext(cur, oth)
#endif

static void
coro_entry_point(struct coro *coro, coro_function_t func)
{
    int return_value = func(coro);
    coro->ended = true;
    coro_yield(coro, return_value);
}

static void
coro_run_deferred(struct coro *coro)
{
    struct lwan_array *array = (struct lwan_array *)&coro->defer;
    struct coro_defer *defers = array->base;

    for (size_t i = array->elements; i != 0; i--) {
        struct coro_defer *defer = &defers[i - 1];

        defer->func(defer->data1, defer->data2);
    }
}

void
coro_reset(struct coro *coro, coro_function_t func, void *data)
{
    unsigned char *stack = (unsigned char *)(coro + 1);

    coro->ended = false;
    coro->data = data;

    coro_run_deferred(coro);
    coro_defer_array_reset(&coro->defer);

#if defined(__x86_64__)
    coro->context[6 /* RDI */] = (uintptr_t) coro;
    coro->context[7 /* RSI */] = (uintptr_t) func;
    coro->context[8 /* RIP */] = (uintptr_t) coro_entry_point;
    coro->context[9 /* RSP */] = (uintptr_t) stack + CORO_STACK_MIN;
#elif defined(__i386__)
    /* Align stack and make room for two arguments */
    stack = (unsigned char *)((uintptr_t)(stack + CORO_STACK_MIN -
        sizeof(uintptr_t) * 2) & 0xfffffff0);

    uintptr_t *argp = (uintptr_t *)stack;
    *argp++ = 0;
    *argp++ = (uintptr_t)coro;
    *argp++ = (uintptr_t)func;

    coro->context[5 /* EIP */] = (uintptr_t) coro_entry_point;
    coro->context[6 /* ESP */] = (uintptr_t) stack;
#else
    getcontext(&coro->context);

    coro->context.uc_stack.ss_sp = stack;
    coro->context.uc_stack.ss_size = CORO_STACK_MIN;
    coro->context.uc_stack.ss_flags = 0;
    coro->context.uc_link = NULL;

    makecontext(&coro->context, (void (*)())coro_entry_point, 2, coro, func);
#endif
}

ALWAYS_INLINE struct coro *
coro_new(struct coro_switcher *switcher, coro_function_t function, void *data)
{
    struct coro *coro = malloc(sizeof(*coro) + CORO_STACK_MIN);
    if (UNLIKELY(!coro))
        return NULL;

    if (UNLIKELY(coro_defer_array_init(&coro->defer) < 0)) {
        free(coro);
        return NULL;
    }

    coro->switcher = switcher;
    coro_reset(coro, function, data);

#if !defined(NDEBUG) && defined(USE_VALGRIND)
    char *stack = (char *)(coro + 1);
    coro->vg_stack_id = VALGRIND_STACK_REGISTER(stack, stack + CORO_STACK_MIN);
#endif

    return coro;
}

ALWAYS_INLINE void *
coro_get_data(struct coro *coro)
{
    assert(coro);

    return coro->data;
}

ALWAYS_INLINE int
coro_resume(struct coro *coro)
{
    assert(coro);
    assert(coro->ended == false);

#if defined(__x86_64__) || defined(__i386__)
    coro_swapcontext(&coro->switcher->caller, &coro->context);
    if (!coro->ended)
        memcpy(&coro->context, &coro->switcher->callee,
                    sizeof(coro->context));
#else
    coro_context prev_caller;

    memcpy(&prev_caller, &coro->switcher->caller, sizeof(prev_caller));
    coro_swapcontext(&coro->switcher->caller, &coro->context);
    if (!coro->ended) {
        memcpy(&coro->context, &coro->switcher->callee,
                    sizeof(coro->context));
        memcpy(&coro->switcher->caller, &prev_caller,
                    sizeof(coro->switcher->caller));
    }
#endif

    return coro->yield_value;
}

ALWAYS_INLINE int
coro_resume_value(struct coro *coro, int value)
{
    assert(coro);
    assert(coro->ended == false);

    coro->yield_value = value;
    return coro_resume(coro);
}

ALWAYS_INLINE int
coro_yield(struct coro *coro, int value)
{
    assert(coro);
    coro->yield_value = value;
    coro_swapcontext(&coro->switcher->callee, &coro->switcher->caller);
    return coro->yield_value;
}

void
coro_free(struct coro *coro)
{
    assert(coro);
#if !defined(NDEBUG) && defined(USE_VALGRIND)
    VALGRIND_STACK_DEREGISTER(coro->vg_stack_id);
#endif
    coro_run_deferred(coro);
    coro_defer_array_reset(&coro->defer);
    free(coro);
}

static void
coro_defer_any(struct coro *coro, defer_func func, void *data1, void *data2)
{
    struct coro_defer *defer;

    assert(func);

    defer = coro_defer_array_append(&coro->defer);
    if (UNLIKELY(!defer)) {
        lwan_status_error("Could not add new deferred function for coro %p", coro);
        return;
    }

    defer->func = func;
    defer->data1 = data1;
    defer->data2 = data2;
}

ALWAYS_INLINE void
coro_defer(struct coro *coro, void (*func)(void *data), void *data)
{
    coro_defer_any(coro, func, data, NULL);
}

ALWAYS_INLINE void
coro_defer2(struct coro *coro, void (*func)(void *data1, void *data2),
            void *data1, void *data2)
{
    coro_defer_any(coro, func, data1, data2);
}

void *
coro_malloc_full(struct coro *coro, size_t size, void (*destroy_func)())
{
    void *ptr = malloc(size);

    if (LIKELY(ptr))
        coro_defer(coro, destroy_func, ptr);

    return ptr;
}

inline void *
coro_malloc(struct coro *coro, size_t size)
{
    return coro_malloc_full(coro, size, free);
}

char *
coro_strndup(struct coro *coro, const char *str, size_t max_len)
{
    const size_t len = max_len + 1;
    char *dup = coro_malloc(coro, len);
    if (LIKELY(dup)) {
        memcpy(dup, str, len);
        dup[len - 1] = '\0';
    }
    return dup;
}

char *
coro_strdup(struct coro *coro, const char *str)
{
    return coro_strndup(coro, str, strlen(str));
}

char *
coro_printf(struct coro *coro, const char *fmt, ...)
{
    va_list values;
    int len;
    char *tmp_str;

    va_start(values, fmt);
    len = vasprintf(&tmp_str, fmt, values);
    va_end(values);

    if (UNLIKELY(len < 0))
        return NULL;

    coro_defer(coro, CORO_DEFER(free), tmp_str);
    return tmp_str;
}
