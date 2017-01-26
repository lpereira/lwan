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

#pragma once

#include <stddef.h>
#if defined(__x86_64__)
#include <stdint.h>
typedef uintptr_t coro_context[10];
#elif defined(__i386__)
#include <stdint.h>
typedef uintptr_t coro_context[7];
#else
#include <ucontext.h>
typedef ucontext_t coro_context;
#endif

struct coro;

typedef int    (*coro_function_t)	(struct coro *coro);

struct coro_switcher {
    coro_context caller;
    coro_context callee;
};

struct coro *coro_new(struct coro_switcher *switcher, coro_function_t function, void *data);
void	coro_free(struct coro *coro);

void    coro_reset(struct coro *coro, coro_function_t func, void *data);

int	coro_resume(struct coro *coro);
int	coro_resume_value(struct coro *coro, int value);
int	coro_yield(struct coro *coro, int value);

void   *coro_get_data(struct coro *coro);

void    coro_defer(struct coro *coro, void (*func)(void *data), void *data);
void    coro_defer2(struct coro *coro, void (*func)(void *data1, void *data2),
            void *data1, void *data2);

void   *coro_malloc(struct coro *coro, size_t sz);
void   *coro_malloc_full(struct coro *coro, size_t size, void (*destroy_func)());
char   *coro_strdup(struct coro *coro, const char *str);
char   *coro_strndup(struct coro *coro, const char *str, size_t len);
char   *coro_printf(struct coro *coro, const char *fmt, ...);

#define CORO_DEFER(fn)		((void (*)(void *))(fn))
#define CORO_DEFER2(fn)		((void (*)(void *, void *))(fn))

