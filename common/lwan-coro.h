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
typedef uintptr_t coro_context_t[10];
#elif defined(__i386__)
#include <stdint.h>
typedef uintptr_t coro_context_t[7];
#else
#include <ucontext.h>
typedef ucontext_t coro_context_t;
#endif

typedef struct coro_t_			coro_t;
typedef struct coro_switcher_t_		coro_switcher_t;

typedef int    (*coro_function_t)	(coro_t *coro);

struct coro_switcher_t_ {
    coro_context_t caller;
    coro_context_t callee;
};

coro_t *coro_new(coro_switcher_t *switcher, coro_function_t function, void *data);
void	coro_free(coro_t *coro);

void    coro_reset(coro_t *coro, coro_function_t func, void *data);

int	coro_resume(coro_t *coro);
int	coro_resume_value(coro_t *coro, int value);
int	coro_yield(coro_t *coro, int value);

void   *coro_get_data(coro_t *coro);

void    coro_defer(coro_t *coro, void (*func)(void *data), void *data);
void    coro_defer2(coro_t *coro, void (*func)(void *data1, void *data2),
            void *data1, void *data2);
void    coro_collect_garbage(coro_t *coro);

void   *coro_malloc(coro_t *coro, size_t sz);
void   *coro_malloc_full(coro_t *coro, size_t size, bool sticky, void (*destroy_func)());
char   *coro_strdup(coro_t *coro, const char *str);
char   *coro_printf(coro_t *coro, const char *fmt, ...);

#define CORO_DEFER(fn)		((void (*)(void *))(fn))
#define CORO_DEFER2(fn)		((void (*)(void *, void *))(fn))

