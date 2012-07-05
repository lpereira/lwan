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

#ifndef __LWAN_CORO_H__
#define __LWAN_CORO_H__

#include <unistd.h>
#include <ucontext.h>

typedef struct coro_t_			coro_t;
typedef struct coro_switcher_t_		coro_switcher_t;

typedef int    (*coro_function_t)	(coro_t *coro);

struct coro_switcher_t_ {
    ucontext_t caller;
    ucontext_t callee;
};

typedef enum {
    CORO_NEW,
    CORO_RUNNING,
    CORO_FINISHED
} coro_state_t;

coro_t *coro_new(coro_switcher_t *switcher, coro_function_t function, void *data);
coro_t *coro_new_full(coro_switcher_t *switcher, ssize_t stack_size, coro_function_t function, void *data);
void	coro_free(coro_t *coro);

int	coro_resume(coro_t *coro);
void	coro_yield(coro_t *coro, int value);

void   		*coro_get_data(coro_t *coro);
coro_state_t	 coro_get_state(coro_t *coro);

void    coro_defer(coro_t *coro, void (*func)(void *data), void *data);
void   *coro_malloc(coro_t *coro, size_t sz);

#endif /* __LWAN_CORO_H__ */
