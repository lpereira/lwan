/* ==========================================================================
 * timeout.h - Tickless hierarchical timing wheel.
 * --------------------------------------------------------------------------
 * Copyright (c) 2013, 2014  William Ahern
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to permit
 * persons to whom the Software is furnished to do so, subject to the
 * following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
 * NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
 * USE OR OTHER DEALINGS IN THE SOFTWARE.
 * ==========================================================================
 */
#ifndef TIMEOUT_H
#define TIMEOUT_H

#include <stdbool.h> /* bool */
#include <stdio.h>   /* FILE */

#include <inttypes.h> /* PRIu64 PRIx64 PRIX64 uint64_t */

#include "list.h"

/*
 * I N T E G E R  T Y P E  I N T E R F A C E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define TIMEOUT_C(n) UINT64_C(n)
#define TIMEOUT_PRIu PRIu64
#define TIMEOUT_PRIx PRIx64
#define TIMEOUT_PRIX PRIX64

typedef uint64_t timeout_t;

#define timeout_error_t int /* for documentation purposes */

/*
 * T I M E O U T  I N T E R F A C E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define TIMEOUT_ABS 0x01 /* treat timeout values as absolute */

#define TIMEOUT_INITIALIZER(flags)                                             \
    {                                                                          \
        (flags)                                                                \
    }

struct timeout {
    int flags;

    timeout_t expires;
    /* absolute expiration time */

    struct list_head *pending;
    /* timeout list if pending on wheel or expiry queue */

    struct list_node tqe;
    /* entry member for struct timeout_list lists */
}; /* struct timeout */

struct timeout *timeout_init(struct timeout *);
/* initialize timeout structure (same as TIMEOUT_INITIALIZER) */

/*
 * T I M I N G  W H E E L  I N T E R F A C E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

struct timeouts;

struct timeouts *timeouts_open(timeout_error_t *);
/* open a new timing wheel, setting optional HZ (for float conversions) */

void timeouts_close(struct timeouts *);
/* destroy timing wheel */

void timeouts_update(struct timeouts *, timeout_t);
/* update timing wheel with current absolute time */

timeout_t timeouts_timeout(struct timeouts *);
/* return interval to next required update */

void timeouts_add(struct timeouts *, struct timeout *, timeout_t);
/* add timeout to timing wheel */

void timeouts_del(struct timeouts *, struct timeout *);
/* remove timeout from any timing wheel or expired queue (okay if on neither) */

struct timeout *timeouts_get(struct timeouts *);
/* return any expired timeout (caller should loop until NULL-return) */

#endif /* TIMEOUT_H */
