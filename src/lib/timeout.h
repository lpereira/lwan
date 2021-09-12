/*
 * timeout.h - Tickless hierarchical timing wheel.
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
 */

#pragma once
#include <inttypes.h> /* uint64_t */

#include "list.h"

/* Integer type interfaces */

#define TIMEOUT_C(n) UINT64_C(n)

typedef uint64_t timeout_t;

#define timeout_error_t int /* for documentation purposes */

/* Timeout interfaces */

#define TIMEOUT_ABS 0x01 /* treat timeout values as absolute */

#define TIMEOUT_INITIALIZER(flags)                                             \
    {                                                                          \
        (flags)                                                                \
    }

struct timeout {
    int flags;

    /* absolute expiration time */
    timeout_t expires;

    /* timeout list if pending on wheel or expiry queue */
    struct list_head *pending;

    /* entry member for struct timeout_list lists */
    struct list_node tqe;
};

/* initialize timeout structure (same as TIMEOUT_INITIALIZER) */
struct timeout *timeout_init(struct timeout *);

/* Timing wheel interfaces */

struct timeouts;

/* open a new timing wheel, setting optional HZ (for float conversions) */
struct timeouts *timeouts_open(timeout_error_t *);

/* destroy timing wheel */
void timeouts_close(struct timeouts *);

/* update timing wheel with current absolute time */
void timeouts_update(struct timeouts *, timeout_t);

/* return interval to next required update */
timeout_t timeouts_timeout(struct timeouts *);

/* add timeout to timing wheel */
void timeouts_add(struct timeouts *, struct timeout *, timeout_t);

/* remove timeout from any timing wheel or expired queue (okay if on neither) */
void timeouts_del(struct timeouts *, struct timeout *);

/* return any expired timeout (caller should loop until NULL-return) */
struct timeout *timeouts_get(struct timeouts *);
