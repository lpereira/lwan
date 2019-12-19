/* ==========================================================================
 * timeout.c - Tickless hierarchical timing wheel.
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

#include <assert.h>

#include <limits.h> /* CHAR_BIT */

#include <stddef.h> /* NULL */
#include <stdlib.h> /* malloc(3) free(3) */

#include <inttypes.h> /* UINT64_C uint64_t */

#include <string.h> /* memset(3) */

#include <errno.h> /* errno */

#include "lwan-private.h"

#include "list.h"

#include "timeout.h"

/*
 * A N C I L L A R Y  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define abstime_t timeout_t /* for documentation purposes */
#define reltime_t timeout_t /* "" */

#if !defined MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

#if !defined MAX
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif

/*
 * B I T  M A N I P U L A T I O N  R O U T I N E S
 *
 * The macros and routines below implement wheel parameterization. The
 * inputs are:
 *
 *   WHEEL_BIT - The number of value bits mapped in each wheel. The
 *               lowest-order WHEEL_BIT bits index the lowest-order (highest
 *               resolution) wheel, the next group of WHEEL_BIT bits the
 *               higher wheel, etc.
 *
 *   WHEEL_NUM - The number of wheels. WHEEL_BIT * WHEEL_NUM = the number of
 *               value bits used by all the wheels. For the default of 6 and
 *               4, only the low 24 bits are processed. Any timeout value
 *               larger than this will cycle through again.
 *
 * The implementation uses bit fields to remember which slot in each wheel
 * is populated, and to generate masks of expiring slots according to the
 * current update interval (i.e. the "tickless" aspect). The slots to
 * process in a wheel are (populated-set & interval-mask).
 *
 * WHEEL_BIT cannot be larger than 6 bits because 2^6 -> 64 is the largest
 * number of slots which can be tracked in a uint64_t integer bit field.
 * WHEEL_BIT cannot be smaller than 3 bits because of our rotr and rotl
 * routines, which only operate on all the value bits in an integer, and
 * there's no integer smaller than uint8_t.
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define WHEEL_BIT 6
#define WHEEL_NUM 4

#define WHEEL_LEN (1U << WHEEL_BIT)
#define WHEEL_MAX (WHEEL_LEN - 1)
#define WHEEL_MASK (WHEEL_LEN - 1)
#define TIMEOUT_MAX ((TIMEOUT_C(1) << (WHEEL_BIT * WHEEL_NUM)) - 1)

/* On GCC and clang and some others, we can use __builtin functions. They
 * are not defined for n==0, but these are never called with n==0. */

#define ctz64(n) __builtin_ctzll(n)
#define clz64(n) __builtin_clzll(n)
#if LONG_BITS == 32
#define ctz32(n) __builtin_ctzl(n)
#define clz32(n) __builtin_clzl(n)
#else
#define ctz32(n) __builtin_ctz(n)
#define clz32(n) __builtin_clz(n)
#endif

#define ctz(n) ctz64(n)
#define clz(n) clz64(n)
#define fls(n) ((int)(64 - clz64(n)))

#define WHEEL_C(n) UINT64_C(n)
#define WHEEL_PRIu PRIu64
#define WHEEL_PRIx PRIx64

typedef uint64_t wheel_t;

/* See "Safe, Efficient, and Portable Rotate in C/C++" by John Regehr
 *     http://blog.regehr.org/archives/1063
 * These should be recognized by the backend C compiler and turned into a rol
 */

#define WHEEL_T_BITS ((CHAR_BIT) * sizeof(wheel_t))

static inline wheel_t rotl(const wheel_t v, uint32_t n)
{
    assert(n < WHEEL_T_BITS);
    return (v << n) | (v >> (-n & (WHEEL_T_BITS - 1)));
}

static inline wheel_t rotr(const wheel_t v, uint32_t n)
{
    assert(n < WHEEL_T_BITS);
    return (v >> n) | (v << (-n & (WHEEL_T_BITS - 1)));
}

#undef WHEEL_T_BITS

/*
 * T I M E R  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

struct timeouts {
    struct list_head wheel[WHEEL_NUM][WHEEL_LEN];
    struct list_head expired;

    wheel_t pending[WHEEL_NUM];

    timeout_t curtime;
};

static struct timeouts *timeouts_init(struct timeouts *T)
{
    unsigned i, j;

    for (i = 0; i < N_ELEMENTS(T->wheel); i++) {
        for (j = 0; j < N_ELEMENTS(T->wheel[i]); j++) {
            list_head_init(&T->wheel[i][j]);
        }
    }

    list_head_init(&T->expired);

    for (i = 0; i < N_ELEMENTS(T->pending); i++) {
        T->pending[i] = 0;
    }

    T->curtime = 0;

    return T;
}

struct timeouts *timeouts_open(timeout_error_t *error)
{
    struct timeouts *T;

    if ((T = lwan_aligned_alloc(sizeof *T, 64)))
        return timeouts_init(T);

    *error = errno;

    return NULL;
}

void timeouts_close(struct timeouts *T)
{
    free(T);
}

void timeouts_del(struct timeouts *T, struct timeout *to)
{
    if (to->pending) {
        list_del_from(to->pending, &to->tqe);

        if (to->pending != &T->expired && list_empty(to->pending)) {
            ptrdiff_t index = to->pending - &T->wheel[0][0];
            ptrdiff_t wheel = index / WHEEL_LEN;
            ptrdiff_t slot = index % WHEEL_LEN;

            T->pending[wheel] &= ~(WHEEL_C(1) << slot);
        }

        to->pending = NULL;
    }
}

static inline reltime_t timeout_rem(struct timeouts *T, struct timeout *to)
{
    return to->expires - T->curtime;
}

static inline int timeout_wheel(timeout_t timeout)
{
    /* must be called with timeout != 0, so fls input is nonzero */
    return (fls(MIN(timeout, TIMEOUT_MAX)) - 1) / WHEEL_BIT;
}

static inline int timeout_slot(int wheel, timeout_t expires)
{
    return (int)(WHEEL_MASK & ((expires >> (wheel * WHEEL_BIT)) - !!wheel));
}

static void
timeouts_sched(struct timeouts *T, struct timeout *to, timeout_t expires)
{
    timeout_t rem;
    int wheel, slot;

    timeouts_del(T, to);

    to->expires = expires;

    if (expires > T->curtime) {
        rem = timeout_rem(T, to);

        /* rem is nonzero since:
         *   rem == timeout_rem(T,to),
         *       == to->expires - T->curtime
         *   and above we have expires > T->curtime.
         */
        wheel = timeout_wheel(rem);
        slot = timeout_slot(wheel, to->expires);

        to->pending = &T->wheel[wheel][slot];

        T->pending[wheel] |= WHEEL_C(1) << slot;
    } else {
        to->pending = &T->expired;
    }

    list_add_tail(to->pending, &to->tqe);
}

void timeouts_add(struct timeouts *T, struct timeout *to, timeout_t timeout)
{
    if (to->flags & TIMEOUT_ABS)
        timeouts_sched(T, to, timeout);
    else
        timeouts_sched(T, to, T->curtime + timeout);
}

void timeouts_update(struct timeouts *T, abstime_t curtime)
{
    timeout_t elapsed = curtime - T->curtime;
    struct list_head todo;
    int wheel;

    list_head_init(&todo);

    /*
     * There's no avoiding looping over every wheel. It's best to keep
     * WHEEL_NUM smallish.
     */
    for (wheel = 0; wheel < WHEEL_NUM; wheel++) {
        wheel_t pending;

        /*
         * Calculate the slots expiring in this wheel
         *
         * If the elapsed time is greater than the maximum period of
         * the wheel, mark every position as expiring.
         *
         * Otherwise, to determine the expired slots fill in all the
         * bits between the last slot processed and the current
         * slot, inclusive of the last slot. We'll bitwise-AND this
         * with our pending set below.
         *
         * If a wheel rolls over, force a tick of the next higher
         * wheel.
         */
        if ((elapsed >> (wheel * WHEEL_BIT)) > WHEEL_MAX) {
            pending = (wheel_t)~WHEEL_C(0);
        } else {
            const timeout_t wheel_mask = (timeout_t)WHEEL_MASK;
            wheel_t _elapsed = WHEEL_MASK & (elapsed >> (wheel * WHEEL_BIT));
            unsigned int oslot, nslot;

            /*
             * TODO: It's likely that at least one of the
             * following three bit fill operations is redundant
             * or can be replaced with a simpler operation.
             */
            oslot = (unsigned int)(wheel_mask &
                                   (T->curtime >> (wheel * WHEEL_BIT)));
            pending = rotl(((UINT64_C(1) << _elapsed) - 1), oslot);

            nslot =
                (unsigned int)(wheel_mask & (curtime >> (wheel * WHEEL_BIT)));
            pending |= rotr(rotl(((WHEEL_C(1) << _elapsed) - 1), nslot),
                            (unsigned int)_elapsed);
            pending |= WHEEL_C(1) << nslot;
        }

        while (pending & T->pending[wheel]) {
            /* ctz input cannot be zero: loop condition. */
            int slot = ctz(pending & T->pending[wheel]);

            list_append_list(&todo, &T->wheel[wheel][slot]);
            list_head_init(&T->wheel[wheel][slot]);

            T->pending[wheel] &= ~(UINT64_C(1) << slot);
        }

        if (!(0x1 & pending))
            break; /* break if we didn't wrap around end of wheel */

        /* if we're continuing, the next wheel must tick at least once */
        elapsed = MAX(elapsed, (WHEEL_LEN << (wheel * WHEEL_BIT)));
    }

    T->curtime = curtime;

    struct timeout *to, *next;
    list_for_each_safe (&todo, to, next, tqe) {
        list_del_from(&todo, &to->tqe);
        to->pending = NULL;

        timeouts_sched(T, to, to->expires);
    }

    return;
}

/*
 * Calculate the interval before needing to process any timeouts pending on
 * any wheel.
 *
 * (This is separated from the public API routine so we can evaluate our
 * wheel invariant assertions irrespective of the expired queue.)
 *
 * This might return a timeout value sooner than any installed timeout if
 * only higher-order wheels have timeouts pending. We can only know when to
 * process a wheel, not precisely when a timeout is scheduled. Our timeout
 * accuracy could be off by 2^(N*M)-1 units where N is the wheel number and
 * M is WHEEL_BIT. Only timeouts which have fallen through to wheel 0 can be
 * known exactly.
 *
 * We should never return a timeout larger than the lowest actual timeout.
 */
static timeout_t timeouts_int(struct timeouts *T)
{
    const timeout_t wheel_mask = (timeout_t)WHEEL_MASK;
    timeout_t timeout = ~TIMEOUT_C(0), _timeout;
    timeout_t relmask;
    unsigned int slot;
    int wheel;

    relmask = 0;

    for (wheel = 0; wheel < WHEEL_NUM; wheel++) {
        if (T->pending[wheel]) {
            slot = (unsigned int)(wheel_mask & (T->curtime >> (wheel * WHEEL_BIT)));

            /* ctz input cannot be zero: T->pending[wheel] is
             * nonzero, so rotr() is nonzero. */
            _timeout = (timeout_t)(ctz(rotr(T->pending[wheel], slot)) + !!wheel)
                       << (wheel * WHEEL_BIT);
            /* +1 to higher order wheels as those timeouts are one rotation in
             * the future (otherwise they'd be on a lower wheel or expired) */

            _timeout -= relmask & T->curtime;
            /* reduce by how much lower wheels have progressed */

            timeout = MIN(_timeout, timeout);
        }

        relmask <<= WHEEL_BIT;
        relmask |= WHEEL_MASK;
    }

    return timeout;
}

/*
 * Calculate the interval our caller can wait before needing to process
 * events.
 */
timeout_t timeouts_timeout(struct timeouts *T)
{
    if (!list_empty(&T->expired))
        return 0;

    return timeouts_int(T);
}

struct timeout *timeouts_get(struct timeouts *T)
{
    if (!list_empty(&T->expired)) {
        struct timeout *to = list_top(&T->expired, struct timeout, tqe);

        list_del_from(&T->expired, &to->tqe);
        to->pending = NULL;

        return to;
    } else {
        return NULL;
    }
}
