/*
 * SPSC Bounded Queue
 * Based on public domain C++ version by mstump[1]. Released under
 * the same license terms.
 *
 * [1] https://github.com/mstump/queues/blob/master/include/spsc-bounded-queue.hpp
 */

#include <malloc.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>

#include "queue.h"
#include "lwan-private.h"

#if !defined(ATOMIC_RELAXED)

#define ATOMIC_RELAXED		__ATOMIC_RELAXED
#define ATOMIC_ACQUIRE		__ATOMIC_ACQUIRE
#define ATOMIC_RELEASE		__ATOMIC_RELEASE

#endif

#if defined(__GNUC__)

# if (__GNUC__ * 100 + __GNUC_MINOR__ >= 470)
#   define HAS_GCC_ATOMIC 1
# else
#   define HAS_SYNC_ATOMIC 1
#endif

#endif

#if HAS_GCC_ATOMIC

#define ATOMIC_INIT(P, V)	do { (P) = (V); } while (0)

#define ATOMIC_LOAD(P, O)	__atomic_load_n((P), (O))
#define ATOMIC_STORE(P, V, O)	__atomic_store_n((P), (V), (O))

#elif HAS_SYNC_ATOMIC

#define ATOMIC_INIT(P, V)	do { (P) = (V); } while(0)

#define ATOMIC_LOAD(P, O)	({ __sync_fetch_and_add((P), 0); })
#define ATOMIC_STORE(P, V, O)	({ __sync_synchronize(); __sync_lock_test_and_set((P), (V)); })

#else

#error Unsupported compiler.

#endif

int
spsc_queue_init(struct spsc_queue *q, size_t size)
{
    if (size == 0)
        return -EINVAL;

    size = lwan_nextpow2(size);
    q->buffer = memalign(sizeof(void *), (1 + size) * sizeof(void *));
    if (!q->buffer)
        return -errno;

    ATOMIC_INIT(q->head, 0);
    ATOMIC_INIT(q->tail, 0);

    q->size = size;
    q->mask = size - 1;

    return 0;
}

void
spsc_queue_free(struct spsc_queue *q)
{
    free(q->buffer);
}

bool
spsc_queue_push(struct spsc_queue *q, void *input)
{
    const size_t head = ATOMIC_LOAD(&q->head, ATOMIC_RELAXED);

    if (((ATOMIC_LOAD(&q->tail, ATOMIC_ACQUIRE) - (head + 1)) & q->mask) >= 1) {
        q->buffer[head & q->mask] = input;
        ATOMIC_STORE(&q->head, head + 1, ATOMIC_RELEASE);

        return true;
    }

    return false;
}

void *
spsc_queue_pop(struct spsc_queue *q)
{
    const size_t tail = ATOMIC_LOAD(&q->tail, ATOMIC_RELAXED);

    if (((ATOMIC_LOAD(&q->head, ATOMIC_ACQUIRE) - tail) & q->mask) >= 1) {
        void *output = q->buffer[tail & q->mask];

        ATOMIC_STORE(&q->tail, tail + 1, ATOMIC_RELEASE);

        return output;
    }

    return NULL;
}
