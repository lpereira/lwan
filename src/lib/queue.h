/*
 * SPSC Bounded Queue
 * Based on public domain C++ version by mstump[1]. Released under
 * the same license terms.
 *
 * [1] https://github.com/mstump/queues/blob/master/include/spsc-bounded-queue.hpp
 */

#pragma once

struct spsc_queue {
    size_t size;
    size_t mask;
    void **buffer;
    char cache_line_pad0[64 - sizeof(size_t) + sizeof(size_t) + sizeof(void *)];

    size_t head;
    char cache_line_pad1[64 - sizeof(size_t)];

    size_t tail;
    char cache_line_pad2[64 - sizeof(size_t)];    
};

int spsc_queue_init(struct spsc_queue *q, size_t size);

void spsc_queue_free(struct spsc_queue *q);

bool spsc_queue_push(struct spsc_queue *q, void *input);

void *spsc_queue_pop(struct spsc_queue *q);
