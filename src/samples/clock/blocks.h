#pragma once

#include <stdbool.h>
#include <stdint.h>

struct block_state {
    int num_to_draw;
    int block_index;
    int fall_index;
    int x_shift;
};

void blocks_init(struct block_state states[static 4]);
uint64_t blocks_draw(struct block_state states[static 4],
                     unsigned char *buffer,
                     bool odd_second);
