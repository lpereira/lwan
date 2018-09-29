#pragma once

#include <stdint.h>
#include <stdbool.h>

struct block_state {
    int num_to_draw;
    int block_index;
    int fall_index;
    int x_shift;
};

void blocks_init(struct block_state *states);
uint64_t blocks_draw(struct block_state *states, unsigned char *buffer, bool odd_second);
