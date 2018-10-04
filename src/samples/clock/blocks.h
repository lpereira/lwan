#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "gifenc.h"

struct block_state {
    int num_to_draw;
    int block_index;
    int fall_index;
    int x_shift;
};

struct blocks {
    struct block_state states[4];
    int last_digits[4];
    ge_GIF *gif;
};

void blocks_init(struct blocks *blocks, ge_GIF *gif);
uint64_t blocks_draw(struct blocks *blocks, bool odd_second);
