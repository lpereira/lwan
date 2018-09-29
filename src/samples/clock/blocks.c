/*
 * Falling block clock
 * Copyright (c) 2018 Leandro A. F. Pereira <leandro@hardinfo.org>
 *
 * Inspired by code written by Tobias Blum
 * https://github.com/toblum/esp_p10_tetris_clock
 *
 * Licensed under the terms of the MIT License.
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "blocks.h"

enum shape {
    SHAPE_SQUARE = 0,
    SHAPE_L = 1,
    SHAPE_L_REVERSE = 2,
    SHAPE_I = 3,
    SHAPE_S = 4,
    SHAPE_S_REVERSE = 5,
    SHAPE_T = 6,
    SHAPE_MAX,
};

enum color {
    COLOR_BLACK = 0,
    COLOR_RED = 1,
    COLOR_GREEN = 2,
    COLOR_ORANGE = 3,
    COLOR_BLUE = 4,
    COLOR_MAGENTA = 5,
    COLOR_CYAN = 6,
    COLOR_YELLOW = 11,
    COLOR_WHITE = 15,
    COLOR_MAX,
};

struct fall {
    enum shape shape;
    enum color color;
    int x_pos;
    int y_stop;
    int n_rot;
};

static const int offs[SHAPE_MAX][4][8] = {
    [SHAPE_SQUARE][0] = {0, 0, 1, 0, 0, -1, 1, -1},
    [SHAPE_SQUARE][1] = {0, 0, 1, 0, 0, -1, 1, -1},
    [SHAPE_SQUARE][2] = {0, 0, 1, 0, 0, -1, 1, -1},
    [SHAPE_SQUARE][3] = {0, 0, 1, 0, 0, -1, 1, -1},
    [SHAPE_L][0] = {0, 0, 1, 0, 0, -1, 0, -2},
    [SHAPE_L][1] = {0, 0, 0, -1, 1, -1, 2, -1},
    [SHAPE_L][2] = {1, 0, 1, -1, 1, -2, 0, -2},
    [SHAPE_L][3] = {0, 0, 1, 0, 2, 0, 2, -1},
    [SHAPE_L_REVERSE][0] = {0, 0, 1, 0, 1, -1, 1, -2},
    [SHAPE_L_REVERSE][1] = {0, 0, 1, 0, 2, 0, 0, -1},
    [SHAPE_L_REVERSE][2] = {0, 0, 0, -1, 0, -2, 1, -2},
    [SHAPE_L_REVERSE][3] = {0, -1, 1, -1, 2, -1, 2, 0},
    [SHAPE_I][0] = {0, 0, 1, 0, 2, 0, 3, 0},
    [SHAPE_I][1] = {0, 0, 0, -1, 0, -2, 0, -3},
    [SHAPE_I][2] = {0, 0, 1, 0, 2, 0, 3, 0},
    [SHAPE_I][3] = {0, 0, 0, -1, 0, -2, 0, -3},
    [SHAPE_S][0] = {1, 0, 0, -1, 1, -1, 0, -2},
    [SHAPE_S][1] = {0, 0, 1, 0, 1, -1, 2, -1},
    [SHAPE_S][2] = {1, 0, 0, -1, 1, -1, 0, -2},
    [SHAPE_S][3] = {0, 0, 1, 0, 1, -1, 2, -1},
    [SHAPE_S_REVERSE][0] = {0, 0, 0, -1, 1, -1, 1, -2},
    [SHAPE_S_REVERSE][1] = {1, 0, 2, 0, 0, -1, 1, -1},
    [SHAPE_S_REVERSE][2] = {0, 0, 0, -1, 1, -1, 1, -2},
    [SHAPE_S_REVERSE][3] = {1, 0, 2, 0, 0, -1, 1, -1},
    [SHAPE_T][0] = {0, 0, 1, 0, 2, 0, 1, -1},
    [SHAPE_T][1] = {0, 0, 0, -1, 0, -2, 1, -1},
    [SHAPE_T][2] = {1, 0, 0, -1, 1, -1, 2, -1},
    [SHAPE_T][3] = {1, 0, 0, -1, 1, -1, 1, -2},
};

static const struct fall fall0[] = {
    {SHAPE_L_REVERSE, COLOR_CYAN, 4, 16, 0},
    {SHAPE_S, COLOR_ORANGE, 2, 16, 1},
    {SHAPE_I, COLOR_YELLOW, 0, 16, 1},
    {SHAPE_T, COLOR_MAGENTA, 1, 16, 1},
    {SHAPE_S_REVERSE, COLOR_GREEN, 4, 14, 0},
    {SHAPE_T, COLOR_MAGENTA, 0, 13, 3},
    {SHAPE_S_REVERSE, COLOR_GREEN, 4, 12, 0},
    {SHAPE_S_REVERSE, COLOR_GREEN, 0, 11, 0},
    {SHAPE_T, COLOR_MAGENTA, 4, 10, 1},
    {SHAPE_T, COLOR_MAGENTA, 0, 9, 1},
    {SHAPE_S_REVERSE, COLOR_GREEN, 1, 8, 1},
    {SHAPE_L_REVERSE, COLOR_CYAN, 3, 8, 3},
    {SHAPE_MAX, COLOR_MAX, 0, 0, 0},
};

static const struct fall fall1[] = {
    {SHAPE_L_REVERSE, COLOR_CYAN, 4, 16, 0},
    {SHAPE_I, COLOR_YELLOW, 4, 15, 1},
    {SHAPE_I, COLOR_YELLOW, 5, 13, 3},
    {SHAPE_L_REVERSE, COLOR_CYAN, 4, 11, 2},
    {SHAPE_SQUARE, COLOR_RED, 4, 8, 0},
    {SHAPE_MAX, COLOR_MAX, 0, 0, 0},
};

static const struct fall fall2[] = {
    {SHAPE_SQUARE, COLOR_RED, 4, 16, 0},
    {SHAPE_I, COLOR_YELLOW, 0, 16, 1},
    {SHAPE_L, COLOR_BLUE, 1, 16, 3},
    {SHAPE_L, COLOR_BLUE, 1, 15, 0},
    {SHAPE_I, COLOR_YELLOW, 1, 12, 2},
    {SHAPE_L, COLOR_BLUE, 0, 12, 1},
    {SHAPE_L_REVERSE, COLOR_CYAN, 3, 12, 3},
    {SHAPE_SQUARE, COLOR_RED, 4, 10, 0},
    {SHAPE_I, COLOR_YELLOW, 1, 8, 0},
    {SHAPE_L_REVERSE, COLOR_CYAN, 3, 8, 3},
    {SHAPE_L, COLOR_BLUE, 0, 8, 1},
    {SHAPE_MAX, COLOR_MAX, 0, 0, 0},
};

static const struct fall fall3[] = {
    {SHAPE_L, COLOR_BLUE, 3, 16, 3},
    {SHAPE_L_REVERSE, COLOR_CYAN, 0, 16, 1},
    {SHAPE_I, COLOR_YELLOW, 1, 15, 2},
    {SHAPE_SQUARE, COLOR_RED, 4, 14, 0},
    {SHAPE_I, COLOR_YELLOW, 1, 12, 2},
    {SHAPE_L, COLOR_BLUE, 0, 12, 1},
    {SHAPE_I, COLOR_YELLOW, 5, 12, 3},
    {SHAPE_L_REVERSE, COLOR_CYAN, 3, 11, 0},
    {SHAPE_I, COLOR_YELLOW, 1, 8, 0},
    {SHAPE_L, COLOR_BLUE, 0, 8, 1},
    {SHAPE_L_REVERSE, COLOR_CYAN, 3, 8, 3},
    {SHAPE_MAX, COLOR_MAX, 0, 0, 0},
};

static const struct fall fall4[] = {
    {SHAPE_SQUARE, COLOR_RED, 4, 16, 0},
    {SHAPE_SQUARE, COLOR_RED, 4, 14, 0},
    {SHAPE_I, COLOR_YELLOW, 1, 12, 0},
    {SHAPE_L, COLOR_BLUE, 0, 12, 1},
    {SHAPE_L_REVERSE, COLOR_CYAN, 0, 10, 0},
    {SHAPE_L_REVERSE, COLOR_CYAN, 3, 12, 3},
    {SHAPE_I, COLOR_YELLOW, 4, 10, 3},
    {SHAPE_L_REVERSE, COLOR_CYAN, 0, 9, 2},
    {SHAPE_I, COLOR_YELLOW, 5, 10, 1},
    {SHAPE_MAX, COLOR_MAX, 0, 0, 0},
};

static const struct fall fall5[] = {
    {SHAPE_SQUARE, COLOR_RED, 0, 16, 0},
    {SHAPE_L_REVERSE, COLOR_CYAN, 2, 16, 1},
    {SHAPE_L_REVERSE, COLOR_CYAN, 3, 15, 0},
    {SHAPE_I, COLOR_YELLOW, 5, 16, 1},
    {SHAPE_I, COLOR_YELLOW, 1, 12, 0},
    {SHAPE_L, COLOR_BLUE, 0, 12, 1},
    {SHAPE_L_REVERSE, COLOR_CYAN, 3, 12, 3},
    {SHAPE_SQUARE, COLOR_RED, 0, 10, 0},
    {SHAPE_I, COLOR_YELLOW, 1, 8, 2},
    {SHAPE_L, COLOR_BLUE, 0, 8, 1},
    {SHAPE_L_REVERSE, COLOR_CYAN, 3, 8, 3},
    {SHAPE_MAX, COLOR_MAX, 0, 0, 0},
};

static const struct fall fall6[] = {
    {SHAPE_L_REVERSE, COLOR_CYAN, 0, 16, 1},
    {SHAPE_S_REVERSE, COLOR_GREEN, 2, 16, 1},
    {SHAPE_T, COLOR_MAGENTA, 0, 15, 3},
    {SHAPE_T, COLOR_MAGENTA, 4, 16, 3},
    {SHAPE_S_REVERSE, COLOR_GREEN, 4, 14, 0},
    {SHAPE_I, COLOR_YELLOW, 1, 12, 2},
    {SHAPE_L_REVERSE, COLOR_CYAN, 0, 13, 2},
    {SHAPE_I, COLOR_YELLOW, 2, 11, 0},
    {SHAPE_SQUARE, COLOR_RED, 0, 10, 0},
    {SHAPE_I, COLOR_YELLOW, 1, 8, 0},
    {SHAPE_L, COLOR_BLUE, 0, 8, 1},
    {SHAPE_L_REVERSE, COLOR_CYAN, 3, 8, 3},
    {SHAPE_MAX, COLOR_MAX, 0, 0, 0},
};

static const struct fall fall7[] = {
    {SHAPE_SQUARE, COLOR_RED, 4, 16, 0},
    {SHAPE_L, COLOR_BLUE, 4, 14, 0},
    {SHAPE_I, COLOR_YELLOW, 5, 13, 1},
    {SHAPE_L_REVERSE, COLOR_CYAN, 4, 11, 2},
    {SHAPE_I, COLOR_YELLOW, 1, 8, 2},
    {SHAPE_L_REVERSE, COLOR_CYAN, 3, 8, 3},
    {SHAPE_L, COLOR_BLUE, 0, 8, 1},
    {SHAPE_MAX, COLOR_MAX, 0, 0, 0},
};

static const struct fall fall8[] = {
    {SHAPE_I, COLOR_YELLOW, 1, 16, 0},
    {SHAPE_T, COLOR_MAGENTA, 0, 16, 1},
    {SHAPE_I, COLOR_YELLOW, 5, 16, 1},
    {SHAPE_L, COLOR_BLUE, 2, 15, 3},
    {SHAPE_S, COLOR_ORANGE, 0, 14, 0},
    {SHAPE_L, COLOR_BLUE, 1, 12, 3},
    {SHAPE_T, COLOR_MAGENTA, 4, 13, 1},
    {SHAPE_L_REVERSE, COLOR_CYAN, 0, 11, 1},
    {SHAPE_S, COLOR_ORANGE, 0, 10, 0},
    {SHAPE_S, COLOR_ORANGE, 4, 11, 0},
    {SHAPE_S_REVERSE, COLOR_GREEN, 0, 8, 1},
    {SHAPE_S_REVERSE, COLOR_GREEN, 2, 8, 1},
    {SHAPE_L, COLOR_BLUE, 4, 9, 2},
    {SHAPE_MAX, COLOR_MAX, 0, 0, 0},
};

static const struct fall fall9[] = {
    {SHAPE_SQUARE, COLOR_RED, 0, 16, 0},
    {SHAPE_I, COLOR_YELLOW, 2, 16, 0},
    {SHAPE_L, COLOR_BLUE, 2, 15, 3},
    {SHAPE_L, COLOR_BLUE, 4, 15, 2},
    {SHAPE_I, COLOR_YELLOW, 1, 12, 2},
    {SHAPE_I, COLOR_YELLOW, 5, 12, 3},
    {SHAPE_S_REVERSE, COLOR_GREEN, 0, 12, 0},
    {SHAPE_L, COLOR_BLUE, 2, 11, 3},
    {SHAPE_S_REVERSE, COLOR_GREEN, 4, 9, 0},
    {SHAPE_T, COLOR_MAGENTA, 0, 10, 1},
    {SHAPE_S_REVERSE, COLOR_GREEN, 0, 8, 1},
    {SHAPE_T, COLOR_MAGENTA, 2, 8, 2},
    {SHAPE_MAX, COLOR_MAX, 0, 0, 0},
};

static const struct fall *fall[] = {
    fall0, fall1, fall2, fall3, fall4, fall5, fall6, fall7, fall8, fall9,
};

static int block_sizes[10];

__attribute__((constructor)) void calculate_block_sizes(void)
{
    for (int i = 0; i < 10; i++) {
        const struct fall *instr = fall[i];

        while (instr->shape != SHAPE_MAX)
            instr++;

        block_sizes[i] = (int)(instr - fall[i]) + 1;
    }
}

static void draw_shape(enum shape shape,
                       enum color color,
                       int x,
                       int y,
                       int rot,
                       unsigned char *buffer)
{
    assert(rot >= 0 && rot <= 3);

    if (y < 0)
        return;

    for (int i = 0; i < 8; i += 2) {
        int x_off = offs[shape][rot][i + 0];
        int y_off = offs[shape][rot][i + 1];
        int dx = x + x_off;

        if (dx < 32)
            buffer[(y + y_off) * 32 + dx] = color;
    }
}

void blocks_init(struct block_state *states)
{
    states[0] = (struct block_state){1, 0, 0, 1};
    states[1] = (struct block_state){2, 0, 0, 8};
    states[2] = (struct block_state){3, 0, 0, 18};
    states[3] = (struct block_state){4, 0, 0, 25};
}

uint64_t blocks_draw(struct block_state *states, unsigned char *buffer, bool odd_second)
{
    int digits_fallen = 0;
    int i;

    memset(buffer, COLOR_BLACK, 32 * 16);

    for (i = 0; i < 4; i++) {
        struct block_state *state = &states[i];

        if (state->block_index < block_sizes[state->num_to_draw]) {
            const struct fall *curr =
                &fall[state->num_to_draw][state->block_index];
            int rotations = curr->n_rot;

            switch (rotations) {
            case 1:
                if (state->fall_index < curr->y_stop / 2)
                    rotations = 0;
                break;
            case 2:
                if (state->fall_index < curr->y_stop / 3)
                    rotations = 0;
                else if (state->fall_index < curr->y_stop / 3 * 2)
                    rotations = 1;
                break;
            case 3:
                if (state->fall_index < curr->y_stop / 4)
                    rotations = 0;
                else if (state->fall_index < curr->y_stop / 4 * 2)
                    rotations = 1;
                else if (state->fall_index < curr->y_stop / 4 * 3)
                    rotations = 2;
                break;
            }

            draw_shape(curr->shape, curr->color, curr->x_pos + state->x_shift,
                       state->fall_index - 1, rotations, buffer);
            state->fall_index++;

            if (state->fall_index > curr->y_stop) {
                state->fall_index = 0;
                state->block_index++;
            }

            digits_fallen++;
        }

        if (state->block_index > 0) {
            for (int j = 0; j < state->block_index; j++) {
                const struct fall *fallen = &fall[state->num_to_draw][j];

                draw_shape(fallen->shape, fallen->color,
                           fallen->x_pos + state->x_shift, fallen->y_stop - 1,
                           fallen->n_rot, buffer);
            }
        }
    }

    if (odd_second & 1) {
        draw_shape(SHAPE_SQUARE, COLOR_WHITE, 15, 13, 0, buffer);
        draw_shape(SHAPE_SQUARE, COLOR_WHITE, 15, 9, 0, buffer);
    }

    return digits_fallen ? 100 : 500;
}
