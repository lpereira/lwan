/*
 * Falling block clock
 * Copyright (c) 2018 L. A. F. Pereira <l@tia.mat.br>
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
    SHAPE_L_REV = 2,
    SHAPE_I = 3,
    SHAPE_S = 4,
    SHAPE_S_REV = 5,
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

enum rotation {
    ROT_0,
    ROT_90,
    ROT_180,
    ROT_270,
    ROT_MAX,
};

struct fall {
    unsigned short shape : 3;
    unsigned short int x_pos : 3;
    unsigned short int y_stop : 6;
    unsigned short int n_rot : 2;
};

static const enum color colors[] = {
    [SHAPE_SQUARE] = COLOR_RED, [SHAPE_L] = COLOR_CYAN,
    [SHAPE_L_REV] = COLOR_BLUE, [SHAPE_I] = COLOR_YELLOW,
    [SHAPE_S] = COLOR_GREEN,    [SHAPE_S_REV] = COLOR_ORANGE,
    [SHAPE_T] = COLOR_MAGENTA,
};

#define PAIR(x, y) (((x) + 3) << 3 | ((y) + 3))
#define OFF(x1, y1, x2, y2, x3, y3, x4, y4)                                    \
    PAIR(x1, y1) << 24 | PAIR(x2, y2) << 16 | PAIR(x3, y3) << 8 | PAIR(x4, y4)

static const unsigned int offs[SHAPE_MAX][ROT_MAX] = {
    [SHAPE_SQUARE][ROT_0] = OFF(0, 0, 1, 0, 0, -1, 1, -1),
    [SHAPE_SQUARE][ROT_90] = OFF(0, 0, 1, 0, 0, -1, 1, -1),
    [SHAPE_SQUARE][ROT_180] = OFF(0, 0, 1, 0, 0, -1, 1, -1),
    [SHAPE_SQUARE][ROT_270] = OFF(0, 0, 1, 0, 0, -1, 1, -1),
    [SHAPE_L][ROT_0] = OFF(0, 0, 1, 0, 0, -1, 0, -2),
    [SHAPE_L][ROT_90] = OFF(0, 0, 0, -1, 1, -1, 2, -1),
    [SHAPE_L][ROT_180] = OFF(1, 0, 1, -1, 1, -2, 0, -2),
    [SHAPE_L][ROT_270] = OFF(0, 0, 1, 0, 2, 0, 2, -1),
    [SHAPE_L_REV][ROT_0] = OFF(0, 0, 1, 0, 1, -1, 1, -2),
    [SHAPE_L_REV][ROT_90] = OFF(0, 0, 1, 0, 2, 0, 0, -1),
    [SHAPE_L_REV][ROT_180] = OFF(0, 0, 0, -1, 0, -2, 1, -2),
    [SHAPE_L_REV][ROT_270] = OFF(0, -1, 1, -1, 2, -1, 2, 0),
    [SHAPE_I][ROT_0] = OFF(0, 0, 1, 0, 2, 0, 3, 0),
    [SHAPE_I][ROT_90] = OFF(0, 0, 0, -1, 0, -2, 0, -3),
    [SHAPE_I][ROT_180] = OFF(0, 0, 1, 0, 2, 0, 3, 0),
    [SHAPE_I][ROT_270] = OFF(0, 0, 0, -1, 0, -2, 0, -3),
    [SHAPE_S][ROT_0] = OFF(1, 0, 0, -1, 1, -1, 0, -2),
    [SHAPE_S][ROT_90] = OFF(0, 0, 1, 0, 1, -1, 2, -1),
    [SHAPE_S][ROT_180] = OFF(1, 0, 0, -1, 1, -1, 0, -2),
    [SHAPE_S][ROT_270] = OFF(0, 0, 1, 0, 1, -1, 2, -1),
    [SHAPE_S_REV][ROT_0] = OFF(0, 0, 0, -1, 1, -1, 1, -2),
    [SHAPE_S_REV][ROT_90] = OFF(1, 0, 2, 0, 0, -1, 1, -1),
    [SHAPE_S_REV][ROT_180] = OFF(0, 0, 0, -1, 1, -1, 1, -2),
    [SHAPE_S_REV][ROT_270] = OFF(1, 0, 2, 0, 0, -1, 1, -1),
    [SHAPE_T][ROT_0] = OFF(0, 0, 1, 0, 2, 0, 1, -1),
    [SHAPE_T][ROT_90] = OFF(0, 0, 0, -1, 0, -2, 1, -1),
    [SHAPE_T][ROT_180] = OFF(1, 0, 0, -1, 1, -1, 2, -1),
    [SHAPE_T][ROT_270] = OFF(1, 0, 0, -1, 1, -1, 1, -2),
};

#undef PAIR
#undef OFF

static const struct fall fall0[] = {
    {SHAPE_L_REV, 4, 16, 0}, {SHAPE_S, 2, 16, 1},     {SHAPE_I, 0, 16, 1},
    {SHAPE_T, 1, 16, 1},     {SHAPE_S_REV, 4, 14, 0}, {SHAPE_T, 0, 13, 3},
    {SHAPE_S_REV, 4, 12, 0}, {SHAPE_S_REV, 0, 11, 0}, {SHAPE_T, 4, 10, 1},
    {SHAPE_T, 0, 9, 1},      {SHAPE_S_REV, 1, 8, 1},  {SHAPE_L_REV, 3, 8, 3},
    {SHAPE_MAX, 0, 0, 0},
};

static const struct fall fall1[] = {
    {SHAPE_L_REV, 4, 16, 0}, {SHAPE_I, 4, 15, 1},     {SHAPE_I, 5, 13, 3},
    {SHAPE_L_REV, 4, 11, 2}, {SHAPE_SQUARE, 4, 8, 0}, {SHAPE_MAX, 0, 0, 0},
};

static const struct fall fall2[] = {
    {SHAPE_SQUARE, 4, 16, 0}, {SHAPE_I, 0, 16, 1},      {SHAPE_L, 1, 16, 3},
    {SHAPE_L, 1, 15, 0},      {SHAPE_I, 1, 12, 2},      {SHAPE_L, 0, 12, 1},
    {SHAPE_L_REV, 3, 12, 3},  {SHAPE_SQUARE, 4, 10, 0}, {SHAPE_I, 1, 8, 0},
    {SHAPE_L_REV, 3, 8, 3},   {SHAPE_L, 0, 8, 1},       {SHAPE_MAX, 0, 0, 0},
};

static const struct fall fall3[] = {
    {SHAPE_L, 3, 16, 3},      {SHAPE_L_REV, 0, 16, 1}, {SHAPE_I, 1, 15, 2},
    {SHAPE_SQUARE, 4, 14, 0}, {SHAPE_I, 1, 12, 2},     {SHAPE_L, 0, 12, 1},
    {SHAPE_I, 5, 12, 3},      {SHAPE_L_REV, 3, 11, 0}, {SHAPE_I, 1, 8, 0},
    {SHAPE_L, 0, 8, 1},       {SHAPE_L_REV, 3, 8, 3},  {SHAPE_MAX, 0, 0, 0},
};

static const struct fall fall4[] = {
    {SHAPE_SQUARE, 4, 16, 0}, {SHAPE_SQUARE, 4, 14, 0}, {SHAPE_I, 1, 12, 0},
    {SHAPE_L, 0, 12, 1},      {SHAPE_L_REV, 0, 10, 0},  {SHAPE_L_REV, 3, 12, 3},
    {SHAPE_I, 4, 10, 3},      {SHAPE_L_REV, 0, 9, 2},   {SHAPE_I, 5, 10, 1},
    {SHAPE_MAX, 0, 0, 0},
};

static const struct fall fall5[] = {
    {SHAPE_SQUARE, 0, 16, 0}, {SHAPE_L_REV, 2, 16, 1},  {SHAPE_L_REV, 3, 15, 0},
    {SHAPE_I, 5, 16, 1},      {SHAPE_I, 1, 12, 0},      {SHAPE_L, 0, 12, 1},
    {SHAPE_L_REV, 3, 12, 3},  {SHAPE_SQUARE, 0, 10, 0}, {SHAPE_I, 1, 8, 2},
    {SHAPE_L, 0, 8, 1},       {SHAPE_L_REV, 3, 8, 3},   {SHAPE_MAX, 0, 0, 0},
};

static const struct fall fall6[] = {
    {SHAPE_L_REV, 0, 16, 1}, {SHAPE_S_REV, 2, 16, 1}, {SHAPE_T, 0, 15, 3},
    {SHAPE_T, 4, 16, 3},     {SHAPE_S_REV, 4, 14, 0}, {SHAPE_I, 1, 12, 2},
    {SHAPE_L_REV, 0, 13, 2}, {SHAPE_I, 2, 11, 0},     {SHAPE_SQUARE, 0, 10, 0},
    {SHAPE_I, 1, 8, 0},      {SHAPE_L, 0, 8, 1},      {SHAPE_L_REV, 3, 8, 3},
    {SHAPE_MAX, 0, 0, 0},
};

static const struct fall fall7[] = {
    {SHAPE_SQUARE, 4, 16, 0}, {SHAPE_L, 4, 14, 0},  {SHAPE_I, 5, 13, 1},
    {SHAPE_L_REV, 4, 11, 2},  {SHAPE_I, 1, 8, 2},   {SHAPE_L_REV, 3, 8, 3},
    {SHAPE_L, 0, 8, 1},       {SHAPE_MAX, 0, 0, 0},
};

static const struct fall fall8[] = {
    {SHAPE_I, 1, 16, 0}, {SHAPE_T, 0, 16, 1},     {SHAPE_I, 5, 16, 1},
    {SHAPE_L, 2, 15, 3}, {SHAPE_S, 0, 14, 0},     {SHAPE_L, 1, 12, 3},
    {SHAPE_T, 4, 13, 1}, {SHAPE_L_REV, 0, 11, 1}, {SHAPE_S, 0, 10, 0},
    {SHAPE_S, 4, 11, 0}, {SHAPE_S_REV, 0, 8, 1},  {SHAPE_S_REV, 2, 8, 1},
    {SHAPE_L, 4, 9, 2},  {SHAPE_MAX, 0, 0, 0},
};

static const struct fall fall9[] = {
    {SHAPE_SQUARE, 0, 16, 0}, {SHAPE_I, 2, 16, 0},    {SHAPE_L, 2, 15, 3},
    {SHAPE_L, 4, 15, 2},      {SHAPE_I, 1, 12, 2},    {SHAPE_I, 5, 12, 3},
    {SHAPE_S_REV, 0, 12, 0},  {SHAPE_L, 2, 11, 3},    {SHAPE_S_REV, 4, 9, 0},
    {SHAPE_T, 0, 10, 1},      {SHAPE_S_REV, 0, 8, 1}, {SHAPE_T, 2, 8, 2},
    {SHAPE_MAX, 0, 0, 0},
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

static void draw_shape_full(enum shape shape,
                            enum color color,
                            int x,
                            int y,
                            int w,
                            int h,
                            enum rotation rot,
                            unsigned char *buffer)
{
    unsigned int offset = offs[shape][rot];
    const int area = w * h;

    for (int i = 0; i < 4; i++) {
        int y_off, x_off, dx, dy, index;

        y_off = ((int)(offset & 7)) - 3;
        offset >>= 3;
        x_off = ((int)(offset & 7)) - 3;
        offset >>= 5;

        dx = x + x_off;
        dy = y + y_off;
        index = dy * 32 + dx;

        if (index >= 0 && index < area && dx < w)
            buffer[index] = (unsigned char)color;
    }
}

static void draw_shape(enum shape shape,
                       int x,
                       int y,
                       int w,
                       int h,
                       enum rotation rot,
                       unsigned char *buffer)
{
    draw_shape_full(shape, colors[shape], x, y, w, h, rot, buffer);
}

void blocks_init(struct blocks *blocks, ge_GIF *gif)
{
    blocks->states[0] = (struct block_state){0, 0, 0, 1};
    blocks->states[1] = (struct block_state){0, 0, 0, 8};
    blocks->states[2] = (struct block_state){0, 0, 0, 18};
    blocks->states[3] = (struct block_state){0, 0, 0, 25};
    blocks->gif = gif;
    memset(blocks->last_digits, 0, sizeof(blocks->last_digits));
}

uint64_t blocks_draw(struct blocks *blocks, bool odd_second)
{
    unsigned char *frame = blocks->gif->frame;
    int digits_fallen = 0;
    int i;
    int w = blocks->gif->w;
    int h = blocks->gif->h;

    memset(frame, COLOR_BLACK, (size_t)(w * h));

    for (i = 0; i < 4; i++) {
        struct block_state *state = &blocks->states[i];

        if (state->num_to_draw != blocks->last_digits[i]) {
            state->fall_index = 0;
            state->block_index = 0;
            blocks->last_digits[i] = state->num_to_draw;
        }

        if (state->block_index < block_sizes[state->num_to_draw]) {
            const struct fall *curr =
                &fall[state->num_to_draw][state->block_index];
            int rotations = curr->n_rot;

            switch (rotations) {
            case 1:
                if (state->fall_index < curr->y_stop / 2)
                    rotations = ROT_0;
                break;
            case 2:
                if (state->fall_index < curr->y_stop / 3)
                    rotations = ROT_0;
                else if (state->fall_index < curr->y_stop / 3 * 2)
                    rotations = ROT_90;
                break;
            case 3:
                if (state->fall_index < curr->y_stop / 4)
                    rotations = ROT_0;
                else if (state->fall_index < curr->y_stop / 4 * 2)
                    rotations = ROT_90;
                else if (state->fall_index < curr->y_stop / 4 * 3)
                    rotations = ROT_180;
                break;
            }

            assert(rotations >= 0 && rotations < ROT_MAX);

            draw_shape(curr->shape, curr->x_pos + state->x_shift,
                       state->fall_index - 1, w, h,
                       (enum rotation)rotations, frame);
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

                draw_shape(fallen->shape, fallen->x_pos + state->x_shift,
                           fallen->y_stop - 1, w, h, fallen->n_rot, frame);
            }
        }
    }

    if (odd_second) {
        draw_shape_full(SHAPE_SQUARE, COLOR_WHITE, 15, 13, w, h, ROT_0, frame);
        draw_shape_full(SHAPE_SQUARE, COLOR_WHITE, 15, 9, w, h, ROT_0, frame);
    }

    return digits_fallen ? 100 : 500;
}
