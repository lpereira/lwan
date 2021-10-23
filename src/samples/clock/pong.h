/*
 * C port of Daniel Esteban's Pong Clock for Lwan
 * Copyright (C) 2019 Daniel Esteban <conejo@conejo.me>
 * Copyright (C) 2020 L. A. F. Pereira <l@tia.mat.br>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is 
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#pragma once

#include <stdint.h>
#include <time.h>
#include "gifenc.h"

struct pong_time {
    time_t last_time;
    char time[4];
    int hour, minute;
};

struct pong {
    ge_GIF *gif;
    struct {
        float pos;
        float vel;
    } ball_x, ball_y;
    struct {
        int y;
        float target_y;
    } player_left, player_right;
    int player_loss;
    int game_stopped;
    struct pong_time time;
};

void pong_init(struct pong *pong, ge_GIF *gif);
uint64_t pong_draw(struct pong *pong);
