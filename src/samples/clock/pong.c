/*
 * C port of Daniel Esteban's Pong Clock for Lwan
 * Copyright (C) 2019 Daniel Esteban <conejo@conejo.me>
 * Copyright (C) 2020 Leandro A. F. Pereira <leandro@hardinfo.org>
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

#include <limits.h>
#include <stdlib.h>
#include <math.h>

#include "pong.h"

extern const uint8_t digital_clock_font[10][5];

static float rand_float(float scale)
{
    return ((float)rand() / (float)(RAND_MAX)) * scale;
}

static void pong_time_update(struct pong_time *pong_time)
{
    time_t cur_time = time(NULL);

    if (cur_time != pong_time->last_time) {
        char digits[5];

        strftime(digits, sizeof(digits), "%H%M", localtime(&cur_time));

        for (int i = 0; i < 4; i++)
            pong_time->time[i] = digits[i] - '0';

        pong_time->hour = (digits[0] - '0') * 10 + digits[1] - '0';
        pong_time->minute = (digits[2] - '0') * 10 + digits[3] - '0';

        pong_time->last_time = cur_time;
    }
}

void pong_init(struct pong *pong, ge_GIF *gif)
{
    float ball_y = rand_float(16.0f) + 8.0f;

    *pong = (struct pong){
        .gif = gif,
        .ball_x = {.pos = 31.0f, .vel = 1.0f},
        .ball_y = {.pos = ball_y, .vel = rand() % 2 ? -0.5f : 0.5f},
        .player_left = {.y = 8, .target_y = ball_y},
        .player_right = {.y = 18, .target_y = ball_y},
        .player_loss = 0,
        .game_stopped = 0,
    };

    pong_time_update(&pong->time);
}

static void draw_pixel(unsigned char *frame, int x, int y, unsigned char color)
{
    if (x < 64 && y < 32)
        frame[y * 64 + x] = color;
}

static void pong_draw_net(const struct pong *pong)
{
    for (int i = 1; i < 32; i += 2)
        draw_pixel(pong->gif->frame, 31, i, 6);
}

static void pong_draw_player(const struct pong *pong, int x, int y)
{
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 8; j++)
            draw_pixel(pong->gif->frame, x + i, y + j, 3);
    }
}

static void pong_draw_ball(const struct pong *pong)
{
    int x = (int)pong->ball_x.pos;
    int y = (int)pong->ball_y.pos;

    draw_pixel(pong->gif->frame, x, y, 1);
    draw_pixel(pong->gif->frame, x + 1, y, 1);
    draw_pixel(pong->gif->frame, x, y + 1, 1);
    draw_pixel(pong->gif->frame, x + 1, y + 1, 1);
}

static void pong_draw_time(const struct pong *pong)
{
    static const uint8_t base_offsets[] = {23, 23, 25, 25};
    static const uint8_t colors[] = {0, 6};
    unsigned char *frame = pong->gif->frame;

    for (int digit = 0; digit < 4; digit++) {
        int dig = pong->time.time[digit];
        uint8_t off = base_offsets[digit];

        for (int line = 0, base = digit * 4; line < 5; line++, base += 64) {
            frame[base + 0 + off] = colors[!!(digital_clock_font[dig][line] & 1<<2)];
            frame[base + 1 + off] = colors[!!(digital_clock_font[dig][line] & 1<<1)];
            frame[base + 2 + off] = colors[!!(digital_clock_font[dig][line] & 1<<0)];
        }
    }
}

static float pong_calculate_end_point(const struct pong *pong, bool hit)
{
    float x = pong->ball_x.pos;
    float y = pong->ball_y.pos;
    float vel_x = pong->ball_x.vel;
    float vel_y = pong->ball_y.vel;

    for (;;) {
        x += vel_x;
        y += vel_y;
        if (hit) {
            if (x >= 60.0f || x <= 2.0f)
                return y;
        } else {
            if (x >= 62.0f || x <= 0.0f)
                return y;
        }
        if (y >= 30.0f || y <= 0.0f)
            vel_y = -vel_y;
    }
}

uint64_t pong_draw(struct pong *pong)
{
    if (pong->game_stopped < 20) {
        pong->game_stopped++;
    } else {
        pong->ball_x.pos += pong->ball_x.vel;
        pong->ball_y.pos += pong->ball_y.vel;

        if ((pong->ball_x.pos >= 60.0f && pong->player_loss != 1) ||
            (pong->ball_x.pos <= 2.0f && pong->player_loss != -1)) {
            pong->ball_x.vel = -pong->ball_x.vel;
            if (rand() % 4 > 0) {
                if (rand() % 2 == 0) {
                    if (pong->ball_y.vel > 0.0f && pong->ball_y.vel < 2.5f)
                        pong->ball_y.vel += 0.2f;
                    else if (pong->ball_y.vel < 0.0f &&
                             pong->ball_y.vel > -2.5f)
                        pong->ball_y.vel -= 0.2f;

                    if (pong->ball_x.pos >= 60.0f)
                        pong->player_right.target_y += 1.0f + rand_float(3);
                    else
                        pong->player_left.target_y += 1.0f + rand_float(3);
                } else {
                    if (pong->ball_y.vel > 0.5f)
                        pong->ball_y.vel -= 0.2f;
                    else if (pong->ball_y.vel < -0.5f)
                        pong->ball_y.vel += 0.2f;

                    if (pong->ball_x.pos >= 60.0f)
                        pong->player_right.target_y -= 1.0f + rand_float(3);
                    else
                        pong->player_left.target_y -= 1.0f + rand_float(3);
                }

                if (pong->player_left.target_y < 0.0f)
                    pong->player_left.target_y = 0.0f;
                else if (pong->player_left.target_y > 24.0f)
                    pong->player_left.target_y = 24.0f;

                if (pong->player_right.target_y < 0.0f)
                    pong->player_right.target_y = 0.0f;
                else if (pong->player_right.target_y > 24.0f)
                    pong->player_right.target_y = 24.0f;
            }
        } else if ((pong->ball_x.pos > 62.0f && pong->player_loss == 1) ||
                   (pong->ball_x.pos < 0.0f && pong->player_loss == -1)) {
            pong_init(pong, pong->gif);
        }

        if (pong->ball_y.pos >= 30.0f || pong->ball_y.pos <= 0.0f)
            pong->ball_y.vel = -pong->ball_y.vel;

        if (roundf(pong->ball_x.pos) == 40.0f + rand_float(13)) {
            pong->player_left.target_y = pong->ball_y.pos - 3.0f;

            if (pong->player_left.target_y < 0.0f)
                pong->player_left.target_y = 0.0f;
            else if (pong->player_left.target_y > 24.0f)
                pong->player_left.target_y = 24.0f;
        }
        if (roundf(pong->ball_x.pos) == 8 + rand_float(13)) {
            pong->player_right.target_y = pong->ball_y.pos - 3;

            if (pong->player_right.target_y < 0)
                pong->player_right.target_y = 0;
            else if (pong->player_right.target_y > 24)
                pong->player_right.target_y = 24;
        }

        if (pong->player_left.target_y > pong->player_left.y)
            pong->player_left.y++;
        else if (pong->player_left.target_y < pong->player_left.y)
            pong->player_left.y--;

        if (pong->player_right.target_y > pong->player_right.y)
            pong->player_right.y++;
        else if (pong->player_right.target_y < pong->player_right.y)
            pong->player_right.y--;

        /* If the ball is in the middle, check if we need to lose and calculate
         * the endpoint to avoid/hit the ball */
        if (roundf(pong->ball_x.pos) == 32.0f) {
            struct pong_time cur_time;

            pong_time_update(&cur_time);

            if (cur_time.minute != pong->time.minute && pong->player_loss == 0) {
                /* Need to change one or the other */
                if (cur_time.minute == 0) /* Need to change the hour */
                    pong->player_loss = 1;
                else /* Need to change the minute */
                    pong->player_loss = -1;
            }

            if (pong->ball_x.vel < 0) { /* Moving to the left */
                pong->player_left.target_y =
                    pong_calculate_end_point(pong, pong->player_loss != -1) - 3;
                if (pong->player_loss == -1) { /* We need to lose */
                    if (pong->player_left.target_y < 16)
                        pong->player_left.target_y = 19 + rand_float(5);
                    else
                        pong->player_left.target_y = 5 + rand_float(2);
                }

                if (pong->player_left.target_y < 0)
                    pong->player_left.target_y = 0;
                else if (pong->player_left.target_y > 24)
                    pong->player_left.target_y = 24;
            } else if (pong->ball_x.vel > 0) { /* Moving to the right */
                pong->player_right.target_y =
                    pong_calculate_end_point(pong, pong->player_loss != 1) - 3;
                if (pong->player_loss == -1) { /* We need to lose */
                    if (pong->player_right.target_y < 16)
                        pong->player_right.target_y = 19 + rand_float(5);
                    else
                        pong->player_right.target_y = 5 + rand_float(2);
                }

                if (pong->player_right.target_y < 0)
                    pong->player_right.target_y = 0;
                else if (pong->player_right.target_y > 24)
                    pong->player_right.target_y = 24;
            }

            if (pong->ball_y.pos < 0)
                pong->ball_y.pos = 0;
            else if (pong->ball_y.pos > 30)
                pong->ball_y.pos = 30;
        }
    }

    memset(pong->gif->frame, 0, 64 * 32);
    pong_draw_net(pong);
    pong_draw_time(pong);
    pong_draw_player(pong, 0, pong->player_left.y);
    pong_draw_player(pong, 62, pong->player_right.y);
    pong_draw_ball(pong);

    return 8;
}
