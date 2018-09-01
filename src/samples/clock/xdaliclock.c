/*
 * Lwan port of Dali Clock
 * Copyright (c) 2018 Leandro A. F. Pereira <leandro@hardinfo.org>
 *
 * Based on:
 * Dali Clock - a melting digital clock for Pebble.
 * Copyright (c) 2014 Joshua Wise <joshua@joshuawise.com>
 * Copyright (c) 1991-2010 Jamie Zawinski <jwz@jwz.org>
 *
 * Permission to use, copy, modify, distribute, and sell this software and its
 * documentation for any purpose is hereby granted without fee, provided that
 * the above copyright notice appear in all copies and that both that
 * copyright notice and this permission notice appear in supporting
 * documentation.  No representations are made about the suitability of this
 * software for any purpose.  It is provided "as is" without express or
 * implied warranty.
 */

#include <stdint.h>
#include <stdlib.h>

#include "gifenc.h"
#include "numbers.h"
#include "lwan-private.h"

#define ANIMATION_TIME_MSEC 1000

/**************************************************************************/
/* Scanline parsing.
 *
 * (Largely stolen from the PalmOS original).
 */

#define MAX_SEGS_PER_LINE 3

struct scanline {
    POS left[MAX_SEGS_PER_LINE], right[MAX_SEGS_PER_LINE];
};

struct frame {
    struct scanline scanlines[1];
};

struct xdaliclock {
    ge_GIF *gif_enc;

    int current_digits[6];
    int target_digits[6];

    struct frame *temp_frame;
    struct frame *clear_frame;

    uint32_t animtime;
    uint32_t fps;

    time_t last_time;
};

enum paint_color { BACKGROUND, FOREGROUND };

static struct frame *base_frames[12];
static POS char_height, char_width, colon_width;

static struct frame *frame_mk(int width, int height)
{
    struct frame *fr =
        calloc(1, sizeof(struct frame) +
                      (sizeof(struct scanline) * ((size_t)height - 1)));
    POS half_width = (POS)(width / 2);
    int x, y;

    if (!fr)
        return NULL;

    for (y = 0; y < height; y++) {
        for (x = 0; x < MAX_SEGS_PER_LINE; x++) {
            fr->scanlines[y].left[x] = half_width;
            fr->scanlines[y].right[x] = half_width;
        }
    }

    return fr;
}

static inline bool get_bit(const unsigned char *bits, int x, int y, int width)
{
    return bits[(y * ((width + 7) >> 3)) + (x >> 3)] & 1 << (x & 7);
}

static struct frame *
frame_from_pixmap(const unsigned char *bits, int width, int height)
{
    int x, y;
    struct frame *frame;
    POS *left, *right;
    POS half_width = (POS)(width / 2);

    frame = frame_mk(width, height);
    if (!frame)
        return NULL;

    for (y = 0; y < height; y++) {
        int seg, end;
        x = 0;

        left = frame->scanlines[y].left;
        right = frame->scanlines[y].right;

        for (seg = 0; seg < MAX_SEGS_PER_LINE; seg++) {
            left[seg] = half_width;
            right[seg] = half_width;
        }

        for (seg = 0; seg < MAX_SEGS_PER_LINE; seg++) {
            for (; x < width; x++) {
                if (get_bit(bits, x, y, width))
                    break;
            }
            if (x == width)
                break;
            left[seg] = (POS)x;
            for (; x < width; x++) {
                if (!get_bit(bits, x, y, width))
                    break;
            }
            right[seg] = (POS)x;
        }

        for (; x < width; x++) {
            if (get_bit(bits, x, y, width)) {
                /* This means the font is too curvy.  Increase MAX_SEGS_PER_LINE
                   and recompile. */
                lwan_status_debug("builtin font is bogus");
                return NULL;
            }
        }

        /* If there were any segments on this line, then replicate the last
           one out to the end of the line.  If it's blank, leave it alone,
           meaning it will be a 0-pixel-wide line down the middle.
         */
        end = seg;
        if (end > 0) {
            for (; seg < MAX_SEGS_PER_LINE; seg++) {
                left[seg] = left[end - 1];
                right[seg] = right[end - 1];
            }
        }
    }

    return frame;
}

__attribute__((constructor)) static void initialize_numbers(void)
{
    const struct raw_number *raw = get_raw_numbers();

    char_width = raw[0].width;
    char_height = raw[0].height;
    colon_width = raw[10].width;

    for (unsigned int i = 0; i < N_ELEMENTS(base_frames); i++) {
        struct frame *frame;

        frame = frame_from_pixmap(raw[i].bits, raw[i].width, raw[i].height);
        if (!frame)
            lwan_status_critical("Could not allocate frame");

        /* The base frames leak, but it's only one per program instance */
        base_frames[i] = frame;
    }
}

static inline POS lerp(const struct xdaliclock *xdc, POS a, POS b)
{
    uint32_t part_a = a * (65536 - xdc->animtime);
    uint32_t part_b = b * (xdc->animtime + 1);

    return (POS)((part_a + part_b) / 65536);
}

static void frame_lerp(struct xdaliclock *xdc, int digit)
{
    const int from = xdc->current_digits[digit];
    const int to = xdc->target_digits[digit];
    struct frame *fromf = (from >= 0) ? base_frames[from] : xdc->clear_frame;
    struct frame *tof = (to >= 0) ? base_frames[to] : xdc->clear_frame;
    int x, y;

    for (y = 0; y < char_height; y++) {
        struct scanline *line = &xdc->temp_frame->scanlines[y];
        struct scanline *to_line = &tof->scanlines[y];
        struct scanline *from_line = &fromf->scanlines[y];

        for (x = 0; x < MAX_SEGS_PER_LINE; x++) {
            line->left[x] = lerp(xdc, from_line->left[x], to_line->left[x]);
            line->right[x] = lerp(xdc, from_line->right[x], to_line->right[x]);
        }
    }
}

static void draw_horizontal_line(struct xdaliclock *xdc,
                                 int x1,
                                 int x2,
                                 int y,
                                 int screen_width,
                                 enum paint_color pc)
{
    uint8_t color = (pc == BACKGROUND) ? 0 : 3;

    if (x1 > screen_width)
        x1 = screen_width;
    else if (x1 < 0)
        x1 = 0;

    if (x2 > screen_width)
        x2 = screen_width;
    else if (x2 < 0)
        x2 = 0;

    if (x1 == x2)
        return;

    if (x1 > x2) {
        int swap = x1;
        x1 = x2;
        x2 = swap;
    }

    memset(xdc->gif_enc->frame + y * screen_width + x1, color,
           (size_t)(x2 - x1));
}

static void frame_render(struct xdaliclock *xdc, int x)
{
    struct frame *frame = xdc->temp_frame;
    int px, py;

    for (py = 0; py < char_height; py++) {
        struct scanline *line = &frame->scanlines[py];
        int last_right = 0;

        for (px = 0; px < MAX_SEGS_PER_LINE; px++) {
            if (px > 0 && (line->left[px] == line->right[px] ||
                           (line->left[px] == line->left[px - 1] &&
                            line->right[px] == line->right[px - 1]))) {
                continue;
            }

            /* Erase the line between the last segment and this segment.
             */
            draw_horizontal_line(xdc, x + last_right, x + line->left[px], py,
                                 xdc->gif_enc->w, BACKGROUND);

            /* Draw the line of this segment.
             */
            draw_horizontal_line(xdc, x + line->left[px], x + line->right[px],
                                 py, xdc->gif_enc->w, FOREGROUND);

            last_right = line->right[px];
        }

        /* Erase the line between the last segment and the right edge.
         */
        draw_horizontal_line(xdc, x + last_right, x + char_width, py,
                             xdc->gif_enc->w, BACKGROUND);
    }
}

void xdaliclock_update(struct xdaliclock *xdc)
{
    const int offsets[] = {
        0, 0, char_width / 2, char_width / 2, char_width, char_width,
    };
    time_t now;

    now = time(NULL);
    if (now != xdc->last_time) {
        struct tm *tm = localtime(&now);

        for (int i = 0; i < 6; i++)
            xdc->current_digits[i] = xdc->target_digits[i];

        xdc->target_digits[0] = tm->tm_hour / 10;
        xdc->target_digits[1] = tm->tm_hour % 10;
        xdc->target_digits[2] = tm->tm_min / 10;
        xdc->target_digits[3] = tm->tm_min % 10;
        xdc->target_digits[4] = tm->tm_sec / 10;
        xdc->target_digits[5] = tm->tm_sec % 10;

        xdc->last_time = now;
        xdc->animtime = 0;
    }

    for (int digit = 0, x = 0; digit < 6; digit++, x += char_width) {
        frame_lerp(xdc, digit);
        frame_render(xdc, x + offsets[digit]);
    }

    xdc->animtime += 65535 / (xdc->fps + 1);
}

struct xdaliclock *xdaliclock_new(ge_GIF *ge)
{
    struct xdaliclock *xdc = malloc(sizeof(*xdc));

    if (!xdc)
        return NULL;

    xdc->animtime = 0;
    xdc->fps = 10;
    xdc->gif_enc = ge;
    xdc->last_time = 0;

    xdc->temp_frame = frame_mk(char_width, char_height);
    if (!xdc->temp_frame)
        goto out;

    xdc->clear_frame = frame_mk(char_width, char_height);
    if (!xdc->clear_frame)
        goto out;

    for (unsigned int i = 0; i < N_ELEMENTS(xdc->target_digits); i++)
        xdc->target_digits[i] = xdc->current_digits[i] = -1;

    return xdc;

out:
    free(xdc);
    return NULL;
}

void xdaliclock_free(struct xdaliclock *xdc)
{
    if (!xdc)
        return;

    free(xdc->temp_frame);
    free(xdc->clear_frame);
    free(xdc);
}

uint32_t xdaliclock_get_frame_time(const struct xdaliclock *xdc)
{
    return ANIMATION_TIME_MSEC / xdc->fps;
}
