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

#define FRAMES_PER_SECOND 10

#if (FRAMES_PER_SECOND + 1) > 15
#error Animation easing routine needs to be updated for this framerate
#endif

/**************************************************************************/
/* Scanline parsing.
 *
 * (Largely stolen from the PalmOS original).
 */

#define MAX_SEGS_PER_LINE 2

struct scanline {
    POS left[MAX_SEGS_PER_LINE], right[MAX_SEGS_PER_LINE];
};

struct frame {
    struct scanline scanlines[1];
};

struct xdaliclock {
    ge_GIF *gif_enc;

    int current_digits[8];
    int target_digits[8];

    struct frame *temp_frame;
    struct frame *clear_frame;

    uint32_t frame;
};

enum paint_color { BACKGROUND, FOREGROUND };

static struct frame *base_frames[12];
static POS char_height, char_width, colon_width;
static int digit_widths[8];
static unsigned int easing[FRAMES_PER_SECOND];

static struct frame *frame_mk(int width, int height)
{
    struct frame *fr = malloc(sizeof(struct frame) +
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
                lwan_status_critical(
                    "Font too curvy. Increase MAX_SEGS_PER_LINE "
                    "and recompile");
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

    const int widths[] = {
        [0] = char_width, [1] = char_width, [2] = colon_width,
        [3] = char_width, [4] = char_width, [5] = colon_width,
        [6] = char_width, [7] = char_width, [8] = 0 /* avoid UB */,
    };
    memcpy(digit_widths, widths, sizeof(digit_widths));

    /* Pre-compute easing function. */
    for (unsigned int i = 0; i < FRAMES_PER_SECOND - 1; i++)
        easing[i] = 65535u - 65535u / (1u << (i + 1));
    easing[FRAMES_PER_SECOND - 1] = 65535u;
}

static inline POS lerp(const struct xdaliclock *xdc, POS a, POS b, unsigned int anim)
{
    uint32_t part_a = a * (65536 - anim);
    uint32_t part_b = b * (anim + 1);

    return (POS)((part_a + part_b) / 65536);
}

static void frame_lerp(struct xdaliclock *xdc, int digit, unsigned int anim)
{
    const int from = xdc->current_digits[digit];
    const int to = xdc->target_digits[digit];
    const struct frame *tof = (to >= 0) ? base_frames[to] : xdc->clear_frame;
    int x, y;

    if (from == to) {
        /* Lerping not necessary: just copy the scanlines. */
        memcpy(&xdc->temp_frame->scanlines, &tof->scanlines,
               char_height * sizeof(struct scanline));
    } else {
        const struct frame *fromf =
            (from >= 0) ? base_frames[from] : xdc->clear_frame;

        for (y = 0; y < char_height; y++) {
            struct scanline *line = &xdc->temp_frame->scanlines[y];
            const struct scanline *to_line = &tof->scanlines[y];
            const struct scanline *from_line = &fromf->scanlines[y];

            for (x = 0; x < MAX_SEGS_PER_LINE; x++) {
                line->left[x] = lerp(xdc, from_line->left[x], to_line->left[x], anim);
                line->right[x] =
                    lerp(xdc, from_line->right[x], to_line->right[x], anim);
            }
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
    const struct frame *frame = xdc->temp_frame;
    int px, py;

    for (py = 0; py < char_height; py++) {
        const struct scanline *line = &frame->scanlines[py];
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
    if (xdc->frame >= FRAMES_PER_SECOND) {
        const time_t now = time(NULL);
        const struct tm *tm = localtime(&now);

        memcpy(xdc->current_digits, xdc->target_digits,
               sizeof(xdc->current_digits));

        xdc->target_digits[0] = tm->tm_hour / 10;
        xdc->target_digits[1] = tm->tm_hour % 10;
        xdc->target_digits[2] = 10;
        xdc->target_digits[3] = tm->tm_min / 10;
        xdc->target_digits[4] = tm->tm_min % 10;
        xdc->target_digits[5] = 10;
        xdc->target_digits[6] = tm->tm_sec / 10;
        xdc->target_digits[7] = tm->tm_sec % 10;

        xdc->frame = 0;
    }

    for (int digit = 0, x = 0; digit < 8; x += digit_widths[digit++]) {
        frame_lerp(xdc, digit, easing[xdc->frame]);
        frame_render(xdc, x);
    }

    xdc->frame++;
}

struct xdaliclock *xdaliclock_new(ge_GIF *ge)
{
    struct xdaliclock *xdc = malloc(sizeof(*xdc));

    if (!xdc)
        return NULL;

    xdc->temp_frame = frame_mk(char_width, char_height);
    if (!xdc->temp_frame)
        goto out;

    xdc->clear_frame = frame_mk(char_width, char_height);
    if (!xdc->clear_frame)
        goto out;

    for (unsigned int i = 0; i < N_ELEMENTS(xdc->target_digits); i++)
        xdc->target_digits[i] = xdc->current_digits[i] = -1;

    /* Ensure time() is called the first time xdaliclock_update() is called */
    xdc->frame = FRAMES_PER_SECOND;
    xdc->gif_enc = ge;

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

uint32_t xdaliclock_get_frame_time(const struct xdaliclock *xdc
                                   __attribute__((unused)))
{
    return 1000 / FRAMES_PER_SECOND;
}
