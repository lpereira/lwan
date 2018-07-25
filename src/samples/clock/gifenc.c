/*
 * All of the source code and documentation for gifenc is released into the
 * public domain and provided without warranty of any kind.
 *
 * Author: Marcel Rodrigues <https://github.com/lecram>
 */
#include "gifenc.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static uint8_t vga[0x30] = {
    0x00, 0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0xAA, 0x00, 0xAA, 0x55, 0x00,
    0x00, 0x00, 0xAA, 0xAA, 0x00, 0xAA, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0x55, 0x55, 0x55, 0xFF, 0x55, 0x55, 0x55, 0xFF, 0x55, 0xFF, 0xFF, 0x55,
    0x55, 0x55, 0xFF, 0xFF, 0x55, 0xFF, 0x55, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wpointer-sign"

struct Node {
    uint16_t key;
    struct Node *children[];
};
typedef struct Node Node;

static Node *new_node(uint16_t key, int degree)
{
    Node *node = calloc(1, sizeof(*node) + degree * sizeof(Node *));
    if (node)
        node->key = key;
    return node;
}

static Node *new_trie(int degree, int *nkeys)
{
    Node *root = new_node(0, degree);
    /* Create nodes for single pixels. */
    for (*nkeys = 0; *nkeys < degree; (*nkeys)++)
        root->children[*nkeys] = new_node(*nkeys, degree);
    *nkeys += 2; /* skip clear code and stop code */
    return root;
}

static void del_trie(Node *root, int degree)
{
    if (!root)
        return;
    for (int i = 0; i < degree; i++)
        del_trie(root->children[i], degree);
    free(root);
}

static void put_loop(ge_GIF *gif, uint16_t loop);

static void write_num(struct lwan_strbuf *buf, int16_t num)
{
    lwan_strbuf_append_char(buf, num & 0xff);
    lwan_strbuf_append_char(buf, num >> 8);
}

ge_GIF *ge_new_gif(struct lwan_strbuf *buf,
                   uint16_t width,
                   uint16_t height,
                   uint8_t *palette,
                   int depth,
                   int loop)
{
    int i, r, g, b, v;
    ge_GIF *gif = calloc(1, sizeof(*gif) + 2 * width * height);

    if (!gif)
        goto no_gif;

    gif->w = width;
    gif->h = height;
    gif->depth = depth > 1 ? depth : 2;
    gif->frame = (uint8_t *)&gif[1];
    gif->back = &gif->frame[width * height];
    gif->buf = buf;

    lwan_strbuf_append_str(buf, "GIF89a", 6);
    write_num(buf, width);
    write_num(buf, height);
    lwan_strbuf_append_str(buf, (const char[]){0xF0 | (depth - 1), 0x00, 0x00},
                           3);

    if (palette) {
        lwan_strbuf_append_str(buf, palette, 3 << depth);
    } else if (depth <= 4) {
        lwan_strbuf_append_str(buf, vga, 3 << depth);
    } else {
        lwan_strbuf_append_str(buf, vga, sizeof(vga));

        i = 0x10;
        for (r = 0; r < 6; r++) {
            for (g = 0; g < 6; g++) {
                for (b = 0; b < 6; b++) {
                    lwan_strbuf_append_str(
                        buf, (const char[]){r * 51, g * 51, b * 51}, 3);
                    if (++i == 1 << depth)
                        goto done_gct;
                }
            }
        }
        for (i = 1; i <= 24; i++) {
            v = i * 0xFF / 25;
            lwan_strbuf_append_str(buf, (const char[]){v, v, v}, 3);
        }
    }

done_gct:
    if (loop >= 0 && loop <= 0xFFFF)
        put_loop(gif, (uint16_t)loop);
    return gif;

no_gif:
    return NULL;
}

static void put_loop(ge_GIF *gif, uint16_t loop)
{
    lwan_strbuf_append_str(gif->buf, (const char[]){'!', 0xFF, 0x0B}, 3);
    lwan_strbuf_append_str(gif->buf, "NETSCAPE2.0", 11);
    lwan_strbuf_append_str(gif->buf, (const char[]){0x03, 0x01}, 2);
    write_num(gif->buf, loop);
    lwan_strbuf_append_char(gif->buf, '\0');
}

/* Add packed key to buffer, updating offset and partial.
 *   gif->offset holds position to put next *bit*
 *   gif->partial holds bits to include in next byte */
static void put_key(ge_GIF *gif, uint16_t key, int key_size)
{
    int byte_offset, bit_offset, bits_to_write;

    byte_offset = gif->offset / 8;
    bit_offset = gif->offset % 8;
    gif->partial |= ((uint32_t)key) << bit_offset;
    bits_to_write = bit_offset + key_size;

    while (bits_to_write >= 8) {
        gif->buffer[byte_offset++] = gif->partial & 0xFF;

        if (byte_offset == 0xFF) {
            lwan_strbuf_append_char(gif->buf, 0xff);
            lwan_strbuf_append_str(gif->buf, gif->buffer, 0xff);

            byte_offset = 0;
        }

        gif->partial >>= 8;
        bits_to_write -= 8;
    }
    gif->offset = (gif->offset + key_size) % (0xFF * 8);
}

static void end_key(ge_GIF *gif)
{
    int byte_offset;

    byte_offset = gif->offset / 8;
    if (gif->offset % 8)
        gif->buffer[byte_offset++] = gif->partial & 0xFF;

    lwan_strbuf_append_char(gif->buf, byte_offset);
    lwan_strbuf_append_str(gif->buf, gif->buffer, byte_offset);
    lwan_strbuf_append_char(gif->buf, '\0');

    gif->offset = gif->partial = 0;
}

static void
put_image(ge_GIF *gif, uint16_t w, uint16_t h, uint16_t x, uint16_t y)
{
    int nkeys, key_size, i, j;
    Node *node, *child, *root;
    int degree = 1 << gif->depth;

    lwan_strbuf_append_char(gif->buf, ',');
    write_num(gif->buf, x);
    write_num(gif->buf, y);
    write_num(gif->buf, w);
    write_num(gif->buf, h);
    lwan_strbuf_append_str(gif->buf, (const char[]){0x00, gif->depth}, 2);

    root = node = new_trie(degree, &nkeys);
    key_size = gif->depth + 1;
    put_key(gif, degree, key_size); /* clear code */

    for (i = y; i < y + h; i++) {
        for (j = x; j < x + w; j++) {
            uint8_t pixel = gif->frame[i * gif->w + j] & (degree - 1);
            child = node->children[pixel];

            if (child) {
                node = child;
            } else {
                put_key(gif, node->key, key_size);
                if (nkeys < 0x1000) {
                    if (nkeys == (1 << key_size))
                        key_size++;
                    node->children[pixel] = new_node(nkeys++, degree);
                } else {
                    put_key(gif, degree, key_size); /* clear code */
                    del_trie(root, degree);
                    root = node = new_trie(degree, &nkeys);
                    key_size = gif->depth + 1;
                }
                node = root->children[pixel];
            }
        }
    }

    put_key(gif, node->key, key_size);
    put_key(gif, degree + 1, key_size); /* stop code */
    end_key(gif);
    del_trie(root, degree);
}

static int
get_bbox(ge_GIF *gif, uint16_t *w, uint16_t *h, uint16_t *x, uint16_t *y)
{
    int i, j, k;
    int left, right, top, bottom;

    left = gif->w;
    right = 0;
    top = gif->h;
    bottom = 0;
    k = 0;
    for (i = 0; i < gif->h; i++) {
        for (j = 0; j < gif->w; j++, k++) {
            if (gif->frame[k] != gif->back[k]) {
                if (j < left)
                    left = j;
                if (j > right)
                    right = j;
                if (i < top)
                    top = i;
                if (i > bottom)
                    bottom = i;
            }
        }
    }

    if (left != gif->w && top != gif->h) {
        *x = left;
        *y = top;
        *w = right - left + 1;
        *h = bottom - top + 1;
        return 1;
    } else {
        return 0;
    }
}

static void set_delay(ge_GIF *gif, uint16_t d)
{
    lwan_strbuf_append_str(gif->buf, (const char[]){'!', 0xF9, 0x04, 0x04}, 4);
    write_num(gif->buf, d);
    lwan_strbuf_append_str(gif->buf, "\0\0", 2);
}

void ge_add_frame(ge_GIF *gif, uint16_t delay)
{
    uint16_t w, h, x, y;
    uint8_t *tmp;

    if (delay)
        set_delay(gif, delay);
    if (gif->nframes == 0) {
        w = gif->w;
        h = gif->h;
        x = y = 0;
    } else if (!get_bbox(gif, &w, &h, &x, &y)) {
        /* image's not changed; save one pixel just to add delay */
        w = h = 1;
        x = y = 0;
    }
    put_image(gif, w, h, x, y);
    gif->nframes++;
    tmp = gif->back;
    gif->back = gif->frame;
    gif->frame = tmp;
}

struct lwan_strbuf *ge_close_gif(ge_GIF *gif)
{
    struct lwan_strbuf *buf = gif->buf;

    lwan_strbuf_append_char(gif->buf, ';');
    free(gif);

    return buf;
}
