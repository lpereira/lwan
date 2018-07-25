/*
 * All of the source code and documentation for gifenc is released into the
 * public domain and provided without warranty of any kind.
 *
 * Author: Marcel Rodrigues <https://github.com/lecram>
 */

#ifndef GIFENC_H
#define GIFENC_H

#include <lwan-strbuf.h>
#include <stdint.h>

typedef struct ge_GIF {
    struct lwan_strbuf *buf;
    uint16_t w, h;
    int depth;
    int offset;
    int nframes;
    uint8_t *frame, *back;
    uint32_t partial;
    uint8_t buffer[0xFF];
} ge_GIF;

ge_GIF *ge_new_gif(struct lwan_strbuf *buf,
                   uint16_t width,
                   uint16_t height,
                   uint8_t *palette,
                   int depth,
                   int loop);
void ge_add_frame(ge_GIF *gif, uint16_t delay);
struct lwan_strbuf *ge_close_gif(ge_GIF *gif);

#endif /* GIFENC_H */
