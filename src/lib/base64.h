#pragma once

#include <stdbool.h>
#include <stddef.h>

unsigned char *base64_encode(const unsigned char *src, size_t len,
			      size_t *out_len);
unsigned char *base64_decode(const unsigned char *src, size_t len,
                             size_t *out_len);

bool base64_validate(const unsigned char *src, size_t len);

static inline size_t base64_encoded_len(size_t decoded_len)
{
    /* This counts the padding bytes (by rounding to the next multiple of 4). */
    return ((4u * decoded_len / 3u) + 3u) & ~3u;
}
