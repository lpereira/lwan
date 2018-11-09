#pragma once

#include <stdbool.h>
#include <stddef.h>

unsigned char *base64_encode(const unsigned char *src, size_t len,
			      size_t *out_len);
unsigned char *base64_decode(const unsigned char *src, size_t len,
                             size_t *out_len);

bool base64_validate(const unsigned char *src, size_t len);
