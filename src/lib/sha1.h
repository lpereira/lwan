/*
SHA-1 in C
By Steve Reid <steve@edmweb.com>
100% Public Domain
*/

#pragma once

#include <sys/types.h>
#include <stdint.h>

typedef struct {
    size_t count[2];
    uint32_t state[5];
    unsigned char buffer[64];
} sha1_context;

void sha1_init(sha1_context* context);
void sha1_update(sha1_context* context, const unsigned char* data, size_t len);
void sha1_finalize(sha1_context* context, unsigned char digest[20]);
