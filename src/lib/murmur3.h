//-----------------------------------------------------------------------------
// MurmurHash3 was written by Austin Appleby, and is placed in the
// public domain. The author hereby disclaims copyright to this source
// code.

#pragma once

#include <stdint.h>

//-----------------------------------------------------------------------------

uint64_t murmur3_fmix64(uint64_t k);
void murmur3_set_seed(const uint32_t seed);
unsigned int murmur3_simple(const void *key);

//-----------------------------------------------------------------------------
