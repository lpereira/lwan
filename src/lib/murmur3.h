//-----------------------------------------------------------------------------
// MurmurHash3 was written by Austin Appleby, and is placed in the
// public domain. The author hereby disclaims copyright to this source
// code.

#pragma once

#include <stdint.h>

//-----------------------------------------------------------------------------

void murmur3_set_seed(const uint32_t seed);
unsigned int murmur3_simple(const void *key);

//-----------------------------------------------------------------------------
