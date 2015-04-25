//-----------------------------------------------------------------------------
// MurmurHash3 was written by Austin Appleby, and is placed in the public
// domain. The author hereby disclaims copyright to this source code.

// Note - The x86 and x64 versions do _not_ produce the same results, as the
// algorithms are optimized for their respective platforms. You can still
// compile and run any of them on any platform, but your performance with the
// non-native version will be less than optimal.

#include "murmur3.h"
#include <stdint.h>
#include <string.h>

//-----------------------------------------------------------------------------
// Platform-specific functions and macros

#ifdef __GNUC__
#define FORCE_INLINE __attribute__((always_inline)) inline
#else                /*  */
#define FORCE_INLINE
#endif                /*  */

#ifndef __x86_64__
static FORCE_INLINE uint32_t rotl32(uint32_t x, int8_t r)
{
    return (x << r) | (x >> (32 - r));
}
#endif

static FORCE_INLINE uint64_t rotl64(uint64_t x, int8_t r)
{
    return (x << r) | (x >> (64 - r));
}

#define ROTL32(x,y)    rotl32(x,y)
#define ROTL64(x,y)    rotl64(x,y)

#define BIG_CONSTANT(x) (x##LLU)

//-----------------------------------------------------------------------------
// Finalization mix - force all bits of a hash block to avalanche
#ifndef __x86_64__
static FORCE_INLINE uint32_t fmix32(uint32_t h)
{
    h ^= h >> 16;
    h *= 0x85ebca6b;
    h ^= h >> 13;
    h *= 0xc2b2ae35;
    h ^= h >> 16;
    return h;
}
#endif

//----------
static FORCE_INLINE uint64_t fmix64(uint64_t k)
{
    k ^= k >> 33;
    k *= BIG_CONSTANT(0xff51afd7ed558ccd);
    k ^= k >> 33;
    k *= BIG_CONSTANT(0xc4ceb9fe1a85ec53);
    k ^= k >> 33;
    return k;
}


//-----------------------------------------------------------------------------
#ifndef __x86_64__
FORCE_INLINE static void
MurmurHash3_x86_32(const void *key, size_t len, uint32_t seed, void *out)
{
    const uint8_t *data = (const uint8_t *)key;
    const size_t nblocks = len / 4;
    size_t i;
    uint32_t h1 = seed;
    uint32_t c1 = 0xcc9e2d51;
    uint32_t c2 = 0x1b873593;

    //----------
    // body
    const uint32_t *blocks = (const uint32_t *)(data + nblocks * 4);
    for (i = -nblocks; i; i++) {
        uint32_t k1;

        memcpy(&k1, blocks + i, sizeof(k1));

        k1 *= c1;
        k1 = ROTL32(k1, 15);
        k1 *= c2;
        h1 ^= k1;
        h1 = ROTL32(h1, 13);
        h1 = h1 * 5 + 0xe6546b64;
    }

    //----------
    // tail
    const uint8_t *tail = (const uint8_t *)(data + nblocks * 4);
    uint32_t k1 = 0;
    switch (len & 3) {
    case 3:
        k1 ^= (uint32_t)tail[2] << 16;
    case 2:
        k1 ^= (uint32_t)tail[1] << 8;
    case 1:
        k1 ^= (uint32_t)tail[0];
        k1 *= c1;
        k1 = ROTL32(k1, 15);
        k1 *= c2;
        h1 ^= k1;
    };

    //----------
    // finalization
    h1 ^= (uint32_t)len;
    h1 = fmix32(h1);
    *(uint32_t *) out = h1;
}


//-----------------------------------------------------------------------------
FORCE_INLINE static void MurmurHash3_x86_128 (const void *key, const size_t len,
                                              uint32_t seed, void *out)
{
    size_t i;
    const uint8_t * data = (const uint8_t*)key;
    const size_t nblocks = len / 16;

    uint32_t h1 = seed;
    uint32_t h2 = seed;
    uint32_t h3 = seed;
    uint32_t h4 = seed;

    const uint32_t c1 = 0x239b961b;
    const uint32_t c2 = 0xab0e9789;
    const uint32_t c3 = 0x38b34ae5;
    const uint32_t c4 = 0xa1e38b93;

    //----------
    // body

    const uint32_t * blocks = (const uint32_t *)(data + nblocks*16);

    for(i = -nblocks; i; i++) {
        uint32_t k1, k2, k3, k4;

        memcpy(&k1, blocks + i * 4 + 0, sizeof(k1));
        memcpy(&k2, blocks + i * 4 + 1, sizeof(k2));
        memcpy(&k3, blocks + i * 4 + 2, sizeof(k3));
        memcpy(&k4, blocks + i * 4 + 3, sizeof(k4));

        k1 *= c1; k1 = ROTL32(k1,15); k1 *= c2; h1 ^= k1;
        h1 = ROTL32(h1,19); h1 += h2; h1 = h1*5+0x561ccd1b;
        k2 *= c2; k2 = ROTL32(k2,16); k2 *= c3; h2 ^= k2;
        h2 = ROTL32(h2,17); h2 += h3; h2 = h2*5+0x0bcaa747;
        k3 *= c3; k3 = ROTL32(k3,17); k3 *= c4; h3 ^= k3;
        h3 = ROTL32(h3,15); h3 += h4; h3 = h3*5+0x96cd1c35;
        k4 *= c4; k4 = ROTL32(k4,18); k4 *= c1; h4 ^= k4;
        h4 = ROTL32(h4,13); h4 += h1; h4 = h4*5+0x32ac3b17;
    }

    //----------
    // tail

    const uint8_t * tail = (const uint8_t*)(data + nblocks*16);

    uint32_t k1 = 0;
    uint32_t k2 = 0;
    uint32_t k3 = 0;
    uint32_t k4 = 0;

    switch(len & 15) {
    case 15: k4 ^= (uint32_t)tail[14] << 16;
    case 14: k4 ^= (uint32_t)tail[13] << 8;
    case 13: k4 ^= (uint32_t)tail[12] << 0;
             k4 *= c4; k4 = ROTL32(k4,18); k4 *= c1; h4 ^= k4;

    case 12: k3 ^= (uint32_t)tail[11] << 24;
    case 11: k3 ^= (uint32_t)tail[10] << 16;
    case 10: k3 ^= (uint32_t)tail[ 9] << 8;
    case  9: k3 ^= (uint32_t)tail[ 8] << 0;
             k3 *= c3; k3 = ROTL32(k3,17); k3 *= c4; h3 ^= k3;

    case  8: k2 ^= (uint32_t)tail[ 7] << 24;
    case  7: k2 ^= (uint32_t)tail[ 6] << 16;
    case  6: k2 ^= (uint32_t)tail[ 5] << 8;
    case  5: k2 ^= (uint32_t)tail[ 4] << 0;
             k2 *= c2; k2 = ROTL32(k2,16); k2 *= c3; h2 ^= k2;

    case  4: k1 ^= (uint32_t)tail[ 3] << 24;
    case  3: k1 ^= (uint32_t)tail[ 2] << 16;
    case  2: k1 ^= (uint32_t)tail[ 1] << 8;
    case  1: k1 ^= (uint32_t)tail[ 0] << 0;
             k1 *= c1; k1 = ROTL32(k1,15); k1 *= c2; h1 ^= k1;
    }

    //----------
    // finalization

    h1 ^= (uint32_t)len; h2 ^= (uint32_t)len;
    h3 ^= (uint32_t)len; h4 ^= (uint32_t)len;

    h1 += h2; h1 += h3; h1 += h4;
    h2 += h1; h3 += h1; h4 += h1;

    h1 = fmix32(h1);
    h2 = fmix32(h2);
    h3 = fmix32(h3);
    h4 = fmix32(h4);

    h1 += h2; h1 += h3; h1 += h4;
    h2 += h1; h3 += h1; h4 += h1;

    ((uint32_t*)out)[0] = h1;
    ((uint32_t*)out)[1] = h2;
    ((uint32_t*)out)[2] = h3;
    ((uint32_t*)out)[3] = h4;
}
#endif

//-----------------------------------------------------------------------------
FORCE_INLINE static void
MurmurHash3_x64_128(const void *key, const size_t len, const uint32_t seed,
            void *out)
{
    const uint8_t *data = (const uint8_t *)key;
    const size_t nblocks = len / 16;
    size_t i;
    uint64_t h1 = seed;
    uint64_t h2 = seed;
    uint64_t c1 = BIG_CONSTANT(0x87c37b91114253d5);
    uint64_t c2 = BIG_CONSTANT(0x4cf5ad432745937f);

    //----------
    // body
    const uint64_t *blocks = (const uint64_t *)(data);
    for (i = 0; i < nblocks; i++) {
        uint64_t k1, k2;

        memcpy(&k1, blocks + i * 2 + 0, sizeof(k1));
        memcpy(&k2, blocks + i * 2 + 1, sizeof(k2));

        k1 *= c1;
        k1 = ROTL64(k1, 31);
        k1 *= c2;
        h1 ^= k1;
        h1 = ROTL64(h1, 27);
        h1 += h2;
        h1 = h1 * 5 + 0x52dce729;
        k2 *= c2;
        k2 = ROTL64(k2, 33);
        k2 *= c1;
        h2 ^= k2;
        h2 = ROTL64(h2, 31);
        h2 += h1;
        h2 = h2 * 5 + 0x38495ab5;
    }

        //----------
        // tail
    const uint8_t *tail = (const uint8_t *)(data + nblocks * 16);
    uint64_t k1 = 0;
    uint64_t k2 = 0;
    switch (len & 15) {
    case 15:
        k2 ^= (uint64_t) (tail[14]) << 48;
    case 14:
        k2 ^= (uint64_t) (tail[13]) << 40;
    case 13:
        k2 ^= (uint64_t) (tail[12]) << 32;
    case 12:
        k2 ^= (uint64_t) (tail[11]) << 24;
    case 11:
        k2 ^= (uint64_t) (tail[10]) << 16;
    case 10:
        k2 ^= (uint64_t) (tail[9]) << 8;
    case 9:
        k2 ^= (uint64_t) (tail[8]) << 0;
        k2 *= c2;
        k2 = ROTL64(k2, 33);
        k2 *= c1;
        h2 ^= k2;
    case 8:
        k1 ^= (uint64_t) (tail[7]) << 56;
    case 7:
        k1 ^= (uint64_t) (tail[6]) << 48;
    case 6:
        k1 ^= (uint64_t) (tail[5]) << 40;
    case 5:
        k1 ^= (uint64_t) (tail[4]) << 32;
    case 4:
        k1 ^= (uint64_t) (tail[3]) << 24;
    case 3:
        k1 ^= (uint64_t) (tail[2]) << 16;
    case 2:
        k1 ^= (uint64_t) (tail[1]) << 8;
    case 1:
        k1 ^= (uint64_t) (tail[0]) << 0;
        k1 *= c1;
        k1 = ROTL64(k1, 31);
        k1 *= c2;
        h1 ^= k1;
    };

    //----------
    // finalization
    h1 ^= (uint64_t)len;
    h2 ^= (uint64_t)len;
    h1 += h2;
    h2 += h1;
    h1 = fmix64(h1);
    h2 = fmix64(h2);
    h1 += h2;
    h2 += h1;
    ((uint64_t *) out)[0] = h1;
    ((uint64_t *) out)[1] = h2;
}


//-----------------------------------------------------------------------------
unsigned int
murmur3_simple(const void *keyptr)
{
    size_t len = strlen((char *)keyptr);
#ifdef __x86_64__
    uint64_t hash[2];
    MurmurHash3_x64_128(keyptr, len, 0xdeadbeef, hash);
    return (unsigned int)hash[1];
#else
    if (len <= 16) {
        unsigned int hash;
        MurmurHash3_x86_32(keyptr, len, 0xdeadbeef, &hash);
        return hash;
    }

    unsigned int hash[4];
    MurmurHash3_x86_128(keyptr, len, 0xdeadbeef, hash);
    return hash[3];
#endif
}
