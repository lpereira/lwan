/*
SHA-1 in C
By Steve Reid <steve@edmweb.com>
100% Public Domain

Test Vectors (from FIPS PUB 180-1)
"abc"
  A9993E36 4706816A BA3E2571 7850C26C 9CD0D89D
"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
  84983E44 1C3BD26E BAAE4AA1 F95129E5 E54670F1
A million repetitions of "a"
  34AA973C D4C4DAA4 F61EEB2B DBAD2731 6534016F
*/

#include "sha1.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <endian.h>

#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

/* blk0() and blk() perform the initial expand. */
/* I got the idea of expanding during the round function from SSLeay */
#define blk0(i) (block[i] = htobe32(block[i]))
#define blk(i)                                                                 \
    (block[i & 15] = rol(block[(i + 13) & 15] ^ block[(i + 8) & 15] ^          \
                             block[(i + 2) & 15] ^ block[i & 15],              \
                         1))

/* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
#define R0(v, w, x, y, z, i)                                                   \
    z += ((w & (x ^ y)) ^ y) + blk0(i) + 0x5A827999 + rol(v, 5);               \
    w = rol(w, 30);
#define R1(v, w, x, y, z, i)                                                   \
    z += ((w & (x ^ y)) ^ y) + blk(i) + 0x5A827999 + rol(v, 5);                \
    w = rol(w, 30);
#define R2(v, w, x, y, z, i)                                                   \
    z += (w ^ x ^ y) + blk(i) + 0x6ED9EBA1 + rol(v, 5);                        \
    w = rol(w, 30);
#define R3(v, w, x, y, z, i)                                                   \
    z += (((w | x) & y) | (w & x)) + blk(i) + 0x8F1BBCDC + rol(v, 5);          \
    w = rol(w, 30);
#define R4(v, w, x, y, z, i)                                                   \
    z += (w ^ x ^ y) + blk(i) + 0xCA62C1D6 + rol(v, 5);                        \
    w = rol(w, 30);

/* Hash a single 512-bit block. This is the core of the algorithm. */

#define STATE(i)		state[(index + (i)) % 5]

static void sha1_transform(uint32_t orig_state[5], const unsigned char buffer[64])
{
    uint32_t state[5];
    uint32_t block[16];
    int round = 0;
    int index = 0;

    memcpy(block, buffer, sizeof(block));

    /* Copy context->state[] to working vars */
    memcpy(state, orig_state, sizeof(state));

    /* 4 rounds of 20 operations each. */
    for (; round < 16; round++, index += 4) {
        R0(STATE(0), STATE(1), STATE(2), STATE(3), STATE(4), round);
    }
    for (; round < 20; round++, index += 4) {
        R1(STATE(0), STATE(1), STATE(2), STATE(3), STATE(4), round);
    }

    for (; round < 40; round++, index += 4) {
        R2(STATE(0), STATE(1), STATE(2), STATE(3), STATE(4), round);
    }

    for (; round < 60; round++, index += 4) {
        R3(STATE(0), STATE(1), STATE(2), STATE(3), STATE(4), round);
    }

    for (; round < 80; round++, index += 4) {
        R4(STATE(0), STATE(1), STATE(2), STATE(3), STATE(4), round);
    }

    /* Add the working vars back into context.state[] */
    for (int i = 0; i < 5; i++)
        orig_state[i] += state[i];

    /* Wipe transient state */
    memset(state, 0, sizeof(state));
    memset(block, 0, sizeof(block));
    __asm__ volatile("" : : "g"(block), "g"(state) : "memory");
}

/* sha1_init - Initialize new context */

void sha1_init(sha1_context *context)
{
    /* SHA1 initialization constants */
    context->state[0] = 0x67452301;
    context->state[1] = 0xEFCDAB89;
    context->state[2] = 0x98BADCFE;
    context->state[3] = 0x10325476;
    context->state[4] = 0xC3D2E1F0;
    context->count[0] = context->count[1] = 0;
}

/* Run your data through this. */

void sha1_update(sha1_context *context, const unsigned char *data, size_t len)
{
    size_t i;
    size_t j;

    j = context->count[0];
    if ((context->count[0] += len << 3) < j)
        context->count[1]++;
    context->count[1] += (len >> 29);

    j = (j >> 3) & 63;

    if ((j + len) > 63) {
        i = 64 - j;
        memcpy(&context->buffer[j], data, i);
        sha1_transform(context->state, context->buffer);

        for (; i + 63 < len; i += 64)
            sha1_transform(context->state, &data[i]);

        j = 0;
    } else {
        i = 0;
    }

    memcpy(&context->buffer[j], &data[i], len - i);
}

/* Add padding and return the message digest. */

void sha1_finalize(sha1_context *context, unsigned char digest[20])
{
    unsigned i;
    unsigned char finalcount[8];
    unsigned char c;

    for (i = 0; i < 8; i++) {
        finalcount[i] = (unsigned char)((context->count[(i >= 4 ? 0 : 1)] >>
                                         ((3 - (i & 3)) * 8)) &
                                        255); /* Endian independent */
    }

    c = 0200;
    sha1_update(context, &c, 1);
    while ((context->count[0] & 504) != 448) {
        c = 0000;
        sha1_update(context, &c, 1);
    }
    sha1_update(context, finalcount, 8); /* Should cause a sha1_transform() */
    for (i = 0; i < 20; i++) {
        digest[i] =
            (unsigned char)((context->state[i >> 2] >> ((3 - (i & 3)) * 8)) &
                            255);
    }

    /* Wipe variables */
    memset(context, '\0', sizeof(*context));
    __asm__ volatile("" : : "g"(context) : "memory");

    memset(&finalcount, '\0', sizeof(finalcount));
    __asm__ volatile("" : : "g"(finalcount) : "memory");
}


#ifdef SHA1_TEST
#include <unistd.h>

int main(int argc, char *argv)
{
    sha1_context ctx;
    unsigned char buffer[512];
    unsigned char digest[20];

    sha1_init(&ctx);

    for (;;) {
        ssize_t r = read(fileno(stdin), buffer, sizeof(buffer));

        if (r < 0) {
            perror("read");
            return 1;
        }

        sha1_update(&ctx, buffer, (size_t)r);

        if (r < (ssize_t)sizeof(buffer))
            break;
    }

    sha1_finalize(&ctx, digest);

    printf("%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%"
           "02x%02x%02x%02x\n",
           digest[0], digest[1], digest[2], digest[3], digest[4], digest[5],
           digest[6], digest[7], digest[8], digest[9], digest[10], digest[11],
           digest[12], digest[13], digest[14], digest[15], digest[16],
           digest[17], digest[18], digest[19]);
}
#endif
