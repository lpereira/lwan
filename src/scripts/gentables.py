#!/usr/bin/python
# Prototype decoder for Huffman-encoded HPACK data
# Copyright (c) 2022 L. A.  F. Pereira <l@tia.mat.br>
#
# How this works: This is a standard Huffman decoder, but instead of
# using a traditional binary tree and use each input bit to drive the
# traversal, going down a tree level for every input bit, it has a
# table where the index helps traverse this tree multiple levels in
# parallel.  In practice, this means that for the shortest -- and thus
# common -- symbols, one can traverse the binary tree with a single
# memory access.  This improves cache utilization and makes memory
# prefetching and branch prediction more useful.
#
# This is my first foray into data compression, so I'm sure I'm missing
# some obvious trick known by folks used to implementing these kinds of
# things.  Some of the things I've identified that could be improved,
# so far:
#
# - Some branches could be removed, especially when processing
#   incorrect inputs.
# - Some tables can be reduced and be converted to pure code.  For
#   instance, level2_11111010[] could be a tiny switch/case statement
#   instead of 8 lines of L1 cache.  Some tables, like
#   level2_11110110[], do not have a lot of information stored in them
#   (two entries, only 1 bit per entry is useful, etc.), which is a
#   good candidate for something like this too.
# - GCC and Clang offer a way to say if a branch is likely or unlikely,
#   and specify the probability for them.  This is perfect because we
#   know the probability -- it's exactly what the length of a Huffman
#   code conveys.  Might be a good idea to find a way to exploit this.
#
# The input for this script is a table obtained directly from the HPACK
# RFC.
#
# This script could potentially be cleaned up and written in a more
# generic way, but I just wanted to experiment with the idea without
# spending a lot of time on something that could potentially not work.

from collections import defaultdict

def pad_table(symbols):
  table = {}
  to_delete = set()
  for symbol, bins in symbols.items():
    short_bin = int(bins[0], 2)
    shift_by = len(bins[0])

    if symbol == 256: # EOS
      element = (0, -1)
    else:
      element = (symbol, shift_by)

    if len(bins) == 1:
      if shift_by == 8:
        table[(short_bin, short_bin)] = element
      else:
        short_bin <<= 8 - shift_by
        from_code = short_bin
        to_code = short_bin + (1 << (8 - shift_by)) - 1

        table[(from_code, to_code)] = element
      to_delete.add(symbol)

  next_table = defaultdict(lambda: {})
  for symbol, bins in symbols.items():
    if not symbol in to_delete:
      next_table[bins[0]][symbol] = bins[1:]

  return table, next_table

def print_table_contents(table):
  for code in sorted(table.keys()):
    symbol, length = table[code]
    if length == 0:
      continue
    code_start, code_end = code

    # Instead of storing length as the total length of the symbol, we store
    # the relative length from the current point. This simplifies the
    # implementation of peek_byte() and (especially) consume().
    if code_start == code_end:
      print(f"[{code_start}] = {{ {symbol}, {length} }},")
    else:
      print(f"[{code_start} ... {code_end}] = {{ {symbol}, {length} }},")

def generate_level(level, next_table):
  next_tables = []

  print(f"static inline const struct h2_huffman_code *next_level{level}(uint8_t peeked_byte) {{")

  for bin, table in next_table.items():
    print(f"static const struct h2_huffman_code level{level}_{bin}[256] = {{")
    table, next_table_ = pad_table(table)
    print_table_contents(table)
    if next_table_:
      next_tables.append(next_table_)
    print("};")

  generated = False
  if len(next_table) == 2:
    values = tuple(next_table.keys())
    value0 = int(values[0], 2)
    value1 = int(values[1], 2)

    mask = value0 & ~value1
    if mask.bit_length() == 1:
      print(f"return peeked_byte & {mask} ? level{level}_{values[0]} : level{level}_{values[1]};")
      generated = True

  if not generated:
      print("switch (peeked_byte) {")
      for bin0 in next_table.keys():
        print(f"case 0b{bin0}: ")
        print(f"return level{level}_{bin0};")
      print("default: return NULL;")
      print("}")
  
  print("}")

  return next_tables

if __name__ == '__main__':
  print("""#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <endian.h>
#include <stdbool.h>
#define LIKELY(x) x
#define UNLIKELY(x) x
static inline uint64_t read64be(const void *ptr) {
  uint64_t v;
  memcpy(&v, ptr, 8);
  return htobe64(v);
}

""")

  symbols = {}
  for symbol, line in enumerate(open("huffman-table.txt")):
    _, code = line.strip().split(")  |", 1)
    code, _ = code.split(" ", 1)
    symbols[symbol] = code.split("|")

  first_level, next_table_first_level = pad_table(symbols)

  print("struct h2_huffman_code {")
  print("   uint8_t symbol;")
  print("   int8_t num_bits;")
  print("};")

  print(f"static const struct h2_huffman_code level0[256] = {{")
  print_table_contents(first_level)
  print("};")

  for table in generate_level(0, next_table_first_level):
    for table in generate_level(1, table):
      # FIXME: some of the tables in level 2 are too big and convey very
      # little information. maybe for these levels we could generate
      # C code instead? these symbols should be really rare anyway
      level2 = generate_level(2, table)
      assert(not level2)

  # These have been inspired by Fabian Giesen's blog posts on "reading bits in
  # far too many ways". Part 2, specifically: https://fgiesen.wordpress.com/2018/02/20/reading-bits-in-far-too-many-ways-part-2/
  print("""struct bit_reader {
    const uint8_t *bitptr;
    uint64_t bitbuf;
    uint64_t total_bitcount;
    int bitcount;
};

static inline uint8_t peek_byte(struct bit_reader *reader)
{
    if (reader->bitcount < 8) {
        // FIXME: need to use shorter reads depending on total_bitcount!
        reader->bitbuf |= read64be(reader->bitptr) >> reader->bitcount;
        reader->bitptr += (63 - reader->bitcount + (reader->bitcount & 1)) >> 3;
        reader->bitcount |= 56;
    }
    return reader->bitbuf >> 56;
}

static inline bool consume(struct bit_reader *reader, int count)
{
    assert(count > 0);
    reader->bitbuf <<= count;
    reader->bitcount -= count;
    return !__builtin_sub_overflow(reader->total_bitcount, count, &reader->total_bitcount);
}
""")
  
  print("""static inline size_t output_size(size_t input_size) {
  /* Smallest input is 5 bits which produces 8 bits. Scaling that to 8 bits, we
   * get 12.8 bits of output per 8 bits of input. */
  return (input_size * 128) / 10;
}""")

  print("""uint8_t *h2_huffman_decode(const uint8_t *input, size_t input_len)
{
    uint8_t *output = malloc(output_size(input_len));
    uint8_t *ret = output;
    struct bit_reader bit_reader = {.bitptr = input,
                                    .total_bitcount = input_len * 8};

    while ((int64_t)bit_reader.total_bitcount > 7) {
        uint8_t peeked_byte = peek_byte(&bit_reader);
        if (LIKELY(level0[peeked_byte].num_bits)) {
            *output++ = level0[peeked_byte].symbol;
            consume(&bit_reader, level0[peeked_byte].num_bits);
            continue;
        }

        if (!consume(&bit_reader, 8))
            goto fail;

        const struct h2_huffman_code *level1 = next_level0(peeked_byte);
        peeked_byte = peek_byte(&bit_reader);
        if (level1[peeked_byte].num_bits) {
            *output++ = level1[peeked_byte].symbol;
            consume(&bit_reader, level1[peeked_byte].num_bits);
            continue;
        }

        if (!consume(&bit_reader, 8))
            goto fail;

        const struct h2_huffman_code *level2 = next_level1(peeked_byte);
        peeked_byte = peek_byte(&bit_reader);
        if (level2[peeked_byte].num_bits) {
            *output++ = level2[peeked_byte].symbol;
            consume(&bit_reader, level2[peeked_byte].num_bits);
            continue;
        }

        if (!consume(&bit_reader, 8))
            goto fail;

        const struct h2_huffman_code *level3 = next_level2(peeked_byte);
        if (LIKELY(level3)) {
            peeked_byte = peek_byte(&bit_reader);
            if (UNLIKELY(level3[peeked_byte].num_bits < 0)) {
                /* EOS found */
                return ret;
            }
            if (LIKELY(level3[peeked_byte].num_bits)) {
                *output++ = level3[peeked_byte].symbol;
                consume(&bit_reader, level3[peeked_byte].num_bits);
                continue;
            }
        }

        goto fail;
    }

    /* FIXME: ensure we're not promoting types unnecessarily here */
    if (bit_reader.total_bitcount) {
        const uint8_t peeked_byte = peek_byte(&bit_reader);
        const uint8_t eos_prefix = ((1 << bit_reader.total_bitcount) - 1)
                                   << (8 - bit_reader.total_bitcount);

        if ((peeked_byte & eos_prefix) == eos_prefix)
            goto done;

        if (level0[peeked_byte].num_bits == (int8_t)bit_reader.total_bitcount) {
            *output = level0[peeked_byte].symbol;
            goto done;
        }

        /* If we get here, then the remaining bits are either:
         *  - Not a prefix of EOS
         *  - Incomplete sequence
         *  - Has overlong padding
         */
        goto fail;
    }

done:
    return ret;

fail:
    free(ret);
    return NULL;
}

int main(int argc, char *argv[]) {
    /* "litespeed" */
    unsigned char litespeed_huff[128] = {0xce, 0x64, 0x97, 0x75, 0x65, 0x2c, 0x9f};
    unsigned char *decoded;
    
    decoded = h2_huffman_decode(litespeed_huff, 7);
    if (!decoded) {
        puts("could not decode");
        return 1;
    }
    printf("%s\\n", !strcmp(decoded, "LiteSpeed") ? "pass!" : "fail!");
    printf("decoded: '%s'\\n", decoded);
    free(decoded);

    unsigned char x_fb_debug[128] = {
        0xa7, 0x06, 0xa7, 0x63, 0x97, 0xc6, 0x1d, 0xc9, 0xbb, 0xa3, 0xc6, 0x5e,
        0x52, 0xf2, 0x6a, 0xba, 0x66, 0x17, 0xe6, 0x71, 0x37, 0x0a, 0x3c, 0x74,
        0xb3, 0x8d, 0x12, 0x92, 0x5e, 0x71, 0xf9, 0xea, 0x4d, 0xc2, 0x42, 0x24,
        0xb7, 0xf6, 0x93, 0x66, 0x39, 0xab, 0xd1, 0x8d, 0xff, 0xcf, 0x07, 0xdf,
        0x8b, 0xac, 0x7f, 0xef, 0x65, 0x5d, 0x9f, 0x8c, 0x9d, 0x3c, 0x72, 0x8f,
        0xc5, 0xfd, 0x9e, 0xd0, 0x51, 0xb1, 0xdf, 0x46, 0xc8, 0x20,
    };
    decoded = h2_huffman_decode(x_fb_debug, 6*12-2);
    if (!decoded) {
        puts("could not decode");
        return 1;
    }
    printf("%s\\n", !strcmp(decoded, "mEO7bfwFStBMwJWfW4pmg2XL25AswjrVlfcfYbxkcS2ssduZmiKoipMH9XwoTGkb+Qnq9bcjwWbwDQzsea/vMQ==") ? "pass!" : "fail!");
    printf("decoded: '%s'\\n", decoded);
    free(decoded);
}
""")
