#include <stdint.h>
#include <stdlib.h>

extern "C" {
uint8_t *lwan_h2_huffman_decode_for_fuzzing(const uint8_t *input,
                                            size_t input_len);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    uint8_t *decoded = lwan_h2_huffman_decode_for_fuzzing(data, size);
    if (decoded) {
        free(decoded);
        return 0;
    }
    return 1;
}
}
