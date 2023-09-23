/* Naïve brute-force perfect hash table generator for HTTP status lookup */

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../lib/lwan-http-status.h"

static inline uint32_t rotate(int v, int n)
{
    uint32_t vv = (uint32_t)v;
    return vv << (32 - n) | vv >> n;
}

int main(void)
{
    uint32_t max_key = 0;
    int min_key = INT_MAX;
#define COMPARE_MAX(ignore1, key, ignore2, ignore3)                            \
    do {                                                                       \
        if (key > max_key)                                                     \
            max_key = key;                                                     \
        if (key < min_key)                                                     \
            min_key = key;                                                     \
    } while (0);
    FOR_EACH_HTTP_STATUS(COMPARE_MAX)
#undef COMPARE_MAX

#define SELECT_KEY(ignore1, key, ignore2, ignore3) key,
    const int keys[] = {FOR_EACH_HTTP_STATUS(SELECT_KEY)};
#undef SELECT_KEY

#define N_KEYS ((int)(sizeof(keys) / sizeof(keys[0])))

    int best_rot = INT_MAX;
    uint32_t best_mod = 64;
    int best_subtract = INT_MAX;

    if (N_KEYS >= best_mod) {
        fprintf(stderr, "table too large!\n");
        return 1;
    }

    for (int subtract = 0; subtract < min_key; subtract++) {
        for (int rot = 0; rot < 32; rot++) {
            for (uint32_t mod = 1; mod < best_mod; mod++) {
                uint64_t set = 0;
                int set_bits = 0;

                for (int key = 0; key < N_KEYS; key++) {
                    uint32_t k = rotate(keys[key] - subtract, rot) % mod;
                    
                    if (!(set & 1ull<<k)) {
                        set |= 1ull<<k;
                        set_bits++;
                    }
                }

                if (set_bits == N_KEYS && mod < best_mod) {
                    best_rot = rot;
                    best_mod = mod;
                    best_subtract = subtract;
                }
            }
        }
    }

    if (best_rot == INT_MAX) {
        fprintf(stderr, "could not figure out the hash table parameters!\n");
        return 1;
    }
    if (best_mod >= 64) {
        fprintf(stderr, "table would be larger than 64 items!\n");
        return 1;
    }

    uint64_t set_values = 0xffffffffffffffffull;
    printf("static ALWAYS_INLINE const char *lwan_lookup_http_status_impl(enum lwan_http_status status) {\n");
    printf("    static const char *table[] = {\n");
#define PRINT_V(ignored1, key, short_desc, long_desc) do { \
        uint32_t k = rotate(key - best_subtract, best_rot) % best_mod; \
        set_values &= ~(1ull<<k); \
        printf("        [%d] = \"%d %s\\0%s\",\n", k, key, short_desc, long_desc); \
    } while(0);
    FOR_EACH_HTTP_STATUS(PRINT_V)
#undef PRINT_V

    for (uint32_t i = 0; i < best_mod; i++) {
        if (set_values & 1ull<<i)
            printf("        [%d] = \"999 Invalid\\0Invalid HTTP status code requested\",\n", i);
    }

    printf("    };\n");

    printf("\n");
    printf("    const uint32_t k = (uint32_t)status - %d;\n", best_subtract);
    printf("    return table[((k << %d) | (k >> %d)) %% %d];\n", 32 - best_rot, best_rot, best_mod);

    printf("}\n");

}
