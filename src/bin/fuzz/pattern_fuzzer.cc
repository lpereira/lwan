#include <stdint.h>
#include <stdio.h>
#include <string.h>

extern "C" {
#include "patterns.h"
#include "lwan-private.h"
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct str_find sf[16];
    static uint8_t static_data[32768];
    struct config *config;
    struct config_line line;
    int indent_level = 0;
    const char *errmsg;

    if (size == 0)
        return 1;

    if (size > sizeof(static_data))
        size = sizeof(static_data);
    memcpy(static_data, data, size);
    static_data[size - 1] = '\0';

    LWAN_NO_DISCARD(str_find((char *)static_data, "foo/(%d+)(%a)(%d+)", sf,
                             N_ELEMENTS(sf), &errmsg));
    LWAN_NO_DISCARD(str_find((char *)static_data, "bar/(%d+)/test", sf,
                             N_ELEMENTS(sf), &errmsg));
    LWAN_NO_DISCARD(str_find((char *)static_data, "lua/rewrite/(%d+)x(%d+)", sf,
                             N_ELEMENTS(sf), &errmsg));

    return 0;
}
