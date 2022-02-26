#include <stdint.h>
#include <stdio.h>
#include <string.h>

extern "C" {
#include "lwan-config.h"
#include "lwan-private.h"
}

static bool dump(struct config *config, int indent_level)
{
    const struct config_line *line;

    if (indent_level > 64)
        return false;

    while ((line = config_read_line(config))) {
        switch (line->type) {
        case CONFIG_LINE_TYPE_LINE:
            LWAN_NO_DISCARD(parse_bool(line->value, false));
            LWAN_NO_DISCARD(parse_long(line->value, 0));
            LWAN_NO_DISCARD(parse_int(line->value, 0));
            LWAN_NO_DISCARD(parse_time_period(line->value, 0));
            break;

        case CONFIG_LINE_TYPE_SECTION_END:
            if (indent_level == 0)
                return false;

            return true;

        case CONFIG_LINE_TYPE_SECTION:
            if (!dump(config, indent_level + 1))
                return false;

            break;
        }
    }

    const char *error = config_last_error(config);

    if (error) {
        printf("Error: %s\n", error);
        return false;
    }

    return true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct config *config;

    config = config_open_for_fuzzing(data, size);
    if (!config)
        return 1;

    bool dumped = dump(config, 0);

    config_close(config);

    return dumped ? 1 : 0;
}
