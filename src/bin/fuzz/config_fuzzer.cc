#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "lwan-config.h"

static bool
dump(struct config *config, struct config_line *line, int indent_level)
{
    if (indent_level > 64)
        return false;

    while (config_read_line(config, line)) {
        switch (line->type) {
        case CONFIG_LINE_TYPE_LINE:
            break;

        case CONFIG_LINE_TYPE_SECTION_END:
            if (indent_level == 0)
                return false;

            return true;

        case CONFIG_LINE_TYPE_SECTION:
            if (!dump(config, line, indent_level + 1))
                return false;

            break;
        }
    }

    if (config_last_error(config)) {
        fprintf(stderr,
                "Error while reading configuration file (line %d): %s\n",
                config_cur_line(config), config_last_error(config));
        return false;
    }

    return true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct config *config;
    struct config_line line;
    int indent_level = 0;

    config = config_open_for_fuzzing(data, size);
    if (!config)
        return 1;

    bool dumped = dump(config, &line, indent_level);

    config_close(config);

    return dumped ? 1 : 0;
}
