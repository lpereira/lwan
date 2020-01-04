#include <stdint.h>
#include <stdio.h>
#include <string.h>

extern "C" {
#include "lwan-private.h"
#include "lwan-template.h"
}

struct file_list {
    const char *full_path;
    const char *rel_path;
    const char *readme;
    struct {
        coro_function_t generator;

        const char *icon;
        const char *icon_alt;
        const char *name;
        const char *type;

        int size;
        const char *unit;

        const char *zebra_class;
    } file_list;
};

int directory_list_generator(struct coro *, void *)
{
    return 0;
}

#undef TPL_STRUCT
#define TPL_STRUCT struct file_list
static const struct lwan_var_descriptor file_list_desc[] = {
    TPL_VAR_STR_ESCAPE(full_path),
    TPL_VAR_STR_ESCAPE(rel_path),
    TPL_VAR_STR_ESCAPE(readme),
    TPL_VAR_SEQUENCE(file_list,
                     directory_list_generator,
                     ((const struct lwan_var_descriptor[]){
                         TPL_VAR_STR(file_list.icon),
                         TPL_VAR_STR(file_list.icon_alt),
                         TPL_VAR_STR(file_list.name),
                         TPL_VAR_STR(file_list.type),
                         TPL_VAR_INT(file_list.size),
                         TPL_VAR_STR(file_list.unit),
                         TPL_VAR_STR(file_list.zebra_class),
                         TPL_VAR_SENTINEL,
                     })),
    TPL_VAR_SENTINEL,
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static char copy[32768];
    struct lwan_tpl *tpl;

    size = LWAN_MIN(sizeof(copy) - 1, size);
    memcpy(copy, data, size);
    copy[size] = '\0';

    tpl = lwan_tpl_compile_string_full(copy, file_list_desc,
                                       LWAN_TPL_FLAG_CONST_TEMPLATE);
    if (tpl)
        lwan_tpl_free(tpl);

    return tpl ? 1 : 0;
}
