/*
 * lwan - web server
 * Copyright (c) 2025 L. A. F. Pereira <l@tia.mat.br>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

/*
 * This is a FORTH dialect compatible with the Forth Salon[1] dialect,
 * to be used as a pixel shader in art projects.
 * [1] https://forthsalon.appspot.com
 */

#define _GNU_SOURCE
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "hash.h"
#include "lwan-array.h"
#include "lwan-private.h"

#include "forth.h"

#define NO_INCBIN
#include "forth-jit-inc.h"

enum forth_opcode {
    OP_CALL_BUILTIN,
    OP_EVAL_CODE,
    OP_NUMBER,
    OP_JUMP_IF,
    OP_JUMP,
    OP_NOP,
};

struct forth_ctx;
struct forth_vars;
union forth_inst;

union forth_inst {
    void (*callback)(union forth_inst *,
                     double *d_stack,
                     double *r_stack,
                     struct forth_vars *vars);
    struct forth_code *code;
    double number;
    size_t pc;
};

DEFINE_ARRAY_TYPE(forth_code, union forth_inst)

struct forth_builtin {
    const char *name;
    size_t name_len;
    union {
        void (*callback)(union forth_inst *,
                         double *d_stack,
                         double *r_stack,
                         struct forth_vars *vars);
        const char *(*callback_compiler)(struct forth_ctx *, const char *);
    };
    int d_pushes;
    int d_pops;
    int r_pushes;
    int r_pops;
};

struct forth_word {
    union {
        void (*callback)(union forth_inst *,
                         double *d_stack,
                         double *r_stack,
                         struct forth_vars *vars);
        const char *(*callback_compiler)(struct forth_ctx *ctx,
                                         const char *code);
        struct forth_code code;
    };
    const struct forth_builtin *builtin;
    int d_stack_len;
    int r_stack_len;
    char name[];
};

struct forth_ctx {
    union {
        struct {
            double d_stack[32];
            double r_stack[32];
        };
        struct {
            union forth_inst *j_stack[32];
            union forth_inst **j;
        };
    };

    struct forth_word *defining_word;
    struct forth_word *main;
    struct hash *words;

    bool is_inside_word_def;
};


static inline bool is_word_builtin(const struct forth_word *w)
{
    return !!w->builtin;
}

static inline bool is_word_compiler(const struct forth_word *w)
{
    const struct forth_builtin *b = w->builtin;
    return b && b >= SECTION_START_SYMBOL(forth_compiler_builtin, b) &&
           b < SECTION_STOP_SYMBOL(forth_compiler_builtin, b);
}

static const struct forth_builtin *find_builtin_by_callback(void *callback)
{
    const struct forth_builtin *iter;

    LWAN_SECTION_FOREACH(forth_builtin, iter) {
        if (iter->callback == callback)
            return iter;
    }
    LWAN_SECTION_FOREACH(forth_compiler_builtin, iter) {
        if (iter->callback_compiler == callback)
            return iter;
    }

    return NULL;
}

static void op_number(union forth_inst *inst,
                      double *d_stack,
                      double *r_stack,
                      struct forth_vars *vars)
{
    *d_stack++ = inst[1].number;
    return inst[2].callback(&inst[2], d_stack, r_stack, vars);
}

static void op_jump_if(union forth_inst *inst,
                       double *d_stack,
                       double *r_stack,
                       struct forth_vars *vars)
{
    size_t pc = (*--d_stack == 0.0) ? inst[1].pc : 2;
    return inst[pc].callback(&inst[pc], d_stack, r_stack, vars);
}

static void op_jump(union forth_inst *inst,
                    double *d_stack,
                    double *r_stack,
                    struct forth_vars *vars)
{
    size_t pc = inst[1].pc;
    return inst[pc].callback(&inst[pc], d_stack, r_stack, vars);
}

static void op_nop(union forth_inst *inst,
                   double *d_stack,
                   double *r_stack,
                   struct forth_vars *vars)
{
    return inst[1].callback(&inst[1], d_stack, r_stack, vars);
}

static void op_halt(union forth_inst *inst __attribute__((unused)),
                    double *d_stack,
                    double *r_stack,
                    struct forth_vars *vars)
{
    vars->final_d_stack_ptr = d_stack;
    vars->final_r_stack_ptr = r_stack;
}

static void op_eval_code(union forth_inst *inst __attribute__((unused)),
                         double *d_stack,
                         double *r_stack,
                         struct forth_vars *vars)
{
    lwan_status_critical("eval_code instruction executed after inlining");
    __builtin_unreachable();
}

static bool check_stack_effects(const struct forth_ctx *ctx,
                                struct forth_word *w)
{
    /* FIXME: this isn't correct when we have JUMP_IF and JUMP
     * instructions: the number of items in the stacks isn't reset
     * to the beginning of either if/else block. */
    const union forth_inst *inst;
    int items_in_d_stack = 0;
    int items_in_r_stack = 0;

    assert(!is_word_builtin(w));

    LWAN_ARRAY_FOREACH(&w->code, inst) {
        if (inst->callback == op_number) {
            items_in_d_stack++;
            inst++; /* skip number immediate */
            continue;
        }
        if (inst->callback == op_jump_if) {
            if (UNLIKELY(!items_in_d_stack)) {
                lwan_status_error("Word `if' requires 1 item(s) in the D stack");
                return false;
            }
            items_in_d_stack--;
            inst++; /* skip pc immediate */
            continue;
        }
        if (inst->callback == op_jump) {
            inst++; /* skip pc immediate */
            continue;
        }
        if (inst->callback == op_halt || inst->callback == op_nop) {
            /* no immediates for these operations */
            continue;
        }
        if (inst->callback == op_eval_code) {
            lwan_status_critical("eval_code instruction shouldn't appear here");
            return false;
        }

        /* all other built-ins */
        const struct forth_builtin *b = find_builtin_by_callback(inst->callback);
        if (UNLIKELY(!b)) {
            lwan_status_critical("Can't find builtin word by callback");
            return false;
        }

        if (UNLIKELY(items_in_d_stack < b->d_pops)) {
            lwan_status_error("Word `%.*s' requires %d item(s) in the D stack",
                    (int)b->name_len, b->name, b->d_pops);
            return false;
        }
        if (UNLIKELY(items_in_r_stack < b->r_pops)) {
            lwan_status_error("Word `%.*s' requires %d item(s) in the R stack",
                    (int)b->name_len, b->name, b->r_pops);
            return false;
        }

        items_in_d_stack -= b->d_pops;
        items_in_d_stack += b->d_pushes;
        items_in_r_stack -= b->r_pops;
        items_in_r_stack += b->r_pushes;

        if (UNLIKELY(items_in_d_stack >= (int)N_ELEMENTS(ctx->d_stack))) {
            lwan_status_error("Program would cause a stack overflow in the D stack");
            return false;
        }
        if (UNLIKELY(items_in_r_stack >= (int)N_ELEMENTS(ctx->r_stack))) {
            lwan_status_error("Program would cause a stack overflow in the R stack");
            return false;
        }
    }

    w->d_stack_len = items_in_d_stack;
    w->r_stack_len = items_in_r_stack;

    return true;
}

#define JS_PUSH(val_)                                                          \
    ({                                                                         \
        if (j > (jump_stack + 64))                                             \
            return false;                                                      \
        *j++ = (val_);                                                         \
    })
#define JS_POP(val_)                                                           \
    ({                                                                         \
        if (j <= jump_stack)                                                   \
            return false;                                                      \
        *--j;                                                                  \
    })

#if defined(DUMP_CODE)
static void dump_code(const struct forth_code *code)
{
    const union forth_inst *inst;

    printf("dumping code @ %p\n", code);

    LWAN_ARRAY_FOREACH (code, inst) {
        printf("%08zu    ",
               forth_code_get_elem_index(code, (union forth_inst *)inst));

        if (inst->callback == op_number) {
            inst++;
            printf("number %lf\n", inst->number);
            continue;
        }
        if (inst->callback == op_jump_if) {
            printf("if [next +%zu, abs %zu]\n", inst[1].pc,
                   forth_code_get_elem_index(code, (union forth_inst *)inst) +
                       inst[1].pc);
            inst++;
            continue;
        }
        if (inst->callback == op_jump) {
            printf("jump to +%zu, abs %zu\n", inst[1].pc,
                   forth_code_get_elem_index(code, (union forth_inst *)inst) +
                       inst[1].pc);
            inst++;
            continue;
        }
        if (inst->callback == op_nop) {
            printf("nop\n");
            continue;
        }
        if (inst->callback == op_halt) {
            printf("halt\n");
            continue;
        }
        if (UNLIKELY(inst->callback == op_eval_code)) {
            lwan_status_critical("eval_code shouldn't exist here");
            __builtin_unreachable();
        }

        const struct forth_builtin *b =
            find_builtin_by_callback(inst->callback);
        if (b) {
            printf("call builtin '%s'\n", b->name);
        } else {
            printf("*** inconsistency; value = %zu ***\n", inst->pc);
        }
    }
}
#endif

#if 0
static const char *c_builtin_name(const struct forth_builtin *b,
                                  char buffer[static 64])
{
    /* FIXME add op_* names to forth_builtin; maybe do this during new_word()? */
    if (streq(b->name, "+"))
        return "op_add";
    if (streq(b->name, "-"))
        return "op_sub";
    if (streq(b->name, "/"))
        return "op_div";
    if (streq(b->name, "*"))
        return "op_mult";
    if (streq(b->name, "<>"))
        return "op_diff";
    if (streq(b->name, "="))
        return "op_eq";
    if (streq(b->name, ">"))
        return "op_gt";
    if (streq(b->name, ">="))
        return "op_gte";
    if (streq(b->name, "<"))
        return "op_lt";
    if (streq(b->name, "<="))
        return "op_lte";
    if (streq(b->name, "**"))
        return "op_pow";
    if (streq(b->name, "%"))
        return "op_mod";
    if (streq(b->name, ">r"))
        return "op_tor";
    if (streq(b->name, "r>"))
        return "op_fromr";
    if (streq(b->name, "r@"))
        return "op_rtord";
    if (streq(b->name, "@"))
        return "op_recall";
    if (streq(b->name, "!"))
        return "op_store";
    if (streq(b->name, "2dup"))
        return "op_2dup";
    if (streq(b->name, "z+"))
        return "op_zplus";
    if (streq(b->name, "z*"))
        return "op_zmult";
    if (streq(b->name, "-rot"))
        return "op_minusrot";
    int ret = snprintf(buffer, 64, "op_%s", b->name);
    return (ret < 0 || ret > 64) ? NULL : buffer;
}


#define GET_TMP(num_)                                                          \
    ({                                                                         \
        int n = (num_);                                                        \
        const char *out;                                                       \
        if (n > last_undeclared) {                                             \
            out = "double tmp";                                                \
            last_undeclared = n;                                               \
        } else {                                                               \
            out = "tmp";                                                       \
        }                                                                      \
        out;                                                                   \
    })

static bool dump_code_c(const struct forth_ir_code *code)
{
    size_t jump_stack[64];
    size_t *j = jump_stack;
    char name_buffer[64];
    int last_tmp = 0;
    int last_undeclared = -1;
    const struct forth_ir *ir;

    printf("dumping code @ %p\n", code);

    fwrite(forth_jit_value.value, forth_jit_value.len, 1, stdout);
    printf("void compute(double x, double y, double t, double *r, double *g, "
           "double *b) {\n");

    LWAN_ARRAY_FOREACH (code, ir) {
        switch (ir->opcode) {
        case OP_EVAL_CODE:
            __builtin_unreachable();
        case OP_CALL_BUILTIN: {
            const struct forth_builtin *b =
                find_builtin_by_callback(ir->callback);
            last_tmp -= b->d_pops;

            if (b->d_pushes == 0) {
                printf("    %s(", c_builtin_name(b, name_buffer));
                for (int arg = 0; arg < b->d_pops; arg++) {
                    printf("tmp%d, ", last_tmp + arg - 1);
                }
                printf(");\n");
            } else if (b->d_pushes == 1) {
                if (streq(b->name, "t") || streq(b->name, "x") ||
                    streq(b->name, "y")) {
                    int t = last_tmp++;
                    printf("    %s%d = %s;\n", GET_TMP(t), t, b->name);
                } else {
                    int t = last_tmp++;
                    printf("    %s%d = %s(", GET_TMP(t), t,
                           c_builtin_name(b, name_buffer));
                    for (int arg = 0; arg < b->d_pops; arg++) {
                        t = last_tmp + arg - 1;
                        if (arg == b->d_pops - 1) {
                            printf("tmp%d", t);
                        } else {
                            printf("tmp%d, ", t);
                        }
                    }
                    printf(");\n");
                }

            } else {
                printf("    %s(", c_builtin_name(b, name_buffer));
                for (int arg = 0; arg < b->d_pops; arg++) {
                    printf("tmp%d, ", last_tmp + arg - 1);
                }
                for (int out_arg = 0; out_arg < b->d_pushes; out_arg++) {
                    int t = last_tmp + out_arg - 1;
                    if (out_arg == b->d_pushes - 1) {
                        printf("&tmp%d", t);
                    } else {
                        printf("&tmp%d, ", t);
                    }
                }
                last_tmp += b->d_pushes;
                printf(");\n");
            }

            break;
        }
        case OP_NUMBER: {
            int t = last_tmp++;
            printf("    %s%d = %lf;\n", GET_TMP(t), t, ir->number);
            break;
        }
        case OP_JUMP_IF:
            printf("    if (tmp%d == 0.0) {\n", --last_tmp);
            JS_PUSH((size_t)last_tmp);
            JS_PUSH((size_t)last_undeclared);
            break;
        case OP_JUMP:
            printf("    } else {\n");
            last_undeclared = (int)JS_POP();
            last_tmp = (int)JS_POP();
            JS_PUSH((size_t)last_undeclared);
            break;
        case OP_NOP:
            printf("    }\n");
            last_undeclared = (int)JS_POP();
            break;
        }
    }

    switch (last_tmp) {
    case 3:
        printf("    *r = tmp2;\n");
        printf("    *g = tmp1;\n");
        printf("    *b = tmp0;\n");
        break;
    case 4:
        printf("    *r = tmp3;\n");
        printf("    *g = tmp2;\n");
        printf("    *b = tmp1;\n");
        break;
    default:
        printf("    *r = *g = *b = 0.0;\n");
    }

    printf("}\n");

    return true;
}

static void dump_code(const struct forth_ir_code *code)
{
    dump_code_ir(code);
    dump_code_c(code);
}
#endif

bool forth_run(struct forth_ctx *ctx, struct forth_vars *vars)
{
    union forth_inst *instr = forth_code_get_elem(&ctx->main->code, 0);
    instr->callback(instr, ctx->d_stack, ctx->r_stack, vars);
    return true;
}

static bool parse_number(const char *ptr, size_t len, double *number)
{
    char *endptr;

    errno = 0;
    *number = strtod(strndupa(ptr, len), &endptr);

    if (errno != 0)
        return false;

    if (*endptr != '\0')
        return false;

    return true;
}

static struct forth_word *new_word(struct forth_ctx *ctx,
                                   const char *name,
                                   size_t len,
                                   void *callback,
                                   const struct forth_builtin *builtin)
{
    if (len > 64)
        return NULL;

    struct forth_word *word = malloc(sizeof(*word) + len + 1);
    if (UNLIKELY(!word))
        return NULL;

    if (callback) {
        word->callback = callback;
    } else {
        forth_code_init(&word->code);
    }

    word->builtin = builtin;
    word->d_stack_len = 0;
    word->r_stack_len = 0;

    strncpy(word->name, name, len);
    word->name[len] = '\0';

    if (!hash_add(ctx->words, word->name, word))
        return word;

    free(word);
    return NULL;
}

static struct forth_word *
lookup_word(struct forth_ctx *ctx, const char *name, size_t len)
{
    return hash_find(ctx->words, strndupa(name, len));
}

#define EMIT(arg)                                                              \
    ({                                                                         \
        union forth_inst *emitted =                                            \
            forth_code_append(&ctx->defining_word->code);                      \
        if (UNLIKELY(!emitted))                                                \
            return NULL;                                                       \
        *emitted = (union forth_inst){arg};                                    \
        emitted;                                                               \
    })

static const char *found_word(struct forth_ctx *ctx,
                              const char *code,
                              const char *word,
                              size_t word_len)
{
    double number;
    if (parse_number(word, word_len, &number)) {
        if (LIKELY(ctx->defining_word)) {
            EMIT(.callback = op_number);
            EMIT(.number = number);
            return code;
        }

        lwan_status_error("Can't redefine number %lf", number);
        return NULL;
    }

    struct forth_word *w = lookup_word(ctx, word, word_len);
    if (ctx->defining_word) {
        if (LIKELY(w)) {
            if (is_word_compiler(w))
                return w->callback_compiler(ctx, code);

            if (is_word_builtin(w)) {
                EMIT(.callback = w->callback);
            } else {
                EMIT(.callback = op_eval_code);
                EMIT(.code = &w->code);
            }
            return code;
        }

        lwan_status_error("Undefined word: \"%.*s\"",
                          (int)word_len, word);
        return NULL;
    }

    if (LIKELY(w != NULL)) {
        lwan_status_error("Word already defined: \"%.*s\"", (int)word_len, word);
        return NULL;
    }

    w = new_word(ctx, word, word_len, NULL, NULL);
    if (UNLIKELY(!w)) {
        lwan_status_error("Can't create new word");
        return NULL;
    }

    ctx->defining_word = w;
    return code;
}

static bool inline_calls_code(const struct forth_code *orig_code,
                              struct forth_code *new_code)
{
    const union forth_inst *inst;
    size_t jump_stack[64];
    size_t *j = jump_stack;

    LWAN_ARRAY_FOREACH (orig_code, inst) {
        if (inst->callback == op_eval_code) {
            inst++;
            if (!inline_calls_code(inst->code, new_code))
                return false;
        } else {
            bool has_imm = false;
            union forth_inst *new_inst = forth_code_append(new_code);
            if (!new_inst)
                return false;

            *new_inst = *inst;

            if (inst->callback == op_jump_if) {
                JS_PUSH(forth_code_len(new_code));
                has_imm = true;
            } else if (inst->callback == op_jump) {
                union forth_inst *if_inst =
                    forth_code_get_elem(new_code, JS_POP());
                if_inst->pc = forth_code_len(new_code) +
                              forth_code_get_elem_index(new_code, if_inst) - 2;

                JS_PUSH(forth_code_len(new_code));
                has_imm = true;
            } else if (inst->callback == op_nop) {
                union forth_inst *else_inst =
                    forth_code_get_elem(new_code, JS_POP());
                else_inst->pc = forth_code_len(new_code) -
                                forth_code_get_elem_index(new_code, else_inst);
            } else if (inst->callback == op_number) {
                has_imm = true;
            }

            if (has_imm) {
                new_inst = forth_code_append(new_code);
                if (!new_inst)
                    return false;

                inst++;
                *new_inst = *inst;
            }
        }
    }

    return true;
}

static bool inline_calls(struct forth_ctx *ctx)
{
    struct forth_code new_main;

    forth_code_init(&new_main);
    if (!inline_calls_code(&ctx->main->code, &new_main)) {
        forth_code_reset(&new_main);
        return false;
    }

    forth_code_reset(&ctx->main->code);
    ctx->main->code = new_main;

    return true;
}

bool forth_parse_string(struct forth_ctx *ctx, const char *code)
{
    assert(ctx);

    ctx->j = ctx->j_stack;

    while (*code) {
        while (isspace(*code))
            code++;

        const char *word_ptr = code;

        while (true) {
            if (*code == '\0') {
                if (word_ptr == code)
                    return true;
                break;
            }
            if (isspace(*code))
                break;
            if (!isprint(*code))
                return false;
            code++;
        }

        code = found_word(ctx, code, word_ptr, (size_t)(code - word_ptr));
        if (!code)
            return false;

        if (*code == '\0')
            break;

        code++;
    }

    EMIT(.callback = op_halt);

    if (!inline_calls(ctx))
        return false;

#if defined(DUMP_CODE)
    dump_code(&ctx->main->code);
#endif

    if (!check_stack_effects(ctx, ctx->main))
        return false;

    return true;
}

#define BUILTIN_DETAIL(name_, id_, struct_id_, d_pushes_, d_pops_, r_pushes_,  \
                       r_pops_)                                                \
    static void id_(union forth_inst *inst, double *d_stack, double *r_stack,  \
                    struct forth_vars *vars);                                  \
    static const struct forth_builtin __attribute__((used))                    \
    __attribute__((section(LWAN_SECTION_NAME(forth_builtin))))                 \
    __attribute__((aligned(8))) struct_id_ = {                                 \
        .name = name_,                                                         \
        .name_len = sizeof(name_) - 1,                                         \
        .callback = id_,                                                       \
        .d_pushes = d_pushes_,                                                 \
        .d_pops = d_pops_,                                                     \
        .r_pushes = r_pushes_,                                                 \
        .r_pops = r_pops_,                                                     \
    };                                                                         \
    static void id_(union forth_inst *inst, double *d_stack, double *r_stack,  \
                    struct forth_vars *vars)

#define BUILTIN_COMPILER_DETAIL(name_, id_, struct_id_)                        \
    static const char *id_(struct forth_ctx *, const char *);                  \
    static const struct forth_builtin __attribute__((used))                    \
    __attribute__((section(LWAN_SECTION_NAME(forth_compiler_builtin))))        \
    __attribute__((aligned(8))) struct_id_ = {                                 \
        .name = name_,                                                         \
        .name_len = sizeof(name_) - 1,                                         \
        .callback_compiler = id_,                                              \
    };                                                                         \
    static const char *id_(struct forth_ctx *ctx __attribute__((unused)),      \
                           const char *code)

#define BUILTIN(name_, d_pushes_, d_pops_)                                     \
    BUILTIN_DETAIL(name_, LWAN_TMP_ID, LWAN_TMP_ID, d_pushes_, d_pops_, 0, 0)
#define BUILTIN_R(name_, d_pushes_, d_pops_, r_pushes_, r_pops_)               \
    BUILTIN_DETAIL(name_, LWAN_TMP_ID, LWAN_TMP_ID, d_pushes_, d_pops_,        \
                   r_pushes_, r_pops_)

#define BUILTIN_COMPILER(name_)                                                \
    BUILTIN_COMPILER_DETAIL(name_, LWAN_TMP_ID, LWAN_TMP_ID)

BUILTIN_COMPILER("\\")
{
    code = strchr(code, '\n');
    return code ? code + 1 : NULL;
}

BUILTIN_COMPILER("(")
{
    code = strchr(code, ')');
    return code ? code + 1 : NULL;
}

BUILTIN_COMPILER(":")
{
    if (UNLIKELY(ctx->is_inside_word_def)) {
        lwan_status_error("Already defining word");
        return NULL;
    }

    ctx->is_inside_word_def = true;
    ctx->defining_word = NULL;
    return code;
}

BUILTIN_COMPILER(";")
{
    if (ctx->j != ctx->j_stack) {
        lwan_status_error("Unmatched if/then/else");
        return NULL;
    }

    if (UNLIKELY(!ctx->is_inside_word_def)) {
        lwan_status_error("Ending word without defining one");
        return NULL;
    }

    ctx->is_inside_word_def = false;

    if (UNLIKELY(!ctx->defining_word)) {
        lwan_status_error("No word provided");
        return NULL;
    }

    ctx->defining_word = ctx->main;
    return code;
}

BUILTIN_COMPILER("if")
{
    if ((size_t)(ctx->j - ctx->j_stack) >= N_ELEMENTS(ctx->j_stack)) {
        lwan_status_error("Too many nested 'if' words");
        return NULL;
    }

    EMIT(.callback = op_jump_if);
    *ctx->j++ = EMIT(.pc = 0);
    return code;
}

static const char *
builtin_else_then(struct forth_ctx *ctx, const char *code, bool is_then)
{
    if (ctx->j == ctx->j_stack) {
        lwan_status_error("'%s' before 'if'", is_then ? "then" : "else");
        return NULL;
    }

    union forth_inst *prev_pc_imm = *--ctx->j;

    if (is_then) {
        EMIT(.callback = op_nop);
    } else {
        EMIT(.callback = op_jump);

        if ((size_t)(ctx->j - ctx->j_stack) >= N_ELEMENTS(ctx->j_stack)) {
            lwan_status_error("Else is too deep");
            return NULL;
        }

        *ctx->j++ = EMIT(.pc = 0);
    }

    prev_pc_imm->pc = forth_code_len(&ctx->defining_word->code);

    return code;
}

BUILTIN_COMPILER("else") { return builtin_else_then(ctx, code, false); }
BUILTIN_COMPILER("then") { return builtin_else_then(ctx, code, true); }

#define PUSH_D(value_) ({ *d_stack = (value_); d_stack++; })
#define PUSH_R(value_) ({ *r_stack = (value_); r_stack++; })
#define DROP_D() ({ d_stack--; })
#define DROP_R() ({ r_stack--; })
#define POP_D() ({ DROP_D(); *d_stack; })
#define POP_R() ({ DROP_R(); *r_stack; })

#define NEXT() return inst[1].callback(&inst[1], d_stack, r_stack, vars)

BUILTIN("x", 1, 0)
{
    PUSH_D(vars->x);
    NEXT();
}
BUILTIN("y", 1, 0)
{
    PUSH_D(vars->y);
    NEXT();
}
BUILTIN("t", 1, 0)
{
    PUSH_D(vars->t);
    NEXT();
}
BUILTIN("dt", 1, 0)
{
    PUSH_D(vars->dt);
    NEXT();
}

BUILTIN("mx", 1, 0)
{
    /* stub */
    PUSH_D(0.0);
    NEXT();
}

BUILTIN("my", 1, 0)
{
    /* stub */
    PUSH_D(0.0);
    NEXT();
}

BUILTIN("button", 1, 1)
{
    /* stub */
    DROP_D();
    PUSH_D(0.0);
    NEXT();
}

BUILTIN("buttons", 1, 0)
{
    /* stub */
    PUSH_D(0.0);
    NEXT();
}

BUILTIN("audio", 0, 1)
{
    /* stub */
    DROP_D();
    NEXT();
}

BUILTIN("sample", 3, 2)
{
    /* stub */
    DROP_D();
    DROP_D();
    PUSH_D(0);
    PUSH_D(0);
    PUSH_D(0);
    NEXT();
}

BUILTIN("bwsample", 1, 2)
{
    /* stub */
    DROP_D();
    DROP_D();
    PUSH_D(0);
    NEXT();
}

BUILTIN_R("push", 0, 1, 1, 0)
{
    PUSH_R(POP_D());
    NEXT();
}

BUILTIN_R("pop", 1, 0, 0, 1)
{
    PUSH_D(POP_R());
    NEXT();
}

BUILTIN_R(">r", 0, 1, 1, 0)
{
    PUSH_R(POP_D());
    NEXT();
}

BUILTIN_R("r>", 1, 0, 0, 1)
{
    PUSH_D(POP_R());
    NEXT();
}

BUILTIN_R("r@", 1, 0, 1, 1)
{
    double v = POP_R();
    PUSH_R(v);
    PUSH_D(v);
    NEXT();
}

BUILTIN("@", 1, 1)
{
    uint32_t slot = (uint32_t)POP_D();
    PUSH_D(vars->memory[slot % (uint32_t)N_ELEMENTS(vars->memory)]);
    NEXT();
}

BUILTIN("!", 0, 2)
{
    double v = POP_D();
    uint32_t slot = (uint32_t)POP_D();
    vars->memory[slot % (uint32_t)N_ELEMENTS(vars->memory)] = v;
    NEXT();
}

BUILTIN("dup", 2, 1)
{
    double v = POP_D();
    PUSH_D(v);
    PUSH_D(v);
    NEXT();
}

BUILTIN("over", 3, 2)
{
    double v1 = POP_D();
    double v2 = POP_D();
    PUSH_D(v2);
    PUSH_D(v1);
    PUSH_D(v2);
    NEXT();
}

BUILTIN("2dup", 4, 2)
{
    double v1 = POP_D();
    double v2 = POP_D();
    PUSH_D(v2);
    PUSH_D(v1);
    PUSH_D(v2);
    PUSH_D(v1);
    NEXT();
}

BUILTIN("z+", 2, 4)
{
    double v1 = POP_D();
    double v2 = POP_D();
    double v3 = POP_D();
    double v4 = POP_D();
    PUSH_D(v2 + v4);
    PUSH_D(v1 + v3);
    NEXT();
}

BUILTIN("z*", 2, 4)
{
    double v1 = POP_D();
    double v2 = POP_D();
    double v3 = POP_D();
    double v4 = POP_D();
    PUSH_D(v4 * v2 - v3 * v1);
    PUSH_D(v4 * v1 + v3 * v2);
    NEXT();
}

BUILTIN("drop", 0, 1)
{
    DROP_D();
    NEXT();
}

BUILTIN("swap", 2, 2)
{
    double v1 = POP_D();
    double v2 = POP_D();
    PUSH_D(v1);
    PUSH_D(v2);
    NEXT();
}

BUILTIN("rot", 3, 3)
{
    double v1 = POP_D();
    double v2 = POP_D();
    double v3 = POP_D();
    PUSH_D(v2);
    PUSH_D(v1);
    PUSH_D(v3);
    NEXT();
}

BUILTIN("-rot", 3, 3)
{
    double v1 = POP_D();
    double v2 = POP_D();
    double v3 = POP_D();
    PUSH_D(v1);
    PUSH_D(v3);
    PUSH_D(v2);
    NEXT();
}

BUILTIN("=", 1, 2)
{
    double v1 = POP_D();
    double v2 = POP_D();
    PUSH_D(v1 == v2 ? 1.0 : 0.0);
    NEXT();
}

BUILTIN("<>", 1, 2)
{
    double v1 = POP_D();
    double v2 = POP_D();
    PUSH_D(v1 != v2 ? 1.0 : 0.0);
    NEXT();
}

BUILTIN(">", 1, 2)
{
    double v1 = POP_D();
    double v2 = POP_D();
    PUSH_D(v1 > v2 ? 1.0 : 0.0);
    NEXT();
}

BUILTIN("<", 1, 2)
{
    double v1 = POP_D();
    double v2 = POP_D();
    PUSH_D(v1 < v2 ? 1.0 : 0.0);
    NEXT();
}

BUILTIN(">=", 1, 2)
{
    double v1 = POP_D();
    double v2 = POP_D();
    PUSH_D(v1 >= v2 ? 1.0 : 0.0);
    NEXT();
}

BUILTIN("<=", 1, 2)
{
    double v1 = POP_D();
    double v2 = POP_D();
    PUSH_D(v1 <= v2 ? 1.0 : 0.0);
    NEXT();
}

BUILTIN("+", 1, 2)
{
    PUSH_D(POP_D() + POP_D());
    NEXT();
}

BUILTIN("*", 1, 2)
{
    PUSH_D(POP_D() * POP_D());
    NEXT();
}

BUILTIN("-", 1, 2)
{
    double v = POP_D();
    PUSH_D(POP_D() - v);
    NEXT();
}

BUILTIN("/", 1, 2)
{
    double v = POP_D();
    if (UNLIKELY(v == 0.0)) {
        DROP_D();
        PUSH_D(__builtin_inf());
    } else {
        PUSH_D(POP_D() / v);
    }
    NEXT();
}

BUILTIN("mod", 1, 2)
{
    double v = POP_D();
    PUSH_D(fmod(POP_D(), v));
    NEXT();
}

BUILTIN("pow", 1, 2)
{
    double v = POP_D();
    PUSH_D(pow(fabs(POP_D()), v));
    NEXT();
}

BUILTIN("**", 1, 2)
{
    double v = POP_D();
    PUSH_D(pow(fabs(POP_D()), v));
    NEXT();
}

BUILTIN("atan2", 1, 2)
{
    double v = POP_D();
    PUSH_D(atan2(POP_D(), v));
    NEXT();
}

BUILTIN("and", 1, 2)
{
    double v = POP_D();
    PUSH_D((POP_D() != 0.0 && v != 0.0) ? 1.0 : 0.0);
    NEXT();
}

BUILTIN("or", 1, 2)
{
    double v = POP_D();
    PUSH_D((POP_D() != 0.0 || v != 0.0) ? 1.0 : 0.0);
    NEXT();
}

BUILTIN("not", 1, 1)
{
    PUSH_D(POP_D() != 0.0 ? 0.0 : 1.0);
    NEXT();
}

BUILTIN("min", 1, 2)
{
    double v1 = POP_D();
    double v2 = POP_D();
    PUSH_D(v1 > v2 ? v2 : v1);
    NEXT();
}

BUILTIN("max", 1, 2)
{
    double v1 = POP_D();
    double v2 = POP_D();
    PUSH_D(v1 > v2 ? v1 : v2);
    NEXT();
}

BUILTIN("negate", 1, 1)
{
    PUSH_D(-POP_D());
    NEXT();
}

BUILTIN("sin", 1, 1)
{
    PUSH_D(sin(POP_D()));
    NEXT();
}

BUILTIN("cos", 1, 1)
{
    PUSH_D(cos(POP_D()));
    NEXT();
}

BUILTIN("tan", 1, 1)
{
    PUSH_D(tan(POP_D()));
    NEXT();
}

BUILTIN("log", 1, 1)
{
    PUSH_D(log(fabs(POP_D())));
    NEXT();
}

BUILTIN("exp", 1, 1)
{
    PUSH_D(exp(POP_D()));
    NEXT();
}

BUILTIN("sqrt", 1, 1)
{
    PUSH_D(sqrt(fabs(POP_D())));
    NEXT();
}

BUILTIN("floor", 1, 1)
{
    PUSH_D(floor(POP_D()));
    NEXT();
}

BUILTIN("ceil", 1, 1)
{
    PUSH_D(ceil(POP_D()));
    NEXT();
}

BUILTIN("abs", 1, 1)
{
    PUSH_D(fabs(POP_D()));
    NEXT();
}

BUILTIN("pi", 1, 0)
{
    PUSH_D(M_PI);
    NEXT();
}

BUILTIN("random", 1, 0)
{
    PUSH_D(drand48());
    NEXT();
}

#undef NEXT

__attribute__((no_sanitize_address)) static void
register_builtins(struct forth_ctx *ctx)
{
    const struct forth_builtin *iter;

    LWAN_SECTION_FOREACH(forth_builtin, iter) {
        if (!new_word(ctx, iter->name, iter->name_len, iter->callback, iter)) {
            lwan_status_critical("could not register forth word: %s",
                                 iter->name);
        }
    }
    LWAN_SECTION_FOREACH(forth_compiler_builtin, iter) {
        if (!new_word(ctx, iter->name, iter->name_len, iter->callback_compiler, iter)) {
            lwan_status_critical("could not register forth word: %s",
                                 iter->name);
        }
    }
}

static void word_free(void *ptr)
{
    struct forth_word *word = ptr;

    if (!is_word_builtin(word))
        forth_code_reset(&word->code);
    free(word);
}

struct forth_ctx *forth_new(void)
{
    struct forth_ctx *ctx = malloc(sizeof(*ctx));

    if (!ctx)
        return NULL;

    ctx->is_inside_word_def = false;

    ctx->words = hash_str_new(NULL, word_free);
    if (!ctx->words) {
        free(ctx);
        return NULL;
    }

    struct forth_word *word = new_word(ctx, " ", 1, NULL, NULL);
    if (!word) {
        free(ctx);
        return NULL;
    }

    ctx->main = word;
    ctx->defining_word = word;

    register_builtins(ctx);

    return ctx;
}

void forth_free(struct forth_ctx *ctx)
{
    if (!ctx)
        return;

    hash_unref(ctx->words);
    free(ctx);
}

size_t forth_d_stack_len(const struct forth_ctx *ctx,
        const struct forth_vars *vars)
{
    return (size_t)(vars->final_d_stack_ptr - ctx->d_stack);
}

double forth_d_stack_pop(struct forth_vars *vars)
{
    vars->final_d_stack_ptr--;
    double v = *vars->final_d_stack_ptr;
    return v;
}

#if defined(FUZZ_TEST)
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct forth_ctx *ctx = forth_new();
    if (!ctx)
        return 1;

    char *input = strndup((const char *)data, size);
    if (!input) {
        forth_free(ctx);
        return 1;
    }

    if (!forth_parse_string(ctx, input)) {
        forth_free(ctx);
        free(input);
        return 1;
    }

    free(input);

    struct forth_vars vars = {.x = 1, .y = 0};
    forth_run(ctx, &vars);

    forth_free(ctx);

    return 0;
}
#elif defined(MAIN)
int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    struct forth_ctx *ctx = forth_new();
    if (!ctx)
        return 1;

    if (!forth_parse_string(ctx,
                            ": nice 60 5 4 + + ; : juanita 400 10 5 5 + + + ; "
                            "x if nice else juanita then 2 * 4 / 2 *")) {
        lwan_status_critical("could not parse forth program");
        forth_free(ctx);
        return 1;
    }

    printf("running with x=0\n");
    struct forth_vars vars = {.x = 0, .y = 0};
    if (forth_run(ctx, &vars)) {
        printf("D stack: %zu elems", forth_d_stack_len(ctx, &vars));
        for (size_t len = forth_d_stack_len(ctx, &vars); len; len--) {
            printf("   %lf", forth_d_stack_pop(&vars));
        }
    }

    printf("\nrunning with x=1\n");
    vars = (struct forth_vars){.x = 1, .y = 0};
    if (forth_run(ctx, &vars)) {
        printf("D stack: %zu elems", forth_d_stack_len(ctx, &vars));
        for (size_t len = forth_d_stack_len(ctx, &vars); len; len--) {
            printf("   %lf", forth_d_stack_pop(&vars));
        }
    }

    forth_free(ctx);

    return 0;
}
#endif
