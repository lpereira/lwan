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
struct forth_code;

struct forth_inst {
    union {
        double number;
        struct forth_code *code;
        void (*callback)(struct forth_ctx *ctx, struct forth_vars *vars);
        size_t pc;
    };
    enum forth_opcode opcode;
};

DEFINE_ARRAY_TYPE(forth_code, struct forth_inst)

struct forth_builtin {
    const char *name;
    size_t name_len;
    union {
        void (*callback)(struct forth_ctx *, struct forth_vars *vars);
        const char *(*callback_compiler)(struct forth_ctx *, const char *);
    };
    int d_pushes;
    int d_pops;
    int r_pushes;
    int r_pops;
};

struct forth_word {
    union {
        void (*callback)(struct forth_ctx *ctx, struct forth_vars *vars);
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
    struct {
        size_t pos;
        double values[256];
    } r_stack, d_stack;

    double memory[16];

    struct forth_word *defining_word;
    struct forth_word *main;
    struct hash *words;

    bool is_inside_word_def;
};

#define PUSH_D(value_) ({ ctx->d_stack.values[ctx->d_stack.pos++] = (value_); })
#define PUSH_R(value_) ({ ctx->r_stack.values[ctx->r_stack.pos++] = (value_); })
#define DROP_D() ({ ctx->d_stack.pos--; })
#define DROP_R() ({ ctx->r_stack.pos--; })
#define POP_D() ({ DROP_D(); ctx->d_stack.values[ctx->d_stack.pos]; })
#define POP_R() ({ DROP_R(); ctx->r_stack.values[ctx->r_stack.pos]; })

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

static const struct forth_word *find_word_by_code(const struct forth_ctx *ctx,
                                                  const struct forth_code *code)
{
    struct hash_iter iter;
    const void *name, *value;

    hash_iter_init(ctx->words, &iter);
    while (hash_iter_next(&iter, &name, &value)) {
        const struct forth_word *word = value;
        if (&word->code == code)
            return word;
    }

    return NULL;
}

static bool check_stack_effects(const struct forth_ctx *ctx,
                                struct forth_word *w)
{
    const struct forth_inst *inst;
    int items_in_d_stack = 0;
    int items_in_r_stack = 0;

    assert(!is_word_builtin(w));

    LWAN_ARRAY_FOREACH(&w->code, inst) {
        switch (inst->opcode) {
        case OP_EVAL_CODE: {
            const struct forth_word *cw = find_word_by_code(ctx, inst->code);
            if (UNLIKELY(!cw)) {
                lwan_status_critical("Can't find builtin word by user code");
                return false;
            }

            items_in_d_stack += cw->d_stack_len;
            items_in_r_stack += cw->r_stack_len;
            break;
        }
        case OP_CALL_BUILTIN: {
            const struct forth_builtin *b = find_builtin_by_callback(inst->callback);
            if (UNLIKELY(!b)) {
                lwan_status_critical("Can't find builtin word by callback");
                return false;
            }

            if (items_in_d_stack < b->d_pops) {
                lwan_status_error("Word `%.*s' requires %d item(s) in the D stack",
                        (int)b->name_len, b->name, b->d_pops);
                return false;
            }
            if (items_in_r_stack < b->r_pops) {
                lwan_status_error("Word `%.*s' requires %d item(s) in the R stack",
                        (int)b->name_len, b->name, b->r_pops);
                return false;
            }

            items_in_d_stack -= b->d_pops;
            items_in_d_stack += b->d_pushes;
            items_in_r_stack -= b->r_pops;
            items_in_r_stack += b->r_pushes;
            break;
        }
        case OP_NUMBER:
            items_in_d_stack++;
            break;
        case OP_JUMP_IF:
            if (!items_in_d_stack) {
                lwan_status_error("Word `if' requires 1 item(s) in the D stack");
                return false;
            }
            items_in_d_stack--;
            break;
        case OP_NOP:
        case OP_JUMP:
            continue;
        }
    }

    w->d_stack_len = items_in_d_stack;
    w->r_stack_len = items_in_r_stack;

    return true;
}

#if DUMP_CODE
static void dump_code(const struct forth_code *code)
{
    const struct forth_inst *inst;
    size_t i = 0;

    printf("dumping code @ %p\n", code);

    LWAN_ARRAY_FOREACH (code, inst) {
        printf("%08zu    ", i);
        i++;

        switch (inst->opcode) {
        case OP_EVAL_CODE:
            printf("eval code %p\n", inst->code);
            break;
        case OP_CALL_BUILTIN:
            printf("call builtin %p\n", inst->callback);
            break;
        case OP_NUMBER:
            printf("number %lf\n", inst->number);
            break;
        case OP_JUMP_IF:
            printf("if [next %zu]\n", inst->pc);
            break;
        case OP_JUMP:
            printf("jump to %zu\n", inst->pc);
            break;
        case OP_NOP:
            printf("nop\n");
        }
    }
}
#endif

static bool eval_code(struct forth_ctx *ctx,
                      const struct forth_code *code,
                      struct forth_vars *vars)
{
    const struct forth_inst *inst;

#if DUMP_CODE
    dump_code(code);
#endif

    LWAN_ARRAY_FOREACH (code, inst) {
        switch (inst->opcode) {
        case OP_EVAL_CODE:
            lwan_status_critical("Unreachable");
            __builtin_unreachable();
        case OP_CALL_BUILTIN:
            inst->callback(ctx, vars);
            break;
        case OP_NUMBER:
            PUSH_D(inst->number);
            break;
        case OP_JUMP_IF:
            if (POP_D() == 0.0)
                inst = forth_code_get_elem(code, inst->pc);
            break;
        case OP_JUMP:
            inst = forth_code_get_elem(code, inst->pc);
            break;
        case OP_NOP:
            break;
        }
    }

    return true;
}

bool forth_run(struct forth_ctx *ctx, struct forth_vars *vars)
{
    return eval_code(ctx, &ctx->main->code, vars);
}

static struct forth_inst *new_inst(struct forth_ctx *ctx)
{
    /* FIXME: if last instruction is NOP, maybe we can reuse it? */

    if (UNLIKELY(!ctx->defining_word))
        return NULL;

    return forth_code_append(&ctx->defining_word->code);
}

static bool emit_word_call(struct forth_ctx *ctx, struct forth_word *word)
{
    assert(!is_word_compiler(word));

    struct forth_inst *inst = new_inst(ctx);
    if (UNLIKELY(!inst))
        return false;

    if (is_word_builtin(word)) {
        *inst = (struct forth_inst){.callback = word->callback,
                                    .opcode = OP_CALL_BUILTIN};
    } else {
        *inst =
            (struct forth_inst){.code = &word->code, .opcode = OP_EVAL_CODE};
    }

    return true;
}

static bool emit_number(struct forth_ctx *ctx, double number)
{
    struct forth_inst *inst = new_inst(ctx);
    if (UNLIKELY(!inst))
        return false;

    *inst = (struct forth_inst){.number = number, .opcode = OP_NUMBER};
    return true;
}

static bool emit_jump_if(struct forth_ctx *ctx)
{
    struct forth_inst *inst = new_inst(ctx);
    if (UNLIKELY(!inst))
        return false;

    *inst = (struct forth_inst){.opcode = OP_JUMP_IF};
    return true;
}

static bool emit_jump(struct forth_ctx *ctx)
{
    struct forth_inst *inst = new_inst(ctx);
    if (UNLIKELY(!inst))
        return false;

    *inst = (struct forth_inst){.opcode = OP_JUMP};
    return true;
}

static bool emit_nop(struct forth_ctx *ctx)
{
    struct forth_inst *inst = new_inst(ctx);
    if (UNLIKELY(!inst))
        return false;

    *inst = (struct forth_inst){.opcode = OP_NOP};
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

static const char *found_word(struct forth_ctx *ctx,
                              const char *code,
                              const char *word,
                              size_t word_len)
{
    double number;
    if (parse_number(word, word_len, &number)) {
        if (LIKELY(ctx->defining_word))
            return emit_number(ctx, number) ? code : NULL;

        lwan_status_error("Can't redefine number %lf", number);
        return NULL;
    }

    struct forth_word *w = lookup_word(ctx, word, word_len);
    if (ctx->defining_word) {
        if (LIKELY(w)) {
            if (is_word_compiler(w))
                return w->callback_compiler(ctx, code);
            return emit_word_call(ctx, w) ? code : NULL;
        }

        lwan_status_error("Word \"%.*s\" not defined yet, can't call",
                          (int)word_len, word);
        return NULL; /* word not defined yet */
    }

    if (LIKELY(w != NULL)) { /* redefining word not supported */
        lwan_status_error("Can't redefine word \"%.*s\"", (int)word_len, word);
        return NULL;
    }

    w = new_word(ctx, word, word_len, NULL, NULL);
    if (UNLIKELY(!w)) { /* can't create new word */
        lwan_status_error("Can't create new word");
        return NULL;
    }

    ctx->defining_word = w;
    return code;
}

static bool inline_calls_code(struct forth_ctx *ctx,
                              const struct forth_code *orig_code,
                              struct forth_code *new_code)
{
    const struct forth_inst *inst;

    LWAN_ARRAY_FOREACH (orig_code, inst) {
        if (inst->opcode == OP_EVAL_CODE) {
            if (!inline_calls_code(ctx, inst->code, new_code))
                return false;
        } else {
            struct forth_inst *new_inst = forth_code_append(new_code);
            if (!new_inst)
                return false;

            *new_inst = *inst;

            if (inst->opcode == OP_JUMP_IF) {
                PUSH_R((uint32_t)forth_code_len(new_code) - 1);
            } else if (inst->opcode == OP_JUMP) {
                struct forth_inst *if_inst =
                    forth_code_get_elem(new_code, (uint32_t)POP_R());
                if_inst->pc = forth_code_len(new_code) - 1;
                PUSH_R((int32_t)forth_code_len(new_code) - 1);
            } else if (inst->opcode == OP_NOP) {
                struct forth_inst *else_inst =
                    forth_code_get_elem(new_code, (uint32_t)POP_R());
                else_inst->pc = forth_code_len(new_code) - 1;
            }
        }
    }

    return true;
}

static bool inline_calls(struct forth_ctx *ctx)
{
    struct forth_code new_main;

    forth_code_init(&new_main);
    if (!inline_calls_code(ctx, &ctx->main->code, &new_main)) {
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

    if (!inline_calls(ctx))
        return false;

    if (!check_stack_effects(ctx, ctx->main))
        return false;

    return true;
}

#define BUILTIN_DETAIL(name_, id_, struct_id_, d_pushes_, d_pops_, r_pushes_,  \
                       r_pops_)                                                \
    static void id_(struct forth_ctx *, struct forth_vars *);                  \
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
    static void id_(struct forth_ctx *ctx, struct forth_vars *vars)

#define BUILTIN_COMPILER_DETAIL(name_, id_, struct_id_)                        \
    static const char *id_(struct forth_ctx *, const char *);                  \
    static const struct forth_builtin __attribute__((used))                    \
    __attribute__((section(LWAN_SECTION_NAME(forth_compiler_builtin))))        \
    __attribute__((aligned(8))) struct_id_ = {                                 \
        .name = name_,                                                         \
        .name_len = sizeof(name_) - 1,                                         \
        .callback_compiler = id_,                                              \
    };                                                                         \
    static const char *id_(struct forth_ctx *ctx, const char *code)

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
    if (ctx->r_stack.pos) {
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
    PUSH_R((int32_t)forth_code_len(&ctx->defining_word->code));

    emit_jump_if(ctx);

    return code;
}

static const char *
builtin_else_then(struct forth_ctx *ctx, const char *code, bool is_then)
{
    double v = POP_R();
    if (UNLIKELY(isnan(v))) {
        lwan_status_error("Unbalanced if/else/then");
        return NULL;
    }

    struct forth_inst *inst =
        forth_code_get_elem(&ctx->defining_word->code, (size_t)(int32_t)v);

    inst->pc = forth_code_len(&ctx->defining_word->code);

    if (is_then) {
        emit_nop(ctx);
    } else {
        PUSH_R((int32_t)inst->pc);
        emit_jump(ctx);
    }

    return code;
}

BUILTIN_COMPILER("else") { return builtin_else_then(ctx, code, false); }

BUILTIN_COMPILER("then") { return builtin_else_then(ctx, code, true); }

BUILTIN("x", 1, 0) { PUSH_D(vars->x); }
BUILTIN("y", 1, 0) { PUSH_D(vars->y); }
BUILTIN("t", 1, 0) { PUSH_D(vars->t); }
BUILTIN("dt", 1, 0) { PUSH_D(vars->dt); }

BUILTIN("mx", 1, 0)
{
    /* stub */
    PUSH_D(0.0);
}

BUILTIN("my", 1, 0)
{
    /* stub */
    PUSH_D(0.0);
}

BUILTIN("button", 1, 1)
{
    /* stub */
    DROP_D();
    PUSH_D(0.0);
}

BUILTIN("buttons", 1, 0)
{
    /* stub */
    PUSH_D(0.0);
}

BUILTIN("audio", 0, 1)
{
    /* stub */
    DROP_D();
}

BUILTIN("sample", 3, 2)
{
    /* stub */
    DROP_D();
    DROP_D();
    PUSH_D(0);
    PUSH_D(0);
    PUSH_D(0);
}

BUILTIN("bwsample", 1, 2)
{
    /* stub */
    DROP_D();
    DROP_D();
    PUSH_D(0);
}

BUILTIN_R("push", 0, 1, 1, 0) { PUSH_R(POP_D()); }

BUILTIN_R("pop", 1, 0, 0, 1) { PUSH_D(POP_R()); }

BUILTIN_R(">r", 0, 1, 1, 0) { PUSH_R(POP_D()); }

BUILTIN_R("r>", 1, 0, 0, 1) { PUSH_D(POP_R()); }

BUILTIN_R("r@", 1, 0, 1, 1)
{
    double v = POP_R();
    PUSH_R(v);
    PUSH_D(v);
}

BUILTIN("@", 1, 1)
{
    uint32_t slot = (uint32_t)POP_D();
    PUSH_D(ctx->memory[slot % (uint32_t)N_ELEMENTS(ctx->memory)]);
}

BUILTIN("!", 0, 2)
{
    double v = POP_D();
    uint32_t slot = (uint32_t)POP_D();
    ctx->memory[slot % (uint32_t)N_ELEMENTS(ctx->memory)] = v;
}

BUILTIN("dup", 2, 1)
{
    double v = POP_D();
    PUSH_D(v);
    PUSH_D(v);
}

BUILTIN("over", 3, 2)
{
    double v1 = POP_D();
    double v2 = POP_D();
    PUSH_D(v2);
    PUSH_D(v1);
    PUSH_D(v2);
}

BUILTIN("2dup", 4, 2)
{
    double v1 = POP_D();
    double v2 = POP_D();
    PUSH_D(v2);
    PUSH_D(v1);
    PUSH_D(v2);
    PUSH_D(v1);
}

BUILTIN("z+", 2, 4)
{
    double v1 = POP_D();
    double v2 = POP_D();
    double v3 = POP_D();
    double v4 = POP_D();
    PUSH_D(v2 + v4);
    PUSH_D(v1 + v3);
}

BUILTIN("z*", 2, 4)
{
    double v1 = POP_D();
    double v2 = POP_D();
    double v3 = POP_D();
    double v4 = POP_D();
    PUSH_D(v4 * v2 - v3 * v1);
    PUSH_D(v4 * v1 + v3 * v2);
}

BUILTIN("drop", 0, 1) { DROP_D(); }

BUILTIN("swap", 2, 2)
{
    double v1 = POP_D();
    double v2 = POP_D();
    PUSH_D(v1);
    PUSH_D(v2);
}

BUILTIN("rot", 3, 3)
{
    double v1 = POP_D();
    double v2 = POP_D();
    double v3 = POP_D();
    PUSH_D(v2);
    PUSH_D(v1);
    PUSH_D(v3);
}

BUILTIN("-rot", 3, 3)
{
    double v1 = POP_D();
    double v2 = POP_D();
    double v3 = POP_D();
    PUSH_D(v1);
    PUSH_D(v3);
    PUSH_D(v2);
}

BUILTIN("=", 1, 2)
{
    double v1 = POP_D();
    double v2 = POP_D();
    PUSH_D(v1 == v2 ? 1.0 : 0.0);
}

BUILTIN("<>", 1, 2)
{
    double v1 = POP_D();
    double v2 = POP_D();
    PUSH_D(v1 != v2 ? 1.0 : 0.0);
}

BUILTIN(">", 1, 2)
{
    double v1 = POP_D();
    double v2 = POP_D();
    PUSH_D(v1 > v2 ? 1.0 : 0.0);
}

BUILTIN("<", 1, 2)
{
    double v1 = POP_D();
    double v2 = POP_D();
    PUSH_D(v1 < v2 ? 1.0 : 0.0);
}

BUILTIN(">=", 1, 2)
{
    double v1 = POP_D();
    double v2 = POP_D();
    PUSH_D(v1 >= v2 ? 1.0 : 0.0);
}

BUILTIN("<=", 1, 2)
{
    double v1 = POP_D();
    double v2 = POP_D();
    PUSH_D(v1 <= v2 ? 1.0 : 0.0);
}

BUILTIN("+", 1, 2) { PUSH_D(POP_D() + POP_D()); }

BUILTIN("*", 1, 2) { PUSH_D(POP_D() * POP_D()); }

BUILTIN("-", 1, 2)
{
    double v = POP_D();
    PUSH_D(POP_D() - v);
}

BUILTIN("/", 1, 2)
{
    double v = POP_D();
    if (v == 0.0) {
        DROP_D();
        PUSH_D(INFINITY);
    } else {
        PUSH_D(POP_D() / v);
    }
}

BUILTIN("mod", 1, 2)
{
    double v = POP_D();
    PUSH_D(fmod(POP_D(), v));
}

BUILTIN("pow", 1, 2)
{
    double v = POP_D();
    PUSH_D(pow(fabs(POP_D()), v));
}

BUILTIN("**", 1, 2)
{
    double v = POP_D();
    PUSH_D(pow(fabs(POP_D()), v));
}

BUILTIN("atan2", 1, 2)
{
    double v = POP_D();
    PUSH_D(atan2(POP_D(), v));
}

BUILTIN("and", 1, 2)
{
    double v = POP_D();
    PUSH_D((POP_D() != 0.0 && v != 0.0) ? 1.0 : 0.0);
}

BUILTIN("or", 1, 2)
{
    double v = POP_D();
    PUSH_D((POP_D() != 0.0 || v != 0.0) ? 1.0 : 0.0);
}

BUILTIN("not", 1, 1) { PUSH_D(POP_D() != 0.0 ? 0.0 : 1.0); }

BUILTIN("min", 1, 2)
{
    double v1 = POP_D();
    double v2 = POP_D();
    PUSH_D(v1 > v2 ? v2 : v1);
}

BUILTIN("max", 1, 2)
{
    double v1 = POP_D();
    double v2 = POP_D();
    PUSH_D(v1 > v2 ? v1 : v2);
}

BUILTIN("negate", 1, 1) { PUSH_D(-POP_D()); }

BUILTIN("sin", 1, 1) { PUSH_D(sin(POP_D())); }

BUILTIN("cos", 1, 1) { PUSH_D(cos(POP_D())); }

BUILTIN("tan", 1, 1) { PUSH_D(tan(POP_D())); }

BUILTIN("log", 1, 1) { PUSH_D(log(fabs(POP_D()))); }

BUILTIN("exp", 1, 1) { PUSH_D(log(POP_D())); }

BUILTIN("sqrt", 1, 1) { PUSH_D(sqrt(fabs(POP_D()))); }

BUILTIN("floor", 1, 1) { PUSH_D(floor(POP_D())); }

BUILTIN("ceil", 1, 1) { PUSH_D(ceil(POP_D())); }

BUILTIN("abs", 1, 1) { PUSH_D(fabs(POP_D())); }

BUILTIN("pi", 1, 0) { PUSH_D(M_PI); }

BUILTIN("random", 1, 0) { PUSH_D(drand48()); }

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

    ctx->r_stack.pos = 0;
    ctx->d_stack.pos = 0;

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

size_t forth_d_stack_len(const struct forth_ctx *ctx)
{
    return ctx->d_stack.pos;
}

double forth_d_stack_pop(struct forth_ctx *ctx)
{
    return POP_D();
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
    struct forth_ctx *ctx = forth_new();
    if (!ctx)
        return 1;

    if (!forth_parse_string(ctx,
                            ": nice 60 5 4 + + ; : juanita 400 10 5 5 + + + ; "
                            "x if nice  else juanita then 2 * 4 / 2 *")) {
        lwan_status_critical("could not parse forth program");
        forth_free(ctx);
        return 1;
    }

    struct forth_vars vars = {.x = 1, .y = 0};
    if (forth_run(ctx, &vars)) {
        lwan_status_debug("top of d-stack: %lf", POP_D());
    }

    forth_free(ctx);

    return 0;
}
#endif
