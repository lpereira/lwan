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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
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

enum flags {
    IS_INSIDE_COMMENT = 1 << 0,
    IS_INSIDE_WORD_DEF = 1 << 1,
};

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
        bool (*callback)(struct forth_ctx *ctx, struct forth_vars *vars);
        size_t pc;
    };
    enum forth_opcode opcode;
};

DEFINE_ARRAY_TYPE(forth_code, struct forth_inst)

struct forth_word {
    union {
        bool (*callback)(struct forth_ctx *ctx, struct forth_vars *vars);
        struct forth_code code;
    };
    bool is_builtin;
    bool is_compiler;
    char name[];
};

struct forth_ctx {
    struct forth_word *defining_word;
    struct forth_word *main;

    struct hash *words;

    struct {
        double values[256];
        size_t pos;
    } r_stack, d_stack;

    double memory[64];

    enum flags flags;
};

struct forth_vars {
    double x, y;
    int t, dt;
};

#define PUSH_D(value_)                                                         \
    ({                                                                         \
        if (UNLIKELY(ctx->d_stack.pos >= N_ELEMENTS(ctx->d_stack.values)))     \
            return false;                                                      \
        ctx->d_stack.values[ctx->d_stack.pos++] = (value_);                    \
    })
#define POP_D(value_)                                                          \
    ({                                                                         \
        double v;                                                              \
        if (LIKELY(ctx->d_stack.pos > 0)) {                                    \
            v = ctx->d_stack.values[--ctx->d_stack.pos];                       \
        } else {                                                               \
            v = NAN;                                                           \
        }                                                                      \
        v;                                                                     \
    })
#define PUSH_R(value_)                                                         \
    ({                                                                         \
        if (UNLIKELY(ctx->r_stack.pos >= N_ELEMENTS(ctx->r_stack.values)))     \
            return false;                                                      \
        ctx->r_stack.values[ctx->r_stack.pos++] = (value_);                    \
    })
#define POP_R(value_)                                                          \
    ({                                                                         \
        double v;                                                              \
        if (LIKELY(ctx->r_stack.pos > 0)) {                                    \
            v = ctx->r_stack.values[--ctx->r_stack.pos];                       \
        } else {                                                               \
            v = NAN;                                                           \
        }                                                                      \
        v;                                                                     \
    })
#define LOAD(addr_)                                                            \
    ({                                                                         \
        size_t v = (size_t)(int32_t)(addr_);                                   \
        if (v > N_ELEMENTS(ctx->memory))                                       \
            return false;                                                      \
        ctx->memory[v];                                                        \
    })
#define STORE(addr_, value_)                                                   \
    ({                                                                         \
        size_t v = (size_t)(int32_t)(addr_);                                   \
        if (v > N_ELEMENTS(ctx->memory))                                       \
            return false;                                                      \
        ctx->memory[v] = (value_);                                             \
    })

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
                      struct forth_vars *vars,
                      int recursion_limit)
{
    const struct forth_inst *inst;

    if (recursion_limit == 0) {
        lwan_status_error("recursion limit reached");
        return false;
    }

#if DUMP_CODE
    dump_code(code);
#endif

    LWAN_ARRAY_FOREACH (code, inst) {
        switch (inst->opcode) {
        case OP_EVAL_CODE:
            if (UNLIKELY(!eval_code(ctx, inst->code, vars, recursion_limit - 1)))
                return false;
            break;
        case OP_CALL_BUILTIN:
            if (UNLIKELY(!inst->callback(ctx, vars)))
                return false;
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
    return eval_code(ctx, &ctx->main->code, vars, 100);
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
    struct forth_inst *inst = new_inst(ctx);
    if (UNLIKELY(!inst))
        return false;

    if (word->is_builtin) {
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

static const char* parse_single_line_comment(struct forth_ctx *ctx,
                                             const char *code)
{
    while (*code && *code != '\n')
        code++;
    return code;
}

static const char *parse_begin_parens_comment(struct forth_ctx *ctx,
                                              const char *code)
{
    if (UNLIKELY(ctx->flags & IS_INSIDE_COMMENT))
        return NULL;

    ctx->flags |= IS_INSIDE_COMMENT;
    return code;
}

static const char *parse_begin_word_def(struct forth_ctx *ctx, const char *code)
{
    if (UNLIKELY(ctx->flags & IS_INSIDE_WORD_DEF))
        return NULL;

    ctx->flags |= IS_INSIDE_WORD_DEF;
    ctx->defining_word = NULL;
    return code;
}

static const char *parse_end_word_def(struct forth_ctx *ctx, const char *code)
{
    if (UNLIKELY(!(ctx->flags & IS_INSIDE_WORD_DEF)))
        return NULL;

    ctx->flags &= ~IS_INSIDE_WORD_DEF;

    if (UNLIKELY(!ctx->defining_word))
        return NULL;

    ctx->defining_word = ctx->main;
    return code;
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
                                   bool (*callback)(struct forth_ctx *,
                                                    struct forth_vars *),
                                   bool compiler)
{
    struct forth_word *word = malloc(sizeof(*word) + len + 1);
    if (UNLIKELY(!word))
        return NULL;

    if (callback) {
        word->is_builtin = true;
        word->callback = callback;
    } else {
        word->is_builtin = false;
        forth_code_init(&word->code);
    }

    word->is_compiler = compiler;

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

static bool is_redefining_word(const struct forth_ctx *ctx,
                               const char *word,
                               const size_t word_len)
{
    if (UNLIKELY(!ctx->defining_word)) {
        lwan_status_error("Can't redefine word \"%.*s\"", (int)word_len,
                          word);
        return true;
    }

    return false;
}

static const char *found_word(struct forth_ctx *ctx,
                              const char *code,
                              const char *word,
                              size_t word_len)
{
    if (ctx->flags & IS_INSIDE_COMMENT) {
        if (word_len == 1 && *word == ')')
            ctx->flags &= ~IS_INSIDE_COMMENT;
        return code;
    }

    if (word_len == 1) {
        if (UNLIKELY(is_redefining_word(ctx, word, word_len)))
            return NULL;

        switch (*word) {
        case '\\':
            return parse_single_line_comment(ctx, code);
        case ':':
            return parse_begin_word_def(ctx, code);
        case ';':
            if (ctx->r_stack.pos) {
                lwan_status_error("Unmatched if/then/else");
                return false;
            }

            return parse_end_word_def(ctx, code);
        case '(':
            return parse_begin_parens_comment(ctx, code);
        case ')':
            lwan_status_error("Comment closed without opening");
            return NULL; /* handled above; can't reuse word for non-comment
                            purposes */
        }
    }

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
            bool success = w->is_compiler ? w->callback(ctx, NULL) : emit_word_call(ctx, w);
            return success ? code : NULL;
        }

        lwan_status_error("Word \"%.*s\" not defined yet, can't call",
                          (int)word_len, word);
        return NULL; /* word not defined yet */
    }

    if (LIKELY(w != NULL)) { /* redefining word not supported */
        lwan_status_error("Can't redefine word \"%.*s\"", (int)word_len, word);
        return NULL;
    }

    w = new_word(ctx, word, word_len, NULL, false);
    if (UNLIKELY(!w)) { /* can't create new word */
        lwan_status_error("Can't create new word");
        return NULL;
    }

    ctx->defining_word = w;
    return code;
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

        assert(code > word_ptr);

        code = found_word(ctx, code, word_ptr, (size_t)(code - word_ptr));
        if (!code)
            return false;

        if (*code == '\0')
            break;

        code++;
    }

    return true;
}

struct forth_builtin {
    const char *name;
    size_t name_len;
    bool (*callback)(struct forth_ctx *, struct forth_vars *vars);
    bool compiler;

    void *padding; /* FIXME LWAN_SECTION_FOREACH needs this */
};

#define BUILTIN_DETAIL(name_, id_, struct_id_, compiler_)                      \
    static bool id_(struct forth_ctx *, struct forth_vars *);                  \
    static const struct forth_builtin __attribute__((                          \
        used, section(LWAN_SECTION_NAME(forth_builtin)))) struct_id_ = {       \
        .name = name_,                                                         \
        .name_len = sizeof(name_) - 1,                                         \
        .callback = id_,                                                       \
        .compiler = compiler_,                                                 \
    };                                                                         \
    static bool id_(struct forth_ctx *ctx, struct forth_vars *vars)

#define BUILTIN(name_) BUILTIN_DETAIL(name_, LWAN_TMP_ID, LWAN_TMP_ID, false)
#define BUILTIN_COMPILER(name_) BUILTIN_DETAIL(name_, LWAN_TMP_ID, LWAN_TMP_ID, true)

BUILTIN_COMPILER("if")
{
    if (UNLIKELY(is_redefining_word(ctx, "if", 4)))
        return false;

    PUSH_R((int32_t)forth_code_len(&ctx->defining_word->code));

    emit_jump_if(ctx);

    return true;
}

static bool builtin_else_then(struct forth_ctx *ctx, struct forth_vars *vars, bool is_then)
{
    if (UNLIKELY(is_redefining_word(ctx, is_then ? "then" : "else", 4)))
        return false;

    double v = POP_R();
    if (UNLIKELY(v != v)) {
        lwan_status_error("Unbalanced if/else/then");
        return false;
    }

    struct forth_inst *inst =
        forth_code_get_elem(&ctx->defining_word->code, (int32_t)v);

    inst->pc = forth_code_len(&ctx->defining_word->code);

    if (is_then) {
        emit_nop(ctx);
    } else {
        PUSH_R((int32_t)inst->pc);
        emit_jump(ctx);
    }

    return true;
}

BUILTIN_COMPILER("else") { return builtin_else_then(ctx, vars, false); }

BUILTIN_COMPILER("then") { return builtin_else_then(ctx, vars, true); }

BUILTIN("x")
{
    PUSH_D(vars->x);
    return true;
}
BUILTIN("y")
{
    PUSH_D(vars->y);
    return true;
}
BUILTIN("t")
{
    PUSH_D(vars->t);
    return true;
}
BUILTIN("dt")
{
    PUSH_D(vars->dt);
    return true;
}

BUILTIN("mx")
{
    /* stub */
    PUSH_D(0.0);
    return true;
}

BUILTIN("my")
{
    /* stub */
    PUSH_D(0.0);
    return true;
}

BUILTIN("button")
{
    /* stub */
    POP_D();
    PUSH_D(0.0);
    return true;
}

BUILTIN("buttons")
{
    /* stub */
    PUSH_D(0.0);
    return true;
}

BUILTIN("audio")
{
    /* stub */
    POP_D();
    return true;
}

BUILTIN("sample")
{
    /* stub */
    POP_D();
    POP_D();
    PUSH_D(0);
    PUSH_D(0);
    PUSH_D(0);
    return true;
}

BUILTIN("bwsample")
{
    /* stub */
    POP_D();
    POP_D();
    PUSH_D(0);
    return true;
}

BUILTIN("push")
{
    PUSH_R(POP_D());
    return true;
}
BUILTIN("pop")
{
    PUSH_D(POP_R());
    return true;
}

BUILTIN(">r")
{
    PUSH_R(POP_D());
    return true;
}

BUILTIN("r>")
{
    PUSH_D(POP_R());
    return true;
}

BUILTIN("r@")
{
    double v = POP_R();
    PUSH_R(v);
    PUSH_D(v);
    return true;
}

BUILTIN("@")
{
    double slot = POP_D();
    PUSH_D(LOAD(slot));
    return true;
}

BUILTIN("!")
{
    double v1 = POP_D();
    double v2 = POP_D();
    STORE(v2, v1);
    return true;
}

BUILTIN("dup")
{
    double v = POP_D();
    PUSH_D(v);
    PUSH_D(v);
    return true;
}

BUILTIN("over")
{
    double v1 = POP_D();
    double v2 = POP_D();
    PUSH_D(v2);
    PUSH_D(v1);
    PUSH_D(v2);
    return true;
}

BUILTIN("2dup")
{
    double v1 = POP_D();
    double v2 = POP_D();
    PUSH_D(v2);
    PUSH_D(v1);
    PUSH_D(v2);
    PUSH_D(v1);
    return true;
}

BUILTIN("z+")
{
    double v1 = POP_D();
    double v2 = POP_D();
    double v3 = POP_D();
    double v4 = POP_D();
    PUSH_D(v2 + v4);
    PUSH_D(v1 + v3);
    return true;
}

BUILTIN("z*")
{
    double v1 = POP_D();
    double v2 = POP_D();
    double v3 = POP_D();
    double v4 = POP_D();
    PUSH_D(v4 * v2 - v3 * v1);
    PUSH_D(v4 * v1 + v3 * v2);
    return true;
}

BUILTIN("drop")
{
    POP_D();
    return true;
}

BUILTIN("swap")
{
    double v1 = POP_D();
    double v2 = POP_D();
    PUSH_D(v1);
    PUSH_D(v2);
    return true;
}

BUILTIN("rot")
{
    double v1 = POP_D();
    double v2 = POP_D();
    double v3 = POP_D();
    PUSH_D(v2);
    PUSH_D(v1);
    PUSH_D(v3);
    return true;
}

BUILTIN("-rot")
{
    double v1 = POP_D();
    double v2 = POP_D();
    double v3 = POP_D();
    PUSH_D(v1);
    PUSH_D(v3);
    PUSH_D(v2);
    return true;
}

BUILTIN("=")
{
    double v1 = POP_D();
    double v2 = POP_D();
    PUSH_D(v1 == v2 ? 1.0 : 0.0);
    return true;
}

BUILTIN("<>")
{
    double v1 = POP_D();
    double v2 = POP_D();
    PUSH_D(v1 != v2 ? 1.0 : 0.0);
    return true;
}

BUILTIN(">")
{
    double v1 = POP_D();
    double v2 = POP_D();
    PUSH_D(v1 > v2 ? 1.0 : 0.0);
    return true;
}

BUILTIN("<")
{
    double v1 = POP_D();
    double v2 = POP_D();
    PUSH_D(v1 < v2 ? 1.0 : 0.0);
    return true;
}

BUILTIN(">=")
{
    double v1 = POP_D();
    double v2 = POP_D();
    PUSH_D(v1 >= v2 ? 1.0 : 0.0);
    return true;
}

BUILTIN("<=")
{
    double v1 = POP_D();
    double v2 = POP_D();
    PUSH_D(v1 <= v2 ? 1.0 : 0.0);
    return true;
}

BUILTIN("+")
{
    PUSH_D(POP_D() + POP_D());
    return true;
}

BUILTIN("*")
{
    PUSH_D(POP_D() * POP_D());
    return true;
}

BUILTIN("-")
{
    double v = POP_D();
    PUSH_D(POP_D() - v);
    return true;
}

BUILTIN("/")
{
    double v = POP_D();
    if (v == 0.0)
        PUSH_D(INFINITY);
    else
        PUSH_D(POP_D() / v);

    return true;
}

BUILTIN("mod")
{
    double v = POP_D();
    PUSH_D(fmod(POP_D(), v));
    return true;
}

BUILTIN("pow")
{
    double v = POP_D();
    PUSH_D(pow(fabs(POP_D()), v));
    return true;
}

BUILTIN("**")
{
    double v = POP_D();
    PUSH_D(pow(fabs(POP_D()), v));
    return true;
}

BUILTIN("atan2")
{
    double v = POP_D();
    PUSH_D(atan2(POP_D(), v));
    return true;
}

BUILTIN("and")
{
    double v = POP_D();
    PUSH_D((POP_D() != 0.0 && v != 0.0) ? 1.0 : 0.0);
    return true;
}

BUILTIN("or")
{
    double v = POP_D();
    PUSH_D((POP_D() != 0.0 || v != 0.0) ? 1.0 : 0.0);
    return true;
}

BUILTIN("not")
{
    PUSH_D(POP_D() != 0.0 ? 0.0 : 1.0);
    return true;
}

BUILTIN("min")
{
    double v1 = POP_D();
    double v2 = POP_D();
    PUSH_D(v1 > v2 ? v2 : v1);
    return true;
}

BUILTIN("max")
{
    double v1 = POP_D();
    double v2 = POP_D();
    PUSH_D(v1 > v2 ? v1 : v2);
    return true;
}

BUILTIN("negate")
{
    PUSH_D(-POP_D());
    return true;
}

BUILTIN("sin")
{
    PUSH_D(sin(POP_D()));
    return true;
}

BUILTIN("cos")
{
    PUSH_D(cos(POP_D()));
    return true;
}

BUILTIN("tan")
{
    PUSH_D(tan(POP_D()));
    return true;
}

BUILTIN("log")
{
    PUSH_D(log(fabs(POP_D())));
    return true;
}

BUILTIN("exp")
{
    PUSH_D(log(POP_D()));
    return true;
}

BUILTIN("sqrt")
{
    PUSH_D(sqrt(fabs(POP_D())));
    return true;
}

BUILTIN("floor")
{
    PUSH_D(floor(POP_D()));
    return true;
}

BUILTIN("ceil")
{
    PUSH_D(ceil(POP_D()));
    return true;
}

BUILTIN("abs")
{
    PUSH_D(fabs(POP_D()));
    return true;
}

BUILTIN("pi")
{
    PUSH_D(M_PI);
    return true;
}

BUILTIN("random")
{
    PUSH_D(drand48());
    return true;
}

__attribute__((no_sanitize_address)) static void
register_builtins(struct forth_ctx *ctx)
{
    const struct forth_builtin *iter;

    LWAN_SECTION_FOREACH(forth_builtin, iter) {
        if (!new_word(ctx, iter->name, iter->name_len, iter->callback, iter->compiler)) {
            lwan_status_critical("could not register forth word: %s",
                                 iter->name);
        }
    }
}

static void word_free(void *ptr)
{
    struct forth_word *word = ptr;

    if (!word->is_builtin)
        forth_code_reset(&word->code);
    free(word);
}

struct forth_ctx *forth_new(void)
{
    struct forth_ctx *ctx = malloc(sizeof(*ctx));

    if (!ctx)
        return NULL;

    ctx->flags = 0;

    ctx->words = hash_str_new(NULL, word_free);
    if (!ctx->words) {
        free(ctx);
        return NULL;
    }

    struct forth_word *word = new_word(ctx, " ", 1, NULL, false);
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

    if (!forth_parse_string(ctx, ": nice 60 5 4 + + ; : juanita 400 10 5 5 + + + ; x if nice  else juanita then 2 * 4 / 2 *")) {
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
