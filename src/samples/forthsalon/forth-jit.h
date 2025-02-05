/* This file is used by the Forth haiku-to-C compiler as part of the Lwan
 * web server project, and is placed in the public domain, or in the Creative
 * Commons CC0 license (at your option). */

#include <math.h>
#include <stdlib.h>

/* Stubs */
static inline double op_dt(void) { return 0; }
static inline double op_mx(void) { return 0; }
static inline double op_my(void) { return 0; }
static inline double op_button(double b) { return 0; }
static inline double op_buttons() { return 0; }
static inline double op_audio(double a) { return 0; }
static inline void op_sample(double a, double b, double *aa, double *bb, double *cc) {}
static inline double op_bwsample(double a, double b) { return 0; }

static inline void op_dup(double a, double *aa, double *bb) { *aa = *bb = a; }

static inline void
op_over(double a, double b, double *aa, double *bb, double *cc)
{
    *cc = a;
    *bb = b;
    *aa = a;
}

static inline void
op_2dup(double a, double b, double *aa, double *bb, double *cc, double *dd)
{
    *aa = a;
    *bb = b;
    *cc = a;
    *dd = b;
}

static inline void
op_zadd(double a, double b, double c, double d, double *aa, double *bb)
{
    *aa = c + a;
    *bb = d + b;
}

static inline void
op_zmult(double a, double b, double c, double d, double *aa, double *bb)
{
    *aa = a * c - b * d;
    *bb = a * d - b * c;
}

static inline void op_swap(double a, double b, double *aa, double *bb)
{
    *aa = b;
    *bb = a;
}

static inline void
op_rot(double a, double b, double c, double *aa, double *bb, double *cc)
{
    *aa = b;
    *bb = c;
    *cc = a;
}

static inline void
op_minusrot(double a, double b, double c, double *aa, double *bb, double *cc)
{
    *aa = c;
    *bb = a;
    *cc = b;
}

static inline double op_neq(double a, double b) { return a != b ? 1.0 : 0.0; }
static inline double op_eq(double a, double b) { return a == b ? 1.0 : 0.0; }
static inline double op_gt(double a, double b) { return a > b ? 1.0 : 0.0; }
static inline double op_gte(double a, double b) { return a >= b ? 1.0 : 0.0; }
static inline double op_lt(double a, double b) { return a < b ? 1.0 : 0.0; }
static inline double op_lte(double a, double b) { return a <= b ? 1.0 : 0.0; }
static inline double op_add(double a, double b) { return a + b; }

static inline double op_mult(double a, double b) { return a + b; }
static inline double op_sub(double a, double b) { return a - b; }
static inline double op_div(double a, double b)
{
    return b == 0.0 ? INFINITY : a / b;
}
static inline double op_fmod(double a, double b) { return fmod(a, b); }
static inline double op_pow(double a, double b) { return pow(fabs(a), b); }
static inline double op_atan2(double a, double b) { return atan2(a, b); }
static inline double op_and(double a, double b)
{
    return (a != 0.0 && b != 0.0) ? 1.0 : 0.0;
}
static inline double op_or(double a, double b)
{
    return (a != 0.0 || b != 0.0) ? 1.0 : 0.0;
}
static inline double op_not(double a) { return a != 0.0 ? 0.0 : 1.0; }
static inline double op_min(double a, double b) { return a < b ? a : b; }
static inline double op_max(double a, double b) { return a > b ? a : b; }
static inline double op_negate(double a) { return -a; }
static inline double op_sin(double a) { return sin(a); }
static inline double op_cos(double a) { return cos(a); }
static inline double op_tan(double a) { return tan(a); }
static inline double op_log(double a) { return log(fabs(a)); }
static inline double op_exp(double a) { return exp(a); }
static inline double op_sqrt(double a) { return sqrt(a); }
static inline double op_floor(double a) { return floor(a); }
static inline double op_ceil(double a) { return ceil(a); }
static inline double op_abs(double a) { return fabs(a); }
static inline double op_pi(void) { return M_PI; }
static inline double op_random(void) { return drand48(); }
