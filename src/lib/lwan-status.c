/*
 * lwan - simple web server
 * Copyright (c) 2013 Leandro A. F. Pereira <leandro@hardinfo.org>
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

#define _GNU_SOURCE
#include <errno.h>
#include <libgen.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "lwan-private.h"

enum lwan_status_type {
    STATUS_INFO = 0,
    STATUS_WARNING = 1,
    STATUS_ERROR = 2,
    STATUS_DEBUG = 3,
    STATUS_PERROR = 4,
    STATUS_NONE = 5,
    /* [6,7] are unused so that CRITICAL can be ORed with previous items */
    STATUS_CRITICAL = 8,
};

static volatile bool quiet = false;
static bool use_colors;

static bool can_use_colors(void);

void lwan_status_init(struct lwan *l)
{
#ifdef NDEBUG
    quiet = l->config.quiet;
#else
    quiet = false;
    (void)l;
#endif
    use_colors = can_use_colors();
}

void lwan_status_shutdown(struct lwan *l __attribute__((unused))) {}

static bool can_use_colors(void)
{
    const char *term;

    if (!isatty(fileno(stdout)))
        return false;

    term = secure_getenv("TERM");
    if (term && streq(term, "dumb"))
        return false;

    return true;
}

static int status_index(enum lwan_status_type type)
{
    return use_colors ? (int)type : STATUS_NONE;
}

#define V(c) { .value = c, .len = sizeof(c) - 1 }
static const struct lwan_value start_colors[] = {
    [STATUS_INFO] = V("\033[36m"),       [STATUS_WARNING] = V("\033[33m"),
    [STATUS_DEBUG] = V("\033[37m"),      [STATUS_PERROR] = V("\033[35m"),
    [STATUS_CRITICAL] = V("\033[31;1m"), [STATUS_NONE] = V(""),
};

static inline struct lwan_value start_color(enum lwan_status_type type)
{
    return start_colors[status_index(type)];
}

static inline struct lwan_value end_color(void)
{
    return use_colors ? (struct lwan_value)V("\033[0m\n")
                      : (struct lwan_value)V("\n");
}
#undef V

static inline char *strerror_thunk_r(int error_number, char *buffer, size_t len)
{
#ifdef __GLIBC__
    return strerror_r(error_number, buffer, len);
#else
    if (!strerror_r(error_number, buffer, len))
        return buffer;
    return "Unknown";
#endif
}

#ifndef NDEBUG
static long gettid_cached(void)
{
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    /* Workaround for:
     * https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=15216 */
    return gettid();
#else
    static __thread long tid;

    if (!tid)
        tid = gettid();

    return tid;
#endif
}
#endif

static void
#ifdef NDEBUG
status_out(enum lwan_status_type type, const char *fmt, va_list values)
#else
status_out(const char *file,
           const int line,
           const char *func,
           enum lwan_status_type type,
           const char *fmt,
           va_list values)
#endif
{
    struct lwan_value start = start_color(type);
    struct lwan_value end = end_color();
    int saved_errno = errno;

    flockfile(stdout);

#ifndef NDEBUG
    char *base_name = basename(strdupa(file));
    if (use_colors) {
        printf("\033[32;1m%ld\033[0m", gettid_cached());
        printf(" \033[3m%s:%d\033[0m", base_name, line);
        printf(" \033[33m%s()\033[0m ", func);
    } else {
        printf("%ld %s:%d %s() ", gettid_cached(), base_name, line, func);
    }
#endif

    fwrite_unlocked(start.value, start.len, 1, stdout);
    vprintf(fmt, values);

    if (type & STATUS_PERROR) {
        char errbuf[64];
        char *errmsg =
            strerror_thunk_r(saved_errno, errbuf, sizeof(errbuf) - 1);

        printf(": %s (error number %d)", errmsg, saved_errno);
    }

    fwrite_unlocked(end.value, end.len, 1, stdout);

    funlockfile(stdout);

    errno = saved_errno;
}

#ifdef NDEBUG
#define IMPLEMENT_FUNCTION(fn_name_, type_)                                    \
    void lwan_status_##fn_name_(const char *fmt, ...)                          \
    {                                                                          \
        if (!quiet) {                                                          \
            va_list values;                                                    \
            va_start(values, fmt);                                             \
            status_out(type_, fmt, values);                                    \
            va_end(values);                                                    \
        }                                                                      \
        if ((type_)&STATUS_CRITICAL)                                           \
            exit(1);                                                           \
    }
#else
#define IMPLEMENT_FUNCTION(fn_name_, type_)                                    \
    void lwan_status_##fn_name_##_debug(const char *file, const int line,      \
                                        const char *func, const char *fmt,     \
                                        ...)                                   \
    {                                                                          \
        if (!quiet) {                                                          \
            va_list values;                                                    \
            va_start(values, fmt);                                             \
            status_out(file, line, func, type_, fmt, values);                  \
            va_end(values);                                                    \
        }                                                                      \
        if ((type_)&STATUS_CRITICAL)                                           \
            abort();                                                           \
    }

IMPLEMENT_FUNCTION(debug, STATUS_DEBUG)
#endif

IMPLEMENT_FUNCTION(info, STATUS_INFO)
IMPLEMENT_FUNCTION(warning, STATUS_WARNING)
IMPLEMENT_FUNCTION(error, STATUS_ERROR)
IMPLEMENT_FUNCTION(perror, STATUS_PERROR)

IMPLEMENT_FUNCTION(critical, STATUS_CRITICAL)
IMPLEMENT_FUNCTION(critical_perror, STATUS_CRITICAL | STATUS_PERROR)

#undef IMPLEMENT_FUNCTION
