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
#include <sys/uio.h>
#include <unistd.h>

#include "lwan-private.h"

enum lwan_status_type {
    STATUS_INFO = 1 << 0,
    STATUS_WARNING = 1 << 1,
    STATUS_ERROR = 1 << 2,
    STATUS_PERROR = 1 << 3,
    STATUS_CRITICAL = 1 << 4,
    STATUS_DEBUG = 1 << 5,
};

static volatile bool quiet = false;
static bool use_colors;
static pthread_spinlock_t spinlock;

static bool can_use_colors(void);

void lwan_status_init(struct lwan *l)
{
    pthread_spin_init(&spinlock, PTHREAD_PROCESS_PRIVATE);
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

static const char *get_color_start_for_type(enum lwan_status_type type,
                                            size_t *len_out)
{
    const char *retval;

    if (!use_colors)
        retval = "";
    else if (type & STATUS_INFO)
        retval = "\033[36m";
    else if (type & STATUS_WARNING)
        retval = "\033[33m";
    else if (type & STATUS_CRITICAL)
        retval = "\033[31;1m";
    else if (type & STATUS_DEBUG)
        retval = "\033[37m";
    else if (type & STATUS_PERROR)
        retval = "\033[35m";
    else
        retval = "\033[32m";

    *len_out = strlen(retval);

    return retval;
}

static const char *get_color_end_for_type(enum lwan_status_type type
                                          __attribute__((unused)),
                                          size_t *len_out)
{
    static const char *retval = "\033[0m";

    if (!use_colors) {
        *len_out = 0;
        return "";
    }

    *len_out = strlen(retval);
    return retval;
}

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

#define VEC_STR(s, l)                                                          \
    (struct iovec) { .iov_base = (void *)s, .iov_len = (size_t)(l) }
#define VEC_LITERAL(l) VEC_STR(l, sizeof(l) - 1)
#define VEC_PRINTF(fmt, ...)                                                   \
    ({                                                                         \
        const size_t len = (size_t)(out - buffer) + sizeof(buffer);            \
        int r = snprintf(out, len, fmt, __VA_ARGS__);                          \
        if (UNLIKELY(r < 0 || r >= (int)len))                                  \
            goto out;                                                          \
        struct iovec v = VEC_STR(out, r);                                      \
        out += r + 1;                                                          \
        v;                                                                     \
    })

static void
#ifdef NDEBUG
status_out_msg(enum lwan_status_type type, const char *msg, size_t msg_len)
#else
status_out_msg(const char *file,
               const int line,
               const char *func,
               enum lwan_status_type type,
               const char *msg,
               size_t msg_len)
#endif
{
    size_t start_len, end_len;
    const char *start_color = get_color_start_for_type(type, &start_len);
    const char *end_color = get_color_end_for_type(type, &end_len);
    char buffer[3 * 80 /* 3 * ${COLUMNS} */];
    int saved_errno = errno;
    struct iovec vec[16];
    char *out = buffer;
    int last_vec = 0;

#ifndef NDEBUG
    char *base_name = basename(strdupa(file));
    if (use_colors) {
        vec[last_vec++] = VEC_PRINTF("\033[32;1m%ld\033[0m", gettid());
        vec[last_vec++] = VEC_PRINTF(" \033[3m%s:%d\033[0m", base_name, line);
        vec[last_vec++] = VEC_PRINTF(" \033[33m%s()\033[0m ", func);
    } else {
        vec[last_vec++] = VEC_PRINTF("%ld: ", gettid());
        vec[last_vec++] = VEC_PRINTF("%s:%d ", base_name, line);
        vec[last_vec++] = VEC_PRINTF("%s() ", func);
    }
#endif

    vec[last_vec++] = VEC_STR(start_color, start_len);
    vec[last_vec++] = VEC_STR(msg, msg_len);

    if (type & STATUS_PERROR) {
        char errbuf[64];
        char *errmsg =
            strerror_thunk_r(saved_errno, errbuf, sizeof(errbuf) - 1);

        vec[last_vec++] =
            VEC_PRINTF(": %s (error number %d)", errmsg, saved_errno);
    }

    vec[last_vec++] = VEC_LITERAL(".");
    vec[last_vec++] = VEC_STR(end_color, end_len);
    vec[last_vec++] = VEC_LITERAL("\n");

out:
    if (LIKELY(!pthread_spin_lock(&spinlock))) {
        writev(fileno(stdout), vec, last_vec);
        pthread_spin_unlock(&spinlock);
    }

    errno = saved_errno;
}

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
    char output[2 * 80 /* 2 * ${COLUMNS} */];
    int len;

    len = vsnprintf(output, sizeof(output), fmt, values);
    if (len >= 0) {
#ifdef NDEBUG
        status_out_msg(type, output, (size_t)len);
#else
        status_out_msg(file, line, func, type, output, (size_t)len);
#endif
    }
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
