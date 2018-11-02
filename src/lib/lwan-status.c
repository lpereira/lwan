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
#include "lwan-vecbuf.h"

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

DEFINE_VECBUF_TYPE(status_vb, 16, 80 * 3)

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
    size_t start_len, end_len;
    const char *start_color = get_color_start_for_type(type, &start_len);
    const char *end_color = get_color_end_for_type(type, &end_len);
    struct status_vb vb;
    int saved_errno = errno;

    status_vb_init(&vb);

#ifndef NDEBUG
    char *base_name = basename(strdupa(file));
    if (use_colors) {
        if (status_vb_append_printf(&vb, "\033[32;1m%ld\033[0m", gettid()) < 0)
            goto out;
        if (status_vb_append_printf(&vb, " \033[3m%s:%d\033[0m", base_name,
                                    line) < 0)
            goto out;
        if (status_vb_append_printf(&vb, " \033[33m%s()\033[0m ", func) < 0)
            goto out;
    } else {
        if (status_vb_append_printf(&vb, "%ld: ", gettid()) < 0)
            goto out;
        if (status_vb_append_printf(&vb, "%s:%d ", base_name, line) < 0)
            goto out;
        if (status_vb_append_printf(&vb, "%s() ", func) < 0)
            goto out;
    }
#endif

    if (status_vb_append_str_len(&vb, start_color, start_len) < 0)
        goto out;
    if (status_vb_append_vprintf(&vb, fmt, values) < 0)
        goto out;

    if (type & STATUS_PERROR) {
        char errbuf[64];
        char *errmsg =
            strerror_thunk_r(saved_errno, errbuf, sizeof(errbuf) - 1);

        if (status_vb_append_printf(&vb, ": %s (error number %d)", errmsg,
                                    saved_errno) < 0)
            goto out;
    }

    if (status_vb_append_str_len(&vb, end_color, end_len) < 0)
        goto out;
    if (status_vb_append_str_len(&vb, "\n", 1) < 0)
        goto out;

out:
    if (LIKELY(!pthread_spin_lock(&spinlock))) {
        writev(fileno(stdout), vb.iovec, vb.n);
        pthread_spin_unlock(&spinlock);
    }

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
