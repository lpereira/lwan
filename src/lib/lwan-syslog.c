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

#ifdef HAVE_SYSLOG

#include <syslog.h>

static int prioritylist[] = {
    [STATUS_CRITICAL + STATUS_PERROR] = LOG_CRIT,
    [STATUS_CRITICAL] = LOG_CRIT,
    [STATUS_ERROR] = LOG_ERR,
    [STATUS_WARNING] = LOG_WARNING,
    [STATUS_INFO] = LOG_INFO,
    [STATUS_DEBUG] = LOG_DEBUG,
};

static inline char *strerror_thunk_r(int error_number, char *buffer, size_t len)
{
#if defined(__GLIBC__) && defined(_GNU_SOURCE)
    return strerror_r(error_number, buffer, len);
#else /* XSI-compliant strerror_r() */
    if (!strerror_r(error_number, buffer, len))
        return buffer;
    return "Unknown";
#endif
}

#define APPEND(func, fmt, ...)                                                 \
    len = func(tmp + offs, (unsigned long)(log_len - offs), fmt, __VA_ARGS__); \
    if (len >= log_len - offs - 1) {                                           \
        log_len *= 2;                                                          \
        continue;                                                              \
    } else if (len < 0) {                                                      \
        return;                                                                \
    }                                                                          \
    offs += len;

void lwan_syslog_status_out(
#ifndef NDEBUG
    const char *file,
    const int line,
    const char *func,
    const long tid,
#endif
    enum lwan_status_type type,
    int saved_errno,
    const char *fmt,
    va_list values)
{
    static volatile int log_len = 256;
    char *tmp = NULL;
    char *errmsg = NULL;

#ifndef NDEBUG
    char *base_name = basename(strdupa(file));
#endif

    if (UNLIKELY(type & STATUS_PERROR)) {
        char errbuf[64];
        errmsg = strerror_thunk_r(saved_errno, errbuf, sizeof(errbuf) - 1);
    }

    do {
        va_list copied_values;
        va_copy(copied_values, values);

        tmp = alloca((size_t)log_len);

        int len = 0;
        int offs = 0;

#ifndef NDEBUG
        APPEND(snprintf, "%ld %s:%d %s() ", tid, base_name, line, func)
#endif

        APPEND(vsnprintf, fmt, copied_values)

        if (errmsg) {
            APPEND(snprintf, ": %s (error number %d)", errmsg, saved_errno)
        }
    } while (0);

    syslog(prioritylist[type], "%s", tmp);
}

#undef APPEND

__attribute__((constructor))
__attribute__((no_sanitize_address))
static void register_lwan_to_syslog(void)
{
    openlog("lwan", LOG_NDELAY | LOG_PID | LOG_CONS, LOG_USER);
}

#endif
