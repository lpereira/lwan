/*
 * lwan - web server
 * Copyright (c) 2013 L. A. F. Pereira <l@tia.mat.br>
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

#pragma once

#ifdef NDEBUG
#define DECLARE_LOG_PROTO(type_, ...)                                          \
    void lwan_log_##type_(const char *fmt, ...)                                \
        __attribute__((format(printf, 1, 2)))                                  \
        __attribute__((noinline, cold)) __VA_ARGS__;

#define lwan_log_debug(fmt, ...)                                               \
    do {                                                                       \
    } while (0)
#else
#define DECLARE_LOG_PROTO(type_, ...)                                          \
    void lwan_log_##type_##_debug(const char *file, const int line,            \
                                  const char *func, const char *fmt, ...)      \
        __attribute__((format(printf, 4, 5)))                                  \
        __attribute__((noinline, cold)) __VA_ARGS__;

#define lwan_log_info(fmt, ...)                                                \
    lwan_log_info_debug(__FILE__, __LINE__, __FUNCTION__, fmt, ##__VA_ARGS__)
#define lwan_log_warning(fmt, ...)                                             \
    lwan_log_warning_debug(__FILE__, __LINE__, __FUNCTION__, fmt, ##__VA_ARGS__)
#define lwan_log_error(fmt, ...)                                               \
    lwan_log_error_debug(__FILE__, __LINE__, __FUNCTION__, fmt, ##__VA_ARGS__)
#define lwan_log_perror(fmt, ...)                                              \
    lwan_log_perror_debug(__FILE__, __LINE__, __FUNCTION__, fmt, ##__VA_ARGS__)
#define lwan_log_critical(fmt, ...)                                            \
    lwan_log_critical_debug(__FILE__, __LINE__, __FUNCTION__, fmt,             \
                            ##__VA_ARGS__)
#define lwan_log_critical_perror(fmt, ...)                                     \
    lwan_log_critical_perror_debug(__FILE__, __LINE__, __FUNCTION__, fmt,      \
                                   ##__VA_ARGS__)
#define lwan_log_debug(fmt, ...)                                               \
    lwan_log_debug_debug(__FILE__, __LINE__, __FUNCTION__, fmt, ##__VA_ARGS__)

DECLARE_LOG_PROTO(debug)
#endif

DECLARE_LOG_PROTO(info)
DECLARE_LOG_PROTO(warning)
DECLARE_LOG_PROTO(error)
DECLARE_LOG_PROTO(perror)
DECLARE_LOG_PROTO(critical, __attribute__((noreturn)))
DECLARE_LOG_PROTO(critical_perror, __attribute__((noreturn)))
