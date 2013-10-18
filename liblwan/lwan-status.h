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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifndef _LWAN_STATUS_H_
#define _LWAN_STATUS_H_

#ifdef NDEBUG
#define DECLARE_STATUS_PROTO(type_)                                  \
  void lwan_status_##type_(const char *fmt, ...)                     \
                              __attribute__((format(printf, 1, 2)));

#define lwan_status_debug(fmt, ...)
#else
#define DECLARE_STATUS_PROTO(type_)                                  \
  void lwan_status_##type_##_debug(const char *file, const int line, \
            const char *func, const char *fmt, ...)                  \
                              __attribute__((format(printf, 4, 5)));

#define lwan_status_info(fmt, ...) \
  lwan_status_info_debug(__FILE__, __LINE__, __FUNCTION__, fmt, ##__VA_ARGS__)
#define lwan_status_warning(fmt, ...) \
  lwan_status_warning_debug(__FILE__, __LINE__, __FUNCTION__, fmt, ##__VA_ARGS__)
#define lwan_status_error(fmt, ...) \
  lwan_status_error_debug(__FILE__, __LINE__, __FUNCTION__, fmt, ##__VA_ARGS__)
#define lwan_status_perror(fmt, ...) \
  lwan_status_perror_debug(__FILE__, __LINE__, __FUNCTION__, fmt, ##__VA_ARGS__)
#define lwan_status_critical(fmt, ...) \
  lwan_status_critical_debug(__FILE__, __LINE__, __FUNCTION__, fmt, ##__VA_ARGS__)
#define lwan_status_critical_perror(fmt, ...) \
  lwan_status_critical_perror_debug(__FILE__, __LINE__, __FUNCTION__, fmt, ##__VA_ARGS__)
#define lwan_status_debug(fmt, ...) \
  lwan_status_debug_debug(__FILE__, __LINE__, __FUNCTION__, fmt, ##__VA_ARGS__)

DECLARE_STATUS_PROTO(debug)
#endif

DECLARE_STATUS_PROTO(info)
DECLARE_STATUS_PROTO(warning)
DECLARE_STATUS_PROTO(error)
DECLARE_STATUS_PROTO(perror)
DECLARE_STATUS_PROTO(critical)
DECLARE_STATUS_PROTO(critical_perror)

#endif /* _LWAN_STATUS_H_ */
