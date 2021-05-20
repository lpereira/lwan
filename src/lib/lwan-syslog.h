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

#pragma once

#ifdef HAVE_SYSLOG

#include "lwan-status.h"

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
    va_list values);

#else
#define lwan_syslog_status_out(v, ...)
#endif
