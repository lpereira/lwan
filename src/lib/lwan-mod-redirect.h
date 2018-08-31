/*
 * lwan - simple web server
 * Copyright (c) 2014 Leandro A. F. Pereira <leandro@hardinfo.org>
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

#include "lwan.h"

struct lwan_redirect_settings {
    char *to;
    enum lwan_http_status code;
};

LWAN_MODULE_FORWARD_DECL(redirect)

#define REDIRECT_CODE(to_, code_)                                              \
    .module = LWAN_MODULE_REF(redirect),                                       \
    .args = ((struct lwan_redirect_settings[]) {{                              \
        .to = (to_),                                                           \
        .code = (code_),                                                       \
    }}),                                                                       \
    .flags = (enum lwan_handler_flags)0

#define REDIRECT(to_) REDIRECT_CODE((to_), HTTP_MOVED_PERMANENTLY)
