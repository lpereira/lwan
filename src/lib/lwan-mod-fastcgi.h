/*
 * lwan - simple web server
 * Copyright (c) 2022 L. A. F. Pereira <l@tia.mat.br>
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

#if defined(__cplusplus)
extern "C" {
#endif

#include "lwan.h"

struct lwan_fastcgi_settings {
    const char *address;
    const char *script_path;
    const char *default_index;
};

LWAN_MODULE_FORWARD_DECL(fastcgi);

#define FASTCGI(socket_path_, script_path_, default_index_)                    \
    .module = LWAN_MODULE_REF(fastcgi),                                        \
    .args = ((struct lwan_fastcgi_settings[]){{                                \
        .socket_path = socket_path_,                                           \
        .script_path = script_path_,                                           \
        .default_index = default_index_,                                       \
    }}),                                                                       \
    .flags = (enum lwan_handler_flags)0

#if defined(__cplusplus)
}
#endif
