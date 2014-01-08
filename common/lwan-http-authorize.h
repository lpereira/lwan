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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifndef LWAN_HTTP_AUTHORIZE_H
#define LWAN_HTTP_AUTHORIZE_H

#include "lwan.h"

bool lwan_http_authorize_init(void);
void lwan_http_authorize_shutdown(void);

bool
lwan_http_authorize(lwan_request_t *request,
                    lwan_value_t *authorization,
                    const char *realm,
                    const char *password_file);

#endif /* LWAN_HTTP_AUTHORIZE_H */