/*
 * lwan - simple web server
 * Copyright (c) 2012 Leandro A. F. Pereira <leandro@hardinfo.org>
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

#ifndef __LWAN_SERVE_FILES_H__
#define __LWAN_SERVE_FILES_H__

#include "lwan.h"

struct lwan_serve_files_settings_t {
  char *root_path;
  char *index_html;
};

extern lwan_handler_t serve_files;

#define SERVE_FILES_SETTINGS(root_path_, index_html_) \
  .handler = &serve_files, \
  .args = ((struct lwan_serve_files_settings_t[]) {{ \
    .root_path = root_path_, \
    .index_html = index_html_ \
  }}), \
  .flags = 0

#define SERVE_FILES(root_path) \
  SERVE_FILES_SETTINGS(root_path, NULL)

#endif /* __LWAN_SERVE_FILES_H__ */
