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

#pragma once

#if defined (__cplusplus)
extern "C" {
#endif

#include "lwan.h"

struct lwan_serve_files_settings {
  const char *root_path;
  const char *index_html;
  const char *directory_list_template;
  bool serve_precompressed_files;
  bool auto_index;
};

#define SERVE_FILES_SETTINGS(root_path_, index_html_, serve_precompressed_files_) \
  .module = lwan_module_serve_files(), \
  .args = ((struct lwan_serve_files_settings[]) {{ \
    .root_path = root_path_, \
    .index_html = index_html_, \
    .serve_precompressed_files = serve_precompressed_files_, \
    .directory_list_template = NULL, \
    .auto_index = true \
  }}), \
  .flags = (enum lwan_handler_flags)0

#define SERVE_FILES(root_path) \
  SERVE_FILES_SETTINGS(root_path, NULL, true)

const struct lwan_module *lwan_module_serve_files(void);

#if defined (__cplusplus)
}
#endif
