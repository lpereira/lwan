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

#pragma once

#include <time.h>

#include "list.h"
#include "lwan-coro.h"

struct cache_entry_t {
  struct list_node entries;
  char *key;
  unsigned refs;
  unsigned flags;
  time_t time_to_die;
};

typedef struct cache_entry_t *(*CreateEntryCallback)(
      const char *key, void *context);
typedef void (*DestroyEntryCallback)(
      struct cache_entry_t *entry, void *context);

struct cache_t;

struct cache_t *cache_create(CreateEntryCallback create_entry_cb,
      DestroyEntryCallback destroy_entry_cb,
      void *cb_context,
      time_t time_to_live);
void cache_destroy(struct cache_t *cache);

struct cache_entry_t *cache_get_and_ref_entry(struct cache_t *cache,
      const char *key, int *error);
void cache_entry_unref(struct cache_t *cache, struct cache_entry_t *entry);
struct cache_entry_t *cache_coro_get_and_ref_entry(struct cache_t *cache,
      coro_t *coro, const char *key);
