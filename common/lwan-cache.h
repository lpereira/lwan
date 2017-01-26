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

struct cache_entry {
  struct list_node entries;
  char *key;
  int refs;
  unsigned flags;
  time_t time_to_die;
};

typedef struct cache_entry *(*cache_create_entry_cb)(
      const char *key, void *context);
typedef void (*cache_destroy_entry_cb)(
      struct cache_entry *entry, void *context);

struct cache;

struct cache *cache_create(cache_create_entry_cb create_entry_cb,
      cache_destroy_entry_cb destroy_entry_cb,
      void *cb_context,
      time_t time_to_live);
void cache_destroy(struct cache *cache);

struct cache_entry *cache_get_and_ref_entry(struct cache *cache,
      const char *key, int *error);
void cache_entry_unref(struct cache *cache, struct cache_entry *entry);
struct cache_entry *cache_coro_get_and_ref_entry(struct cache *cache,
      struct coro *coro, const char *key);
