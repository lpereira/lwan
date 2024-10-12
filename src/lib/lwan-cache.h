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
  time_t time_to_expire;
};

typedef struct cache_entry *(*cache_create_entry_cb)(const void *key,
                                                     void *cache_ctx,
                                                     void *create_ctx);
typedef void (*cache_destroy_entry_cb)(struct cache_entry *entry,
                                       void *cache_ctx);
typedef struct hash *(*hash_create_func_cb)(void (*)(void *), void (*)(void *));

struct cache;

struct cache *cache_create(cache_create_entry_cb create_entry_cb,
      cache_destroy_entry_cb destroy_entry_cb,
      void *cb_context,
      time_t time_to_live);
struct cache *cache_create_full(cache_create_entry_cb create_entry_cb,
                           cache_destroy_entry_cb destroy_entry_cb,
                           struct hash *(*hash_create_func)(void (*)(void *), void (*)(void *)),
                           void *cb_context,
                           time_t time_to_live);
void cache_destroy(struct cache *cache);

struct cache_entry *cache_get_and_ref_entry(struct cache *cache,
      const void *key, int *error);
struct cache_entry *cache_get_and_ref_entry_with_ctx(struct cache *cache,
      const void *key, void *create_ctx, int *error);
struct cache_entry *cache_coro_get_and_ref_entry(struct cache *cache,
      struct coro *coro, const void *key);
struct cache_entry *cache_coro_get_and_ref_entry_with_ctx(struct cache *cache,
      struct coro *coro, const void *key, void *create_ctx);
void cache_entry_unref(struct cache *cache, struct cache_entry *entry);

void cache_make_read_only(struct cache *cache);

bool cache_entry_is_new(const struct cache_entry *entry);
