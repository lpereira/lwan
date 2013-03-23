/*
 * lwan - simple web server
 * Copyright (c) 2012, 2013 Leandro A. F. Pereira <leandro@hardinfo.org>
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

#ifndef __MEMCACHE_H__
#define __MEMCACHE_H__

typedef struct memcache_t_ memcache_t;

struct memcache_t_ {
    struct memcache_entry_t *entries;
    int n_entries;

    unsigned int (*hash_key)(void *key);
    int (*cmp_key)(void *key1, void *key2);
    void (*free_key)(void *key);
    void (*free_data)(void *data);
};

struct memcache_entry_t {
    void *key;
    void *data;
};

struct memcache_t_ *
memcache_new_full(int n_entries,
                  unsigned int (*hash_key)(void *key),
                  int (*cmp_key)(void *key1, void *key2),
                  void (*free_key)(void *key),
                  void (*free_data)(void *data));
struct memcache_t_ *
memcache_new_int32(int n_entries,
                   void (*free_data)(void *data));
void memcache_free(memcache_t *m);
void memcache_put(memcache_t *m, void *key, void *data);
void *memcache_get(memcache_t *m, void *key);

#endif /* __MEMCACHE_H__ */
