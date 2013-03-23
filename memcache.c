/*
 * lwan - simple web server
 * Copyright (c) 2012, 2013 Leandro A. F. Pereira <leandro@hardinfo.org>
 *
 * Naive memcache implementation
 * This implements a lucky-recently-used cache: if a key is lucky
 * enough to stay in the cache, it stays in the cache. If it's not,
 * then, bummer: something else replaces it. Most certainly not the
 * best approach to a memcache like structure, but this one is pretty
 * fast and serves merely as an example.
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

#include <stdlib.h>
#include "memcache.h"

static int
cmp_int32(void *key1, void *key2)
{
    return (int)(long)key1 - (int)(long)key2;
}

static unsigned int
hash_int32(void *keyptr)
{
    /* http://www.concentric.net/~Ttwang/tech/inthash.htm */
    int key = (int)(long)keyptr;
    int c2 = 0x27d4eb2d; // a prime or an odd constant

    key = (key ^ 61) ^ (key >> 16);
    key += key << 3;
    key ^= key >> 4;
    key *= c2;
    key ^= key >> 15;

    return key;
}

struct memcache_t_ *
memcache_new_full(int n_entries,
                  unsigned int (*hash_key)(void *key),
                  int (*cmp_key)(void *key1, void *key2),
                  void (*free_key)(void *key),
                  void (*free_data)(void *data))
{
    struct memcache_t_ *m;

    m = malloc(sizeof(*m));
    if (!m)
        return NULL;

    m->entries = calloc(n_entries, sizeof(struct memcache_entry_t));
    if (!m->entries) {
        free(m);
        return NULL;
    }

    m->n_entries = n_entries;
    m->hash_key = hash_key;
    m->cmp_key = cmp_key;
    m->free_key = free_key;
    m->free_data = free_data;

    return m;
}

void
memcache_free(struct memcache_t_ *m)
{
    int i;

    if (!m)
        return;

    if (m->free_key) {
        for (i = 0; i < m->n_entries; i++)
            m->free_key(m->entries[i].key);
    }

    if (m->free_data) {
        for (i = 0; i < m->n_entries; i++)
            m->free_data(m->entries[i].data);
    }

    free(m->entries);
    free(m);
}

struct memcache_t_ *
memcache_new_int32(int n_entries,
                   void (*free_data)(void *data))
{
    return memcache_new_full(n_entries, hash_int32, cmp_int32, NULL, free_data);
}

void
memcache_put(struct memcache_t_ *m, void *key, void *data)
{
    unsigned int hash;
    struct memcache_entry_t *bucket;

    if (!m)
        return;

    hash = m->hash_key(key);
    bucket = &m->entries[hash % m->n_entries];

    if (m->free_key)
        m->free_key(bucket->key);
    if (m->free_data)
        m->free_data(bucket->data);

    bucket->key = key;
    bucket->data = data;
}

void *
memcache_get(struct memcache_t_ *m, void *key)
{
    unsigned int hash;
    struct memcache_entry_t *bucket;

    if (!m)
        return NULL;

    hash = m->hash_key(key);
    bucket = &m->entries[hash % m->n_entries];

    if (m->cmp_key(key, bucket->key) == 0)
        return bucket->data;

    return NULL;
}
