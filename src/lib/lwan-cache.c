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

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "lwan-private.h"

#include "lwan-cache.h"
#include "hash.h"

#define GET_AND_REF_TRIES 5

enum {
    /* Entry flags */
    FLOATING = 1 << 0,
    TEMPORARY = 1 << 1,

    /* Cache flags */
    SHUTTING_DOWN = 1 << 0
};

struct cache {
    struct {
        struct hash *table;
        pthread_rwlock_t lock;
    } hash;

    struct {
        struct list_head list;
        pthread_rwlock_t lock;
    } queue;

    struct {
        cache_create_entry_cb create_entry;
        cache_destroy_entry_cb destroy_entry;
        void *context;
    } cb;

    struct {
        time_t time_to_live;
    } settings;

    unsigned flags;

#ifndef NDEBUG
    struct {
        unsigned hits;
        unsigned misses;
        unsigned evicted;
    } stats;
#endif
};

static bool cache_pruner_job(void *data);

struct cache *cache_create(cache_create_entry_cb create_entry_cb,
                             cache_destroy_entry_cb destroy_entry_cb,
                             void *cb_context,
                             time_t time_to_live)
{
    struct cache *cache;

    assert(create_entry_cb);
    assert(destroy_entry_cb);
    assert(time_to_live > 0);

    cache = calloc(1, sizeof(*cache));
    if (!cache)
        return NULL;

    cache->hash.table = hash_str_new(free, NULL);
    if (!cache->hash.table)
        goto error_no_hash;

    if (pthread_rwlock_init(&cache->hash.lock, NULL))
        goto error_no_hash_lock;
    if (pthread_rwlock_init(&cache->queue.lock, NULL))
        goto error_no_queue_lock;

    cache->cb.create_entry = create_entry_cb;
    cache->cb.destroy_entry = destroy_entry_cb;
    cache->cb.context = cb_context;

    cache->settings.time_to_live = time_to_live;

    list_head_init(&cache->queue.list);

    lwan_job_add(cache_pruner_job, cache);

    return cache;

error_no_queue_lock:
    pthread_rwlock_destroy(&cache->hash.lock);
error_no_hash_lock:
    hash_free(cache->hash.table);
error_no_hash:
    free(cache);

    return NULL;
}

void cache_destroy(struct cache *cache)
{
    assert(cache);

#ifndef NDEBUG
    lwan_status_debug("Cache stats: %d hits, %d misses, %d evictions",
                      cache->stats.hits, cache->stats.misses,
                      cache->stats.evicted);
#endif

    lwan_job_del(cache_pruner_job, cache);
    cache->flags |= SHUTTING_DOWN;
    cache_pruner_job(cache);
    pthread_rwlock_destroy(&cache->hash.lock);
    pthread_rwlock_destroy(&cache->queue.lock);
    hash_free(cache->hash.table);
    free(cache);
}

static ALWAYS_INLINE void convert_to_temporary(struct cache_entry *entry)
{
    entry->flags = TEMPORARY;
}

static struct cache_entry *
l2_cache_get_and_ref_entry(struct cache *cache, const char *key, int *error)
{
    struct cache_entry *entry;
    char *key_copy;

    assert(cache);
    assert(error);
    assert(key);

    *error = 0;

    /* If the lock can't be obtained, return an error to allow, for instance,
     * yielding from the coroutine and trying to obtain the lock at a later
     * time. */
    if (UNLIKELY(pthread_rwlock_tryrdlock(&cache->hash.lock) == EBUSY)) {
        *error = EWOULDBLOCK;
        return NULL;
    }
    /* Find the item in the hash table. If it's there, increment the reference
     * and return it. */
    entry = hash_find(cache->hash.table, key);
    if (LIKELY(entry)) {
        ATOMIC_INC(entry->refs);
        pthread_rwlock_unlock(&cache->hash.lock);
#ifndef NDEBUG
        ATOMIC_INC(cache->stats.hits);
#endif
        return entry;
    }

    /* Unlock the cache so the item can be created. */
    pthread_rwlock_unlock(&cache->hash.lock);

#ifndef NDEBUG
    ATOMIC_INC(cache->stats.misses);
#endif

    key_copy = strdup(key);
    if (UNLIKELY(!key_copy)) {
        *error = ENOMEM;
        return NULL;
    }

    entry = cache->cb.create_entry(key, cache->cb.context);
    if (!entry) {
        free(key_copy);
        return NULL;
    }

    memset(entry, 0, sizeof(*entry));
    entry->key = key_copy;
    entry->refs = 1;

    if (pthread_rwlock_trywrlock(&cache->hash.lock) == EBUSY) {
        /* Couldn't obtain hash lock: instead of waiting, just return
         * the recently-created item as a temporary item. Might result
         * in starvation, though, so this might be changed back to
         * pthread_rwlock_wrlock() again someday if this proves to be
         * a problem. */
        convert_to_temporary(entry);
        return entry;
    }

    if (!hash_add_unique(cache->hash.table, entry->key, entry)) {
        struct timespec time_to_die;

        if (UNLIKELY(clock_gettime(monotonic_clock_id, &time_to_die) < 0))
            lwan_status_critical("clock_gettime");

        entry->time_to_die = time_to_die.tv_sec + cache->settings.time_to_live;

        if (LIKELY(!pthread_rwlock_wrlock(&cache->queue.lock))) {
            list_add_tail(&cache->queue.list, &entry->entries);
            pthread_rwlock_unlock(&cache->queue.lock);
        } else {
            convert_to_temporary(entry);

            /* Ensure item is removed from the hash table; otherwise,
             * another thread could potentially get another reference
             * to this entry and cause an invalid memory access. */
            hash_del(cache->hash.table, entry->key);
        }
    } else {
        /* Either there's another item with the same key (-EEXIST), or
         * there was an error inside the hash table. In either case,
         * just return a TEMPORARY entry so that it is destroyed the first
         * time someone unrefs this entry. TEMPORARY entries are pretty much
         * like FLOATING entries, but unreffing them do not use atomic
         * operations. */
        convert_to_temporary(entry);
    }

    pthread_rwlock_unlock(&cache->hash.lock);
    return entry;
}

static void l2_cache_entry_unref(struct cache *cache, struct cache_entry *entry)
{
    assert(entry);

    if (entry->flags & TEMPORARY) {
        free(entry->key);
        goto destroy_entry;
    }

    if (ATOMIC_DEC(entry->refs))
        return;

    /* FLOATING entries without references won't be picked up by the pruner
     * job, so destroy them right here. */
    if (entry->flags & FLOATING) {
destroy_entry:
        /* FIXME: There's a race condition here: if the cache is destroyed
         * while there are cache items floating around, this will dereference
         * deallocated memory. */
        cache->cb.destroy_entry(entry, cache->cb.context);
    }
}

static bool cache_pruner_job(void *data)
{
    struct cache *cache = data;
    struct cache_entry *node, *next;
    struct timespec now;
    bool shutting_down = cache->flags & SHUTTING_DOWN;
    unsigned evicted = 0;
    struct list_head queue;

    if (UNLIKELY(pthread_rwlock_trywrlock(&cache->queue.lock) == EBUSY))
        return false;

    /* If the queue is empty, there's nothing to do; unlock/return*/
    if (list_empty(&cache->queue.list)) {
        if (UNLIKELY(pthread_rwlock_unlock(&cache->queue.lock)))
            lwan_status_perror("pthread_rwlock_unlock");
        return false;
    }

    /* There are things to do; assign cache queue to a local queue,
     * initialize cache queue to an empty queue. Then unlock */
    list_head_init(&queue);
    list_append_list(&queue, &cache->queue.list);
    list_head_init(&cache->queue.list);

    if (UNLIKELY(pthread_rwlock_unlock(&cache->queue.lock))) {
        lwan_status_perror("pthread_rwlock_unlock");
        goto end;
    }

    if (UNLIKELY(clock_gettime(monotonic_clock_id, &now) < 0)) {
        lwan_status_perror("clock_gettime");
        goto end;
    }

    list_for_each_safe(&queue, node, next, entries) {
        char *key = node->key;

        if (now.tv_sec < node->time_to_die && LIKELY(!shutting_down))
            break;

        list_del(&node->entries);

        if (UNLIKELY(pthread_rwlock_wrlock(&cache->hash.lock))) {
            lwan_status_perror("pthread_rwlock_wrlock");
            continue;
        }

        hash_del(cache->hash.table, key);

        if (UNLIKELY(pthread_rwlock_unlock(&cache->hash.lock)))
            lwan_status_perror("pthread_rwlock_unlock");

        if (ATOMIC_INC(node->refs) == 1) {
            cache->cb.destroy_entry(node, cache->cb.context);
        } else {
            ATOMIC_BITWISE(&node->flags, or, FLOATING);
            /* Decrement the reference and see if we were genuinely the last one
             * holding it.  If so, destroy the entry.  */
            if (!ATOMIC_DEC(node->refs))
                cache->cb.destroy_entry(node, cache->cb.context);
        }

        evicted++;
    }

    /* If local queue has been entirely processed, there's no need to
     * append items in the cache queue to it; just update statistics and
     * return */
    if (list_empty(&queue))
        goto end;

    /* Prepend local, unprocessed queue, to the cache queue. Since the cache
     * item TTL is constant, items created later will be destroyed later. */
    if (LIKELY(!pthread_rwlock_wrlock(&cache->queue.lock))) {
        list_prepend_list(&cache->queue.list, &queue);
        pthread_rwlock_unlock(&cache->queue.lock);
    } else {
        lwan_status_perror("pthread_rwlock_wrlock");
    }

end:
#ifndef NDEBUG
    ATOMIC_AAF(&cache->stats.evicted, evicted);
#endif
    return evicted;
}

static struct cache_entry *l2_cache_coro_get_and_ref_entry(struct cache *cache,
                                                           struct coro *coro,
                                                           const char *key)
{
    for (int tries = GET_AND_REF_TRIES; tries; tries--) {
        int error;
        struct cache_entry *ce = l2_cache_get_and_ref_entry(cache, key, &error);

        if (LIKELY(ce)) {
            /* The reference will be dropped by the L1 cache automatically. */
            return ce;
        }

        /*
         * If the cache would block while reading its hash table, yield and
         * try again. On any other error, just return NULL.
         */
        if (error == EWOULDBLOCK) {
            coro_yield(coro, CONN_CORO_MAY_RESUME);
        } else {
            break;
        }
    }

    return NULL;
}

static __thread struct hash *level1_cache;

struct l1_cache_key {
    struct cache *cache;
    const char *key;
    struct cache_entry *entry;
    int refs;
};

static unsigned int l1_cache_hash(const void *k)
{
    const struct l1_cache_key *key = k;

    return hash_str(key->key);
}

static int l1_cache_cmp(const void *key1, const void *key2)
{
    const struct l1_cache_key *k1 = key1;
    const struct l1_cache_key *k2 = key2;

    if (k1 == k2/* || k1->entry == k2->entry*/)
        return 0;

    /*if (k1->cache == k2->cache)
        return strcmp(k1->key, k2->key);*/

    return 1;
}

static inline struct l1_cache_key *copy_l1_key(const struct l1_cache_key *k)
{
    struct l1_cache_key *kk = malloc(sizeof(*kk));

    if (LIKELY(kk))
        memcpy(kk, k, sizeof(*kk));

    return kk;
}

static inline struct hash *get_l1_cache(void) {
    if (UNLIKELY(!level1_cache)) {
        level1_cache = hash_custom_new(l1_cache_hash, l1_cache_cmp, free, NULL);

        if (UNLIKELY(!level1_cache))
            lwan_status_critical("Could not create L1 cache instance");
    }

    return level1_cache;
}

struct cache_entry *
cache_get_and_ref_entry(struct cache *cache, const char *key, int *error)
{
    const struct l1_cache_key k = { .cache = cache, .key = key };
    struct l1_cache_key *kk;
    struct hash *hash = get_l1_cache();
    struct cache_entry *ce;

    kk = hash_find(hash, &k);
    if (UNLIKELY(!kk)) {
        kk = copy_l1_key(&k);

        if (UNLIKELY(!kk))
            return NULL;

        ce = l2_cache_get_and_ref_entry(cache, key, error);
        if (UNLIKELY(!ce))
            goto free_kk;

        kk->entry = ce;
        kk->key = key;

        *error = hash_add_unique(hash, kk, kk);
        if (UNLIKELY(*error < 0)) {
            l2_cache_entry_unref(cache, ce);
            goto free_kk;
        }
    }
    
    kk->refs++;
    return kk->entry;

free_kk:
    free(kk);
    return NULL;
}

static void l1_cache_entry_unref(void *data)
{
    struct l1_cache_key *kk = data;
    int refs;

    refs = kk->refs--;
    if (!refs) {
        hash_del(get_l1_cache(), kk);
        l2_cache_entry_unref(kk->cache, kk->entry);
    }

    if (refs < 0) abort();
}

void cache_entry_unref(struct cache *cache, struct cache_entry *ce)
{
    const struct l1_cache_key k = { .cache = cache, .key = ce->key };
    struct l1_cache_key *kk = hash_find(get_l1_cache(), &k);

    l1_cache_entry_unref(kk);
}

struct cache_entry *
cache_coro_get_and_ref_entry(struct cache *cache, struct coro *coro, const char *key)
{
    const struct l1_cache_key k = { .cache = cache, .key = key };
    struct hash *hash = get_l1_cache();
    struct l1_cache_key *kk;

    kk = hash_find(hash, &k);
    if (UNLIKELY(!kk)) {
        struct cache_entry *ce;

        kk = copy_l1_key(&k);

        if (UNLIKELY(!kk))
            return NULL;

        ce = l2_cache_coro_get_and_ref_entry(cache, coro, key);
        if (UNLIKELY(!ce))
            goto free_kk;

        kk->entry = ce;
        kk->key = key;

        if (hash_add_unique(hash, kk, kk) < 0) {
            l2_cache_entry_unref(cache, ce);
            goto free_kk;
        }
    }

    kk->refs++;
    coro_defer(coro, CORO_DEFER(l1_cache_entry_unref), kk);

    return kk->entry;

free_kk:
    free(kk);

    return NULL;
}
