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
    FREE_KEY_ON_DESTROY = 1 << 2,

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

struct cache_entry *cache_get_and_ref_entry(struct cache *cache,
                                              const char *key, int *error)
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
    entry = hash_find(cache->hash.table, key);
    if (LIKELY(entry)) {
        ATOMIC_INC(entry->refs);
        pthread_rwlock_unlock(&cache->hash.lock);
#ifndef NDEBUG
        ATOMIC_INC(cache->stats.hits);
#endif
        return entry;
    }

    /* No need to keep the hash table lock locked while the item is being created. */
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
    if (UNLIKELY(!entry)) {
        free(key_copy);
        return NULL;
    }

    *entry = (struct cache_entry) { .key =  key_copy, .refs = 1 };

    if (pthread_rwlock_trywrlock(&cache->hash.lock) == EBUSY) {
        /* Couldn't obtain hash write lock: instead of waiting, just return
         * the recently-created item as a temporary item.  Might result in
         * items not being added to the cache, though, so this might be
         * changed back to pthread_rwlock_wrlock() again someday if this
         * proves to be a problem.  */
        entry->flags = TEMPORARY | FREE_KEY_ON_DESTROY;
        return entry;
    }

    if (!hash_add_unique(cache->hash.table, entry->key, entry)) {
        struct timespec time_to_expire;

        if (UNLIKELY(clock_gettime(monotonic_clock_id, &time_to_expire) < 0))
            lwan_status_critical("clock_gettime");

        entry->time_to_expire = time_to_expire.tv_sec + cache->settings.time_to_live;

        if (LIKELY(!pthread_rwlock_wrlock(&cache->queue.lock))) {
            list_add_tail(&cache->queue.list, &entry->entries);
            pthread_rwlock_unlock(&cache->queue.lock);
        } else {
            /* Key is freed when this entry is removed from the hash
             * table below. */
            entry->flags = TEMPORARY;

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
        entry->flags = TEMPORARY | FREE_KEY_ON_DESTROY;
    }

    pthread_rwlock_unlock(&cache->hash.lock);
    return entry;
}

void cache_entry_unref(struct cache *cache, struct cache_entry *entry)
{
    assert(entry);

    /* FIXME: There's a race condition in this function: if the cache is
     * destroyed while there are either temporary or floating entries,
     * calling the destroy_entry callback function will dereference
     * deallocated memory. */

    if (entry->flags & TEMPORARY) {
        /* FREE_KEY_ON_DESTROY is set on elements that never got into the
         * hash table, so their keys are never destroyed automatically. */
        if (entry->flags & FREE_KEY_ON_DESTROY)
            free(entry->key);

        return cache->cb.destroy_entry(entry, cache->cb.context);
    }

    if (ATOMIC_DEC(entry->refs))
        return;

    /* FLOATING entries without references won't be picked up by the pruner
     * job, so destroy them right here. */
    if (entry->flags & FLOATING) {
        assert(!(entry->flags & FREE_KEY_ON_DESTROY));
        return cache->cb.destroy_entry(entry, cache->cb.context);
    }
}

static bool cache_pruner_job(void *data)
{
    struct cache *cache = data;
    struct cache_entry *node, *next;
    struct timespec now;
    bool shutting_down = cache->flags & SHUTTING_DOWN;
    struct list_head queue;
    unsigned int evicted = 0;

    if (UNLIKELY(pthread_rwlock_trywrlock(&cache->queue.lock) == EBUSY))
        return false;

    /* If the queue is empty, there's nothing to do; unlock/return*/
    if (list_empty(&cache->queue.list)) {
        if (UNLIKELY(pthread_rwlock_unlock(&cache->queue.lock)))
            lwan_status_perror("pthread_rwlock_unlock");
        return false;
    }

    /* There are things to do; work on a local queue so the lock doesn't
     * need to be held while items are being pruned. */
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

        if (now.tv_sec < node->time_to_expire && LIKELY(!shutting_down))
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
            /* If the refcount was 0, and turned 1 after the increment, it means the item can
             * be destroyed here. */
            cache->cb.destroy_entry(node, cache->cb.context);
        } else {
            /* If not, some other thread had references to this object. */
            ATOMIC_BITWISE(&node->flags, or, FLOATING);
            /* If in the time between the ref check above and setting the floating flag the
             * thread holding the reference drops it, if our reference is 0 after dropping it,
             * the pruner thread was the last thread holding the reference to this entry, so
             * it's safe to destroy it at this point. */
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

static void cache_entry_unref_defer(void *data1, void *data2)
{
    cache_entry_unref((struct cache *)data1, (struct cache_entry *)data2);
}

struct cache_entry *cache_coro_get_and_ref_entry(struct cache *cache,
                                                 struct coro *coro,
                                                 const char *key)
{
    for (int tries = GET_AND_REF_TRIES; tries; tries--) {
        int error;
        struct cache_entry *ce = cache_get_and_ref_entry(cache, key, &error);

        if (LIKELY(ce)) {
            /*
             * This is deferred here so that, if the coroutine is killed
             * after it has been yielded, this cache entry is properly
             * freed.
             */
            coro_defer2(coro, cache_entry_unref_defer, cache, ce);
            return ce;
        }

        /*
         * If the cache would block while reading its hash table, yield and
         * try again. On any other error, just return NULL.
         */
        if (error == EWOULDBLOCK) {
            coro_yield(coro, CONN_CORO_YIELD);
        } else {
            break;
        }
    }

    return NULL;
}
