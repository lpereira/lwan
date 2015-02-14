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

#include "lwan.h"
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

struct cache_t {
    struct {
        struct hash *table;
        pthread_rwlock_t lock;
    } hash;

    struct {
        struct list_head list;
        pthread_rwlock_t lock;
    } queue;

    struct {
        CreateEntryCallback create_entry;
        DestroyEntryCallback destroy_entry;
        void *context;
    } cb;

    struct {
        time_t time_to_live;
        clockid_t clock_id;
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

static clockid_t detect_fastest_monotonic_clock(void)
{
#ifdef CLOCK_MONOTONIC_COARSE
    struct timespec ts;

    if (!clock_gettime(CLOCK_MONOTONIC_COARSE, &ts))
        return CLOCK_MONOTONIC_COARSE;
#endif
    return CLOCK_MONOTONIC;
}

static ALWAYS_INLINE void clock_monotonic_gettime(struct cache_t *cache,
    struct timespec *ts)
{
    if (UNLIKELY(clock_gettime(cache->settings.clock_id, ts) < 0))
        lwan_status_perror("clock_gettime");
}

struct cache_t *cache_create(CreateEntryCallback create_entry_cb,
                             DestroyEntryCallback destroy_entry_cb,
                             void *cb_context,
                             time_t time_to_live)
{
    struct cache_t *cache;

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

    cache->settings.clock_id = detect_fastest_monotonic_clock();
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

void cache_destroy(struct cache_t *cache)
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

static ALWAYS_INLINE struct cache_entry_t *convert_to_temporary(
    struct cache_entry_t *entry)
{
    entry->flags = TEMPORARY;
    return entry;
}

struct cache_entry_t *cache_get_and_ref_entry(struct cache_t *cache,
                                              const char *key, int *error)
{
    struct cache_entry_t *entry;

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

    entry = cache->cb.create_entry(key, cache->cb.context);
    if (!entry)
        return NULL;

    memset(entry, 0, sizeof(*entry));
    entry->key = strdup(key);
    entry->refs = 1;

    if (pthread_rwlock_trywrlock(&cache->hash.lock) == EBUSY) {
        /* Couldn't obtain hash lock: instead of waiting, just return
         * the recently-created item as a temporary item. Might result
         * in starvation, though, so this might be changed back to
         * pthread_rwlock_wrlock() again someday if this proves to be
         * a problem. */
        return convert_to_temporary(entry);
    }

    if (!hash_add_unique(cache->hash.table, entry->key, entry)) {
        struct timespec time_to_die;
        clock_monotonic_gettime(cache, &time_to_die);
        entry->time_to_die = time_to_die.tv_sec + cache->settings.time_to_live;

        pthread_rwlock_wrlock(&cache->queue.lock);
        list_add_tail(&cache->queue.list, &entry->entries);
        pthread_rwlock_unlock(&cache->queue.lock);
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

void cache_entry_unref(struct cache_t *cache, struct cache_entry_t *entry)
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
    struct cache_t *cache = data;
    struct cache_entry_t *node, *next;
    struct timespec now;
    bool shutting_down = cache->flags & SHUTTING_DOWN;
    unsigned evicted = 0;
    struct list_head queue;

    if (UNLIKELY(pthread_rwlock_tryrdlock(&cache->queue.lock) == EBUSY))
        return false;

    /* If the queue is empty, there's nothing to do; unlock/return*/
    if (list_empty(&cache->queue.list)) {
        if (UNLIKELY(pthread_rwlock_unlock(&cache->queue.lock) < 0))
            lwan_status_perror("pthread_rwlock_unlock");
        return false;
    }

    /* There are things to do; assign cache queue to a local queue,
     * initialize cache queue to an empty queue. Then unlock */
    list_head_init(&queue);
    list_append_list(&queue, &cache->queue.list);
    list_head_init(&cache->queue.list);

    if (UNLIKELY(pthread_rwlock_unlock(&cache->queue.lock) < 0)) {
        lwan_status_perror("pthread_rwlock_unlock");
        goto end;
    }

    clock_monotonic_gettime(cache, &now);
    list_for_each_safe(&queue, node, next, entries)
    {
        char *key = node->key;

        if (now.tv_sec < node->time_to_die && LIKELY(!shutting_down))
            break;

        list_del(&node->entries);

        if (UNLIKELY(pthread_rwlock_wrlock(&cache->hash.lock) < 0)) {
            lwan_status_perror("pthread_rwlock_wrlock");
            continue;
        }

        hash_del(cache->hash.table, key);

        if (UNLIKELY(pthread_rwlock_unlock(&cache->hash.lock) < 0))
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
    if (pthread_rwlock_trywrlock(&cache->queue.lock) >= 0) {
        list_prepend_list(&cache->queue.list, &queue);

        if (pthread_rwlock_unlock(&cache->queue.lock) < 0)
            lwan_status_perror("pthread_rwlock_unlock");
    } else {
        lwan_status_perror("pthread_rwlock_trywrlock");
    }

end:
#ifndef NDEBUG
    ATOMIC_AAF(&cache->stats.evicted, evicted);
#endif
    return evicted;
}

struct cache_entry_t*
cache_coro_get_and_ref_entry(struct cache_t *cache, coro_t *coro,
                             const char *key)
{
    for (int tries = GET_AND_REF_TRIES; tries; tries--) {
        int error;
        struct cache_entry_t *ce = cache_get_and_ref_entry(cache, key, &error);

        if (LIKELY(ce)) {
            /*
             * This is deferred here so that, if the coroutine is killed
             * after it has been yielded, this cache entry is properly
             * freed.
             */
            coro_defer2(coro, CORO_DEFER2(cache_entry_unref), cache, ce);
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
