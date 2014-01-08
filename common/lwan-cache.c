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
  FLOATING = 1<<0,

  /* Cache flags */
  SHUTTING_DOWN = 1<<0
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
    unsigned hits, misses, evictions;
    cache_get_stats(cache, &hits, &misses, &evictions);
    lwan_status_debug("Cache stats: %d hits, %d misses, %d evictions",
            hits, misses, evictions);
#endif

  lwan_job_del(cache_pruner_job, cache);
  cache->flags |= SHUTTING_DOWN;
  cache_pruner_job(cache);
  pthread_rwlock_destroy(&cache->hash.lock);
  pthread_rwlock_destroy(&cache->queue.lock);
  hash_free(cache->hash.table);
  free(cache);
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

try_adding_again:
  /* Try adding the item to the hash table. If it's already there,
   * destroy the newly-created item, and return the older item. If
   * the item wasn't there, adjust its time to die and add to the
   * reap queue. */
  pthread_rwlock_wrlock(&cache->hash.lock);
  switch (hash_add_unique(cache->hash.table, entry->key, entry)) {
  case -EEXIST: {
      struct cache_entry_t *tmp_entry;

      /* We don't need to write to the hash table anymore, unlock
       * it for writing and lock it for reading. */
      pthread_rwlock_unlock(&cache->hash.lock);
      pthread_rwlock_rdlock(&cache->hash.lock);

      tmp_entry = hash_find(cache->hash.table, key);
      if (tmp_entry) {
        cache->cb.destroy_entry(entry, cache->cb.context);
        entry = tmp_entry;
        goto end;
      }

      pthread_rwlock_unlock(&cache->hash.lock);
      /* This shouldn't really happen, but if it does, just try to
       * add the item to the hash table again. */
      goto try_adding_again;
    }
  default:
    /* This might be any error while reallocating memory to make
     * room for the item inside the hasht able. Just don't add, but
     * return a FLOATING item with one reference, and make it already
     * expired, so that the first unref will actually destroy this
     * item. */
    entry->flags = FLOATING;
    entry->time_to_die = time(NULL);
    entry->refs = 1;
    goto unlock_and_return;
  case 0:
    entry->time_to_die = time(NULL) + cache->settings.time_to_live;
    pthread_rwlock_wrlock(&cache->queue.lock);
    list_add_tail(&cache->queue.list, &entry->entries);
    pthread_rwlock_unlock(&cache->queue.lock);
  }

end:
  ATOMIC_INC(entry->refs);
unlock_and_return:
  pthread_rwlock_unlock(&cache->hash.lock);

  return entry;
}

void cache_entry_unref(struct cache_t *cache, struct cache_entry_t *entry)
{
  assert(entry);

  /* FLOATING entries without references won't be picked up by the pruner
   * job, so destroy them right here. */
  if (!ATOMIC_DEC(entry->refs) && entry->flags & FLOATING)
    cache->cb.destroy_entry(entry, cache->cb.context);
}

static bool cache_pruner_job(void *data)
{
  struct cache_t *cache = data;
  struct cache_entry_t *node, *next;
  time_t now;
  bool shutting_down = cache->flags & SHUTTING_DOWN;
  unsigned evicted = 0;
  struct list_head queue;

  if (UNLIKELY(pthread_rwlock_trywrlock(&cache->queue.lock) == EBUSY))
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

  now = time(NULL);
  list_for_each_safe(&queue, node, next, entries) {
    char *key = node->key;

    if (now < node->time_to_die && LIKELY(!shutting_down))
      break;

    list_del(&node->entries);

    if (UNLIKELY(pthread_rwlock_wrlock(&cache->hash.lock) < 0)) {
      lwan_status_perror("pthread_rwlock_wrlock");
      continue;
    }

    hash_del(cache->hash.table, key);

    if (UNLIKELY(pthread_rwlock_unlock(&cache->hash.lock) < 0))
      lwan_status_perror("pthread_rwlock_unlock");

    if (!ATOMIC_READ(node->refs)) {
      cache->cb.destroy_entry(node, cache->cb.context);
    } else {
      ATOMIC_BITWISE(&node->flags, or, FLOATING);

      /* If preemption occurred before setting item to FLOATING, check
       * if item still have refs; destroy if not */
      if (UNLIKELY(!ATOMIC_READ(node->refs)))
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

void cache_get_stats(struct cache_t *cache, unsigned *hits,
      unsigned *misses, unsigned *evicted)
{
  assert(cache);
#ifndef NDEBUG
  if (hits)
    *hits = cache->stats.hits;
  if (misses)
    *misses = cache->stats.misses;
  if (evicted)
    *evicted = cache->stats.evicted;
#else
  if (hits)
    *hits = 0;
  if (misses)
    *misses = 0;
  if (evicted)
    *evicted = 0;
  (void)cache;
#endif
}

struct cache_entry_t *
cache_coro_get_and_ref_entry(struct cache_t *cache, coro_t *coro,
      const char *key)
{
    struct cache_entry_t *ce;
    int error;
    int tries;

    for (tries = GET_AND_REF_TRIES; tries; tries--) {
        ce = cache_get_and_ref_entry(cache, key, &error);
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
