/*
 * Based on libkmod-hash.c from libkmod - interface to kernel module operations
 * Copyright (C) 2011-2012  ProFUSION embedded systems
 * Copyright (C) 2013 L.Pereira <l@tia.mat.br>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#define _DEFAULT_SOURCE
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "lwan-private.h"
#include "hash.h"

struct hash_bucket {
    void **keys;
    void **values;
    unsigned int *hashvals;

    unsigned int used;
    unsigned int total;
};

struct hash {
    unsigned int count;
    unsigned int n_buckets_mask;

    unsigned (*hash_value)(const void *key);
    int (*key_equal)(const void *k1, const void *k2);
    void (*free_value)(void *value);
    void (*free_key)(void *value);

    struct hash_bucket *buckets;

    unsigned int refs;
};

struct hash_entry {
    void **key;
    void **value;
    unsigned int *hashval;

    /* Only set when adding a new entry if it was already in the
     * hash table -- always 0/false otherwise. */
    bool existing;
};

#define MIN_BUCKETS 64

/* Due to rehashing heuristics, most hash tables won't have more than 4
 * entries in each bucket.  Use a conservative allocation threshold to
 * curb wasteful allocations */
#define STEPS 4

static_assert((MIN_BUCKETS & (MIN_BUCKETS - 1)) == 0,
              "Bucket size is power of 2");

#define DEFAULT_FNV1A_64_SEED 0xcbf29ce484222325ull
#define DEFAULT_FNV1A_32_SEED 0x811c9dc5u

uint64_t fnv1a_64_seed = DEFAULT_FNV1A_64_SEED;
uint32_t fnv1a_32_seed = DEFAULT_FNV1A_32_SEED;

#define ASSERT_SEED_INITIALIZED()                                              \
    do {                                                                       \
        assert(fnv1a_64_seed != DEFAULT_FNV1A_64_SEED);                        \
        assert(fnv1a_32_seed != DEFAULT_FNV1A_32_SEED);                        \
    } while (0)

static inline unsigned int hash_fnv1a_32(const void *keyptr);
static inline unsigned int hash_int_32(const void *keyptr);
static inline unsigned int hash_int_64(const void *keyptr);

static unsigned (*hash_str)(const void *key) = hash_fnv1a_32;
static unsigned (*hash_int)(const void *key) = hash_int_32;
static unsigned (*hash_int64)(const void *key) = hash_int_64;

static bool resize_bucket(struct hash_bucket *bucket, unsigned int new_size)
{
    void **new_keys;
    void **new_values;
    unsigned int *new_hashvals;

    new_keys = reallocarray(bucket->keys, new_size, STEPS * sizeof(void *));
    new_values = reallocarray(bucket->values, new_size, STEPS * sizeof(void *));
    new_hashvals =
        reallocarray(bucket->hashvals, new_size, STEPS * sizeof(unsigned int));

    if (new_keys)
        bucket->keys = new_keys;
    if (new_values)
        bucket->values = new_values;
    if (new_hashvals)
        bucket->hashvals = new_hashvals;

    if (new_keys && new_values && new_hashvals) {
        bucket->total = new_size * STEPS;
        return true;
    }

    return false;
}

static inline unsigned int hash_fnv1a_32(const void *keyptr)
{
    return fnv1a_32(keyptr, strlen(keyptr));
}

static inline unsigned int hash_int_32(const void *keyptr)
{
    unsigned int key = (unsigned int)(long)keyptr;
    return fnv1a_32(&key, sizeof(key));
}

static inline unsigned int hash_int_64(const void *keyptr)
{
    const uint64_t key = (uint64_t)(uintptr_t)keyptr;
    return fnv1a_32(&key, sizeof(key));
}

#if defined(LWAN_HAVE_BUILTIN_CPU_INIT) && defined(LWAN_HAVE_BUILTIN_IA32_CRC32)
static inline unsigned int hash_str_crc32(const void *keyptr)
{
    unsigned int hash = fnv1a_32_seed;
    const char *key = keyptr;
    size_t len = strlen(key);

    ASSERT_SEED_INITIALIZED();

#if __x86_64__
    while (len >= sizeof(uint64_t)) {
        uint64_t data;
        memcpy(&data, key, sizeof(data));
        hash = (unsigned int)__builtin_ia32_crc32di(hash, data);
        key += sizeof(uint64_t);
        len -= sizeof(uint64_t);
    }
#endif /* __x86_64__ */
    while (len >= sizeof(uint32_t)) {
        uint32_t data;
        memcpy(&data, key, sizeof(data));
        hash = __builtin_ia32_crc32si(hash, data);
        key += sizeof(uint32_t);
        len -= sizeof(uint32_t);
    }
    if (*key && *(key + 1)) {
        uint16_t data;
        memcpy(&data, key, sizeof(data));
        hash = __builtin_ia32_crc32hi(hash, data);
        key += sizeof(uint16_t);
    }
    /* Last byte might be the terminating NUL or the last character.
     * For a hash, this doesn't matter, and shaves off a branch.
     */
    hash = __builtin_ia32_crc32qi(hash, (unsigned char)*key);

    return hash;
}

static inline unsigned int hash_int_crc32(const void *keyptr)
{
    ASSERT_SEED_INITIALIZED();

    return __builtin_ia32_crc32si(fnv1a_32_seed,
                                  (unsigned int)(uintptr_t)keyptr);
}

static inline unsigned int hash_int64_crc32(const void *keyptr)
{
    ASSERT_SEED_INITIALIZED();

#ifdef __x86_64__
    return (unsigned int)__builtin_ia32_crc32di(fnv1a_32_seed,
                                                (uint64_t)(uintptr_t)keyptr);
#else
    const uint64_t key = (uint64_t)(uintptr_t)keyptr;
    uint32_t crc;

    crc = __builtin_ia32_crc32si(fnv1a_32_seed, (uint32_t)(key & 0xffffffff));
    crc = __builtin_ia32_crc32si(crc, (uint32_t)(key >> 32));

    return crc;
#endif
}

#endif

LWAN_CONSTRUCTOR(fnv1a_seed, 65535)
{
    uint8_t entropy[128];

    /* The seeds are randomized in order to mitigate the DDoS attack
     * described by Crosby and Wallach in UsenixSec2003.  */
    if (UNLIKELY(lwan_getentropy(entropy, sizeof(entropy), 0) < 0)) {
        lwan_status_critical_perror("Could not initialize FNV1a seed");
        __builtin_unreachable();
    }

    fnv1a_64_seed = fnv1a_64(entropy, sizeof(entropy));
    fnv1a_32_seed = fnv1a_32(entropy, sizeof(entropy));
    lwan_always_bzero(entropy, sizeof(entropy));

#if defined(LWAN_HAVE_BUILTIN_CPU_INIT) && defined(LWAN_HAVE_BUILTIN_IA32_CRC32)
    __builtin_cpu_init();
    if (__builtin_cpu_supports("sse4.2")) {
        lwan_status_debug("Using CRC32 instructions to calculate hashes");
        hash_str = hash_str_crc32;
        hash_int = hash_int_crc32;
        hash_int64 = hash_int64_crc32;
    }
#endif
}

static inline int hash_int_key_equal(const void *k1, const void *k2)
{
    return k1 == k2;
}

static void no_op(void *arg __attribute__((unused))) {}

static struct hash *
hash_internal_new(unsigned int (*hash_value)(const void *key),
                  int (*key_equal)(const void *k1, const void *k2),
                  void (*free_key)(void *value),
                  void (*free_value)(void *value))
{
    struct hash *hash = malloc(sizeof(*hash));

    if (hash == NULL)
        return NULL;

    hash->buckets = calloc(MIN_BUCKETS, sizeof(struct hash_bucket));
    if (hash->buckets == NULL) {
        free(hash);
        return NULL;
    }

    hash->hash_value = hash_value;
    hash->key_equal = key_equal;

    hash->free_value = free_value;
    hash->free_key = free_key;

    hash->n_buckets_mask = MIN_BUCKETS - 1;
    hash->count = 0;

    hash->refs = 1;

    return hash;
}

struct hash *hash_int_new(void (*free_key)(void *value),
                          void (*free_value)(void *value))
{
    return hash_internal_new(hash_int, hash_int_key_equal,
                             free_key ? free_key : no_op,
                             free_value ? free_value : no_op);
}

struct hash *hash_int64_new(void (*free_key)(void *value),
                            void (*free_value)(void *value))
{
    return hash_internal_new(hash_int64, hash_int_key_equal,
                             free_key ? free_key : no_op,
                             free_value ? free_value : no_op);
}

struct hash *hash_str_new(void (*free_key)(void *value),
                          void (*free_value)(void *value))
{
    return hash_internal_new(
        hash_str, (int (*)(const void *, const void *))streq,
        free_key ? free_key : no_op, free_value ? free_value : no_op);
}

struct hash *hash_custom_new(unsigned (*hash_value)(const void *key),
                             int (*key_equal)(const void *k1, const void *k2),
                             void (*free_key)(void *value),
                             void (*free_value)(void *value))
{
    if (UNLIKELY(!hash_value)) {
        lwan_status_critical("hash_value() not provided to hash_custom_new()");
        __builtin_unreachable();
    }
    if (UNLIKELY(!key_equal)) {
        lwan_status_critical("key_equal() not provided to hash_custom_new()");
        __builtin_unreachable();
    }
    return hash_internal_new(hash_value, key_equal, free_key ? free_key : no_op,
                             free_value ? free_value : no_op);
}

static __attribute__((pure)) inline unsigned int
hash_n_buckets(const struct hash *hash)
{
    return hash->n_buckets_mask + 1;
}

struct hash *hash_ref(struct hash *hash)
{
    hash->refs++;
    return hash;
}

void hash_unref(struct hash *hash)
{
    struct hash_bucket *bucket, *bucket_end;

    if (hash == NULL)
        return;

    hash->refs--;
    if (hash->refs)
        return;

    bucket = hash->buckets;
    bucket_end = hash->buckets + hash_n_buckets(hash);
    for (; bucket < bucket_end; bucket++) {
        for (unsigned int entry = 0; entry < bucket->used; entry++) {
            hash->free_value(bucket->values[entry]);
            hash->free_key(bucket->keys[entry]);
        }
        free(bucket->keys);
        free(bucket->values);
        free(bucket->hashvals);
    }
    free(hash->buckets);
    free(hash);
}

static struct hash_entry hash_add_entry_hashed(struct hash *hash,
                                               const void *key,
                                               unsigned int hashval)
{
    unsigned int pos = hashval & hash->n_buckets_mask;
    struct hash_bucket *bucket = hash->buckets + pos;
    unsigned int entry;
    bool existing = false;

    if (bucket->used + 1 >= bucket->total) {
        unsigned int new_bucket_total;

        if (__builtin_add_overflow(bucket->total, 1, &new_bucket_total))
            return (struct hash_entry) {};

        if (!resize_bucket(bucket, new_bucket_total))
            return (struct hash_entry) {};
    }

    for (entry = 0; entry < bucket->used; entry++) {
        if (hashval != bucket->hashvals[entry])
            continue;
        if (hash->key_equal(key, bucket->keys[entry])) {
            existing = true;
            goto done;
        }
    }

    entry = bucket->used;

    bucket->keys[entry] = NULL;
    bucket->values[entry] = NULL;
    bucket->hashvals[entry] = hashval;

    bucket->used++;
    hash->count++;

done:
    return (struct hash_entry){
        .key = &bucket->keys[entry],
        .value = &bucket->values[entry],
        .hashval = &bucket->hashvals[entry],
        .existing = existing,
    };
}

static void rehash(struct hash *hash, unsigned int new_bucket_size)
{
    struct hash_bucket *buckets = calloc(new_bucket_size, sizeof(*buckets));
    const unsigned int n_buckets = hash_n_buckets(hash);
    struct hash hash_copy = *hash;

    assert((new_bucket_size & (new_bucket_size - 1)) == 0);
    assert(hash_n_buckets(hash) != new_bucket_size);

    if (buckets == NULL)
        return;

    hash_copy.count = 0;
    hash_copy.n_buckets_mask = new_bucket_size - 1;
    hash_copy.buckets = buckets;

    struct hash_bucket *bucket;
    struct hash_bucket *bucket_end = hash->buckets + n_buckets;
    for (bucket = hash->buckets; bucket < bucket_end; bucket++) {
        for (unsigned int old = 0; old < bucket->used; old++) {
            struct hash_entry new =
                hash_add_entry_hashed(&hash_copy,
                                      bucket->keys[old],
                                      bucket->hashvals[old]);
            if (UNLIKELY(!new.key))
                goto fail;

            *new.key = bucket->keys[old];
            *new.value = bucket->values[old];
        }
    }

    /* Original table must remain untouched in the event resizing fails:
     * previous loop may return early on allocation failure, so can't free
     * bucket entry arrays there.  */
    for (bucket = hash->buckets; bucket < bucket_end; bucket++) {
        free(bucket->keys);
        free(bucket->values);
        free(bucket->hashvals);
    }
    free(hash->buckets);

    hash->buckets = buckets;
    hash->n_buckets_mask = new_bucket_size - 1;

    assert(hash_copy.count == hash->count);

    return;

fail:
    for (bucket_end = bucket, bucket = hash->buckets; bucket < bucket_end;
         bucket++) {
        free(bucket->keys);
        free(bucket->values);
        free(bucket->hashvals);
    }

    free(buckets);
}

static struct hash_entry hash_add_entry(struct hash *hash, const void *key)
{
    unsigned int hashval = hash->hash_value(key);

    return hash_add_entry_hashed(hash, key, hashval);
}

static inline bool need_rehash_grow(const struct hash *hash)
{
    /* The heuristic to rehash and grow the number of buckets is if there's
     * more than 16 entries per bucket on average.  This is the number of
     * elements in the hashvals array that would fit in a single cache line. */
    return hash->count > hash_n_buckets(hash) * 16;
}

static inline bool need_rehash_shrink(const struct hash *hash)
{
    /* A hash table will be shrunk if, on average, more than 50% of its
     * buckets are empty, but will never have less than MIN_BUCKETS buckets. */
    const unsigned int n_buckets = hash_n_buckets(hash);

    if (n_buckets <= MIN_BUCKETS)
        return false;

    if (hash->count > n_buckets / 2)
        return false;

    return true;
}

/*
 * add or replace key in hash map.
 *
 * none of key or value are copied, just references are remembered as is,
 * make sure they are live while pair exists in hash!
 */
int hash_add(struct hash *hash, const void *key, const void *value)
{
    struct hash_entry entry = hash_add_entry(hash, key);

    if (!entry.key)
        return -errno;
    if (entry.existing) {
        hash->free_key(*entry.key);
        hash->free_value(*entry.value);
    }

    *entry.key = (void *)key;
    *entry.value = (void *)value;

    if (need_rehash_grow(hash))
        rehash(hash, hash_n_buckets(hash) * 2);

    return 0;
}

/* similar to hash_add(), but fails if key already exists */
int hash_add_unique(struct hash *hash, const void *key, const void *value)
{
    struct hash_entry entry = hash_add_entry(hash, key);

    if (!entry.key)
        return -errno;
    if (entry.existing)
        return -EEXIST;

    *entry.key = (void *)key;
    *entry.value = (void *)value;

    if (need_rehash_grow(hash))
        rehash(hash, hash_n_buckets(hash) * 2);

    return 0;
}

static inline struct hash_entry
hash_find_entry(const struct hash *hash, const char *key, unsigned int hashval)
{
    unsigned int pos = hashval & hash->n_buckets_mask;
    const struct hash_bucket *bucket = hash->buckets + pos;

    for (unsigned int entry = 0; entry < bucket->used; entry++) {
        if (hashval != bucket->hashvals[entry])
            continue;
        if (hash->key_equal(key, bucket->keys[entry])) {
            return (struct hash_entry){
                .key = &bucket->keys[entry],
                .value = &bucket->values[entry],
                .hashval = &bucket->hashvals[entry],
            };
        }
    }

    return (struct hash_entry){};
}

void *hash_find(const struct hash *hash, const void *key)
{
    struct hash_entry entry =
        hash_find_entry(hash, key, hash->hash_value(key));

    return entry.key ? *entry.value : NULL;
}

int hash_del(struct hash *hash, const void *key)
{
    unsigned int hashval = hash->hash_value(key);
    unsigned int pos = hashval & hash->n_buckets_mask;
    struct hash_bucket *bucket = hash->buckets + pos;

    struct hash_entry entry = hash_find_entry(hash, key, hashval);
    if (entry.key == NULL)
        return -ENOENT;

    hash->free_value(*entry.value);
    hash->free_key(*entry.key);

    if (bucket->used > 1) {
        /* Instead of compacting the bucket array by moving elements, just copy
         * over the last element on top of the element being removed.  This
         * changes the ordering inside the bucket array, but it's much more
         * efficient, as it always has to copy exactly at most 1 element instead
         * of potentially bucket->used elements. */
        void *last_key = &bucket->keys[bucket->used - 1];

        /* FIXME: Is comparing these pointers UB after calling free_key()? */
        if (entry.key != last_key) {
            *entry.key = last_key;
            *entry.value = bucket->values[bucket->used - 1];
            *entry.hashval = bucket->hashvals[bucket->used - 1];
        }
    }

    bucket->used--;
    hash->count--;

    if (need_rehash_shrink(hash))
        rehash(hash, hash_n_buckets(hash) / 2);

    return 0;
}

unsigned int hash_get_count(const struct hash *hash) { return hash->count; }

void hash_iter_init(const struct hash *hash, struct hash_iter *iter)
{
    iter->hash = hash;
    iter->bucket = 0;
    iter->entry = -1;
}

bool hash_iter_next(struct hash_iter *iter,
                    const void **key,
                    const void **value)
{
    const struct hash_bucket *b = iter->hash->buckets + iter->bucket;

    iter->entry++;

    if ((unsigned int)iter->entry >= b->used) {
        unsigned int n_buckets = hash_n_buckets(iter->hash);

        iter->entry = 0;

        for (iter->bucket++; iter->bucket < n_buckets; iter->bucket++) {
            b = iter->hash->buckets + iter->bucket;

            if (b->used > 0)
                break;
        }

        if (iter->bucket >= n_buckets)
            return false;
    }

    if (value != NULL)
        *value = b->values[iter->entry];
    if (key != NULL)
        *key = b->keys[iter->entry];

    return true;
}
