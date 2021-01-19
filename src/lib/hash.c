/*
 * Based on libkmod-hash.c from libkmod - interface to kernel module operations
 * Copyright (C) 2011-2012  ProFUSION embedded systems
 * Copyright (C) 2013 Leandro Pereira <leandro@hardinfo.org>
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
#include "murmur3.h"

struct hash_bucket {
    const void **keys;
    const void **values;
    unsigned int *hashvals;

    unsigned int used;
    unsigned int total;
};

struct hash {
    unsigned int count;
    unsigned int n_buckets_mask;

    unsigned (*hash_value)(const void *key);
    int (*key_compare)(const void *k1, const void *k2);
    void (*free_value)(void *value);
    void (*free_key)(void *value);

    struct hash_bucket *buckets;
};

struct bucket_entry {
    const struct hash_bucket *bucket;
    unsigned int entry;
};

#define MIN_BUCKETS 64

/* Due to rehashing heuristics, most hash tables won't have more than 4
 * entries in each bucket.  Use a conservative allocation threshold to
 * curb wasteful allocations */
#define STEPS 4

#define DEFAULT_ODD_CONSTANT 0x27d4eb2d

static_assert((MIN_BUCKETS & (MIN_BUCKETS - 1)) == 0,
              "Bucket size is power of 2");

static inline unsigned int hash_int_shift_mult(const void *keyptr);

static unsigned int odd_constant = DEFAULT_ODD_CONSTANT;
static unsigned (*hash_str)(const void *key) = murmur3_simple;
static unsigned (*hash_int)(const void *key) = hash_int_shift_mult;

static bool resize_bucket(struct hash_bucket *bucket, unsigned int new_size)
{
    const void **new_keys;
    const void **new_values;
    unsigned int *new_hashvals;

    new_keys = reallocarray(bucket->keys, new_size, STEPS * sizeof(void *));
    if (!new_keys)
        goto fail_no_keys;

    new_values = reallocarray(bucket->values, new_size, STEPS * sizeof(void *));
    if (!new_values)
        goto fail_no_values;

    new_hashvals =
        reallocarray(bucket->hashvals, new_size, STEPS * sizeof(unsigned int));
    if (!new_hashvals)
        goto fail_no_hashvals;

    bucket->keys = new_keys;
    bucket->values = new_values;
    bucket->hashvals = new_hashvals;
    bucket->total = new_size * STEPS;

    return true;

fail_no_hashvals:
    free(new_values);
fail_no_values:
    free(new_keys);
fail_no_keys:
    return false;
}

static unsigned int get_random_unsigned(void)
{
    unsigned int value = 0;

#if defined(SYS_getrandom)
    long int ret = syscall(SYS_getrandom, &value, sizeof(value), 0);
    if (ret == sizeof(value))
        return value;
#elif defined(HAVE_GETENTROPY)
    int ret = getentropy(&value, sizeof(value));
    if (ret == 0)
        return value;
#endif

    int fd = open("/dev/urandom", O_CLOEXEC | O_RDONLY);
    if (fd < 0) {
        fd = open("/dev/random", O_CLOEXEC | O_RDONLY);
        if (fd < 0)
            return DEFAULT_ODD_CONSTANT;
    }
    if (read(fd, &value, sizeof(value)) != sizeof(value))
        value = DEFAULT_ODD_CONSTANT;
    close(fd);

    return value;
}

static inline unsigned int hash_int_shift_mult(const void *keyptr)
{
    /* http://www.concentric.net/~Ttwang/tech/inthash.htm */
    unsigned int key = (unsigned int)(long)keyptr;
    unsigned int c2 = odd_constant;

    key = (key ^ 61) ^ (key >> 16);
    key += key << 3;
    key ^= key >> 4;
    key *= c2;
    key ^= key >> 15;
    return key;
}

#if defined(HAVE_BUILTIN_CPU_INIT) && defined(HAVE_BUILTIN_IA32_CRC32)
static inline unsigned int hash_str_crc32(const void *keyptr)
{
    unsigned int hash = odd_constant;
    const char *key = keyptr;
    size_t len = strlen(key);

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
    return __builtin_ia32_crc32si(odd_constant,
                                  (unsigned int)(uintptr_t)keyptr);
}
#endif

__attribute__((constructor(65535))) static void initialize_odd_constant(void)
{
    /* This constant is randomized in order to mitigate the DDoS attack
     * described by Crosby and Wallach in UsenixSec2003.  */
    odd_constant = get_random_unsigned() | 1;
    murmur3_set_seed(odd_constant);

#if defined(HAVE_BUILTIN_CPU_INIT) && defined(HAVE_BUILTIN_IA32_CRC32)
    __builtin_cpu_init();
    if (__builtin_cpu_supports("sse4.2")) {
        hash_str = hash_str_crc32;
        hash_int = hash_int_crc32;
    }
#endif
}

static inline int hash_int_key_cmp(const void *k1, const void *k2)
{
    intptr_t a = (intptr_t)k1;
    intptr_t b = (intptr_t)k2;

    return (a > b) - (a < b);
}

static void no_op(void *arg __attribute__((unused))) {}

static struct hash *
hash_internal_new(unsigned int (*hash_value)(const void *key),
                  int (*key_compare)(const void *k1, const void *k2),
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
    hash->key_compare = key_compare;

    hash->free_value = free_value;
    hash->free_key = free_key;

    hash->n_buckets_mask = MIN_BUCKETS - 1;
    hash->count = 0;

    return hash;
}

struct hash *hash_int_new(void (*free_key)(void *value),
                          void (*free_value)(void *value))
{
    return hash_internal_new(hash_int, hash_int_key_cmp,
                             free_key ? free_key : no_op,
                             free_value ? free_value : no_op);
}

struct hash *hash_str_new(void (*free_key)(void *value),
                          void (*free_value)(void *value))
{
    return hash_internal_new(
        hash_str, (int (*)(const void *, const void *))strcmp,
        free_key ? free_key : no_op, free_value ? free_value : no_op);
}

static __attribute__((pure)) inline unsigned int
hash_n_buckets(const struct hash *hash)
{
    return hash->n_buckets_mask + 1;
}

void hash_free(struct hash *hash)
{
    struct hash_bucket *bucket, *bucket_end;

    if (hash == NULL)
        return;

    bucket = hash->buckets;
    bucket_end = hash->buckets + hash_n_buckets(hash);
    for (; bucket < bucket_end; bucket++) {
        for (unsigned int entry = 0; entry < bucket->used; entry++) {
            hash->free_value((void *)bucket->values[entry]);
            hash->free_key((void *)bucket->keys[entry]);
        }
        free(bucket->keys);
        free(bucket->values);
        free(bucket->hashvals);
    }
    free(hash->buckets);
    free(hash);
}

static struct bucket_entry hash_add_entry_hashed(struct hash *hash,
                                                 const void *key,
                                                 unsigned int hashval)
{
    unsigned int pos = hashval & hash->n_buckets_mask;
    struct hash_bucket *bucket = hash->buckets + pos;

    if (bucket->used + 1 >= bucket->total) {
        if (!resize_bucket(bucket, bucket->total + 1))
            return (struct bucket_entry) {};
    }

    for (unsigned int entry = 0; entry < bucket->used; entry++) {
        if (hashval != bucket->hashvals[entry])
            continue;
        if (!hash->key_compare(key, bucket->keys[entry]))
            return (struct bucket_entry){bucket, entry};
    }

    bucket->keys[bucket->used] = NULL;
    bucket->values[bucket->used] = NULL;
    bucket->hashvals[bucket->used] = hashval;

    bucket->used++;
    hash->count++;

    return (struct bucket_entry){bucket, bucket->used - 1};
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
            struct bucket_entry new =
                hash_add_entry_hashed(&hash_copy,
                                      bucket->keys[old],
                                      bucket->hashvals[old]);
            if (UNLIKELY(!new.bucket))
                goto fail;

            new.bucket->keys[new.entry] = bucket->keys[old];
            new.bucket->values[new.entry] = bucket->values[old];
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

static struct bucket_entry hash_add_entry(struct hash *hash, const void *key)
{
    unsigned int hashval = hash->hash_value(key);

    return hash_add_entry_hashed(hash, key, hashval);
}

/*
 * add or replace key in hash map.
 *
 * none of key or value are copied, just references are remembered as is,
 * make sure they are live while pair exists in hash!
 */
int hash_add(struct hash *hash, const void *key, const void *value)
{
    struct bucket_entry entry = hash_add_entry(hash, key);

    if (!entry.bucket)
        return -errno;

    hash->free_value((void *)entry.bucket->values[entry.entry]);
    hash->free_key((void *)entry.bucket->keys[entry.entry]);

    entry.bucket->keys[entry.entry] = key;
    entry.bucket->values[entry.entry] = value;

    if (hash->count > hash->n_buckets_mask)
        rehash(hash, hash_n_buckets(hash) * 2);

    return 0;
}

/* similar to hash_add(), but fails if key already exists */
int hash_add_unique(struct hash *hash, const void *key, const void *value)
{
    struct bucket_entry entry = hash_add_entry(hash, key);

    if (!entry.bucket)
        return -errno;

    if (entry.bucket->keys[entry.entry])
        return -EEXIST;
    if (entry.bucket->values[entry.entry])
        return -EEXIST;

    entry.bucket->keys[entry.entry] = key;
    entry.bucket->values[entry.entry] = value;

    if (hash->count > hash->n_buckets_mask)
        rehash(hash, hash_n_buckets(hash) * 2);

    return 0;
}

static inline struct bucket_entry
hash_find_entry(const struct hash *hash, const char *key, unsigned int hashval)
{
    unsigned int pos = hashval & hash->n_buckets_mask;
    const struct hash_bucket *bucket = hash->buckets + pos;

    for (unsigned int entry = 0; entry < bucket->used; entry++) {
        if (hashval != bucket->hashvals[entry])
            continue;
        if (hash->key_compare(key, bucket->keys[entry]) == 0)
            return (struct bucket_entry){bucket, entry};
    }

    return (struct bucket_entry){};
}

void *hash_find(const struct hash *hash, const void *key)
{
    struct bucket_entry entry =
        hash_find_entry(hash, key, hash->hash_value(key));

    if (entry.bucket)
        return (void *)entry.bucket->values[entry.entry];

    return NULL;
}

int hash_del(struct hash *hash, const void *key)
{
    unsigned int hashval = hash->hash_value(key);
    unsigned int pos = hashval & hash->n_buckets_mask;
    struct hash_bucket *bucket = hash->buckets + pos;

    struct bucket_entry entry =
        hash_find_entry(hash, key, hashval);
    if (entry.bucket == NULL)
        return -ENOENT;

    hash->free_value((void *)entry.bucket->values[entry.entry]);
    hash->free_key((void *)entry.bucket->keys[entry.entry]);

    if (bucket->used > 1) {
        /* Instead of compacting the bucket array by moving elements, just copy
         * over the last element on top of the element being removed.  This
         * changes the ordering inside the bucket array, but it's much more
         * efficient, as it always has to copy exactly at most 1 element instead
         * of potentially bucket->used elements. */
        const unsigned int entry_last = bucket->used - 1;

        if (entry.entry != entry_last) {
            entry.bucket->keys[entry.entry] = entry.bucket->keys[entry_last];
            entry.bucket->values[entry.entry] = entry.bucket->values[entry_last];
            entry.bucket->hashvals[entry.entry] = entry.bucket->hashvals[entry_last];
        }
    }

    bucket->used--;
    hash->count--;

    if (hash->n_buckets_mask > (MIN_BUCKETS - 1) && hash->count < hash->n_buckets_mask / 2) {
        rehash(hash, hash_n_buckets(hash) / 2);
    } else {
        unsigned int steps_used = bucket->used / STEPS;
        unsigned int steps_total = bucket->total / STEPS;

        if (steps_used + 1 < steps_total) {
            unsigned int new_total;

            if (__builtin_add_overflow(steps_used, 1, &new_total))
                return -EOVERFLOW;

            resize_bucket(bucket, new_total);
        }
    }

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
