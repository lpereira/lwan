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

struct hash_entry {
    const char *key;
    const void *value;

    unsigned int hashval;
};

struct hash_bucket {
    struct hash_entry *entries;

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

static unsigned int get_random_unsigned(void)
{
    unsigned int value;

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
        struct hash_entry *entry, *entry_end;
        entry = bucket->entries;
        entry_end = entry + bucket->used;
        for (; entry < entry_end; entry++) {
            hash->free_value((void *)entry->value);
            hash->free_key((void *)entry->key);
        }
        free(bucket->entries);
    }
    free(hash->buckets);
    free(hash);
}

static struct hash_entry *hash_add_entry_hashed(struct hash *hash, const void *key,
                                                unsigned int hashval)
{
    unsigned int pos = hashval & hash->n_buckets_mask;
    struct hash_bucket *bucket = hash->buckets + pos;
    struct hash_entry *entry, *entry_end;

    if (bucket->used + 1 >= bucket->total) {
        unsigned int new_total;
        struct hash_entry *tmp;

        if (__builtin_add_overflow(bucket->total, STEPS, &new_total)) {
            errno = EOVERFLOW;
            return NULL;
        }

        tmp = reallocarray(bucket->entries, new_total, sizeof(*tmp));
        if (tmp == NULL)
            return NULL;

        bucket->entries = tmp;
        bucket->total = new_total;
    }

    entry = bucket->entries;
    entry_end = entry + bucket->used;
    for (; entry < entry_end; entry++) {
        if (hashval != entry->hashval)
            continue;
        if (!hash->key_compare(key, entry->key))
            return entry;
    }

    bucket->used++;
    hash->count++;

    entry->hashval = hashval;
    entry->key = entry->value = NULL;

    return entry;
}

static void rehash(struct hash *hash, unsigned int new_bucket_size)
{
    struct hash_bucket *buckets = calloc(new_bucket_size, sizeof(*buckets));
    const struct hash_bucket *bucket_end = hash->buckets + hash_n_buckets(hash);
    const struct hash_bucket *bucket;
    struct hash hash_copy = *hash;

    assert((new_bucket_size & (new_bucket_size - 1)) == 0);
    assert(hash_n_buckets(hash) != new_bucket_size);

    if (buckets == NULL)
        return;

    hash_copy.count = 0;
    hash_copy.n_buckets_mask = new_bucket_size - 1;
    hash_copy.buckets = buckets;

    for (bucket = hash->buckets; bucket < bucket_end; bucket++) {
        const struct hash_entry *old = bucket->entries;
        const struct hash_entry *old_end = old + bucket->used;

        for (; old < old_end; old++) {
            struct hash_entry *new;

            new = hash_add_entry_hashed(&hash_copy, old->key, old->hashval);
            if (UNLIKELY(!new))
                goto fail;

            new->key = old->key;
            new->value = old->value;
        }
    }

    /* Original table must remain untouched in the event resizing fails:
     * previous loop may return early on allocation failure, so can't free
     * bucket entry arrays there.  */
    for (bucket = hash->buckets; bucket < bucket_end; bucket++)
        free(bucket->entries);
    free(hash->buckets);

    hash->buckets = buckets;
    hash->n_buckets_mask = new_bucket_size - 1;

    assert(hash_copy.count == hash->count);

    return;

fail:
    for (bucket_end = bucket, bucket = hash->buckets; bucket < bucket_end;
         bucket++)
        free(bucket->entries);

    free(buckets);
}

static struct hash_entry *hash_add_entry(struct hash *hash, const void *key)
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
    struct hash_entry *entry = hash_add_entry(hash, key);

    if (!entry)
        return -errno;

    hash->free_value((void *)entry->value);
    hash->free_key((void *)entry->key);

    entry->key = key;
    entry->value = value;

    if (hash->count > hash->n_buckets_mask)
        rehash(hash, hash_n_buckets(hash) * 2);

    return 0;
}

/* similar to hash_add(), but fails if key already exists */
int hash_add_unique(struct hash *hash, const void *key, const void *value)
{
    struct hash_entry *entry = hash_add_entry(hash, key);

    if (!entry)
        return -errno;

    if (entry->key || entry->value)
        return -EEXIST;

    entry->key = key;
    entry->value = value;

    if (hash->count > hash->n_buckets_mask)
        rehash(hash, hash_n_buckets(hash) * 2);

    return 0;
}

static inline struct hash_entry *
hash_find_entry(const struct hash *hash, const char *key, unsigned int hashval)
{
    unsigned int pos = hashval & hash->n_buckets_mask;
    const struct hash_bucket *bucket = hash->buckets + pos;
    struct hash_entry *entry, *entry_end;

    entry = bucket->entries;
    entry_end = entry + bucket->used;
    for (; entry < entry_end; entry++) {
        if (hashval != entry->hashval)
            continue;
        if (hash->key_compare(key, entry->key) == 0)
            return entry;
    }

    return NULL;
}

void *hash_find(const struct hash *hash, const void *key)
{
    const struct hash_entry *entry;

    entry = hash_find_entry(hash, key, hash->hash_value(key));
    if (entry)
        return (void *)entry->value;
    return NULL;
}

int hash_del(struct hash *hash, const void *key)
{
    unsigned int hashval = hash->hash_value(key);
    unsigned int pos = hashval & hash->n_buckets_mask;
    struct hash_bucket *bucket = hash->buckets + pos;
    struct hash_entry *entry;

    entry = hash_find_entry(hash, key, hashval);
    if (entry == NULL)
        return -ENOENT;

    hash->free_value((void *)entry->value);
    hash->free_key((void *)entry->key);

    if (bucket->used > 1) {
        /* Instead of compacting the bucket array by moving elements, just copy
         * over the last element on top of the element being removed.  This
         * changes the ordering inside the bucket array, but it's much more
         * efficient, as it always has to copy exactly at most 1 element instead
         * of potentially bucket->used elements. */
        struct hash_entry *entry_last = bucket->entries + bucket->used - 1;

        if (entry != entry_last)
            memcpy(entry, entry_last, sizeof(*entry));
    }

    bucket->used--;
    hash->count--;

    if (hash->n_buckets_mask > (MIN_BUCKETS - 1) && hash->count < hash->n_buckets_mask / 2) {
        rehash(hash, hash_n_buckets(hash) / 2);
    } else {
        unsigned int steps_used = bucket->used / STEPS;
        unsigned int steps_total = bucket->total / STEPS;

        if (steps_used + 1 < steps_total) {
            struct hash_entry *tmp = reallocarray(
                bucket->entries, steps_used + 1, STEPS * sizeof(*tmp));
            if (tmp) {
                bucket->entries = tmp;
                bucket->total = (steps_used + 1) * STEPS;
            }
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
    const struct hash_entry *e;

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

    e = b->entries + iter->entry;

    if (value != NULL)
        *value = e->value;
    if (key != NULL)
        *key = e->key;

    return true;
}
