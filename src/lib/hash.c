/*
 * lwan - web server
 * Copyright (c) 2026 L. A. F. Pereira <l@tia.mat.br>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "hash.h"
#include "lwan-private.h"

#define INITIAL_CAP 16

struct bucket {
    const void *key;
    const void *value;
};

struct hash {
    uint8_t *tophashes;
    struct bucket *buckets;
    uint32_t len, cap;

    uint32_t (*hash)(const void *key);
    bool (*key_equal)(const void *k1, const void *k2);
    void (*free_key)(void *key);
    void (*free_value)(void *value);

    int refs;
};

uint64_t fnv1a_64_seed = 0xcbf29ce484222325ull;
uint32_t fnv1a_32_seed = 0x811c9dc5u;
LWAN_CONSTRUCTOR(randomize_seed, 65535)
{
    uint8_t entropy[128];

    /* The seeds are randomized in order to mitigate the DDoS attack
     * described by Crosby and Wallach in UsenixSec2003.  */
    if (lwan_getentropy(entropy, sizeof(entropy), 0) < 0) {
        lwan_log_critical("Couldn't randomize hash seeds!");
        __builtin_unreachable();
    }

    fnv1a_32_seed = fnv1a_32(entropy, sizeof(entropy));
    fnv1a_64_seed = fnv1a_64(entropy, sizeof(entropy));
}

static ALWAYS_INLINE uint8_t extract_tophash(const uint32_t hash)
{
    const uint8_t tophash = hash & 0xff;
    return (tophash == '\0') ? 0xa5 : tophash;
}

static uint32_t hash_str_fnv1a(const void *key)
{
    assert(key != NULL);
    return fnv1a_32(key, strlen(key));
}

static bool hash_str_eq(const void *k1, const void *k2)
{
    assert(k1 != NULL);
    assert(k2 != NULL);
    return !strcmp(k1, k2);
}

static uint32_t hash_int_fnv1a(const void *key)
{
    int k = (int)(intptr_t)key;
    return fnv1a_32(&k, sizeof(k));
}

static bool hash_int_eq(const void *k1, const void *k2)
{
    int i1 = (int)(intptr_t)k1;
    int i2 = (int)(intptr_t)k2;
    return i1 == i2;
}

static uint32_t hash_lwan_value_fnv1a(const void *key)
{
    assert(key != NULL);
    const struct lwan_value *v = key;
    return fnv1a_32(v->value, v->len);
}

static bool hash_lwan_value_eq(const void *k1, const void *k2)
{
    const struct lwan_value *v1 = k1;
    const struct lwan_value *v2 = k2;
    if (v1->len == v2->len)
        return !memcmp(v1->value, v2->value, v1->len);
    return false;
}

static uint32_t (*hash_str)(const void *ptr) = hash_str_fnv1a;
static uint32_t (*hash_int)(const void *ptr) = hash_int_fnv1a;
static uint32_t (*hash_lwan_value)(const void *ptr) = hash_lwan_value_fnv1a;

#if defined(LWAN_HAVE_BUILTIN_CPU_INIT) && defined(LWAN_HAVE_BUILTIN_IA32_CRC32)
static uint32_t hash_crc32(const void *ptr, size_t len)
{
    uint32_t hash = fnv1a_32_seed;
    const char *p = ptr;

#if defined(__x86_64__)
    while (len >= 8) {
        hash = (uint32_t)__builtin_ia32_crc32di(hash, string_as_uint64(p));
        p += 8;
        len -= 8;
    }
#endif
    while (len >= 4) {
        hash = __builtin_ia32_crc32si(hash, string_as_uint32(p));
        p += 4;
        len -= 4;
    }
    if (len & 1) {
        /* If we have 1 or 3 bytes left */
        hash = __builtin_ia32_crc32qi(hash, (uint8_t)*p);
        p++;
        len--;
    }
    if (len) {
        /* If len was 3 in the previous check, len will be 2 here.
         * If len was 2 in the previous check, len will be 2 here.
         * If len was 1 in the previous check, this block won't be executed.
         */
        hash = __builtin_ia32_crc32hi(hash, string_as_uint16(p));
    }

    return hash;
}

static uint32_t hash_str_crc32(const void *key)
{
    return hash_crc32(key, strlen(key));
}

static uint32_t hash_int_crc32(const void *key)
{
    int k = (int)(intptr_t)key;
    return __builtin_ia32_crc32si(fnv1a_32_seed, (uint32_t)k);
}

static uint32_t hash_lwan_value_crc32(const void *key)
{
    assert(key != NULL);
    const struct lwan_value *v = key;
    return hash_crc32(v->value, v->len);
}

LWAN_CONSTRUCTOR(detect_crc32, 65534)
{
    __builtin_cpu_init();
    if (__builtin_cpu_supports("sse4.2")) {
        hash_str = hash_str_crc32;
        hash_int = hash_int_crc32;
        hash_lwan_value = hash_lwan_value_crc32;
    }
}
#endif

static void free_key_value_noop(void *unused) {}

struct hash *hash_custom_new(uint32_t (*hash)(const void *key),
                             bool (*key_equal)(const void *k1, const void *k2),
                             void (*free_key)(void *key),
                             void (*free_value)(void *value))
{
    struct hash *ht;
    struct bucket *buckets;
    uint8_t *tophashes;

    if (UNLIKELY(!hash)) {
        lwan_log_error("hash() not provided to hash_custom_new()");
        return NULL;
    }
    if (UNLIKELY(!key_equal)) {
        lwan_log_error("key_equal() not provided to hash_custom_new()");
        return NULL;
    }

    ht = malloc(sizeof(*ht));
    if (UNLIKELY(!ht))
        goto no_hash_table;

    buckets = calloc(INITIAL_CAP, sizeof(struct bucket));
    if (UNLIKELY(!buckets))
        goto no_buckets;
    tophashes = calloc(INITIAL_CAP, sizeof(uint8_t));
    if (UNLIKELY(!tophashes))
        goto no_tophashes;

    *ht = (struct hash){
        .cap = INITIAL_CAP,
        .len = 0,
        .refs = 1,
        .buckets = buckets,
        .tophashes = tophashes,
        .hash = hash,
        .key_equal = key_equal,
        .free_key = free_key ? free_key : free_key_value_noop,
        .free_value = free_value ? free_value : free_key_value_noop,
    };
    return ht;

no_tophashes:
    free(buckets);
no_buckets:
    free(ht);
no_hash_table:
    return NULL;
}

struct hash *hash_str_new(void (*free_key)(void *key),
                          void (*free_value)(void *value))
{
    return hash_custom_new(hash_str, hash_str_eq, free_key, free_value);
}

struct hash *hash_int_new(void (*free_key)(void *key),
                          void (*free_value)(void *value))
{
    return hash_custom_new(hash_int, hash_int_eq, free_key, free_value);
}

struct hash *hash_lwan_value_new(void (*free_key)(void *key),
                                 void (*free_value)(void *value))
{
    return hash_custom_new(hash_lwan_value, hash_lwan_value_eq, free_key,
                           free_value);
}

struct hash *hash_ref(struct hash *ht)
{
    if (ht) {
        ht->refs++;
    }
    return ht;
}

void hash_unref(struct hash *ht)
{
    if (!ht) {
        return;
    }
    ht->refs--;
    if (ht->refs == 0) {
        const void *key, *value;

        HASH_FOREACH (ht, &key, &value) {
            ht->free_key((void *)key);
            ht->free_value((void *)value);
        }

        free(ht->tophashes);
        free(ht->buckets);
        free(ht);
    }
}

static struct bucket *hash_probe_half(const struct hash *ht,
                                      const void *key,
                                      const uint32_t startpos,
                                      const uint32_t endpos,
                                      const uint8_t tophash)
{
    /* FIXME: While using memchr() here is fine (and portable), the second call
     * to memchr() in the presence of a collision won't reuse the memory load
     * the first memchr() made (plus all the work to establish comparison masks
     * and other stuff that might be necessary for a SIMD implementation).
     * Rewrite this so this used SIMD intrinsics directly. */
    const uint8_t *slotptr =
        memchr(ht->tophashes + startpos, tophash, endpos - startpos);

    assert(tophash != '\0');

    while (slotptr) {
        ptrdiff_t slot = slotptr - ht->tophashes;
        struct bucket *bucket = &ht->buckets[slot];
        if (LIKELY(ht->key_equal(bucket->key, key))) {
            return bucket;
        }
        assert(endpos != slot);
        slotptr = memchr(slotptr + 1, tophash, endpos - (size_t)slot - 1);
    }

    return NULL;
}

static struct bucket *hash_probe_half_tombstone(const struct hash *ht,
                                                const uint32_t startpos,
                                                const uint32_t endpos)
{
    const uint8_t *slotptr =
        memchr(ht->tophashes + startpos, '\0', endpos - startpos);

    return LIKELY(slotptr) ? &ht->buckets[slotptr - ht->tophashes] : NULL;
}

static struct bucket *hash_probe_key(const struct hash *ht,
                                     const void *key,
                                     const uint32_t startpos,
                                     const uint8_t tophash,
                                     bool deleting)
{
    struct bucket *bucket;

    bucket = hash_probe_half(ht, key, startpos, ht->cap, tophash);
    if (bucket) {
        return bucket;
    }

    bucket = hash_probe_half(ht, key, 0, startpos, tophash);
    if (bucket && !deleting) {
        /* As items are removed, buckets in the first half may become empty; in
         * that case, move the contents of the bucket in the second half to the
         * first half so probes happen more often in the [startpos..cap]
         * interval.
         *
         * This also happens when the table has been resized: no eager rehashing
         * is performed, so items will either be where they were before the
         * resize, or were moved to the first available slot.  This is very likely
         * to leave items in the wrong position hoping that probing will lazily
         * position them where they should ultimately land. */
        uint8_t *tombstone =
            memchr(ht->tophashes + startpos, '\0', ht->cap - startpos);
        if (tombstone) {
            uint32_t new_slot = (uint32_t)(tombstone - ht->tophashes);
            uint32_t old_slot = (uint32_t)(bucket - ht->buckets);
            struct bucket *new_bucket = &ht->buckets[new_slot];

            ht->tophashes[old_slot] = '\0';
            ht->tophashes[new_slot] = tophash;
            *new_bucket = *bucket;

            return new_bucket;
        }
    }

    return bucket;
}

static struct bucket *hash_probe_tombstone(const struct hash *ht,
                                           const uint32_t startpos)
{
    return hash_probe_half_tombstone(ht, startpos, ht->cap)
               ?: hash_probe_half_tombstone(ht, 0, startpos);
}

static struct bucket *
hash_probe(const struct hash *ht, const void *key, bool deleting)
{
    const uint32_t hash = ht->hash(key);
    const uint32_t startpos = (hash >> 8) & (ht->cap - 1);
    return hash_probe_key(ht, key, startpos, extract_tophash(hash),
                          deleting);
}

static int hash_resize(struct hash *ht, const uint32_t newcap)
{
    struct bucket *newbuckets;
    uint8_t *newtophashes;

    assert(ht->cap != newcap);

    if (UNLIKELY(ht->len >= newcap)) {
        return -ENOSPC;
    }

    if (ht->cap > newcap) {
        /* When shrinking the table, we need to move all elements from the
         * area we're getting rid of to somewhere in the beginning.  We use
         * a first fit strategy here, in the hope that hash_probe() puts the
         * item where it actually belongs.  Things are done this way to
         * avoid re-hashing the table.  */
        uint8_t *tombstone = memchr(ht->tophashes, '\0', newcap);

        for (uint32_t old_slot = newcap; old_slot < ht->cap; old_slot++) {
            if (ht->tophashes[old_slot] == '\0') {
                continue;
            }
            if (UNLIKELY(!tombstone)) {
                lwan_log_critical(
                    "Couldn't find tombstone when shrinking hash table");
                __builtin_unreachable();
            }
            uint32_t new_slot = (uint32_t)(tombstone - ht->tophashes);
            struct bucket *new_bucket = &ht->buckets[new_slot];
            struct bucket *old_bucket = &ht->buckets[old_slot];
            *new_bucket = *old_bucket;
            ht->tophashes[new_slot] = ht->tophashes[old_slot];
            assert(newcap != new_slot);
            tombstone = memchr(tombstone + 1, '\0', newcap - new_slot - 1);
        }
    }

    newtophashes = reallocarray(ht->tophashes, newcap, 1);
    if (UNLIKELY(!newtophashes)) {
        return -ENOMEM;
    }
    ht->tophashes = newtophashes;
    if (newcap > ht->cap) {
        memset(newtophashes + ht->cap, '\0', newcap - ht->cap);
    }

    newbuckets = reallocarray(ht->buckets, newcap, sizeof(struct bucket));
    if (UNLIKELY(!newbuckets)) {
        return -ENOMEM;
    }
    ht->buckets = newbuckets;
    ht->cap = newcap;

    return 0;
}

static int hash_add_internal(struct hash *ht,
                             const void *key,
                             const void *value,
                             const bool unique)
{
    const uint32_t hash = ht->hash(key);
    const uint32_t startpos = (hash >> 8) & (ht->cap - 1);
    const uint8_t tophash = extract_tophash(hash);
    struct bucket *bucket;

    bucket = hash_probe_key(ht, key, startpos, tophash, false);
    if (bucket != NULL) {
        /* Probing found an element in the table with this key already. */
        if (unique) {
            /* Can't replace it, though! */
            return -EEXIST;
        }

        /* Replace it. */
        if (bucket->key != key) {
            ht->free_key((void *)bucket->key);
            bucket->key = key;
        }
        if (bucket->value != value) {
            ht->free_value((void *)bucket->value);
            bucket->value = value;
        }
    } else {
        /* Probing hasn't found an element; look for an empty space. */
        if (ht->len == ht->cap) {
            /* No space in the current table; try making some more */
            uint32_t newcap;
            if (UNLIKELY(__builtin_mul_overflow(ht->cap, 2, &newcap))) {
                return -ENOMEM;
            }

            int r = hash_resize(ht, newcap);
            if (UNLIKELY(r < 0)) {
                return r;
            }
        }

        bucket = hash_probe_tombstone(ht, startpos);
        if (LIKELY(bucket != NULL)) {
            ht->tophashes[bucket - ht->buckets] = tophash;
            bucket->key = key;
            bucket->value = value;
            ht->len++;
        } else {
            lwan_log_critical("Couldn't find tombstone in hash table");
            __builtin_unreachable();
        }
    }

    return 0;
}

int hash_add(struct hash *ht, const void *key, const void *value)
{
    return hash_add_internal(ht, key, value, false);
}

int hash_add_unique(struct hash *ht, const void *key, const void *value)
{
    return hash_add_internal(ht, key, value, true);
}

int hash_del(struct hash *ht, const void *key)
{
    struct bucket *bucket = hash_probe(ht, key, true);

    if (LIKELY(bucket != NULL)) {
        /* Item found! Let's remove it by tombstoning it. */
        ht->tophashes[bucket - ht->buckets] = '\0';
        ht->free_key((void *)bucket->key);
        ht->free_value((void *)bucket->value);
        ht->len--;

        /* Check if the number of items fall below a quarter of the
         * capacity (rather than half) to avoid reallocation thrashing. */
        if (ht->cap > INITIAL_CAP && ht->len < ht->cap / 4) {
            /* Failure to resize to reduce the table won't leave it
             * in an inconsistent state, so don't propagate the error.
             */
            hash_resize(ht, ht->cap / 2);
        }
        return 0;
    }

    return -ENOENT;
}

void *hash_find(const struct hash *ht, const void *key)
{
    struct bucket *bucket = hash_probe(ht, key, false);
    return LIKELY(bucket != NULL) ? (void *)bucket->value : NULL;
}

uint32_t hash_get_count(const struct hash *ht) { return ht->len; }

bool hash_iter_next(struct hash_iter *iter,
                    const void **key,
                    const void **value)
{
    while (iter->slot < iter->ht->cap) {
        const struct bucket *bucket = &iter->ht->buckets[iter->slot];
        const uint8_t tophash = iter->ht->tophashes[iter->slot];

        iter->slot++;

        if (tophash != '\0') {
            if (key) {
                *key = bucket->key;
            }
            if (value) {
                *value = bucket->value;
            }

            return true;
        }
    }

    return false;
}

#if !defined(NDEBUG)
LWAN_SELF_TEST(hash_table)
{
    struct hash *ht = hash_str_new(free, NULL);
    int r;

    assert(ht != NULL);
    assert(ht->len == 0);
    assert(ht->cap == INITIAL_CAP);

    r = hash_add(ht, strdup("foo"), "bar");
    assert(r == 0);
    assert(ht->len == 1);
    assert(ht->cap == INITIAL_CAP);

    r = hash_add(ht, strdup("bar"), "baz");
    assert(r == 0);
    assert(ht->len == 2);
    assert(ht->cap == INITIAL_CAP);

    r = hash_add(ht, strdup("foo"), "foobar");
    assert(r == 0);
    assert(ht->len == 2);
    assert(ht->cap == INITIAL_CAP);

    char *key_copy = strdup("foo");
    r = hash_add_unique(ht, key_copy, "oops");
    assert(r == -EEXIST);
    assert(ht->len == 2);
    assert(ht->cap == INITIAL_CAP);
    free(key_copy);

    const void *key, *value;
    bool has_foo = false, has_bar = false;
    uint32_t count = 0;
    HASH_FOREACH (ht, &key, &value) {
        if (!has_foo && streq((char *)key, "foo") &&
            streq((char *)value, "foobar")) {
            has_foo = true;
        } else if (!has_bar && streq((char *)key, "bar") &&
                   streq((char *)value, "baz")) {
            has_bar = true;
        } else {
            assert(0 && "Unreachable");
        }
        count++;
    }
    assert(has_foo);
    assert(has_bar);
    assert(count == ht->len);

    for (uint32_t i = 0; i < 20; i++) {
        char k[3];
        snprintf(k, 3, "%d", i);
        r = hash_add(ht, strdup(k), k);
        assert(r == 0);
        assert(ht->len == 2 + i + 1);
    }
    assert(ht->cap == 2 * INITIAL_CAP);

    count = 0;
    HASH_FOREACH (ht, &key, &value) {
        count++;
    }
    assert(count == ht->len);

    const char *v;

    v = hash_find(ht, "bar");
    assert(v != NULL);
    assert(streq(v, "baz"));

    v = hash_find(ht, "non-existent-key");
    assert(v == NULL);

    r = hash_del(ht, "foo");
    assert(r == 0);
    assert(ht->len == 21);

    r = hash_del(ht, "non-existent-key");
    assert(r == -ENOENT);
    assert(ht->len == 21);

    r = hash_del(ht, "bar");
    assert(r == 0);
    assert(ht->len == 20);

    for (uint32_t i = 0; i < 20; i++) {
        char k[3];
        snprintf(k, 3, "%d", i);

        r = hash_del(ht, k);
        assert(r == 0);
        assert(ht->len == 20 - i - 1);
    }
    assert(ht->len == 0);

    count = 0;
    HASH_FOREACH (ht, NULL, NULL) {
        count++;
    }
    assert(count == ht->len);

    assert(ht->cap == INITIAL_CAP);

    hash_unref(ht);
}
#endif
