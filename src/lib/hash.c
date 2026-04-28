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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "hash.h"
#include "lwan-private.h"

#define INITIAL_CAP 16

#define DEFAULT_FNV1A_64_SEED 0xcbf29ce484222325ull
#define DEFAULT_FNV1A_32_SEED 0x811c9dc5u

uint64_t fnv1a_64_seed = DEFAULT_FNV1A_64_SEED;
uint32_t fnv1a_32_seed = DEFAULT_FNV1A_32_SEED;

struct bucket {
    const void *key;
    const void *value;
};

struct hash {
    uint8_t *tophashes;
    uint16_t *midhashes;
    struct bucket *buckets;
    uint32_t len, cap;
    int refs;

    uint32_t (*hash)(const void *key);
    bool (*key_equal)(const void *k1, const void *k2);
    void (*free_key)(void *key);
    void (*free_value)(void *value);
};

LWAN_CONSTRUCTOR(fnv1a_seed, 65535)
{
    uint8_t entropy[128];

    if (UNLIKELY(lwan_getentropy(entropy, sizeof(entropy), 0) < 0)) {
        lwan_status_critical_perror("Could not initialize FNV1a seed");
        __builtin_unreachable();
    }

    fnv1a_64_seed = fnv1a_64(entropy, sizeof(entropy));
    fnv1a_32_seed = fnv1a_32(entropy, sizeof(entropy));
    lwan_always_bzero(entropy, sizeof(entropy));
}

static ALWAYS_INLINE uint32_t no_tombstone(uint32_t hash)
{
    /* The tophash is calculated by masking the least significant 8 bits of
     * a 32-bit hash.  A tophash of 0 is used as a "slot is free" marker,
     * so unconditionally set the least significant bit of a hash,
     * regardless of how it was computed, to ensure that it's not a
     * tombstone value. */
    return hash | 1;
}

static uint32_t hash_str(const void *key)
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

static uint32_t hash_int(const void *key)
{
    assert(key != NULL);
    int k = (int)(intptr_t)key;
    return fnv1a_32(&k, sizeof(k));
}

static bool hash_int_eq(const void *k1, const void *k2)
{
    int i1 = (int)(intptr_t)k1;
    int i2 = (int)(intptr_t)k2;
    return i1 == i2;
}

static uint32_t hash_int64(const void *key)
{
    assert(key != NULL);
    int64_t k = (int64_t)(intptr_t)key;
    return fnv1a_32(&k, sizeof(k));
}

static bool hash_int64_eq(const void *k1, const void *k2)
{
    int64_t i1 = (int64_t)(intptr_t)k1;
    int64_t i2 = (int64_t)(intptr_t)k2;
    return i1 == i2;
}

static uint32_t hash_lwan_value(const void *key)
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

static void free_key_value_noop(void *unused) {}

static struct hash *hash_new(uint32_t (*hash)(const void *key),
                             bool (*key_equal)(const void *k1, const void *k2),
                             void (*free_key)(void *key),
                             void (*free_value)(void *value))
{
    struct hash *ht;
    struct bucket *buckets;
    uint8_t *tophashes;
    uint16_t *midhashes;

    ht = malloc(sizeof(*ht));
    if (!ht)
        goto no_hash_table;


    buckets = calloc(INITIAL_CAP, sizeof(struct bucket));
    if (!buckets)
        goto no_buckets;
    tophashes = calloc(INITIAL_CAP, sizeof(uint8_t));
    if (!tophashes)
        goto no_tophashes;
    midhashes = calloc(INITIAL_CAP, sizeof(uint16_t));
    if (!midhashes)
        goto no_midhashes;

    *ht = (struct hash){
        .cap = INITIAL_CAP,
        .len = 0,
        .refs = 1,
        .buckets = buckets,
        .tophashes = tophashes,
        .midhashes = midhashes,
        .hash = hash,
        .key_equal = key_equal,
        .free_key = free_key ? free_key : free_key_value_noop,
        .free_value = free_value ? free_value : free_key_value_noop,
    };
    return ht;

no_midhashes:
    free(tophashes);
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
    return hash_new(hash_str, hash_str_eq, free_key, free_value);
}

struct hash *hash_int_new(void (*free_key)(void *key),
                          void (*free_value)(void *value))
{
    return hash_new(hash_int, hash_int_eq, free_key, free_value);
}

struct hash *hash_int64_new(void (*free_key)(void *key),
                            void (*free_value)(void *value))
{
    return hash_new(hash_int64, hash_int64_eq, free_key, free_value);
}

struct hash *hash_lwan_value_new(void (*free_key)(void *key),
                                 void (*free_value)(void *value))
{
    return hash_new(hash_lwan_value, hash_lwan_value_eq, free_key, free_value);
}

struct hash *hash_ref(struct hash *ht)
{
    ht->refs++;
    return ht;
}

void hash_unref(struct hash *ht)
{
    ht->refs--;
    if (ht->refs == 0) {
        struct hash_iter iter;
        const void *key, *value;

        hash_iter_init(ht, &iter);
        while (hash_iter_next(&iter, &key, &value)) {
            ht->free_key((void *)key);
            ht->free_value((void *)value);
        }

        free(ht->tophashes);
        free(ht->midhashes);
        free(ht->buckets);
        free(ht);
    }
}

static ALWAYS_INLINE bool key_equal(const struct hash *ht,
                                    uint32_t slot,
                                    const void *key,
                                    uint16_t midhash)
{
    return (ht->midhashes[slot] == midhash) &&
           ht->key_equal(ht->buckets[slot].key, key);
}

static int hash_add_internal(struct hash *ht,
                             const void *key,
                             const void *value,
                             bool unique)
{
    uint32_t hash = no_tombstone(ht->hash(key));
    uint16_t midhash = (uint16_t)(hash >> 8);
    uint8_t tophash = hash & 0xff;

    assert(tophash != 0);

    uint8_t *slotptr = memchr(ht->tophashes, tophash, ht->cap);
try_again:
    if (!slotptr) {
        uint32_t slot;
        /* No tophash found; look for tombstone. */
        slotptr = memchr(ht->tophashes, '\0', ht->cap);
        if (slotptr) {
            /* Tombstone found, let's reuse it. */
            slot = (uint32_t)(slotptr - ht->tophashes);
        } else {
            /* No tombstone found; add new item at the end. */

            slot = ht->len;

            if (ht->len == ht->cap) {
                /* No space in the current table; try making some more */
                uint32_t newcap;
                if (__builtin_mul_overflow(ht->cap, 2, &newcap))
                    return -ENOMEM;
                ht->cap = newcap;

                uint8_t *newtophashes =
                    reallocarray(ht->tophashes, ht->cap, sizeof(uint8_t));
                if (!newtophashes)
                    return -errno;
                ht->tophashes = newtophashes;
                memset(ht->tophashes + ht->len, '\0', ht->len);

                uint16_t *newmidhashes =
                    reallocarray(ht->midhashes, ht->cap, sizeof(uint16_t));
                if (!newmidhashes)
                    return -errno;
                ht->midhashes = newmidhashes;

                struct bucket *newbuckets =
                    reallocarray(ht->buckets, ht->cap, sizeof(struct bucket));
                if (!newbuckets)
                    return -errno;
                ht->buckets = newbuckets;
            }
        }

        assert(ht->tophashes[slot] == '\0');

        ht->tophashes[slot] = tophash;
        ht->midhashes[slot] = midhash;
        ht->buckets[slot] = (struct bucket){
            .key = key,
            .value = value,
        };
        ht->len++;
    } else {
        /* Tophash found. Should we replace the item? */
        uint32_t slot = (uint32_t)(slotptr - ht->tophashes);

        if (key_equal(ht, slot, key, midhash)) {
            /* It's the same key! We can replace the value... */
            if (unique) {
                /* ...but can we? */
                return -EEXIST;
            }
            ht->free_key((void *)ht->buckets[slot].key);
            ht->free_value((void *)ht->buckets[slot].value);
            ht->buckets[slot] = (struct bucket){
                .key = key,
                .value = value,
            };
        } else {
            /* tophash matches, but key is different. Try looking for the next
             * tophash! */
            slotptr = memchr(slotptr + 1, tophash, ht->cap - slot - 1);
            goto try_again;
        }
    }

    return 0;
}

int hash_add(struct hash *ht, const void *key, const void *value)
{
    return hash_add_internal(ht, key, value, false) == 0;
}

int hash_add_unique(struct hash *ht, const void *key, const void *value)
{
    return hash_add_internal(ht, key, value, true);
}

int hash_del(struct hash *ht, const void *key)
{
    const uint32_t hash = no_tombstone(ht->hash(key));
    const uint16_t midhash = (uint16_t)(hash >> 8);
    const uint8_t tophash = hash & 0xff;

    uint8_t *slotptr = memchr(ht->tophashes, tophash, ht->cap);
    while (slotptr) {
        uint32_t slot = (uint32_t)(slotptr - ht->tophashes);
        if (key_equal(ht, slot, key, midhash)) {
            /* Item found! Let's remove it by tombstoning it. */
            ht->tophashes[slot] = '\0';
            ht->free_key((void *)ht->buckets[slot].key);
            ht->free_value((void *)ht->buckets[slot].value);
            ht->len--;
            return 0;
        }

        /* tophash matches, but key is different. Try looking for the next
         * tophash! */
        slotptr = memchr(slotptr + 1, tophash, ht->cap - slot - 1);
    }

    return -ENOENT;
}

void *hash_find(const struct hash *ht, const void *key)
{
    const uint32_t hash = no_tombstone(ht->hash(key));
    const uint16_t midhash = (uint16_t)(hash >> 8);
    const uint8_t tophash = hash & 0xff;

    uint8_t *slotptr = memchr(ht->tophashes, tophash, ht->cap);
    while (slotptr) {
        uint32_t slot = (uint32_t)(slotptr - ht->tophashes);
        if (key_equal(ht, slot, key, midhash)) {
            return (void *)ht->buckets[slot].value;
        }
        slotptr = memchr(slotptr + 1, tophash, ht->cap - slot - 1);
    }

    return NULL;
}

uint32_t hash_get_count(const struct hash *ht) { return ht->len; }

void hash_iter_init(const struct hash *ht, struct hash_iter *iter)
{
    iter->ht = ht;
    iter->index = 0;
}

bool hash_iter_next(struct hash_iter *iter,
                    const void **key,
                    const void **value)
{
    while (iter->index < iter->ht->cap) {
        if (iter->ht->tophashes[iter->index] == '\0') {
            iter->index++;
        } else {
            if (key)
                *key = iter->ht->buckets[iter->index].key;
            if (value)
                *value = iter->ht->buckets[iter->index].value;
            iter->index++;
            return true;
        }
    }
    return false;
}
