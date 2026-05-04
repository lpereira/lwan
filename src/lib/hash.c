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
        lwan_status_critical("Couldn't randomize hash seeds!");
        __builtin_unreachable();
    }

    fnv1a_32_seed = fnv1a_32(entropy, sizeof(entropy));
    fnv1a_64_seed = fnv1a_64(entropy, sizeof(entropy));
}

static ALWAYS_INLINE uint8_t no_tombstone(uint8_t tophash)
{
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

static uint32_t hash_int64_fnv1a(const void *key)
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
static uint32_t (*hash_int64)(const void *ptr) = hash_int64_fnv1a;
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

static uint32_t hash_int64_crc32(const void *key)
{
    assert(key != NULL);
    uint64_t k = (uint64_t)(uintptr_t)key;
    uint32_t hash;
#if defined(__x86_64__)
    hash = (uint32_t)__builtin_ia32_crc32di(fnv1a_32_seed, k);
#else
    hash = __builtin_ia32_crc32si(fnv1a_32_seed, (uint32_t)k);
    hash = __builtin_ia32_crc32si(hash, (uint32_t)(k >> 32));
#endif
    return hash;
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
        hash_int64 = hash_int64_crc32;
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

struct hash *hash_int64_new(void (*free_key)(void *key),
                            void (*free_value)(void *value))
{
    return hash_custom_new(hash_int64, hash_int64_eq, free_key, free_value);
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

static int hash_probe_half(const struct hash *ht,
                           const void *key,
                           uint32_t *out_slot,
                           uint32_t startpos,
                           uint32_t endpos,
                           uint8_t tophash)
{
    /* FIXME: While using memchr() here is fine (and portable), the second call
     * to memchr() in the presence of a collision won't reuse the memory load
     * the first memchr() made (plus all the work to establish comparison masks
     * and other stuff that might be necessary for a SIMD implementation).
     * Rewrite this so this used SIMD intrinsics directly. */
    uint8_t *slotptr =
        memchr(ht->tophashes + startpos, tophash, endpos - startpos);

    assert(tophash != '\0');

    while (slotptr) {
        uint32_t slot = (uint32_t)(slotptr - ht->tophashes);
        if (LIKELY(ht->key_equal(ht->buckets[slot].key, key))) {
            *out_slot = slot;
            return 0;
        }
        slotptr = memchr(slotptr + 1, tophash, endpos - slot - 1);
    }

    return -ENOENT;
}

static int hash_probe_half_tombstone(const struct hash *ht,
                                     const void *key,
                                     uint32_t *out_slot,
                                     uint32_t startpos,
                                     uint32_t endpos)
{
    uint8_t *slotptr =
        memchr(ht->tophashes + startpos, '\0', endpos - startpos);

    if (slotptr) {
        *out_slot = (uint32_t)(slotptr - ht->tophashes);
        return 0;
    }

    return -ENOENT;
}

static int hash_probe_startpos(const struct hash *ht,
                               const void *key,
                               uint32_t *out_slot,
                               uint32_t startpos,
                               uint8_t tophash)
{
    if (!hash_probe_half(ht, key, out_slot, startpos, ht->cap, tophash) ||
        !hash_probe_half(ht, key, out_slot, 0, startpos, tophash)) {
        return 0;
    }

    return -ENOENT;
}

static int hash_probe_tombstone(const struct hash *ht,
                                const void *key,
                                uint32_t *out_slot,
                                uint32_t startpos)
{
    if (!hash_probe_half_tombstone(ht, key, out_slot, startpos, ht->cap) ||
        !hash_probe_half_tombstone(ht, key, out_slot, 0, startpos)) {
        return 0;
    }

    return -ENOENT;
}

static int
hash_probe(const struct hash *ht, const void *key, uint32_t *out_slot)
{
    const uint32_t hash = ht->hash(key);
    const uint32_t startpos = (hash >> 8) & (ht->cap - 1);
    return hash_probe_startpos(ht, key, out_slot, startpos,
                               no_tombstone(hash & 0xff));
}

static int hash_resize(struct hash *ht, uint32_t newcap)
{
    struct bucket *newbuckets;
    struct hash clone = *ht;
    uint8_t *newtophashes;
    const void *k, *v;

    assert(ht->cap != newcap);

    if (UNLIKELY(ht->len >= newcap)) {
        return -ENOSPC;
    }

    newtophashes = calloc(newcap, 1);
    if (UNLIKELY(!newtophashes)) {
        return -ENOMEM;
    }

    newbuckets = calloc(newcap, sizeof(struct bucket));
    if (UNLIKELY(!newbuckets)) {
        free(newtophashes);
        return -ENOMEM;
    }

    clone.tophashes = newtophashes;
    clone.buckets = newbuckets;
    clone.len = 0;
    clone.cap = newcap;

    HASH_FOREACH (ht, &k, &v) {
        int r = hash_add(&clone, k, v);
        if (UNLIKELY(r < 0)) {
            free(newtophashes);
            free(newbuckets);
            return r;
        }
    }

    assert(ht->len == clone.len);

    free(ht->tophashes);
    free(ht->buckets);
    ht->tophashes = newtophashes;
    ht->buckets = newbuckets;
    ht->cap = newcap;

    return 0;
}

static int hash_add_internal(struct hash *ht,
                             const void *key,
                             const void *value,
                             bool unique)
{
    const uint32_t hash = ht->hash(key);
    const uint32_t startpos = (hash >> 8) & (ht->cap - 1);
    uint8_t tophash = no_tombstone(hash & 0xff);
    uint32_t slot;

    if (!hash_probe_startpos(ht, key, &slot, startpos, tophash)) {
        /* Probing found an element in the table with this key already. */
        if (unique) {
            /* Can't replace it, though! */
            return -EEXIST;
        }

        /* Replace it. */
        struct bucket *bucket = &ht->buckets[slot];
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

        if (LIKELY(!hash_probe_tombstone(ht, key, &slot, startpos))) {
            ht->tophashes[slot] = tophash;
            ht->buckets[slot] = (struct bucket){
                .key = key,
                .value = value,
            };
            ht->len++;
        } else {
            lwan_status_critical("Couldn't find tombstone in hash table");
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
    uint32_t slot;

    if (LIKELY(!hash_probe(ht, key, &slot))) {
        /* Item found! Let's remove it by tombstoning it. */
        ht->tophashes[slot] = '\0';
        ht->free_key((void *)ht->buckets[slot].key);
        ht->free_value((void *)ht->buckets[slot].value);
        ht->len--;

        if (ht->cap > INITIAL_CAP && ht->len < ht->cap / 2) {
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
    uint32_t slot;

    return LIKELY(!hash_probe(ht, key, &slot)) ? (void *)ht->buckets[slot].value
                                               : NULL;
}

uint32_t hash_get_count(const struct hash *ht) { return ht->len; }

bool hash_iter_next(struct hash_iter *iter,
                    const void **key,
                    const void **value)
{
    while (iter->slot < iter->ht->cap) {
        if (iter->ht->tophashes[iter->slot] == '\0') {
            iter->slot++;
        } else {
            if (key) {
                *key = iter->ht->buckets[iter->slot].key;
            }
            if (value) {
                *value = iter->ht->buckets[iter->slot].value;
            }
            iter->slot++;

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
