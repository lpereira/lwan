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
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "hash.h"
#include "lwan-private.h"

#if defined(__x86_64__)
#include <immintrin.h>
#endif

#define INITIAL_CAP 16

struct bucket {
    const void *key;
    const void *value;
};

struct hash {
    uint8_t *tophashes;
    struct bucket *buckets;
    uint32_t len, cap_shift;

    uint32_t (*hash)(const void *key);
    bool (*key_equal)(const void *k1, const void *k2);
    void (*free_key)(void *key);
    void (*free_value)(void *value);

    int refs;
};

uint64_t fnv1a_64_seed = UINT64_C(0xcbf29ce484222325);
uint32_t fnv1a_32_seed = UINT32_C(0x811c9dc5);
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
        .cap_shift = 32 - __builtin_ctz(INITIAL_CAP),
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

static ALWAYS_INLINE uint32_t hash_cap(const struct hash *ht)
{
    return 1u << (32u - ht->cap_shift);
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

#if defined(__AVX2__)
static uint32_t has_avx2;
LWAN_CONSTRUCTOR(detect_avx2, 65533)
{
    __builtin_cpu_init();
    has_avx2 = __builtin_cpu_supports("avx2");
}
#endif

static struct bucket *hash_probe_half(const struct hash *ht,
                                      const void *key,
                                      uint32_t startpos,
                                      const uint32_t endpos,
                                      const uint8_t tophash)
{
    assert(tophash != '\0');

#if defined(__AVX2__)
    if (has_avx2 && (endpos - startpos >= 32)) {
        const __m256i mask_tophash = _mm256_set1_epi8((char)tophash);
        do {
            struct bucket *start_bucket = &ht->buckets[startpos];
            const __m256i v =
                _mm256_lddqu_si256((__m256i const *)(ht->tophashes + startpos));
            uint32_t m = (uint32_t)_mm256_movemask_epi8(
                _mm256_cmpeq_epi8(v, mask_tophash));

            while (m) {
                struct bucket *bucket = &start_bucket[__builtin_ctz(m)];
                if (LIKELY(ht->key_equal(bucket->key, key))) {
                    return bucket;
                }

                m &= m - 1;
            }

            startpos += 32;
        } while (endpos - startpos >= 32);
    }
#endif

#if defined(__x86_64__)
    if (endpos - startpos >= 16) {
        const __m128i mask_tophash = _mm_set1_epi8((char)tophash);
        do {
            struct bucket *start_bucket = &ht->buckets[startpos];
#if defined(__SSE3__)
            const __m128i v =
                _mm_lddqu_si128((__m128i const *)(ht->tophashes + startpos));
#else
            const __m128i v =
                _mm_loadu_si128((__m128i const *)(ht->tophashes + startpos));
#endif
            uint32_t m =
                (uint32_t)_mm_movemask_epi8(_mm_cmpeq_epi8(v, mask_tophash));

            while (m) {
                struct bucket *bucket = &start_bucket[__builtin_ctz(m)];
                if (LIKELY(ht->key_equal(bucket->key, key))) {
                    return bucket;
                }

                m &= m - 1;
            }

            startpos += 16;
        } while (endpos - startpos >= 16);
    }
#endif

    const uint8_t *slotptr =
        memchr(ht->tophashes + startpos, tophash, endpos - startpos);
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
                                                uint32_t startpos,
                                                const uint32_t endpos)
{
#if defined(__AVX2__)
    if (has_avx2 && (endpos - startpos >= 32)) {
        const __m256i mask_tophash = _mm256_setzero_si256();
        do {
            const __m256i v =
                _mm256_lddqu_si256((__m256i const *)(ht->tophashes + startpos));
            uint32_t m = (uint32_t)_mm256_movemask_epi8(
                _mm256_cmpeq_epi8(v, mask_tophash));
            if (LIKELY(m)) {
                return &ht->buckets[startpos + (uint32_t)__builtin_ctz(m)];
            }
            startpos += 32;
        } while (endpos - startpos >= 32);
    }
#endif

#if defined(__x86_64__)
    if (endpos - startpos >= 16) {
        const __m128i mask_tophash = _mm_setzero_si128();
        do {
#if defined(__SSE3__)
            const __m128i v =
                _mm_lddqu_si128((__m128i const *)(ht->tophashes + startpos));
#else
            const __m128i v =
                _mm_loadu_si128((__m128i const *)(ht->tophashes + startpos));
#endif
            uint32_t m =
                (uint32_t)_mm_movemask_epi8(_mm_cmpeq_epi8(v, mask_tophash));
            if (LIKELY(m)) {
                return &ht->buckets[startpos + (uint32_t)__builtin_ctz(m)];
            }
            startpos += 16;
        } while (endpos - startpos >= 16);
    }
#endif

    const uint8_t *slotptr =
        memchr(ht->tophashes + startpos, '\0', endpos - startpos);

    return LIKELY(slotptr) ? &ht->buckets[slotptr - ht->tophashes] : NULL;
}

static struct bucket *hash_probe_key(const struct hash *ht,
                                     const void *key,
                                     const uint32_t startpos,
                                     const uint8_t tophash)
{
    return hash_probe_half(ht, key, startpos, hash_cap(ht), tophash)
               ?: hash_probe_half(ht, key, 0, startpos, tophash);
}

static struct bucket *hash_probe_tombstone(const struct hash *ht,
                                           const uint32_t startpos)
{
    return hash_probe_half_tombstone(ht, startpos, hash_cap(ht))
               ?: hash_probe_half_tombstone(ht, 0, startpos);
}

static struct bucket *
hash_probe(const struct hash *ht, const void *key)
{
    const uint32_t hash = ht->hash(key);
    const uint32_t startpos = hash >> ht->cap_shift;
    return hash_probe_key(ht, key, startpos, extract_tophash(hash));
}

static int hash_resize(struct hash *ht, const uint32_t newcap_shift)
{
    const uint32_t newcap = 1u << (32u - newcap_shift);
    const uint32_t oldcap = hash_cap(ht);
    struct bucket *newbuckets;
    uint8_t *newtophashes;

    assert(ht->cap_shift != newcap_shift);

    if (UNLIKELY(ht->len >= newcap)) {
        return -ENOSPC;
    }

    ht->cap_shift = newcap_shift;

    /* The hash table only has to be rehashed when being shrunk.  This is because
     * the top bits of the hash are used to determine an item's initial position,
     * making their position fixed regardless of the size of the table.  However,
     * when shrinking the table, items beyond the old capacity of the table must
     * be moved before the cut point. */
    if (newcap < oldcap) {
        uint32_t items_to_move = 0;
#ifndef NDEBUG
        const uint32_t old_len = ht->len;
#endif
        for (uint32_t old_slot = newcap; old_slot < oldcap; old_slot++) {
            items_to_move += !!ht->tophashes[old_slot];
        }
        ht->len -= items_to_move;
        for (uint32_t old_slot = newcap; old_slot < oldcap; old_slot++) {
            if (ht->tophashes[old_slot]) {
                const struct bucket *bucket = &ht->buckets[old_slot];
                hash_add(ht, bucket->key, bucket->value);
            }
        }
        assert(ht->len == old_len);
    }

    newtophashes = reallocarray(ht->tophashes, newcap, 1);
    if (UNLIKELY(!newtophashes)) {
        return -ENOMEM;
    }
    ht->tophashes = newtophashes;
    if (oldcap < newcap) {
        memset(newtophashes + oldcap, '\0', newcap - oldcap);
    }

    newbuckets = reallocarray(ht->buckets, newcap, sizeof(struct bucket));
    if (UNLIKELY(!newbuckets)) {
        return -ENOMEM;
    }
    ht->buckets = newbuckets;

    return 0;
}

static int hash_add_internal(struct hash *ht,
                             const void *key,
                             const void *value,
                             const bool unique)
{
    const uint32_t hash = ht->hash(key);
    const uint32_t startpos = hash >> ht->cap_shift;
    const uint8_t tophash = extract_tophash(hash);
    struct bucket *bucket;

    bucket = hash_probe_key(ht, key, startpos, tophash);
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
        if (ht->len == hash_cap(ht)) {
            /* No space in the current table; try making some more */
            uint32_t newcap_shift = ht->cap_shift - 1;
            if (UNLIKELY(newcap_shift > ht->cap_shift)) {
                return -ENOMEM;
            }

            int r = hash_resize(ht, newcap_shift);
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
    struct bucket *bucket = hash_probe(ht, key);

    if (LIKELY(bucket != NULL)) {
        /* Item found! Let's remove it by tombstoning it. */
        ht->tophashes[bucket - ht->buckets] = '\0';
        ht->free_key((void *)bucket->key);
        ht->free_value((void *)bucket->value);
        ht->len--;

        /* Check if the number of items fall below a quarter of the
         * capacity (rather than half) to avoid reallocation thrashing. */
        uint32_t cap = hash_cap(ht);
        if (cap > INITIAL_CAP && ht->len < cap / 4) {
            /* Failure to resize to reduce the table won't leave it
             * in an inconsistent state, so don't propagate the error.
             */
            hash_resize(ht, ht->cap_shift + 1);
        }
        return 0;
    }

    return -ENOENT;
}

void *hash_find(const struct hash *ht, const void *key)
{
    struct bucket *bucket = hash_probe(ht, key);
    return LIKELY(bucket != NULL) ? (void *)bucket->value : NULL;
}

uint32_t hash_get_count(const struct hash *ht) { return ht->len; }

bool hash_iter_next(struct hash_iter *iter,
                    const void **key,
                    const void **value)
{
    const uint32_t cap = hash_cap(iter->ht);
    while (iter->slot < cap) {
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
    assert(hash_cap(ht) == INITIAL_CAP);

    r = hash_add(ht, strdup("foo"), "bar");
    assert(r == 0);
    assert(ht->len == 1);
    assert(hash_cap(ht) == INITIAL_CAP);

    r = hash_add(ht, strdup("bar"), "baz");
    assert(r == 0);
    assert(ht->len == 2);
    assert(hash_cap(ht) == INITIAL_CAP);

    r = hash_add(ht, strdup("foo"), "foobar");
    assert(r == 0);
    assert(ht->len == 2);
    assert(hash_cap(ht) == INITIAL_CAP);

    char *key_copy = strdup("foo");
    r = hash_add_unique(ht, key_copy, "oops");
    assert(r == -EEXIST);
    assert(ht->len == 2);
    assert(hash_cap(ht) == INITIAL_CAP);
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
    assert(hash_cap(ht) == 2 * INITIAL_CAP);

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

    assert(hash_cap(ht) == INITIAL_CAP);

    hash_unref(ht);
}
#endif
