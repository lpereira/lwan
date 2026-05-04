#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

struct hash;

struct hash_iter {
    const struct hash *ht;
    uint32_t slot;
};

struct hash *hash_int_new(void (*free_key)(void *value),
                          void (*free_value)(void *value));
struct hash *hash_int64_new(void (*free_key)(void *value),
                            void (*free_value)(void *value));
struct hash *hash_str_new(void (*free_key)(void *value),
                          void (*free_value)(void *value));
struct hash *hash_lwan_value_new(void (*free_key)(void *value),
                                 void (*free_value)(void *value));

struct hash *hash_custom_new(unsigned (*hash_value)(const void *key),
                             bool (*key_equal)(const void *k1, const void *k2),
                             void (*free_key)(void *value),
                             void (*free_value)(void *value));

struct hash *hash_ref(struct hash *ht);
void hash_unref(struct hash *ht);

int hash_add(struct hash *ht, const void *key, const void *value);
int hash_add_unique(struct hash *ht, const void *key, const void *value);
int hash_del(struct hash *ht, const void *key);
void *hash_find(const struct hash *ht, const void *key);
uint32_t hash_get_count(const struct hash *ht);

static inline struct hash_iter hash_iter(const struct hash *ht) {
    return (struct hash_iter){
        .ht = hash,
        .slot = 0,
    };
}
bool hash_iter_next(struct hash_iter *iter,
                    const void **key,
                    const void **value);

#define HASH_FOREACH_IMPL(hash_, iter_, key_, value_)                          \
    for (struct hash_iter iter_ = hash_iter(hash_);                            \
         hash_iter_next(&iter_, (key_), (value_));)
#define HASH_FOREACH(hash_, key_, value_)                                      \
    HASH_FOREACH_IMPL(hash_, LWAN_TMP_ID, key_, value_)

static inline uint64_t fnv1a_64(const void *buffer, size_t len)
{
    const unsigned char *data = (unsigned char *)buffer;
    extern uint64_t fnv1a_64_seed;
    uint64_t hash;

    for (hash = fnv1a_64_seed; len--; data++) {
        hash = (hash ^ *data) * 0x100000001b3ul;
    }

    return hash;
}

static inline uint32_t fnv1a_32(const void *buffer, size_t len)
{
    const unsigned char *data = (unsigned char *)buffer;
    extern uint32_t fnv1a_32_seed;
    uint32_t hash;

    for (hash = fnv1a_32_seed; len--; data++) {
        hash = (hash ^ *data) * 0x1000193u;
    }

    return hash;
}
