#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

struct hash;

struct hash_iter {
    const struct hash *ht;
    size_t index;
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

struct hash *hash_ref(struct hash *hash);
void hash_unref(struct hash *hash);

int hash_add(struct hash *hash, const void *key, const void *value);
int hash_add_unique(struct hash *hash, const void *key, const void *value);
int hash_del(struct hash *hash, const void *key);
void *hash_find(const struct hash *hash, const void *key);
uint32_t hash_get_count(const struct hash *hash);
void hash_iter_init(const struct hash *hash, struct hash_iter *iter);
bool hash_iter_next(struct hash_iter *iter,
                    const void **key,
                    const void **value);

#define FNV1A_64_SEED 0xcbf29ce484222325ull
#define FNV1A_32_SEED 0x811c9dc5u

static inline uint64_t fnv1a_64(const void *buffer, size_t len)
{
    const unsigned char *data = (unsigned char *)buffer;
    uint64_t hash;

    for (hash = FNV1A_64_SEED; len--; data++) {
        hash = (hash ^ *data) * 0x100000001b3ul;
    }

    return hash;
}

static inline uint32_t fnv1a_32(const void *buffer, size_t len)
{
    const unsigned char *data = (unsigned char *)buffer;
    uint32_t hash;

    for (hash = FNV1A_32_SEED; len--; data++) {
        hash = (hash ^ *data) * 0x1000193u;
    }

    return hash;
}
