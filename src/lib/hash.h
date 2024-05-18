#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

struct hash;

struct hash_iter {
    const struct hash *hash;
    unsigned int bucket;
    int entry;
};

struct hash *hash_int_new(void (*free_key)(void *value),
                          void (*free_value)(void *value));
struct hash *hash_int64_new(void (*free_key)(void *value),
                            void (*free_value)(void *value));
struct hash *hash_str_new(void (*free_key)(void *value),
                          void (*free_value)(void *value));

struct hash *hash_ref(struct hash *hash);
void hash_unref(struct hash *hash);

int hash_add(struct hash *hash, const void *key, const void *value);
int hash_add_unique(struct hash *hash, const void *key, const void *value);
int hash_del(struct hash *hash, const void *key);
void *hash_find(const struct hash *hash, const void *key);
unsigned int hash_get_count(const struct hash *hash);
void hash_iter_init(const struct hash *hash, struct hash_iter *iter);
bool hash_iter_next(struct hash_iter *iter,
                    const void **key,
                    const void **value);

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
