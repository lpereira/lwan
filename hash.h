#pragma once

#include <stdbool.h>

struct hash;

struct hash_iter {
	const struct hash *hash;
	unsigned int bucket;
	unsigned int entry;
};

struct hash *hash_int_new(unsigned int n_buckets,
					void (*free_key)(void *value),
					void (*free_value)(void *value));
struct hash *hash_str_new(unsigned int n_buckets,
					void (*free_key)(void *value),
					void (*free_value)(void *value));
void hash_free(struct hash *hash);
int hash_add(struct hash *hash, const void *key, const void *value);
int hash_add_unique(struct hash *hash, const void *key, const void *value);
int hash_del(struct hash *hash, const void *key);
void *hash_find(const struct hash *hash, const void *key);
unsigned int hash_get_count(const struct hash *hash);
void hash_iter_init(const struct hash *hash, struct hash_iter *iter);
bool hash_iter_next(struct hash_iter *iter, const void **key,
							const void **value);
