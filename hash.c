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

#include "hash.h"

#ifndef USE_HARDWARE_CRC32
#include "murmur3.h"
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

struct hash_entry {
	const char *key;
	const void *value;
};

struct hash_bucket {
	struct hash_entry *entries;
	unsigned used;
	unsigned total;
};

struct hash {
	unsigned count;
	unsigned step;
	unsigned n_buckets;
	unsigned (*hash_value)(const void *key, unsigned len);
	int (*key_compare)(const void *k1, const void *k2, size_t len);
	int (*key_length)(const void *key);
	void (*free_value)(void *value);
	void (*free_key)(void *value);
	struct hash_bucket buckets[];
};

static inline unsigned hash_int(const void *keyptr, unsigned len __attribute__((unused)))
{
	/* http://www.concentric.net/~Ttwang/tech/inthash.htm */
	int key = (int)(long)keyptr;
	int c2 = 0x27d4eb2d; // a prime or an odd constant

	key = (key ^ 61) ^ (key >> 16);
	key += key << 3;
	key ^= key >> 4;
	key *= c2;
	key ^= key >> 15;
	return key;
}

#ifdef USE_HARDWARE_CRC32
static inline unsigned hash_crc32(const void *keyptr, unsigned len)
{
	unsigned hash = 0xABAD1DEA;
	const char *key = keyptr;

	while (len >= sizeof(uint32_t)) {
		hash = __builtin_ia32_crc32si(hash, *((uint32_t *)key));
		key += sizeof(uint32_t);
		len -= sizeof(uint32_t);
	}
	if (len >= sizeof(uint16_t)) {
		hash = __builtin_ia32_crc32hi(hash, *((uint16_t *)key));
		key += sizeof(uint16_t);
		len -= sizeof(uint16_t);
	}
	if (len)
		hash = __builtin_ia32_crc32qi(hash, *key);

	return hash;
}

static inline unsigned calculate_pos(unsigned hash,
			unsigned n_buckets __attribute__((unused)))
{
	return __builtin_popcount(hash);
}
#else
static inline unsigned calculate_pos(unsigned hash, unsigned n_buckets)
{
	return hash % n_buckets;
}
#endif

static inline int hash_int_key_cmp(const void *k1, const void *k2, size_t len __attribute__((unused)))
{
	int a = (int)(long)k1;
	int b = (int)(long)k2;
	return a - b;
}

static int hash_int_length(const void *key __attribute__((unused)))
{
	return sizeof(int);
}

static struct hash *hash_internal_new(unsigned n_buckets,
					unsigned (*hash_value)(const void *key, unsigned len),
					int (*key_compare)(const void *k1, const void *k2, size_t len),
					int (*key_length)(const void *key),
					void (*free_key)(void *value),
					void (*free_value)(void *value))
{
	struct hash *hash = calloc(1, sizeof(struct hash) +
				n_buckets * sizeof(struct hash_bucket));
	if (hash == NULL)
		return NULL;
	hash->hash_value = hash_value;
	hash->key_compare = key_compare;
	hash->key_length = key_length;
	hash->free_value = free_value;
	hash->free_key = free_key;

#ifdef USE_HARDWARE_CRC32
	hash->n_buckets = 32;
	hash->step = 8;
#else
	hash->n_buckets = n_buckets;
	hash->step = n_buckets / 32;
	if (hash->step == 0)
		hash->step = 4;
	else if (hash->step > 64)
		hash->step = 64;
#endif
	return hash;
}

struct hash *hash_int_new(unsigned n_buckets,
					void (*free_key)(void *value),
					void (*free_value)(void *value))
{
	return hash_internal_new(n_buckets,
			hash_int,
			hash_int_key_cmp,
			hash_int_length,
			free_key,
			free_value);
}

struct hash *hash_str_new(unsigned n_buckets,
					void (*free_key)(void *value),
					void (*free_value)(void *value))
{
	return hash_internal_new(n_buckets,
#ifdef USE_HARDWARE_CRC32
			hash_crc32,
#else
			murmur3_simple,
#endif
			(int (*)(const void *, const void *, size_t))strncmp,
			(int (*)(const void *))strlen,
			free_key,
			free_value);
}

void hash_free(struct hash *hash)
{
	struct hash_bucket *bucket, *bucket_end;

	if (hash == NULL)
		return;

	bucket = hash->buckets;
	bucket_end = bucket + hash->n_buckets;
	for (; bucket < bucket_end; bucket++) {
		if (hash->free_value) {
			struct hash_entry *entry, *entry_end;
			entry = bucket->entries;
			entry_end = entry + bucket->used;
			for (; entry < entry_end; entry++) {
				hash->free_value((void *)entry->value);
				if (hash->free_key)
					hash->free_key((void *)entry->key);
			}
		}
		free(bucket->entries);
	}
	free(hash);
}

/*
 * add or replace key in hash map.
 *
 * none of key or value are copied, just references are remembered as is,
 * make sure they are live while pair exists in hash!
 */
int hash_add(struct hash *hash, const void *key, const void *value)
{
	unsigned keylen = hash->key_length(key);
	unsigned hashval = hash->hash_value(key, keylen);
	unsigned pos = calculate_pos(hashval, hash->n_buckets);
	struct hash_bucket *bucket = hash->buckets + pos;
	struct hash_entry *entry, *entry_end;

	if (bucket->used + 1 >= bucket->total) {
		unsigned new_total = bucket->total + hash->step;
		size_t size = new_total * sizeof(struct hash_entry);
		struct hash_entry *tmp = realloc(bucket->entries, size);
		if (tmp == NULL)
			return -errno;
		bucket->entries = tmp;
		bucket->total = new_total;
	}

	entry = bucket->entries;
	entry_end = entry + bucket->used;
	for (; entry < entry_end; entry++) {
		int c = hash->key_compare(key, entry->key, keylen);
		if (c == 0) {
			if (hash->free_value)
				hash->free_value((void *)entry->value);
			entry->value = value;
			return 0;
		} else if (c < 0) {
			memmove(entry + 1, entry,
				(entry_end - entry) * sizeof(struct hash_entry));
			break;
		}
	}

	entry->key = key;
	entry->value = value;
	bucket->used++;
	hash->count++;
	return 0;
}

/* similar to hash_add(), but fails if key already exists */
int hash_add_unique(struct hash *hash, const void *key, const void *value)
{
	unsigned keylen = hash->key_length(key);
	unsigned hashval = hash->hash_value(key, keylen);
	unsigned pos = calculate_pos(hashval, hash->n_buckets);
	struct hash_bucket *bucket = hash->buckets + pos;
	struct hash_entry *entry, *entry_end;

	if (bucket->used + 1 >= bucket->total) {
		unsigned new_total = bucket->total + hash->step;
		size_t size = new_total * sizeof(struct hash_entry);
		struct hash_entry *tmp = realloc(bucket->entries, size);
		if (tmp == NULL)
			return -errno;
		bucket->entries = tmp;
		bucket->total = new_total;
	}

	entry = bucket->entries;
	entry_end = entry + bucket->used;
	for (; entry < entry_end; entry++) {
		int c = hash->key_compare(key, entry->key, keylen);
		if (c == 0)
			return -EEXIST;
		else if (c < 0) {
			memmove(entry + 1, entry,
				(entry_end - entry) * sizeof(struct hash_entry));
			break;
		}
	}

	entry->key = key;
	entry->value = value;
	bucket->used++;
	hash->count++;
	return 0;
}

static inline struct hash_entry *hash_find_entry(const struct hash *hash,
								const char *key,
								unsigned hashval,
								unsigned keylen)
{
	unsigned pos = calculate_pos(hashval, hash->n_buckets);
	const struct hash_bucket *bucket = hash->buckets + pos;
	size_t lower_bound = 0;
	size_t upper_bound = bucket->used;

	while (lower_bound < upper_bound) {
		size_t idx = (lower_bound + upper_bound) / 2;
		const struct hash_entry *ptr = bucket->entries + idx;
		int cmp = hash->key_compare(key, ptr->key, keylen);
		if (!cmp)
			return (void *)ptr;
		if (cmp > 0)
			lower_bound = idx + 1;
		else
			upper_bound = idx;
	}

	return NULL;
}

void *hash_find(const struct hash *hash, const void *key)
{
	const struct hash_entry *entry;
	unsigned keylen = hash->key_length(key);

	entry = hash_find_entry(hash, key, hash->hash_value(key, keylen), keylen);
	if (entry)
		return (void *)entry->value;
	return NULL;
}

int hash_del(struct hash *hash, const void *key)
{
	unsigned keylen = hash->key_length(key);
	unsigned hashval = hash->hash_value(key, keylen);
	unsigned pos = calculate_pos(hashval, hash->n_buckets);
	unsigned steps_used, steps_total;
	struct hash_bucket *bucket = hash->buckets + pos;
	struct hash_entry *entry, *entry_end;

	entry = hash_find_entry(hash, key, hashval, keylen);
	if (entry == NULL)
		return -ENOENT;

	if (hash->free_value)
		hash->free_value((void *)entry->value);
	if (hash->free_key)
		hash->free_key((void *)entry->key);

	entry_end = bucket->entries + bucket->used;
	memmove(entry, entry + 1,
		(entry_end - entry) * sizeof(struct hash_entry));

	bucket->used--;
	hash->count--;

	steps_used = bucket->used / hash->step;
	steps_total = bucket->total / hash->step;
	if (steps_used + 1 < steps_total) {
		size_t size = (steps_used + 1) *
			hash->step * sizeof(struct hash_entry);
		struct hash_entry *tmp = realloc(bucket->entries, size);
		if (tmp) {
			bucket->entries = tmp;
			bucket->total = (steps_used + 1) * hash->step;
		}
	}

	return 0;
}

unsigned hash_get_count(const struct hash *hash)
{
	return hash->count;
}

void hash_iter_init(const struct hash *hash, struct hash_iter *iter)
{
	iter->hash = hash;
	iter->bucket = 0;
	iter->entry = -1;
}

bool hash_iter_next(struct hash_iter *iter, const void **key,
							const void **value)
{
	const struct hash_bucket *b = iter->hash->buckets + iter->bucket;
	const struct hash_entry *e;

	iter->entry++;

	if (iter->entry >= b->used) {
		iter->entry = 0;

		for (iter->bucket++; iter->bucket < iter->hash->n_buckets;
							iter->bucket++) {
			b = iter->hash->buckets + iter->bucket;

			if (b->used > 0)
				break;
		}

		if (iter->bucket >= iter->hash->n_buckets)
			return false;
	}

	e = b->entries + iter->entry;

	if (value != NULL)
		*value = e->value;
	if (key != NULL)
		*key = e->key;

	return true;
}

struct del_list {
	struct del_list *next;
	const void *key;
};

void hash_del_predicate(struct hash *hash,
			bool (*predicate)(const void *key, const size_t key_len, const void *data),
			const void *data)
{
	struct hash_iter iter;
	struct del_list *del_list = NULL;
	const void *key;

	hash_iter_init(hash, &iter);
	while (hash_iter_next(&iter, &key, NULL)) {
		struct del_list *node;

		if (!predicate(key, hash->key_length(key), data))
			continue;

		node = malloc(sizeof(*node));
		if (!node)
			goto out;
		node->key = key;
		node->next = del_list;
		del_list = node;
	}

out:

	while (del_list) {
		struct del_list *tmp = del_list->next;

		hash_del(hash, del_list->key);
		free(del_list);
		del_list = tmp;
	}
}
