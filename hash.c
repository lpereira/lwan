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

static const unsigned n_buckets = 512;
static const unsigned steps = 64;

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
	unsigned (*hash_value)(const void *key);
	int (*key_compare)(const void *k1, const void *k2);
	void (*free_value)(void *value);
	void (*free_key)(void *value);
	struct hash_bucket buckets[];
};

static inline unsigned hash_int(const void *keyptr)
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
static inline unsigned hash_crc32(const void *keyptr)
{
	unsigned hash = 0xABAD1DEA;
	const char *key = keyptr;
	size_t len = strlen(key);

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
#endif

static inline int hash_int_key_cmp(const void *k1, const void *k2)
{
	int a = (int)(long)k1;
	int b = (int)(long)k2;
	return a - b;
}

static struct hash *hash_internal_new(
			unsigned (*hash_value)(const void *key),
			int (*key_compare)(const void *k1, const void *k2),
			void (*free_key)(void *value),
			void (*free_value)(void *value))
{
	struct hash *hash = calloc(1, sizeof(struct hash) +
				n_buckets * sizeof(struct hash_bucket));
	if (hash == NULL)
		return NULL;
	hash->hash_value = hash_value;
	hash->key_compare = key_compare;
	hash->free_value = free_value;
	hash->free_key = free_key;
	return hash;
}

struct hash *hash_int_new(void (*free_key)(void *value),
			void (*free_value)(void *value))
{
	return hash_internal_new(hash_int,
			hash_int_key_cmp,
			free_key,
			free_value);
}

struct hash *hash_str_new(void (*free_key)(void *value),
			void (*free_value)(void *value))
{
	return hash_internal_new(
#ifdef USE_HARDWARE_CRC32
			hash_crc32,
#else
			murmur3_simple,
#endif
			(int (*)(const void *, const void *))strcmp,
			free_key,
			free_value);
}

void hash_free(struct hash *hash)
{
	struct hash_bucket *bucket, *bucket_end;

	if (hash == NULL)
		return;

	bucket = hash->buckets;
	bucket_end = bucket + n_buckets;
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
	unsigned hashval = hash->hash_value(key);
	unsigned pos = hashval & (n_buckets - 1);
	struct hash_bucket *bucket = hash->buckets + pos;
	struct hash_entry *entry, *entry_end;

	if (bucket->used + 1 >= bucket->total) {
		unsigned new_total = bucket->total + steps;
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
		int c = hash->key_compare(key, entry->key);
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
	unsigned hashval = hash->hash_value(key);
	unsigned pos = hashval & (n_buckets - 1);
	struct hash_bucket *bucket = hash->buckets + pos;
	struct hash_entry *entry, *entry_end;

	if (bucket->used + 1 >= bucket->total) {
		unsigned new_total = bucket->total + steps;
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
		int c = hash->key_compare(key, entry->key);
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
								unsigned hashval)
{
	unsigned pos = hashval & (n_buckets - 1);
	const struct hash_bucket *bucket = hash->buckets + pos;
	size_t lower_bound = 0;
	size_t upper_bound = bucket->used;

	while (lower_bound < upper_bound) {
		size_t idx = (lower_bound + upper_bound) / 2;
		const struct hash_entry *ptr = bucket->entries + idx;
		int cmp = hash->key_compare(key, ptr->key);
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

	entry = hash_find_entry(hash, key, hash->hash_value(key));
	if (entry)
		return (void *)entry->value;
	return NULL;
}

int hash_del(struct hash *hash, const void *key)
{
	unsigned hashval = hash->hash_value(key);
	unsigned pos = hashval & (n_buckets - 1);
	unsigned steps_used, steps_total;
	struct hash_bucket *bucket = hash->buckets + pos;
	struct hash_entry *entry, *entry_end;

	entry = hash_find_entry(hash, key, hashval);
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

	steps_used = bucket->used / steps;
	steps_total = bucket->total / steps;
	if (steps_used + 1 < steps_total) {
		size_t size = (steps_used + 1) *
			steps * sizeof(struct hash_entry);
		struct hash_entry *tmp = realloc(bucket->entries, size);
		if (tmp) {
			bucket->entries = tmp;
			bucket->total = (steps_used + 1) * steps;
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

		for (iter->bucket++; iter->bucket < n_buckets;
							iter->bucket++) {
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
