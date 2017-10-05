/*
 * lwan - simple web server
 * Copyright (c) 2012 Leandro A. F. Pereira <leandro@hardinfo.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

struct lwan_trie_node {
    struct lwan_trie_node *next[8];
    struct lwan_trie_leaf *leaf;
    int ref_count;
};

struct lwan_trie_leaf {
    char *key;
    void *data;
    struct lwan_trie_leaf *next;
};

struct lwan_trie {
    struct lwan_trie_node *root;
    void (*free_node)(void *data);
};

bool		 lwan_trie_init(struct lwan_trie *trie, void (*free_node)(void *data));
void		 lwan_trie_destroy(struct lwan_trie *trie);
void		 lwan_trie_add(struct lwan_trie *trie, const char *key, void *data);
void 		*lwan_trie_lookup_full(struct lwan_trie *trie, const char *key, bool prefix);
void 		*lwan_trie_lookup_prefix(struct lwan_trie *trie, const char *key);
void		*lwan_trie_lookup_exact(struct lwan_trie *trie, const char *key);
int32_t		 lwan_trie_entry_count(struct lwan_trie *trie);

