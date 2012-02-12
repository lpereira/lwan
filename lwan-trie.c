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

#include <stdio.h>
#include <stdlib.h>

#include "lwan.h"

typedef struct lwan_trie_node_t_	lwan_trie_node_t;

struct lwan_trie_node_t_ {
    void *data;
    int ref_count;
    lwan_trie_node_t *next[256];
};

struct lwan_trie_t_ {
    lwan_trie_node_t *root;
};

lwan_trie_t *
lwan_trie_new(void)
{
    return calloc(1, sizeof(lwan_trie_t));
}

void
lwan_trie_add(lwan_trie_t *trie, const char *key, void *data)
{
    if (!trie || !key || !data)
        return;

    lwan_trie_node_t **knode, *node;

    for (knode = &trie->root; ; knode = &node->next[(int)*key++]) {
        if (!(node = *knode)) {
            *knode = node = calloc(1, sizeof(*node));
            if (!node) {
                perror("calloc: trie node");
                exit(-1);
            }
        }
        ++node->ref_count;

        if (!*key) {
            node->data = data;
            return;
        }
    }
}

static void *
_lookup_node(lwan_trie_node_t *root, const char *key, bool prefix)
{
    if (!root)
        return NULL;

    lwan_trie_node_t *node, *previous_node = NULL;

    for (node = root; node && *key; node = node->next[(int)*key++])
        previous_node = node;

    if (node)
        return node;
    if (prefix && previous_node)
        return previous_node;
    return NULL;
}

ALWAYS_INLINE void *
lwan_trie_lookup_full(lwan_trie_t *trie, const char *key, bool prefix)
{
    if (!trie)
        return NULL;

    lwan_trie_node_t *node = _lookup_node(trie->root, key, prefix);
    return node ? node->data : NULL;
}

ALWAYS_INLINE void *
lwan_trie_lookup_prefix(lwan_trie_t *trie, const char *key)
{
    return lwan_trie_lookup_full(trie, key, true);
}

ALWAYS_INLINE void *
lwan_trie_lookup_exact(lwan_trie_t *trie, const char *key)
{
    return lwan_trie_lookup_full(trie, key, false);
}

ALWAYS_INLINE int32_t
lwan_trie_entry_count(lwan_trie_t *trie)
{
    return (trie && trie->root) ? trie->root->ref_count : 0;
}

static void
lwan_trie_node_destroy(lwan_trie_node_t *node)
{
    if (!node)
        return;

    int32_t i;
    int32_t nodes_destroyed = node->ref_count;

    for (i = 0; nodes_destroyed > 0 && i < 256; i++) {
        if (node->next[i]) {
            lwan_trie_node_destroy(node->next[i]);
            --nodes_destroyed;
        }
    }
    free(node);
}

void
lwan_trie_destroy(lwan_trie_t *trie)
{
    if (!trie || !trie->root)
        return;
    lwan_trie_node_destroy(trie->root);
    free(trie);
}
