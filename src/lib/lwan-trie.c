/*
 * lwan - web server
 * Copyright (c) 2012 L. A. F. Pereira <l@tia.mat.br>
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

#include <stdlib.h>
#include <string.h>

#include "lwan-private.h"

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

bool lwan_trie_init(struct lwan_trie *trie, void (*free_node)(void *data))
{
    if (!trie)
        return false;
    trie->root = NULL;
    trie->free_node = free_node;
    arena_init0(&trie->arena);
    return true;
}

static ALWAYS_INLINE struct lwan_trie_leaf *
find_leaf_with_key(struct lwan_trie_node *node, const char *key, size_t len)
{
    struct lwan_trie_leaf *leaf = node->leaf;

    if (!leaf)
        return NULL;

    if (!leaf->next) /* No collisions -- no need to strncmp() */
        return leaf;

    for (; leaf; leaf = leaf->next) {
        if (!strncmp(leaf->key, key, len - 1))
            return leaf;
    }

    return NULL;
}

#define GET_NODE()                                                             \
    do {                                                                       \
        if (!(node = *knode)) {                                                \
            *knode = node = arena_alloc(&trie->arena, sizeof(*node));          \
            if (UNLIKELY(!node))                                               \
                goto oom;                                                      \
        }                                                                      \
        ++node->ref_count;                                                     \
    } while (0)

static char *arena_strdup(struct arena *a, const char *s)
{
    size_t len = strlen(s) + 1;
    char *ptr = arena_alloc(a, len);
    if (UNLIKELY(!ptr))
        return NULL;
    memcpy(ptr, s, len);
    return ptr;
}

void lwan_trie_add(struct lwan_trie *trie, const char *key, void *data)
{
    if (UNLIKELY(!trie || !key || !data))
        return;

    struct lwan_trie_node **knode, *node;
    const char *orig_key = key;

    /* Traverse the trie, allocating nodes if necessary */
    for (knode = &trie->root; *key; knode = &node->next[(int)(*key++ & 7)])
        GET_NODE();

    /* Get the leaf node (allocate it if necessary) */
    GET_NODE();

    struct lwan_trie_leaf *leaf =
        find_leaf_with_key(node, orig_key, (size_t)(key - orig_key));
    bool had_key = leaf;
    if (!leaf) {
        leaf = arena_alloc(&trie->arena, sizeof(*leaf));
        if (UNLIKELY(!leaf))
            lwan_status_critical_perror("malloc");
    } else if (trie->free_node) {
        trie->free_node(leaf->data);
    }

    leaf->data = data;
    if (!had_key) {
        leaf->key = arena_strdup(&trie->arena, orig_key);
        leaf->next = node->leaf;
        node->leaf = leaf;
    }
    return;

oom:
    lwan_status_critical_perror("calloc");
}

#undef GET_NODE

static ALWAYS_INLINE struct lwan_trie_node *
lookup_node(struct lwan_trie_node *root, const char *key, size_t *prefix_len)
{
    struct lwan_trie_node *node, *previous_node = NULL;
    const char *orig_key = key;

    for (node = root; node && *key; node = node->next[(int)(*key++ & 7)]) {
        if (node->leaf)
            previous_node = node;
    }

    *prefix_len = (size_t)(key - orig_key);

    if (node && node->leaf)
        return node;

    return previous_node;
}

ALWAYS_INLINE void *lwan_trie_lookup_prefix(struct lwan_trie *trie,
                                            const char *key)
{
    assert(trie);
    assert(key);

    size_t prefix_len;
    struct lwan_trie_node *node = lookup_node(trie->root, key, &prefix_len);

    if (node) {
        struct lwan_trie_leaf *leaf = find_leaf_with_key(node, key, prefix_len);

        if (leaf)
            return leaf->data;
    }

    return NULL;
}

static void lwan_trie_node_destroy(struct lwan_trie *trie,
                                   struct lwan_trie_node *node)
{
    if (!node)
        return;

    int32_t nodes_destroyed = node->ref_count;

    for (struct lwan_trie_leaf *leaf = node->leaf; leaf;) {
        struct lwan_trie_leaf *tmp = leaf->next;

        if (trie->free_node)
            trie->free_node(leaf->data);

        leaf = tmp;
    }

    for (int32_t i = 0; nodes_destroyed > 0 && i < 8; i++) {
        if (node->next[i]) {
            lwan_trie_node_destroy(trie, node->next[i]);
            --nodes_destroyed;
        }
    }
}

void lwan_trie_destroy(struct lwan_trie *trie)
{
    if (!trie || !trie->root)
        return;
    lwan_trie_node_destroy(trie, trie->root);
    arena_reset(&trie->arena);
}
