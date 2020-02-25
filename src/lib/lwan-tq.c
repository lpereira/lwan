/*
 * lwan - simple web server
 * Copyright (c) 2019 Leandro A. F. Pereira <leandro@hardinfo.org>
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

#include <unistd.h>

#include "lwan-private.h"
#include "lwan-tq.h"

static inline int timeout_queue_node_to_idx(struct timeout_queue *tq,
                                            struct lwan_connection *conn)
{
    return (conn == &tq->head) ? -1 : (int)(ptrdiff_t)(conn - tq->conns);
}

static inline struct lwan_connection *
timeout_queue_idx_to_node(struct timeout_queue *tq, int idx)
{
    return (idx < 0) ? &tq->head : &tq->conns[idx];
}

inline void timeout_queue_insert(struct timeout_queue *tq,
                                 struct lwan_connection *new_node)
{
    new_node->next = -1;
    new_node->prev = tq->head.prev;
    struct lwan_connection *prev = timeout_queue_idx_to_node(tq, tq->head.prev);
    tq->head.prev = prev->next = timeout_queue_node_to_idx(tq, new_node);
}

static inline void timeout_queue_remove(struct timeout_queue *tq,
                                        struct lwan_connection *node)
{
    struct lwan_connection *prev = timeout_queue_idx_to_node(tq, node->prev);
    struct lwan_connection *next = timeout_queue_idx_to_node(tq, node->next);

    next->prev = node->prev;
    prev->next = node->next;

    node->next = node->prev = -1;
}

bool timeout_queue_empty(struct timeout_queue *tq) { return tq->head.next < 0; }

void timeout_queue_move_to_last(struct timeout_queue *tq,
                                struct lwan_connection *conn)
{
    /* CONN_IS_KEEP_ALIVE isn't checked here because non-keep-alive connections
     * are closed in the request processing coroutine after they have been
     * served.  In practice, if this is called, it's a keep-alive connection. */
    conn->time_to_expire = tq->current_time + tq->move_to_last_bump;

    timeout_queue_remove(tq, conn);
    timeout_queue_insert(tq, conn);
}

void timeout_queue_init(struct timeout_queue *tq, const struct lwan *lwan)
{
    *tq = (struct timeout_queue){
        .lwan = lwan,
        .conns = lwan->conns,
        .current_time = 0,
        .move_to_last_bump = lwan->config.keep_alive_timeout,
        .head.next = -1,
        .head.prev = -1,
        .timeout = (struct timeout){},
    };
}

void timeout_queue_expire(struct timeout_queue *tq,
                          struct lwan_connection *conn)
{
    timeout_queue_remove(tq, conn);

    if (LIKELY(conn->coro)) {
        coro_free(conn->coro);
        conn->coro = NULL;

        close(lwan_connection_get_fd(tq->lwan, conn));
    }
}

void timeout_queue_expire_waiting(struct timeout_queue *tq)
{
    tq->current_time++;

    while (!timeout_queue_empty(tq)) {
        struct lwan_connection *conn =
            timeout_queue_idx_to_node(tq, tq->head.next);

        if (conn->time_to_expire > tq->current_time)
            return;

        timeout_queue_expire(tq, conn);
    }

    /* Timeout queue exhausted: reset epoch */
    tq->current_time = 0;
}

void timeout_queue_expire_all(struct timeout_queue *tq)
{
    while (!timeout_queue_empty(tq)) {
        struct lwan_connection *conn =
            timeout_queue_idx_to_node(tq, tq->head.next);
        timeout_queue_expire(tq, conn);
    }
}
