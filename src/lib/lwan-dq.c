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
#include "lwan-dq.h"

static inline int death_queue_node_to_idx(struct death_queue *dq,
                                          struct lwan_connection *conn)
{
    return (conn == &dq->head) ? -1 : (int)(ptrdiff_t)(conn - dq->conns);
}

static inline struct lwan_connection *
death_queue_idx_to_node(struct death_queue *dq, int idx)
{
    return (idx < 0) ? &dq->head : &dq->conns[idx];
}

void death_queue_insert(struct death_queue *dq,
                        struct lwan_connection *new_node)
{
    new_node->next = -1;
    new_node->prev = dq->head.prev;
    struct lwan_connection *prev = death_queue_idx_to_node(dq, dq->head.prev);
    dq->head.prev = prev->next = death_queue_node_to_idx(dq, new_node);
}

static void death_queue_remove(struct death_queue *dq,
                               struct lwan_connection *node)
{
    struct lwan_connection *prev = death_queue_idx_to_node(dq, node->prev);
    struct lwan_connection *next = death_queue_idx_to_node(dq, node->next);

    next->prev = node->prev;
    prev->next = node->next;

    node->next = node->prev = -1;
}

bool death_queue_empty(struct death_queue *dq) { return dq->head.next < 0; }

void death_queue_move_to_last(struct death_queue *dq,
                              struct lwan_connection *conn)
{
    /*
     * If the connection isn't keep alive, it might have a coroutine that
     * should be resumed.  If that's the case, schedule for this request to
     * die according to the keep alive timeout.
     *
     * If it's not a keep alive connection, or the coroutine shouldn't be
     * resumed -- then just mark it to be reaped right away.
     */
    conn->time_to_die = dq->time;
    if (conn->flags & (CONN_KEEP_ALIVE | CONN_SHOULD_RESUME_CORO))
        conn->time_to_die += dq->keep_alive_timeout;

    death_queue_remove(dq, conn);
    death_queue_insert(dq, conn);
}

void death_queue_init(struct death_queue *dq, const struct lwan *lwan)
{
    dq->lwan = lwan;
    dq->conns = lwan->conns;
    dq->time = 0;
    dq->keep_alive_timeout = lwan->config.keep_alive_timeout;
    dq->head.next = dq->head.prev = -1;
    dq->timeout = (struct timeout){};
}

void death_queue_kill(struct death_queue *dq, struct lwan_connection *conn)
{
    death_queue_remove(dq, conn);
    if (LIKELY(conn->coro)) {
        coro_free(conn->coro);
        conn->coro = NULL;
    }
    if (conn->flags & CONN_IS_ALIVE) {
        conn->flags &= ~CONN_IS_ALIVE;
        close(lwan_connection_get_fd(dq->lwan, conn));
    }
}

void death_queue_kill_waiting(struct death_queue *dq)
{
    dq->time++;

    while (!death_queue_empty(dq)) {
        struct lwan_connection *conn =
            death_queue_idx_to_node(dq, dq->head.next);

        if (conn->time_to_die > dq->time)
            return;

        death_queue_kill(dq, conn);
    }

    /* Death queue exhausted: reset epoch */
    dq->time = 0;
}

void death_queue_kill_all(struct death_queue *dq)
{
    while (!death_queue_empty(dq)) {
        struct lwan_connection *conn =
            death_queue_idx_to_node(dq, dq->head.next);
        death_queue_kill(dq, conn);
    }
}
