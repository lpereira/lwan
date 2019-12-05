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

#pragma once

struct timeout_queue {
    const struct lwan *lwan;
    struct lwan_connection *conns;
    struct lwan_connection head;
    struct timeout timeout;
    unsigned time;
    unsigned short keep_alive_timeout;
};

void timeout_queue_init(struct timeout_queue *tq, const struct lwan *l);

void timeout_queue_insert(struct timeout_queue *tq,
                          struct lwan_connection *new_node);
void timeout_queue_expire(struct timeout_queue *tq, struct lwan_connection *node);
void timeout_queue_move_to_last(struct timeout_queue *tq,
                                struct lwan_connection *conn);

void timeout_queue_expire_waiting(struct timeout_queue *tq);
void timeout_queue_expire_all(struct timeout_queue *tq);

bool timeout_queue_empty(struct timeout_queue *tq);
