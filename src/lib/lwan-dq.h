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

struct death_queue {
    const struct lwan *lwan;
    struct lwan_connection *conns;
    struct lwan_connection head;
    struct timeout timeout;
    unsigned time;
    unsigned short keep_alive_timeout;
};

void death_queue_init(struct death_queue *dq, const struct lwan *l);

void death_queue_insert(struct death_queue *dq,
                        struct lwan_connection *new_node);
void death_queue_kill(struct death_queue *dq, struct lwan_connection *node);
void death_queue_move_to_last(struct death_queue *dq,
                              struct lwan_connection *conn);

void death_queue_kill_waiting(struct death_queue *dq);
void death_queue_kill_all(struct death_queue *dq);

bool death_queue_empty(struct death_queue *dq);

