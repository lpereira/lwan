/*
 * lwan - web server
 * Copyright (c) 2020 L. A. F. Pereira <l@tia.mat.br>
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

#include "lwan.h"

struct lwan_pubsub_topic;
struct lwan_pubsub_msg;
struct lwan_pubsub_subscriber;

struct lwan_pubsub_topic *lwan_pubsub_new_topic(void);
void lwan_pubsub_free_topic(struct lwan_pubsub_topic *topic);

bool lwan_pubsub_publish(struct lwan_pubsub_topic *topic,
                         const void *contents,
                         size_t len);
bool lwan_pubsub_publishf(struct lwan_pubsub_topic *topic,
                          const char *format,
                          ...) __attribute__((format(printf, 2, 3)));

struct lwan_pubsub_subscriber *
lwan_pubsub_subscribe(struct lwan_pubsub_topic *topic);
void lwan_pubsub_unsubscribe(struct lwan_pubsub_topic *topic,
                             struct lwan_pubsub_subscriber *sub);

struct lwan_pubsub_msg *lwan_pubsub_consume(struct lwan_pubsub_subscriber *sub);
const struct lwan_value *lwan_pubsub_msg_value(const struct lwan_pubsub_msg *msg);
void lwan_pubsub_msg_done(struct lwan_pubsub_msg *msg);

int lwan_pubsub_get_notification_fd(struct lwan_pubsub_subscriber *sub);

#define LWAN_PUBSUB_FOREACH_MSG(sub_, msg_)                                    \
    for (msg_ = lwan_pubsub_consume(sub_); msg_;                               \
         msg_ = lwan_pubsub_consume(sub_))
