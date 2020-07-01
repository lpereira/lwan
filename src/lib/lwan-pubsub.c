/*
 * lwan - simple web server
 * Copyright (c) 2020 Leandro A. F. Pereira <leandro@hardinfo.org>
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

#include <pthread.h>

#include "list.h"
#include "lwan-private.h"

struct lwan_pubsub_topic {
    struct list_head subscribers;
    pthread_mutex_t lock;
};

struct lwan_pubsub_msg {
    struct lwan_value value;
    int refcount;
};

struct lwan_pubsub_sub_msg {
    struct list_node message;
    struct lwan_pubsub_msg *msg;
};

struct lwan_pubsub_subscriber {
    struct list_node subscriber;

    struct list_head messages;
    pthread_mutex_t lock;
};

static void lwan_pubsub_unsubscribe_internal(struct lwan_pubsub_topic *topic,
                                             struct lwan_pubsub_subscriber *sub,
                                             bool take_topic_lock);

struct lwan_pubsub_topic *lwan_pubsub_new_topic(void)
{
    struct lwan_pubsub_topic *topic = calloc(1, sizeof(*topic));

    if (!topic)
        return NULL;

    list_head_init(&topic->subscribers);
    pthread_mutex_init(&topic->lock, NULL);

    return topic;
}

void lwan_pubsub_free_topic(struct lwan_pubsub_topic *topic)
{
    struct lwan_pubsub_subscriber *iter, *next;

    pthread_mutex_lock(&topic->lock);
    list_for_each_safe (&topic->subscribers, iter, next, subscriber)
        lwan_pubsub_unsubscribe_internal(topic, iter, false);
    pthread_mutex_unlock(&topic->lock);

    pthread_mutex_destroy(&topic->lock);

    free(topic);
}

static void *my_memdup(const void *src, size_t len)
{
    void *dup = malloc(len);

    return dup ? memcpy(dup, src, len) : NULL;
}

bool lwan_pubsub_publish(struct lwan_pubsub_topic *topic,
                         const void *contents,
                         size_t len)
{
    struct lwan_pubsub_msg *msg = calloc(1, sizeof(*msg));
    struct lwan_pubsub_subscriber *sub;
    bool published = false;

    if (!msg)
        return false;

    msg->value = (struct lwan_value){
        .value = my_memdup(contents, len),
        .len = len,
    };
    if (!msg->value.value) {
        free(msg);
        return false;
    }

    pthread_mutex_lock(&topic->lock);
    list_for_each (&topic->subscribers, sub, subscriber) {
        struct lwan_pubsub_sub_msg *sub_msg = malloc(sizeof(*sub_msg));

        if (!sub_msg) {
            lwan_status_warning("Dropping message: couldn't allocate memory");
            continue;
        }

        published = true;
        sub_msg->msg = msg;

        pthread_mutex_lock(&sub->lock);
        msg->refcount++;
        list_add_tail(&sub->messages, &sub_msg->message);
        pthread_mutex_unlock(&sub->lock);
    }
    pthread_mutex_unlock(&topic->lock);

    if (!published)
        free(msg);

    return true;
}

struct lwan_pubsub_subscriber *
lwan_pubsub_subscribe(struct lwan_pubsub_topic *topic)
{
    struct lwan_pubsub_subscriber *sub = calloc(1, sizeof(*sub));

    if (!sub)
        return NULL;

    pthread_mutex_init(&sub->lock, NULL);
    list_head_init(&sub->messages);

    pthread_mutex_lock(&topic->lock);
    list_add(&topic->subscribers, &sub->subscriber);
    pthread_mutex_unlock(&topic->lock);

    return sub;
}

struct lwan_pubsub_msg *lwan_pubsub_consume(struct lwan_pubsub_subscriber *sub)
{
    struct lwan_pubsub_sub_msg *sub_msg;
    struct lwan_pubsub_msg *msg;

    pthread_mutex_lock(&sub->lock);
    sub_msg = list_pop(&sub->messages, struct lwan_pubsub_sub_msg, message);
    pthread_mutex_unlock(&sub->lock);

    if (sub_msg) {
        msg = sub_msg->msg;
        free(sub_msg);
        return msg;
    }

    return NULL;
}

void lwan_pubsub_msg_done(struct lwan_pubsub_msg *msg)
{
    if (!ATOMIC_DEC(msg->refcount)) {
        free(msg->value.value);
        free(msg);
    }
}

static void lwan_pubsub_unsubscribe_internal(struct lwan_pubsub_topic *topic,
                                             struct lwan_pubsub_subscriber *sub,
                                             bool take_topic_lock)
{
    struct lwan_pubsub_sub_msg *iter, *next;
    struct list_head to_free;

    if (take_topic_lock)
        pthread_mutex_lock(&topic->lock);
    list_del(&sub->subscriber);
    if (take_topic_lock)
        pthread_mutex_unlock(&topic->lock);

    list_head_init(&to_free);

    pthread_mutex_lock(&sub->lock);
    list_for_each_safe (&sub->messages, iter, next, message) {
        list_del(&iter->message);

        if (!ATOMIC_DEC(iter->msg->refcount))
            list_add(&to_free, &iter->message);
    }
    pthread_mutex_unlock(&sub->lock);
    pthread_mutex_destroy(&sub->lock);

    list_for_each_safe (&to_free, iter, next, message) {
        free(iter->msg->value.value);
        free(iter->msg);
        free(iter);
    }

    free(sub);
}

void lwan_pubsub_unsubscribe(struct lwan_pubsub_topic *topic,
                             struct lwan_pubsub_subscriber *sub)
{
    return (void)lwan_pubsub_unsubscribe_internal(topic, sub, true);
}

const struct lwan_value *lwan_pubsub_msg_value(const struct lwan_pubsub_msg *msg)
{
    return &msg->value;
}
