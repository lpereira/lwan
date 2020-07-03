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
#include "ringbuffer.h"
#include "lwan-private.h"

struct lwan_pubsub_topic {
    struct list_head subscribers;
    pthread_mutex_t lock;
};

struct lwan_pubsub_msg {
    struct lwan_value value;
    int refcount;
};

DEFINE_RING_BUFFER_TYPE(lwan_pubsub_msg_ref, struct lwan_pubsub_msg *, 16)

struct lwan_pubsub_sub_queue_rb {
    struct list_node rb;
    struct lwan_pubsub_msg_ref ref;
};

struct lwan_pubsub_sub_queue {
    struct list_head rbs;
};

struct lwan_pubsub_subscriber {
    struct list_node subscriber;

    pthread_mutex_t lock;
    struct lwan_pubsub_sub_queue queue;
};

static bool lwan_pubsub_queue_init(struct lwan_pubsub_sub_queue *queue)
{
    struct lwan_pubsub_sub_queue_rb *rb;

    rb = malloc(sizeof(*rb));
    if (!rb)
        return false;

    lwan_pubsub_msg_ref_init(&rb->ref);
    list_head_init(&queue->rbs);
    list_add(&queue->rbs, &rb->rb);

    return true;
}

static bool lwan_pubsub_queue_put(struct lwan_pubsub_sub_queue *queue,
                                  const struct lwan_pubsub_msg *msg)
{
    struct lwan_pubsub_sub_queue_rb *rb;

    list_for_each (&queue->rbs, rb, rb) {
        if (lwan_pubsub_msg_ref_try_put(&rb->ref, &msg))
            return true;
    }

    rb = malloc(sizeof(*rb));
    if (!rb)
        return false;

    lwan_pubsub_msg_ref_init(&rb->ref);
    lwan_pubsub_msg_ref_put(&rb->ref, &msg);
    list_add_tail(&queue->rbs, &rb->rb);

    return true;
}

static struct lwan_pubsub_msg *
lwan_pubsub_queue_get(struct lwan_pubsub_sub_queue *queue)
{
    struct lwan_pubsub_sub_queue_rb *rb, *next;

    list_for_each_safe (&queue->rbs, rb, next, rb) {
        if (lwan_pubsub_msg_ref_empty(&rb->ref)) {
            list_del(&rb->rb);
            free(rb);
            continue;
        }

        return lwan_pubsub_msg_ref_get(&rb->ref);
    }

    return NULL;
}

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

void lwan_pubsub_msg_done(struct lwan_pubsub_msg *msg)
{
    if (!ATOMIC_DEC(msg->refcount)) {
        free(msg->value.value);
        free(msg);
    }
}

bool lwan_pubsub_publish(struct lwan_pubsub_topic *topic,
                         const void *contents,
                         size_t len)
{
    struct lwan_pubsub_msg *msg = calloc(1, sizeof(*msg));
    struct lwan_pubsub_subscriber *sub;

    if (!msg)
        return false;

    /* Initialize refcount to 1, so we can drop one ref after publishing to
     * all subscribers.  If it drops to 0, it means we didn't publish the
     * message and we can free it. */
    msg->refcount = 1;

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
        ATOMIC_INC(msg->refcount);

        pthread_mutex_lock(&sub->lock);
        if (!lwan_pubsub_queue_put(&sub->queue, msg)) {
            lwan_status_warning("Couldn't enqueue message, dropping");
            ATOMIC_DEC(msg->refcount);
        }
        pthread_mutex_unlock(&sub->lock);
    }
    pthread_mutex_unlock(&topic->lock);

    lwan_pubsub_msg_done(msg);

    return true;
}

struct lwan_pubsub_subscriber *
lwan_pubsub_subscribe(struct lwan_pubsub_topic *topic)
{
    struct lwan_pubsub_subscriber *sub = calloc(1, sizeof(*sub));

    if (!sub)
        return NULL;

    pthread_mutex_init(&sub->lock, NULL);
    lwan_pubsub_queue_init(&sub->queue);

    pthread_mutex_lock(&topic->lock);
    list_add(&topic->subscribers, &sub->subscriber);
    pthread_mutex_unlock(&topic->lock);

    return sub;
}

struct lwan_pubsub_msg *lwan_pubsub_consume(struct lwan_pubsub_subscriber *sub)
{
    struct lwan_pubsub_msg *msg;

    pthread_mutex_lock(&sub->lock);
    msg = lwan_pubsub_queue_get(&sub->queue);
    pthread_mutex_unlock(&sub->lock);

    return msg;
}

static void lwan_pubsub_unsubscribe_internal(struct lwan_pubsub_topic *topic,
                                             struct lwan_pubsub_subscriber *sub,
                                             bool take_topic_lock)
{
    struct lwan_pubsub_msg *iter;

    if (take_topic_lock)
        pthread_mutex_lock(&topic->lock);
    list_del(&sub->subscriber);
    if (take_topic_lock)
        pthread_mutex_unlock(&topic->lock);

    pthread_mutex_lock(&sub->lock);
    while ((iter = lwan_pubsub_queue_get(&sub->queue)))
        lwan_pubsub_msg_done(iter);
    pthread_mutex_unlock(&sub->lock);

    pthread_mutex_destroy(&sub->lock);
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
