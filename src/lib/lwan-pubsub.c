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

#define _GNU_SOURCE
#include <stdarg.h>
#include <stdio.h>
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
    unsigned int refcount;
};

DEFINE_RING_BUFFER_TYPE(lwan_pubsub_msg_ref_ring, struct lwan_pubsub_msg *, 16)

struct lwan_pubsub_msg_ref {
    struct list_node ref;
    struct lwan_pubsub_msg_ref_ring ring;
};

struct lwan_pubsub_subscriber {
    struct list_node subscriber;

    pthread_mutex_t lock;
    struct list_head msg_refs;
};

static void lwan_pubsub_queue_init(struct lwan_pubsub_subscriber *sub)
{
    list_head_init(&sub->msg_refs);
}

static bool lwan_pubsub_queue_put(struct lwan_pubsub_subscriber *sub,
                                  const struct lwan_pubsub_msg *msg)
{
    struct lwan_pubsub_msg_ref *ref;

    ref = list_tail(&sub->msg_refs, struct lwan_pubsub_msg_ref, ref);
    if (ref) {
        /* Try putting the message in the last ringbuffer in this queue: if it's
         * full, will need to allocate a new ring buffer, even if others might
         * have space in them:  the FIFO order must be preserved, and short of
         * compacting the queue at this point -- which will eventually happen
         * as it is consumed -- this is the only option. */
        if (lwan_pubsub_msg_ref_ring_try_put(&ref->ring, &msg))
            return true;
    }

    ref = malloc(sizeof(*ref));
    if (!ref)
        return false;

    lwan_pubsub_msg_ref_ring_init(&ref->ring);
    lwan_pubsub_msg_ref_ring_put(&ref->ring, &msg);
    list_add_tail(&sub->msg_refs, &ref->ref);

    return true;
}

static struct lwan_pubsub_msg *
lwan_pubsub_queue_get(struct lwan_pubsub_subscriber *sub)
{
    struct lwan_pubsub_msg_ref *ref, *next;

    list_for_each_safe (&sub->msg_refs, ref, next, ref) {
        struct lwan_pubsub_msg *msg;

        if (lwan_pubsub_msg_ref_ring_empty(&ref->ring)) {
            list_del(&ref->ref);
            free(ref);
            continue;
        }

        msg = lwan_pubsub_msg_ref_ring_get(&ref->ring);

        if (ref->ref.next != ref->ref.prev) {
            /* If this segment isn't the last one, try pulling in just one
             * element from the next segment, as there's space in the
             * current segment now.
             *
             * This might lead to an empty ring buffer segment in the middle
             * of the linked list.  This is by design, to introduce some
             * hysteresis and avoid the pathological case where malloc churn
             * will happen when subscribers consume at the same rate as
             * publishers are able to publish.
             *
             * The condition above will take care of these empty segments
             * once they're dealt with, eventually compacting the queue
             * completely (and ultimately reducing it to an empty list
             * without any ring buffers).
             */
            struct lwan_pubsub_msg_ref *next_ring;

            next_ring = container_of(ref->ref.next, struct lwan_pubsub_msg_ref, ref);
            if (!lwan_pubsub_msg_ref_ring_empty(&next_ring->ring)) {
                const struct lwan_pubsub_msg *next_msg;

                next_msg = lwan_pubsub_msg_ref_ring_get(&next_ring->ring);
                lwan_pubsub_msg_ref_ring_put(&ref->ring, &next_msg);
            }
        }

        return msg;
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

void lwan_pubsub_msg_done(struct lwan_pubsub_msg *msg)
{
    if (!ATOMIC_DEC(msg->refcount)) {
        free(msg->value.value);
        free(msg);
    }
}

static bool lwan_pubsub_publish_value(struct lwan_pubsub_topic *topic,
                                      const struct lwan_value value)
{
    struct lwan_pubsub_msg *msg = malloc(sizeof(*msg));
    struct lwan_pubsub_subscriber *sub;

    if (!msg)
        return false;

    /* Initialize refcount to 1, so we can drop one ref after publishing to
     * all subscribers.  If it drops to 0, it means we didn't publish the
     * message and we can free it. */
    msg->refcount = 1;
    msg->value = value;

    pthread_mutex_lock(&topic->lock);
    list_for_each (&topic->subscribers, sub, subscriber) {
        ATOMIC_INC(msg->refcount);

        pthread_mutex_lock(&sub->lock);
        if (!lwan_pubsub_queue_put(sub, msg)) {
            lwan_status_warning("Couldn't enqueue message, dropping");
            ATOMIC_DEC(msg->refcount);
        }
        pthread_mutex_unlock(&sub->lock);
    }
    pthread_mutex_unlock(&topic->lock);

    lwan_pubsub_msg_done(msg);

    return true;
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
    const struct lwan_value value = { .value = my_memdup(contents, len), .len = len };

    if (!value.value)
        return false;

    return lwan_pubsub_publish_value(topic, value);
}

bool lwan_pubsub_publishf(struct lwan_pubsub_topic *topic,
                          const char *format,
                          ...)
{
    char *msg;
    int len;
    va_list ap;

    va_start(ap, format);
    len = vasprintf(&msg, format, ap);
    va_end(ap);

    if (len < 0)
        return false;

    const struct lwan_value value = { .value = msg, .len = (size_t)len };
    return lwan_pubsub_publish_value(topic, value);
}

struct lwan_pubsub_subscriber *
lwan_pubsub_subscribe(struct lwan_pubsub_topic *topic)
{
    struct lwan_pubsub_subscriber *sub = calloc(1, sizeof(*sub));

    if (!sub)
        return NULL;

    pthread_mutex_init(&sub->lock, NULL);
    lwan_pubsub_queue_init(sub);

    pthread_mutex_lock(&topic->lock);
    list_add(&topic->subscribers, &sub->subscriber);
    pthread_mutex_unlock(&topic->lock);

    return sub;
}

struct lwan_pubsub_msg *lwan_pubsub_consume(struct lwan_pubsub_subscriber *sub)
{
    struct lwan_pubsub_msg *msg;

    pthread_mutex_lock(&sub->lock);
    msg = lwan_pubsub_queue_get(sub);
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
    while ((iter = lwan_pubsub_queue_get(sub)))
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
