/*
 * lwan - simple web server
 * Copyright (c) 2012, 2013 Leandro A. F. Pereira <leandro@hardinfo.org>
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

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

#include "lwan-private.h"

struct death_queue_t {
    lwan_connection_t *conns;
    lwan_connection_t head;
    unsigned time;
    unsigned short keep_alive_timeout;
};

static const uint32_t events_by_write_flag[] = {
    EPOLLOUT | EPOLLRDHUP | EPOLLERR,
    EPOLLIN | EPOLLRDHUP | EPOLLERR | EPOLLET
};

static inline int death_queue_node_to_idx(struct death_queue_t *dq,
    lwan_connection_t *conn)
{
    return (conn == &dq->head) ? -1 : (int)(ptrdiff_t)(conn - dq->conns);
}

static inline lwan_connection_t *death_queue_idx_to_node(struct death_queue_t *dq,
    int idx)
{
    return (idx < 0) ? &dq->head : &dq->conns[idx];
}

static void death_queue_insert(struct death_queue_t *dq,
    lwan_connection_t *new_node)
{
    new_node->next = -1;
    new_node->prev = dq->head.prev;
    lwan_connection_t *prev = death_queue_idx_to_node(dq, dq->head.prev);
    dq->head.prev = prev->next = death_queue_node_to_idx(dq, new_node);
}

static void death_queue_remove(struct death_queue_t *dq,
    lwan_connection_t *node)
{
    lwan_connection_t *prev = death_queue_idx_to_node(dq, node->prev);
    lwan_connection_t *next = death_queue_idx_to_node(dq, node->next);
    next->prev = node->prev;
    prev->next = node->next;
}

static bool death_queue_empty(struct death_queue_t *dq)
{
    return dq->head.next < 0;
}

static void death_queue_move_to_last(struct death_queue_t *dq,
    lwan_connection_t *conn)
{
    /*
     * If the connection isn't keep alive, it might have a coroutine that
     * should be resumed.  If that's the case, schedule for this request to
     * die according to the keep alive timeout.
     *
     * If it's not a keep alive connection, or the coroutine shouldn't be
     * resumed -- then just mark it to be reaped right away.
     */
    conn->time_to_die = dq->time + dq->keep_alive_timeout *
            (unsigned)!!(conn->flags & (CONN_KEEP_ALIVE | CONN_SHOULD_RESUME_CORO));

    death_queue_remove(dq, conn);
    death_queue_insert(dq, conn);
}

static void
death_queue_init(struct death_queue_t *dq, lwan_connection_t *conns,
    unsigned short keep_alive_timeout)
{
    dq->conns = conns;
    dq->time = 0;
    dq->keep_alive_timeout = keep_alive_timeout;
    dq->head.next = dq->head.prev = -1;
}

static ALWAYS_INLINE int
death_queue_epoll_timeout(struct death_queue_t *dq)
{
    return death_queue_empty(dq) ? -1 : 1000;
}

static ALWAYS_INLINE void
destroy_coro(struct death_queue_t *dq, lwan_connection_t *conn)
{
    death_queue_remove(dq, conn);
    if (LIKELY(conn->coro)) {
        coro_free(conn->coro);
        conn->coro = NULL;
    }
    if (conn->flags & CONN_IS_ALIVE) {
        conn->flags &= ~CONN_IS_ALIVE;
        close(lwan_connection_get_fd(conn));
    }
}

static ALWAYS_INLINE int
min(const int a, const int b)
{
    return a < b ? a : b;
}

static int
process_request_coro(coro_t *coro)
{
    strbuf_t *strbuf = coro_malloc_full(coro, sizeof(*strbuf), strbuf_free);
    if (UNLIKELY(!strbuf))
        return CONN_CORO_ABORT;

    lwan_connection_t *conn = coro_get_data(coro);
    int fd = lwan_connection_get_fd(conn);
    char request_buffer[DEFAULT_BUFFER_SIZE];
    lwan_value_t buffer = {
        .value = request_buffer,
        .len = 0
    };
    char *next_request = NULL;
    lwan_request_flags_t pipelined_flags = 0;

    while (true) {
        lwan_request_t request = {
            .conn = conn,
            .fd = fd,
            .response = {
                .buffer = strbuf
            },
            .flags = pipelined_flags
        };

        assert(conn->flags & CONN_IS_ALIVE);
        strbuf_init(strbuf);

        next_request = lwan_process_request(conn->thread->lwan, &request, &buffer,
            next_request);

        if (request.flags & REQUEST_PIPELINED) {
            coro_yield(coro, CONN_CORO_MAY_RESUME);
            pipelined_flags = REQUEST_PIPELINED;
        } else {
            break;
        }
    }

    return CONN_CORO_FINISHED;
}

static ALWAYS_INLINE void
resume_coro_if_needed(struct death_queue_t *dq, lwan_connection_t *conn,
    int epoll_fd)
{
    assert(conn->coro);

    if (!(conn->flags & CONN_SHOULD_RESUME_CORO))
        return;

    lwan_connection_coro_yield_t yield_result = coro_resume(conn->coro);
    /* CONN_CORO_ABORT is -1, but comparing with 0 is cheaper */
    if (yield_result < CONN_CORO_MAY_RESUME) {
        destroy_coro(dq, conn);
        return;
    }

    bool write_events;
    if (conn->flags & CONN_MUST_READ) {
        write_events = true;
    } else {
        bool should_resume_coro = (yield_result == CONN_CORO_MAY_RESUME);

        if (should_resume_coro)
            conn->flags |= CONN_SHOULD_RESUME_CORO;
        else
            conn->flags &= ~CONN_SHOULD_RESUME_CORO;

        write_events = (conn->flags & CONN_WRITE_EVENTS);
        if (should_resume_coro == write_events)
            return;
    }

    struct epoll_event event = {
        .events = events_by_write_flag[write_events],
        .data.ptr = conn
    };

    int fd = lwan_connection_get_fd(conn);
    if (UNLIKELY(epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &event) < 0))
        lwan_status_perror("epoll_ctl");

    conn->flags ^= CONN_WRITE_EVENTS;
}

static void
death_queue_kill_waiting(struct death_queue_t *dq)
{
    dq->time++;

    while (!death_queue_empty(dq)) {
        lwan_connection_t *conn = death_queue_idx_to_node(dq, dq->head.next);

        if (conn->time_to_die > dq->time)
            return;

        destroy_coro(dq, conn);
    }

    /* Death queue exhausted: reset epoch */
    dq->time = 0;
}

void
lwan_format_rfc_time(time_t t, char buffer[30])
{
    struct tm tm;

    if (UNLIKELY(!gmtime_r(&t, &tm))) {
        lwan_status_perror("gmtime_r");
        return;
    }

    if (UNLIKELY(!strftime(buffer, 30, "%a, %d %b %Y %H:%M:%S GMT", &tm)))
        lwan_status_perror("strftime");
}

static void
update_date_cache(lwan_thread_t *thread)
{
    time_t now = time(NULL);
    if (now != thread->date.last) {
        thread->date.last = now;
        lwan_format_rfc_time(now, thread->date.date);
        lwan_format_rfc_time(now + (time_t)thread->lwan->config.expires,
                    thread->date.expires);
    }
}

static ALWAYS_INLINE void
spawn_or_reset_coro_if_needed(lwan_connection_t *conn,
            coro_switcher_t *switcher, struct death_queue_t *dq)
{
    if (conn->coro) {
        if (conn->flags & CONN_SHOULD_RESUME_CORO)
            return;

        coro_reset(conn->coro, process_request_coro, conn);
    } else {
        conn->coro = coro_new(switcher, process_request_coro, conn);

        death_queue_insert(dq, conn);
        conn->flags |= CONN_IS_ALIVE;
    }
    conn->flags |= CONN_SHOULD_RESUME_CORO;
    conn->flags &= ~CONN_WRITE_EVENTS;
}

static lwan_connection_t *
grab_and_watch_client(lwan_thread_t *t, lwan_connection_t *conns)
{
    int fd;
    if (UNLIKELY(read(t->pipe_fd[0], &fd, sizeof(int)) != sizeof(int))) {
        lwan_status_perror("read");
        return NULL;
    }

    struct epoll_event event = {
        .events = events_by_write_flag[1],
        .data.ptr = &conns[fd]
    };
    if (UNLIKELY(epoll_ctl(t->epoll_fd, EPOLL_CTL_ADD, fd, &event) < 0))
        lwan_status_critical_perror("epoll_ctl");

    return &conns[fd];
}

static void *
thread_io_loop(void *data)
{
    lwan_thread_t *t = data;
    struct epoll_event *events;
    lwan_connection_t *conns = t->lwan->conns;
    coro_switcher_t switcher;
    struct death_queue_t dq;
    int epoll_fd = t->epoll_fd;
    int n_fds;
    const int max_events = min((int)t->lwan->thread.max_fd, 1024);

    lwan_status_debug("Starting IO loop on thread #%d", t->id + 1);

    events = calloc((size_t)max_events, sizeof(*events));
    if (UNLIKELY(!events))
        lwan_status_critical("Could not allocate memory for events");

    death_queue_init(&dq, conns, t->lwan->config.keep_alive_timeout);

    for (;;) {
        switch (n_fds = epoll_wait(epoll_fd, events, max_events,
                                   death_queue_epoll_timeout(&dq))) {
        case -1:
            switch (errno) {
            case EBADF:
            case EINVAL:
                goto epoll_fd_closed;
            }
            continue;
        case 0: /* timeout: shutdown waiting sockets */
            death_queue_kill_waiting(&dq);
            break;
        default: /* activity in some of this poller's file descriptor */
            update_date_cache(t);

            for (struct epoll_event *ep_event = events; n_fds--; ep_event++) {
                lwan_connection_t *conn;

                if (!ep_event->data.ptr) {
                    conn = grab_and_watch_client(t, conns);
                    if (UNLIKELY(!conn))
                        continue;
                    spawn_or_reset_coro_if_needed(conn, &switcher, &dq);
                } else {
                    conn = ep_event->data.ptr;
                    if (UNLIKELY(ep_event->events & (EPOLLRDHUP | EPOLLHUP))) {
                        destroy_coro(&dq, conn);
                        continue;
                    }

                    spawn_or_reset_coro_if_needed(conn, &switcher, &dq);
                    resume_coro_if_needed(&dq, conn, epoll_fd);
                }

                death_queue_move_to_last(&dq, conn);
            }
        }
    }

epoll_fd_closed:
    free(events);

    return NULL;
}

static void
create_thread(lwan_t *l, short thread_n)
{
    pthread_attr_t attr;
    lwan_thread_t *thread = &l->thread.threads[thread_n];

    memset(thread, 0, sizeof(*thread));
    thread->lwan = l;
    thread->id = thread_n;

    if ((thread->epoll_fd = epoll_create1(EPOLL_CLOEXEC)) < 0)
        lwan_status_critical_perror("epoll_create");

    if (pthread_attr_init(&attr))
        lwan_status_critical_perror("pthread_attr_init");

    if (pthread_attr_setscope(&attr, PTHREAD_SCOPE_SYSTEM))
        lwan_status_critical_perror("pthread_attr_setscope");

    if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE))
        lwan_status_critical_perror("pthread_attr_setdetachstate");

    if (pthread_create(&thread->self, &attr, thread_io_loop, thread))
        lwan_status_critical_perror("pthread_create");

    if (pthread_attr_destroy(&attr))
        lwan_status_critical_perror("pthread_attr_destroy");

    if (pipe2(thread->pipe_fd, O_NONBLOCK | O_CLOEXEC) < 0)
        lwan_status_critical_perror("pipe");

    struct epoll_event event = { .events = EPOLLIN, .data.ptr = NULL };
    if (epoll_ctl(thread->epoll_fd, EPOLL_CTL_ADD, thread->pipe_fd[0], &event) < 0)
        lwan_status_critical_perror("epoll_ctl");
}

void
lwan_thread_add_client(lwan_thread_t *t, int fd)
{
    t->lwan->conns[fd].flags = 0;
    t->lwan->conns[fd].thread = t;

    if (UNLIKELY(write(t->pipe_fd[1], &fd, sizeof(int)) < 0))
        lwan_status_perror("write");
}

void
lwan_thread_init(lwan_t *l)
{
    lwan_status_debug("Initializing threads");

    l->thread.threads = calloc((size_t)l->thread.count, sizeof(lwan_thread_t));
    if (!l->thread.threads)
        lwan_status_critical("Could not allocate memory for threads");

    for (short i = 0; i < l->thread.count; i++)
        create_thread(l, i);
}

void
lwan_thread_shutdown(lwan_t *l)
{
    lwan_status_debug("Shutting down threads");

    for (int i = l->thread.count - 1; i >= 0; i--) {
        lwan_thread_t *t = &l->thread.threads[i];

        /* Closing epoll_fd makes the thread gracefully finish. */
        close(t->epoll_fd);

        close(t->pipe_fd[0]);
        close(t->pipe_fd[1]);

        pthread_tryjoin_np(l->thread.threads[i].self, NULL);
    }

    free(l->thread.threads);
}
