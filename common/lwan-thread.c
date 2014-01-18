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
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

#include "lwan.h"

struct death_queue_t {
    unsigned last;
    unsigned first;
    unsigned population;
    unsigned max;
    unsigned time;
    int *queue;
    lwan_connection_t *conns;
};

#define ONE_HOUR 3600
#define ONE_DAY (ONE_HOUR * 24)
#define ONE_WEEK (ONE_DAY * 7)
#define ONE_MONTH (ONE_DAY * 31)

static ALWAYS_INLINE int
min(const int a, const int b)
{
    return a < b ? a : b;
}

static ALWAYS_INLINE void
_destroy_coro(lwan_connection_t *conn)
{
    if (LIKELY(conn->coro)) {
        coro_free(conn->coro);
        conn->coro = NULL;
    }
    if (conn->flags & CONN_IS_ALIVE) {
        conn->flags &= ~CONN_IS_ALIVE;
        close(lwan_connection_get_fd(conn));
    }
}

static int
_process_request_coro(coro_t *coro)
{
    lwan_connection_t *conn = coro_get_data(coro);
    lwan_request_t request = {
        .conn = conn,
        .fd = lwan_connection_get_fd(conn),
        .response = {
            .buffer = conn->response_buffer
        }
    };

    assert(conn->flags & CONN_IS_ALIVE);

    strbuf_reset(conn->response_buffer);
    lwan_process_request(conn->thread->lwan, &request);

    return CONN_CORO_FINISHED;
}

static ALWAYS_INLINE void
_resume_coro_if_needed(lwan_connection_t *conn, int epoll_fd)
{
    assert(conn->coro);

    if (!(conn->flags & CONN_SHOULD_RESUME_CORO))
        return;

    lwan_connection_coro_yield_t yield_result = coro_resume(conn->coro);
    /* CONN_CORO_ABORT is -1, but comparing with 0 is cheaper */
    if (yield_result < CONN_CORO_MAY_RESUME) {
        _destroy_coro(conn);
        return;
    }

    bool should_resume_coro = yield_result == CONN_CORO_MAY_RESUME;
    bool write_events = conn->flags & CONN_WRITE_EVENTS;
    if (should_resume_coro)
        conn->flags |= CONN_SHOULD_RESUME_CORO;
    else
        conn->flags &= ~CONN_SHOULD_RESUME_CORO;
    if (should_resume_coro == write_events)
        return;

    static const int const events_by_write_flag[] = {
        EPOLLOUT | EPOLLRDHUP | EPOLLERR,
        EPOLLIN | EPOLLRDHUP | EPOLLERR | EPOLLET
    };
    int fd = lwan_connection_get_fd(conn);
    struct epoll_event event = {
        .events = events_by_write_flag[write_events],
        .data.ptr = conn
    };

    if (UNLIKELY(epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &event) < 0))
        lwan_status_perror("epoll_ctl");

    conn->flags ^= CONN_WRITE_EVENTS;
}

static void
_death_queue_init(struct death_queue_t *dq,
            lwan_connection_t *conns, unsigned max)
{
    dq->queue = calloc(1, max * sizeof(int));
    dq->last = 0;
    dq->first = 0;
    dq->population = 0;
    dq->time = 0;
    dq->max = max;
    dq->conns = conns;
}

static void
_death_queue_shutdown(struct death_queue_t *dq)
{
    if (!dq)
        return;
    free(dq->queue);
}

static void
_death_queue_pop(struct death_queue_t *dq)
{
    dq->first++;
    dq->population--;
    dq->first %= dq->max;
}

static void
_death_queue_push(struct death_queue_t *dq, lwan_connection_t *conn)
{
    dq->queue[dq->last] = lwan_connection_get_fd(conn);
    dq->last++;
    dq->population++;
    dq->last %= dq->max;
    conn->flags |= CONN_IS_ALIVE;
}

static ALWAYS_INLINE lwan_connection_t *
_death_queue_first(struct death_queue_t *dq)
{
    return &dq->conns[dq->queue[dq->first]];
}

static ALWAYS_INLINE int
_death_queue_epoll_timeout(struct death_queue_t *dq)
{
    return dq->population ? 1000 : -1;
}

static void
_death_queue_kill_waiting(struct death_queue_t *dq)
{
    dq->time++;

    while (dq->population) {
        lwan_connection_t *conn = _death_queue_first(dq);

        if (conn->time_to_die > dq->time)
            break;

        _death_queue_pop(dq);
        _destroy_coro(conn);
    }
}

void
lwan_format_rfc_time(time_t t, char buffer[32])
{
    struct tm tm;

    if (UNLIKELY(!gmtime_r(&t, &tm))) {
        lwan_status_perror("gmtime_r");
        return;
    }

    if (UNLIKELY(!strftime(buffer, 31, "%a, %d %b %Y %H:%M:%S GMT", &tm)))
        lwan_status_perror("strftime");
}

static void
_update_date_cache(lwan_thread_t *thread)
{
    time_t now = time(NULL);
    if (now != thread->date.last) {
        thread->date.last = now;
        lwan_format_rfc_time(now, thread->date.date);
        lwan_format_rfc_time(now + ONE_WEEK, thread->date.expires);
    }
}

static ALWAYS_INLINE void
_spawn_or_reset_coro_if_needed(lwan_connection_t *conn,
            coro_switcher_t *switcher, struct death_queue_t *dq)
{
    if (conn->coro) {
        if (conn->flags & CONN_SHOULD_RESUME_CORO)
            return;

        coro_reset(conn->coro, _process_request_coro, conn);
    } else {
        conn->coro = coro_new(switcher, _process_request_coro, conn);
        _death_queue_push(dq, conn);
    }
    conn->flags |= CONN_SHOULD_RESUME_CORO;
    conn->flags &= ~CONN_WRITE_EVENTS;
}

static void *
_thread_io_loop(void *data)
{
    lwan_thread_t *t = data;
    struct epoll_event *events, *ep_event;
    lwan_connection_t *conns = t->lwan->conns;
    coro_switcher_t switcher;
    struct death_queue_t dq;
    int epoll_fd = t->epoll_fd;
    int n_fds;
    const short keep_alive_timeout = t->lwan->config.keep_alive_timeout;
    const int max_events = min(t->lwan->thread.max_fd, 1024);

    lwan_status_debug("Starting IO loop on thread #%d", t->id + 1);

    events = calloc(max_events, sizeof(*events));
    if (UNLIKELY(!events))
        lwan_status_critical("Could not allocate memory for events");

    _death_queue_init(&dq, conns, t->lwan->thread.max_fd);

    for (;;) {
        switch (n_fds = epoll_wait(epoll_fd, events, max_events,
                                   _death_queue_epoll_timeout(&dq))) {
        case -1:
            switch (errno) {
            case EBADF:
            case EINVAL:
                goto epoll_fd_closed;
            }
            continue;
        case 0: /* timeout: shutdown waiting sockets */
            _death_queue_kill_waiting(&dq);
            break;
        default: /* activity in some of this poller's file descriptor */
            _update_date_cache(t);

            for (ep_event = events; n_fds--; ep_event++) {
                lwan_connection_t *conn = ep_event->data.ptr;

                if (UNLIKELY(ep_event->events & (EPOLLRDHUP | EPOLLHUP))) {
                    _destroy_coro(conn);
                    continue;
                }

                _spawn_or_reset_coro_if_needed(conn, &switcher, &dq);
                _resume_coro_if_needed(conn, epoll_fd);

                /*
                 * If the connection isn't keep alive, it might have a
                 * coroutine that should be resumed.  If that's the case,
                 * schedule for this request to die according to the keep
                 * alive timeout.
                 *
                 * If it's not a keep alive connection, or the coroutine
                 * shouldn't be resumed -- then just mark it to be reaped
                 * right away.
                 */
                conn->time_to_die = dq.time;
                conn->time_to_die += keep_alive_timeout *
                        !!(conn->flags & (CONN_KEEP_ALIVE | CONN_SHOULD_RESUME_CORO));
            }
        }
    }

epoll_fd_closed:
    _death_queue_shutdown(&dq);
    free(events);

    return NULL;
}

static void
_create_thread(lwan_t *l, int thread_n)
{
    pthread_attr_t attr;
    lwan_thread_t *thread = &l->thread.threads[thread_n];

    memset(thread, 0, sizeof(*thread));
    thread->lwan = l;
    thread->id = thread_n;

    if ((thread->epoll_fd = epoll_create1(0)) < 0)
        lwan_status_critical_perror("epoll_create");

    if (pthread_attr_init(&attr))
        lwan_status_critical_perror("pthread_attr_init");

    if (pthread_attr_setscope(&attr, PTHREAD_SCOPE_SYSTEM))
        lwan_status_critical_perror("pthread_attr_setscope");

    if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE))
        lwan_status_critical_perror("pthread_attr_setdetachstate");

    if (pthread_create(&thread->self, &attr, _thread_io_loop, thread))
        lwan_status_critical_perror("pthread_create");

    if (pthread_attr_destroy(&attr))
        lwan_status_critical_perror("pthread_attr_destroy");
}

void
lwan_thread_init(lwan_t *l)
{
    int i;

    lwan_status_debug("Initializing threads");

    l->thread.threads = malloc(sizeof(lwan_thread_t) * l->thread.count);
    if (!l->thread.threads)
        lwan_status_critical("Could not allocate memory for threads");

    for (i = l->thread.count - 1; i >= 0; i--)
        _create_thread(l, i);
}

void
lwan_thread_shutdown(lwan_t *l)
{
    int i;

    lwan_status_debug("Shutting down threads");

    /*
     * Closing epoll_fd makes the thread gracefully finish; it might
     * take a while to notice this if keep-alive timeout is high.
     * Thread shutdown is performed in separate loops so that we
     * don't wait one thread to join when there are others to be
     * finalized.
     */
    for (i = l->thread.count - 1; i >= 0; i--)
        close(l->thread.threads[i].epoll_fd);
    for (i = l->thread.count - 1; i >= 0; i--)
#ifdef __linux__
        pthread_tryjoin_np(l->thread.threads[i].self, NULL);
#else
        pthread_join(l->thread.threads[i].self, NULL);
#endif /* __linux__ */

    free(l->thread.threads);
}
