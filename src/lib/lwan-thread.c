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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

#if defined(HAVE_EVENTFD)
#include <sys/eventfd.h>
#endif

#include "lwan-private.h"
#include "lwan-dq.h"
#include "list.h"

static const uint32_t events_by_write_flag[] = {
    EPOLLOUT | EPOLLRDHUP | EPOLLERR,
    EPOLLIN | EPOLLRDHUP | EPOLLERR
};

static ALWAYS_INLINE int min(const int a, const int b) { return a < b ? a : b; }

#define REQUEST_FLAG(bool_, name_)                                             \
    ((enum lwan_request_flags)(((uint32_t)lwan->config.bool_)                  \
                               << REQUEST_##name_##_SHIFT))
static_assert(sizeof(enum lwan_request_flags) == sizeof(uint32_t),
              "lwan_request_flags has the same size as uint32_t");

__attribute__((noreturn)) static int process_request_coro(struct coro *coro,
                                                          void *data)
{
    /* NOTE: This function should not return; coro_yield should be used
     * instead.  This ensures the storage for `strbuf` is alive when the
     * coroutine ends and lwan_strbuf_free() is called. */
    struct lwan_connection *conn = data;
    const enum lwan_request_flags flags_filter =
        (REQUEST_PROXIED | REQUEST_ALLOW_CORS);
    struct lwan_strbuf strbuf;
    struct lwan *lwan = conn->thread->lwan;
    int fd = lwan_connection_get_fd(lwan, conn);
    char request_buffer[DEFAULT_BUFFER_SIZE];
    struct lwan_value buffer = {.value = request_buffer, .len = 0};
    char *next_request = NULL;
    enum lwan_request_flags flags = 0;
    struct lwan_proxy proxy;

    if (UNLIKELY(!lwan_strbuf_init(&strbuf))) {
        coro_yield(coro, CONN_CORO_ABORT);
        __builtin_unreachable();
    }
    coro_defer(coro, CORO_DEFER(lwan_strbuf_free), &strbuf);

    flags |= REQUEST_FLAG(proxy_protocol, ALLOW_PROXY_REQS) |
             REQUEST_FLAG(allow_cors, ALLOW_CORS);

    while (true) {
        struct lwan_request request = {.conn = conn,
                                       .fd = fd,
                                       .response = {.buffer = &strbuf},
                                       .flags = flags,
                                       .proxy = &proxy};

        assert(conn->flags & CONN_IS_ALIVE);

        size_t generation = coro_deferred_get_generation(coro);
        next_request =
            lwan_process_request(lwan, &request, &buffer, next_request);
        coro_deferred_run(coro, generation);

        if (next_request && *next_request)
            conn->flags |= CONN_FLIP_FLAGS;

        coro_yield(coro, CONN_CORO_MAY_RESUME);

        lwan_strbuf_reset(&strbuf);
        flags = request.flags & flags_filter;
    }
}

#undef REQUEST_FLAG

static void update_epoll_flags(struct death_queue *dq,
                               struct lwan_connection *conn,
                               int epoll_fd,
                               enum lwan_connection_coro_yield yield_result)
{
    uint32_t events = 0;
    bool write_events;

    if (UNLIKELY(conn->flags & CONN_RESUMED_FROM_TIMER)) {
        conn->flags &= ~(CONN_RESUMED_FROM_TIMER | CONN_WRITE_EVENTS);
        write_events = false;
    } else if (UNLIKELY(conn->flags & CONN_SUSPENDED_BY_TIMER)) {
        /* CONN_WRITE_EVENTS shouldn't be flipped in this case. */
        events = EPOLLERR | EPOLLRDHUP;
    } else if (conn->flags & CONN_MUST_READ) {
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

    if (LIKELY(!events)) {
        events = events_by_write_flag[write_events];
        conn->flags ^= CONN_WRITE_EVENTS;
    }

    struct epoll_event event = {.events = events, .data.ptr = conn};

    int fd = lwan_connection_get_fd(dq->lwan, conn);
    if (UNLIKELY(epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &event) < 0))
        lwan_status_perror("epoll_ctl");
}

static ALWAYS_INLINE void resume_coro_if_needed(struct death_queue *dq,
                                                struct lwan_connection *conn,
                                                int epoll_fd)
{
    const enum lwan_connection_flags update_mask =
        CONN_FLIP_FLAGS | CONN_RESUMED_FROM_TIMER | CONN_SUSPENDED_BY_TIMER;

    assert(conn->coro);

    if (!(conn->flags & CONN_SHOULD_RESUME_CORO))
        return;

    enum lwan_connection_coro_yield yield_result = coro_resume(conn->coro);
    /* CONN_CORO_ABORT is -1, but comparing with 0 is cheaper */
    if (UNLIKELY(yield_result < CONN_CORO_MAY_RESUME)) {
        death_queue_kill(dq, conn);
        return;
    }

    if (conn->flags & update_mask) {
        conn->flags &= ~CONN_FLIP_FLAGS;
        update_epoll_flags(dq, conn, epoll_fd, yield_result);
    }
}

static void update_date_cache(struct lwan_thread *thread)
{
    time_t now = time(NULL);

    lwan_format_rfc_time(now, thread->date.date);
    lwan_format_rfc_time(now + (time_t)thread->lwan->config.expires,
                         thread->date.expires);
}

static ALWAYS_INLINE void spawn_coro(struct lwan_connection *conn,
                                     struct coro_switcher *switcher,
                                     struct death_queue *dq)
{
    struct lwan_thread *t = conn->thread;

    assert(!conn->coro);
    assert(!(conn->flags & CONN_IS_ALIVE));
    assert(t);
    assert((uintptr_t)t >= (uintptr_t)dq->lwan->thread.threads);
    assert((uintptr_t)t <
           (uintptr_t)(dq->lwan->thread.threads + dq->lwan->thread.count));

    *conn = (struct lwan_connection) {
        .coro = coro_new(switcher, process_request_coro, conn),
        .flags = CONN_IS_ALIVE | CONN_SHOULD_RESUME_CORO,
        .time_to_die = dq->time + dq->keep_alive_timeout,
        .thread = t,
    };
    if (UNLIKELY(!conn->coro)) {
        conn->flags = 0;
        lwan_status_error("Could not create coroutine");
        return;
    }

    death_queue_insert(dq, conn);
}

static void accept_nudge(int pipe_fd,
                         struct lwan_thread *t,
                         struct lwan_connection *conns,
                         struct death_queue *dq,
                         struct coro_switcher *switcher,
                         int epoll_fd)
{
    uint64_t event;
    int new_fd;

    /* Errors are ignored here as pipe_fd serves just as a way to wake the
     * thread from epoll_wait().  It's fine to consume the queue at this
     * point, regardless of the error type. */
    (void)read(pipe_fd, &event, sizeof(event));

    while (spsc_queue_pop(&t->pending_fds, &new_fd)) {
        struct lwan_connection *conn = &conns[new_fd];
        struct epoll_event ev = {.events = events_by_write_flag[1],
                                 .data.ptr = conn};

        if (LIKELY(!epoll_ctl(epoll_fd, EPOLL_CTL_ADD, new_fd, &ev)))
            spawn_coro(conn, switcher, dq);
    }

    timeouts_add(t->wheel, &dq->timeout, 1000);
}

static bool process_pending_timers(struct death_queue *dq,
                                   struct lwan_thread *t,
                                   int epoll_fd)
{
    struct timeout *timeout;
    bool processed_dq_timeout = false;

    while ((timeout = timeouts_get(t->wheel))) {
        struct lwan_request *request;

        if (timeout == &dq->timeout) {
            death_queue_kill_waiting(dq);
            processed_dq_timeout = true;
            continue;
        }

        request = container_of(timeout, struct lwan_request, timeout);

        request->conn->flags &= ~CONN_SUSPENDED_BY_TIMER;
        request->conn->flags |= CONN_RESUMED_FROM_TIMER;
        update_epoll_flags(dq, request->conn, epoll_fd, CONN_CORO_MAY_RESUME);
    }

    if (processed_dq_timeout) {
        /* dq timeout expires every 1000ms if there are connections, so
         * update the date cache at this point as well.  */
        update_date_cache(t);

        if (!death_queue_empty(dq)) {
            timeouts_add(t->wheel, &dq->timeout, 1000);
            return true;
        }

        timeouts_del(t->wheel, &dq->timeout);
    }

    return false;
}

static int
turn_timer_wheel(struct death_queue *dq, struct lwan_thread *t, int epoll_fd)
{
    timeout_t wheel_timeout;
    struct timespec now;

    if (UNLIKELY(clock_gettime(monotonic_clock_id, &now) < 0))
        lwan_status_critical("Could not get monotonic time");

    timeouts_update(t->wheel,
                    (timeout_t)(now.tv_sec * 1000 + now.tv_nsec / 1000000));

    wheel_timeout = timeouts_timeout(t->wheel);
    if (UNLIKELY((int64_t)wheel_timeout < 0))
        goto infinite_timeout;

    if (wheel_timeout == 0) {
        if (!process_pending_timers(dq, t, epoll_fd))
            goto infinite_timeout;

        wheel_timeout = timeouts_timeout(t->wheel);
        if (wheel_timeout == 0)
            goto infinite_timeout;
    }

    return (int)wheel_timeout;

infinite_timeout:
    return -1;
}

static void *thread_io_loop(void *data)
{
    struct lwan_thread *t = data;
    int epoll_fd = t->epoll_fd;
    const int read_pipe_fd = t->pipe_fd[0];
    const int max_events = min((int)t->lwan->thread.max_fd, 1024);
    struct lwan *lwan = t->lwan;
    struct epoll_event *events;
    struct coro_switcher switcher;
    struct death_queue dq;

    lwan_status_debug("Starting IO loop on thread #%d",
                      (unsigned short)(ptrdiff_t)(t - t->lwan->thread.threads) +
                          1);
    lwan_set_thread_name("worker");

    events = calloc((size_t)max_events, sizeof(*events));
    if (UNLIKELY(!events))
        lwan_status_critical("Could not allocate memory for events");

    update_date_cache(t);

    death_queue_init(&dq, lwan);

    pthread_barrier_wait(&lwan->thread.barrier);

    for (;;) {
        int timeout = turn_timer_wheel(&dq, t, epoll_fd);
        int n_fds = epoll_wait(epoll_fd, events, max_events, timeout);

        if (UNLIKELY(n_fds < 0)) {
            if (errno == EBADF || errno == EINVAL)
                break;
            continue;
        }

        for (struct epoll_event *event = events; n_fds--; event++) {
            struct lwan_connection *conn;

            if (UNLIKELY(!event->data.ptr)) {
                accept_nudge(read_pipe_fd, t, lwan->conns, &dq, &switcher,
                             epoll_fd);
                continue;
            }

            conn = event->data.ptr;

            if (UNLIKELY(event->events & (EPOLLRDHUP | EPOLLHUP))) {
                death_queue_kill(&dq, conn);
                continue;
            }

            resume_coro_if_needed(&dq, conn, epoll_fd);
            death_queue_move_to_last(&dq, conn);
        }
    }

    pthread_barrier_wait(&lwan->thread.barrier);

    death_queue_kill_all(&dq);
    free(events);

    return NULL;
}

static void create_thread(struct lwan *l, struct lwan_thread *thread)
{
    int ignore;
    pthread_attr_t attr;

    memset(thread, 0, sizeof(*thread));
    thread->lwan = l;

    thread->wheel = timeouts_open(&ignore);
    if (!thread->wheel)
        lwan_status_critical("Could not create timer wheel");

    if ((thread->epoll_fd = epoll_create1(EPOLL_CLOEXEC)) < 0)
        lwan_status_critical_perror("epoll_create");

    if (pthread_attr_init(&attr))
        lwan_status_critical_perror("pthread_attr_init");

    if (pthread_attr_setscope(&attr, PTHREAD_SCOPE_SYSTEM))
        lwan_status_critical_perror("pthread_attr_setscope");

    if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE))
        lwan_status_critical_perror("pthread_attr_setdetachstate");

#if defined(HAVE_EVENTFD)
    int efd = eventfd(0, EFD_NONBLOCK | EFD_SEMAPHORE | EFD_CLOEXEC);
    if (efd < 0)
        lwan_status_critical_perror("eventfd");

    thread->pipe_fd[0] = thread->pipe_fd[1] = efd;
#else
    if (pipe2(thread->pipe_fd, O_NONBLOCK | O_CLOEXEC) < 0)
        lwan_status_critical_perror("pipe");
#endif

    struct epoll_event event = { .events = EPOLLIN, .data.ptr = NULL };
    if (epoll_ctl(thread->epoll_fd, EPOLL_CTL_ADD, thread->pipe_fd[0], &event) < 0)
        lwan_status_critical_perror("epoll_ctl");

    if (pthread_create(&thread->self, &attr, thread_io_loop, thread))
        lwan_status_critical_perror("pthread_create");

    if (pthread_attr_destroy(&attr))
        lwan_status_critical_perror("pthread_attr_destroy");

    size_t n_queue_fds = thread->lwan->thread.max_fd;
    if (n_queue_fds > 128)
        n_queue_fds = 128;
    if (spsc_queue_init(&thread->pending_fds, n_queue_fds) < 0) {
        lwan_status_critical("Could not initialize pending fd "
                             "queue width %zu elements", n_queue_fds);
    }
}

void lwan_thread_nudge(struct lwan_thread *t)
{
    uint64_t event = 1;

    if (UNLIKELY(write(t->pipe_fd[1], &event, sizeof(event)) < 0))
        lwan_status_perror("write");
}

void lwan_thread_add_client(struct lwan_thread *t, int fd)
{
    for (int i = 0; i < 10; i++) {
        bool pushed = spsc_queue_push(&t->pending_fds, fd);

        if (LIKELY(pushed))
            return;

        /* Queue is full; nudge the thread to consume it. */
        lwan_thread_nudge(t);
    }

    lwan_status_error("Dropping connection %d", fd);
    /* FIXME: send "busy" response now, even without receiving request? */
    close(fd);
}

#if defined(__linux__) && defined(__x86_64__)
static bool read_cpu_topology(struct lwan *l, uint32_t siblings[])
{
    char path[PATH_MAX];

    for (unsigned short i = 0; i < l->n_cpus; i++) {
        FILE *sib;
        uint32_t id, sibling;

        snprintf(path, sizeof(path),
                 "/sys/devices/system/cpu/cpu%hd/topology/thread_siblings_list",
                 i);

        sib = fopen(path, "re");
        if (!sib) {
            lwan_status_warning("Could not open `%s` to determine CPU topology",
                                path);
            return false;
        }

        switch (fscanf(sib, "%u-%u", &id, &sibling)) {
        case 1: /* No SMT */
            siblings[i] = id;
            break;
        case 2: /* SMT */
            siblings[i] = sibling;
            break;
        default:
            lwan_status_critical("%s has invalid format", path);
            __builtin_unreachable();
        }

        fclose(sib);
    }

    return true;
}

static void
siblings_to_schedtbl(struct lwan *l, uint32_t siblings[], uint32_t schedtbl[])
{
    int *seen = alloca(l->n_cpus * sizeof(int));
    int n_schedtbl = 0;

    for (uint32_t i = 0; i < l->n_cpus; i++)
        seen[i] = -1;

    for (uint32_t i = 0; i < l->n_cpus; i++) {
        if (seen[siblings[i]] < 0) {
            seen[siblings[i]] = (int)i;
        } else {
            schedtbl[n_schedtbl++] = (uint32_t)seen[siblings[i]];
            schedtbl[n_schedtbl++] = i;
        }
    }

    if (!n_schedtbl)
        memcpy(schedtbl, seen, l->n_cpus * sizeof(int));
}

static void
topology_to_schedtbl(struct lwan *l, uint32_t schedtbl[], uint32_t n_threads)
{
    uint32_t *siblings = alloca(l->n_cpus * sizeof(uint32_t));

    if (!read_cpu_topology(l, siblings)) {
        for (uint32_t i = 0; i < n_threads; i++)
            schedtbl[i] = (i / 2) % l->thread.count;
    } else {
        uint32_t *affinity = alloca(l->n_cpus * sizeof(uint32_t));

        siblings_to_schedtbl(l, siblings, affinity);

        for (uint32_t i = 0; i < n_threads; i++)
            schedtbl[i] = affinity[i % l->n_cpus];
    }
}

static void
adjust_threads_affinity(struct lwan *l, uint32_t *schedtbl, uint32_t mask)
{
    for (uint32_t i = 0; i < l->thread.count; i++) {
        cpu_set_t set;

        CPU_ZERO(&set);
        CPU_SET(schedtbl[i & mask], &set);

        if (pthread_setaffinity_np(l->thread.threads[i].self, sizeof(set),
                                   &set))
            lwan_status_warning("Could not set affinity for thread %d", i);
    }
}
#elif defined(__x86_64__)
static void
topology_to_schedtbl(struct lwan *l, uint32_t schedtbl[], uint32_t n_threads)
{
    for (uint32_t i = 0; i < n_threads; i++)
        schedtbl[i] = (i / 2) % l->thread.count;
}

static void
adjust_threads_affinity(struct lwan *l, uint32_t *schedtbl, uint32_t n)
{
}
#endif

void lwan_thread_init(struct lwan *l)
{
    if (pthread_barrier_init(&l->thread.barrier, NULL,
                             (unsigned)l->thread.count + 1))
        lwan_status_critical("Could not create barrier");

    lwan_status_debug("Initializing threads");

    l->thread.threads =
        calloc((size_t)l->thread.count, sizeof(struct lwan_thread));
    if (!l->thread.threads)
        lwan_status_critical("Could not allocate memory for threads");

    for (short i = 0; i < l->thread.count; i++)
        create_thread(l, &l->thread.threads[i]);

    const unsigned int total_conns = l->thread.max_fd * l->thread.count;
#ifdef __x86_64__
    static_assert(sizeof(struct lwan_connection) == 32,
                  "Two connections per cache line");
    /*
     * Pre-schedule each file descriptor, to reduce some operations in the
     * fast path.
     *
     * Since struct lwan_connection is guaranteed to be 32-byte long, two of
     * them can fill up a cache line.  Assume siblings share cache lines and
     * use the CPU topology to group two connections per cache line in such
     * a way that false sharing is avoided.
     */
    uint32_t n_threads = (uint32_t)lwan_nextpow2((size_t)((l->thread.count - 1) * 2));
    uint32_t *schedtbl = alloca(n_threads * sizeof(uint32_t));

    topology_to_schedtbl(l, schedtbl, n_threads);

    n_threads--; /* Transform count into mask for AND below */
    adjust_threads_affinity(l, schedtbl, n_threads);
    for (unsigned int i = 0; i < total_conns; i++)
        l->conns[i].thread = &l->thread.threads[schedtbl[i & n_threads]];
#else
    for (unsigned int i = 0; i < total_conns; i++)
        l->conns[i].thread = &l->thread.threads[i % l->thread.count];
#endif

    pthread_barrier_wait(&l->thread.barrier);

    lwan_status_debug("IO threads created and ready to serve");
}

void lwan_thread_shutdown(struct lwan *l)
{
    lwan_status_debug("Shutting down threads");

    for (int i = 0; i < l->thread.count; i++) {
        struct lwan_thread *t = &l->thread.threads[i];

        close(t->epoll_fd);
        lwan_thread_nudge(t);
    }

    pthread_barrier_wait(&l->thread.barrier);
    pthread_barrier_destroy(&l->thread.barrier);

    for (int i = 0; i < l->thread.count; i++) {
        struct lwan_thread *t = &l->thread.threads[i];

        close(t->pipe_fd[0]);
#if !defined(HAVE_EVENTFD)
        close(t->pipe_fd[1]);
#endif

        pthread_join(l->thread.threads[i].self, NULL);
        spsc_queue_free(&t->pending_fds);
        timeouts_close(t->wheel);
    }

    free(l->thread.threads);
}
