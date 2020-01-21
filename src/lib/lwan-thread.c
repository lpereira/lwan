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
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#if defined(HAVE_EVENTFD)
#include <sys/eventfd.h>
#endif

#include "lwan-private.h"
#include "lwan-tq.h"
#include "list.h"

static void lwan_strbuf_free_defer(void *data)
{
    lwan_strbuf_free((struct lwan_strbuf *)data);
}

static void graceful_close(struct lwan *l,
                           struct lwan_connection *conn,
                           char buffer[static DEFAULT_BUFFER_SIZE])
{
    int fd = lwan_connection_get_fd(l, conn);

    while (TIOCOUTQ) {
        /* This ioctl isn't probably doing what it says on the tin; the details
         * are subtle, but it seems to do the trick to allow gracefully closing
         * the connection in some cases with minimal system calls. */
        int bytes_waiting;
        int r = ioctl(fd, TIOCOUTQ, &bytes_waiting);

        if (!r && !bytes_waiting) /* See note about close(2) below. */
            return;
        if (r < 0 && errno == EINTR)
            continue;

        break;
    }

    if (UNLIKELY(shutdown(fd, SHUT_WR) < 0)) {
        if (UNLIKELY(errno == ENOTCONN))
            return;
    }

    for (int tries = 0; tries < 20; tries++) {
        ssize_t r = read(fd, buffer, DEFAULT_BUFFER_SIZE);

        if (!r)
            break;

        if (r < 0) {
            switch (errno) {
            case EINTR:
                continue;
            case EAGAIN:
                coro_yield(conn->coro, CONN_CORO_WANT_READ);
                continue;
            default:
                return;
            }
        }

        coro_yield(conn->coro, CONN_CORO_YIELD);
    }

    /* close(2) will be called when the coroutine yields with CONN_CORO_ABORT */
}

__attribute__((noreturn)) static int process_request_coro(struct coro *coro,
                                                          void *data)
{
    /* NOTE: This function should not return; coro_yield should be used
     * instead.  This ensures the storage for `strbuf` is alive when the
     * coroutine ends and lwan_strbuf_free() is called. */
    struct lwan_connection *conn = data;
    struct lwan *lwan = conn->thread->lwan;
    int fd = lwan_connection_get_fd(lwan, conn);
    enum lwan_request_flags flags = lwan->config.request_flags;
    struct lwan_strbuf strbuf = LWAN_STRBUF_STATIC_INIT;
    char request_buffer[DEFAULT_BUFFER_SIZE];
    struct lwan_value buffer = {.value = request_buffer, .len = 0};
    char *next_request = NULL;
    struct lwan_proxy proxy;

    coro_defer(coro, lwan_strbuf_free_defer, &strbuf);

    const size_t init_gen = 1; /* 1 call to coro_defer() */
    assert(init_gen == coro_deferred_get_generation(coro));

    while (true) {
        struct lwan_request request = {.conn = conn,
                                       .fd = fd,
                                       .response = {.buffer = &strbuf},
                                       .flags = flags,
                                       .proxy = &proxy};

        next_request =
            lwan_process_request(lwan, &request, &buffer, next_request);

        if (coro_deferred_get_generation(coro) > ((2 * LWAN_ARRAY_INCREMENT) / 3)) {
            /* Batch execution of coro_defers() up to 2/3 LWAN_ARRAY_INCREMENT times,
             * to avoid moving deferred array to heap in most cases.  (This is to give
             * some slack to the next request being processed by this coro.) */
            coro_deferred_run(coro, init_gen);
        }

        if (LIKELY(conn->flags & CONN_IS_KEEP_ALIVE)) {
            if (next_request && *next_request) {
                conn->flags |= CONN_CORK;
                coro_yield(coro, CONN_CORO_WANT_WRITE);
            } else {
                conn->flags &= ~CONN_CORK;
                coro_yield(coro, CONN_CORO_WANT_READ);
            }
        } else {
            graceful_close(lwan, conn, request_buffer);
            break;
        }

        lwan_strbuf_reset(&strbuf);

        /* Only allow flags from config. */
        flags = request.flags & (REQUEST_PROXIED | REQUEST_ALLOW_CORS);
    }

    coro_yield(coro, CONN_CORO_ABORT);
    __builtin_unreachable();
}

#undef REQUEST_FLAG

static ALWAYS_INLINE uint32_t
conn_flags_to_epoll_events(enum lwan_connection_flags flags)
{
    static const uint32_t map[CONN_EVENTS_MASK + 1] = {
        [0 /* Suspended by timer */] = EPOLLRDHUP,
        [CONN_EVENTS_WRITE] = EPOLLOUT | EPOLLRDHUP,
        [CONN_EVENTS_READ] = EPOLLIN | EPOLLRDHUP,
        [CONN_EVENTS_READ_WRITE] = EPOLLIN | EPOLLOUT | EPOLLRDHUP,
    };

    return map[flags & CONN_EVENTS_MASK];
}

#if defined(__linux__)
# define CONN_EVENTS_RESUME_TIMER CONN_EVENTS_READ_WRITE
#else
/* Kqueue doesn't like when you filter on both read and write, so
 * wait only on write when resuming a coro suspended by a timer.
 * The I/O wrappers should yield if trying to read without anything
 * in the buffer, changing the filter to only read, so this is OK. */
# define CONN_EVENTS_RESUME_TIMER CONN_EVENTS_WRITE
#endif

static void update_epoll_flags(int fd,
                               struct lwan_connection *conn,
                               int epoll_fd,
                               enum lwan_connection_coro_yield yield_result)
{
    static const enum lwan_connection_flags or_mask[CONN_CORO_MAX] = {
        [CONN_CORO_YIELD] = 0,
        [CONN_CORO_WANT_READ_WRITE] = CONN_EVENTS_READ_WRITE,
        [CONN_CORO_WANT_READ] = CONN_EVENTS_READ,
        [CONN_CORO_WANT_WRITE] = CONN_EVENTS_WRITE,

        /* While the coro is suspended, we're not interested in either EPOLLIN
         * or EPOLLOUT events.  We still want to track this fd in epoll, though,
         * so unset both so that only EPOLLRDHUP (plus the implicitly-set ones)
         * are set. */
        [CONN_CORO_SUSPEND_TIMER] = CONN_SUSPENDED_TIMER,

        /* Either EPOLLIN or EPOLLOUT have to be set here.  There's no need to
         * know which event, because they were both cleared when the coro was
         * suspended. So set both flags here. This works because EPOLLET isn't
         * used. */
        [CONN_CORO_RESUME_TIMER] = CONN_EVENTS_RESUME_TIMER,
    };
    static const enum lwan_connection_flags and_mask[CONN_CORO_MAX] = {
        [CONN_CORO_YIELD] = ~0,
        [CONN_CORO_WANT_READ_WRITE] = ~0,
        [CONN_CORO_WANT_READ] = ~CONN_EVENTS_WRITE,
        [CONN_CORO_WANT_WRITE] = ~CONN_EVENTS_READ,
        [CONN_CORO_SUSPEND_TIMER] = ~CONN_EVENTS_READ_WRITE,
        [CONN_CORO_RESUME_TIMER] = ~CONN_SUSPENDED_TIMER,
    };
    enum lwan_connection_flags prev_flags = conn->flags;

    conn->flags |= or_mask[yield_result];
    conn->flags &= and_mask[yield_result];

    if (conn->flags == prev_flags)
        return;

    struct epoll_event event = {
        .events = conn_flags_to_epoll_events(conn->flags),
        .data.ptr = conn,
    };

    if (UNLIKELY(epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &event) < 0))
        lwan_status_perror("epoll_ctl");
}

static ALWAYS_INLINE void
resume_coro(struct timeout_queue *tq, struct lwan_connection *conn, int epoll_fd)
{
    assert(conn->coro);

    enum lwan_connection_coro_yield yield_result = coro_resume(conn->coro);
    if (yield_result == CONN_CORO_ABORT) {
        timeout_queue_expire(tq, conn);
        return;
    }

    update_epoll_flags(lwan_connection_get_fd(tq->lwan, conn), conn, epoll_fd,
                       yield_result);
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
                                     struct timeout_queue *tq)
{
    struct lwan_thread *t = conn->thread;

    assert(!conn->coro);
    assert(t);
    assert((uintptr_t)t >= (uintptr_t)tq->lwan->thread.threads);
    assert((uintptr_t)t <
           (uintptr_t)(tq->lwan->thread.threads + tq->lwan->thread.count));

    *conn = (struct lwan_connection) {
        .coro = coro_new(switcher, process_request_coro, conn),
        .flags = CONN_EVENTS_READ,
        .time_to_expire = tq->time + tq->keep_alive_timeout,
        .thread = t,
    };
    if (UNLIKELY(!conn->coro)) {
        conn->flags = 0;
        lwan_status_error("Could not create coroutine");
        return;
    }

    timeout_queue_insert(tq, conn);
}

static void accept_nudge(int pipe_fd,
                         struct lwan_thread *t,
                         struct lwan_connection *conns,
                         struct timeout_queue *tq,
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
        struct epoll_event ev = {
            .data.ptr = conn,
            .events = conn_flags_to_epoll_events(CONN_EVENTS_READ),
        };

        if (LIKELY(!epoll_ctl(epoll_fd, EPOLL_CTL_ADD, new_fd, &ev)))
            spawn_coro(conn, switcher, tq);
    }

    timeouts_add(t->wheel, &tq->timeout, 1000);
}

static bool process_pending_timers(struct timeout_queue *tq,
                                   struct lwan_thread *t,
                                   int epoll_fd)
{
    struct timeout *timeout;
    bool should_expire_timers = false;

    while ((timeout = timeouts_get(t->wheel))) {
        struct lwan_request *request;

        if (timeout == &tq->timeout) {
            should_expire_timers = true;
            continue;
        }

        request = container_of(timeout, struct lwan_request, timeout);

        update_epoll_flags(request->fd, request->conn, epoll_fd,
                           CONN_CORO_RESUME_TIMER);
    }

    if (should_expire_timers) {
        timeout_queue_expire_waiting(tq);

        /* tq timeout expires every 1000ms if there are connections, so
         * update the date cache at this point as well.  */
        update_date_cache(t);

        if (!timeout_queue_empty(tq)) {
            timeouts_add(t->wheel, &tq->timeout, 1000);
            return true;
        }

        timeouts_del(t->wheel, &tq->timeout);
    }

    return false;
}

static int
turn_timer_wheel(struct timeout_queue *tq, struct lwan_thread *t, int epoll_fd)
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
        if (!process_pending_timers(tq, t, epoll_fd))
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
    const int max_events = LWAN_MIN((int)t->lwan->thread.max_fd, 1024);
    struct lwan *lwan = t->lwan;
    struct epoll_event *events;
    struct coro_switcher switcher;
    struct timeout_queue tq;

    lwan_status_debug("Worker thread #%zd starting",
                      t - t->lwan->thread.threads + 1);
    lwan_set_thread_name("worker");

    events = calloc((size_t)max_events, sizeof(*events));
    if (UNLIKELY(!events))
        lwan_status_critical("Could not allocate memory for events");

    update_date_cache(t);

    timeout_queue_init(&tq, lwan);

    pthread_barrier_wait(&lwan->thread.barrier);

    for (;;) {
        int timeout = turn_timer_wheel(&tq, t, epoll_fd);
        int n_fds = epoll_wait(epoll_fd, events, max_events, timeout);

        if (UNLIKELY(n_fds < 0)) {
            if (errno == EBADF || errno == EINVAL)
                break;
            continue;
        }

        for (struct epoll_event *event = events; n_fds--; event++) {
            struct lwan_connection *conn;

            if (UNLIKELY(!event->data.ptr)) {
                accept_nudge(read_pipe_fd, t, lwan->conns, &tq, &switcher,
                             epoll_fd);
                continue;
            }

            conn = event->data.ptr;

            if (UNLIKELY(event->events & (EPOLLRDHUP | EPOLLHUP))) {
                timeout_queue_expire(&tq, conn);
                continue;
            }

            resume_coro(&tq, conn, epoll_fd);
            timeout_queue_move_to_last(&tq, conn);
        }
    }

    pthread_barrier_wait(&lwan->thread.barrier);

    timeout_queue_expire_all(&tq);
    free(events);

    return NULL;
}

static void create_thread(struct lwan *l, struct lwan_thread *thread,
                          const size_t n_queue_fds)
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
        char separator;

        snprintf(path, sizeof(path),
                 "/sys/devices/system/cpu/cpu%hd/topology/thread_siblings_list",
                 i);

        sib = fopen(path, "re");
        if (!sib) {
            lwan_status_warning("Could not open `%s` to determine CPU topology",
                                path);
            return false;
        }

        switch (fscanf(sib, "%u%c%u", &id, &separator, &sibling)) {
        case 2: /* No SMT */
            siblings[i] = id;
            break;
        case 3: /* SMT */
            if (!(separator == ',' || separator == '-')) {
                lwan_status_critical("Expecting either ',' or '-' for sibling separator");
                __builtin_unreachable();
            }

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

    const size_t n_queue_fds = LWAN_MIN(l->thread.max_fd / l->thread.count,
                                        (size_t)(2 * lwan_socket_get_backlog_size()));
    lwan_status_debug("Pending client file descriptor queue has %zu items", n_queue_fds);
    for (short i = 0; i < l->thread.count; i++)
        create_thread(l, &l->thread.threads[i], n_queue_fds);

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

    lwan_status_debug("Worker threads created and ready to serve");
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
