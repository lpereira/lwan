/*
 * lwan - web server
 * Copyright (c) 2012, 2013 L. A. F. Pereira <l@tia.mat.br>
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

#if defined(LWAN_HAVE_SO_ATTACH_REUSEPORT_CBPF)
#include <linux/filter.h>
#endif

#if defined(LWAN_HAVE_MBEDTLS)
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/gcm.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl_internal.h>

#include <linux/tls.h>
#include <netinet/tcp.h>
#endif

#include "list.h"
#include "lwan-private.h"
#include "lwan-tq.h"

static void lwan_strbuf_free_defer(void *data)
{
    return lwan_strbuf_free((struct lwan_strbuf *)data);
}

static void graceful_close(struct lwan *l,
                           struct lwan_connection *conn)
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

    char buffer[128];
    for (int tries = 0; tries < 20; tries++) {
        ssize_t r = recv(fd, buffer, sizeof(buffer), MSG_TRUNC);

        if (!r)
            break;

        if (r < 0) {
            switch (errno) {
            case EAGAIN:
                break;
            case EINTR:
                continue;
            default:
                return;
            }
        }

        coro_yield(conn->coro, CONN_CORO_WANT_READ);
    }

    /* close(2) will be called when the coroutine yields with CONN_CORO_ABORT */
}

#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
static void lwan_random_seed_prng_for_thread(const struct lwan_thread *t)
{
    (void)t;
}

uint64_t lwan_random_uint64(void)
{
    static uint64_t value = 1;

    return ATOMIC_INC(value);
}
#else
static __thread __uint128_t lehmer64_state;

static void lwan_random_seed_prng_for_thread(const struct lwan_thread *t)
{
    if (lwan_getentropy(&lehmer64_state, sizeof(lehmer64_state), 0) < 0) {
        lwan_status_warning("Couldn't get proper entropy for PRNG, using fallback seed");
        uintptr_t ptr = (uintptr_t)t;
        lehmer64_state |= fnv1a_64(&ptr, sizeof(ptr));
        lehmer64_state <<= 64;
        lehmer64_state |= fnv1a_64(&t->epoll_fd, sizeof(t->epoll_fd));
    }
}

uint64_t lwan_random_uint64(void)
{
    /* https://lemire.me/blog/2019/03/19/the-fastest-conventional-random-number-generator-that-can-pass-big-crush/ */
    lehmer64_state *= 0xda942042e4dd58b5ull;
    return (uint64_t)(lehmer64_state >> 64);
}
#endif

uint64_t lwan_request_get_id(struct lwan_request *request)
{
    struct lwan_request_parser_helper *helper = request->helper;

    if (helper->request_id == 0) {
        helper->request_id = lwan_random_uint64();

        if (UNLIKELY(helper->request_id == 0)) {
            lwan_random_seed_prng_for_thread(request->conn->thread);
            return lwan_request_get_id(request);
        }
    }

    return helper->request_id;
}

#if defined(LWAN_HAVE_MBEDTLS)
static bool
lwan_setup_tls_keys(int fd, const mbedtls_ssl_context *ssl, int rx_or_tx)
{
    struct tls12_crypto_info_aes_gcm_128 info = {
        .info = {.version = TLS_1_2_VERSION,
                 .cipher_type = TLS_CIPHER_AES_GCM_128},
    };
    const unsigned char *salt, *iv, *rec_seq;
    const mbedtls_gcm_context *gcm_ctx;
    const mbedtls_aes_context *aes_ctx;

    switch (rx_or_tx) {
    case TLS_RX:
        salt = ssl->transform->iv_dec;
        rec_seq = ssl->in_ctr;
        gcm_ctx = ssl->transform->cipher_ctx_dec.cipher_ctx;
        break;
    case TLS_TX:
        salt = ssl->transform->iv_enc;
        rec_seq = ssl->cur_out_ctr;
        gcm_ctx = ssl->transform->cipher_ctx_enc.cipher_ctx;
        break;
    default:
        __builtin_unreachable();
    }

    iv = salt + 4;
    aes_ctx = gcm_ctx->cipher_ctx.cipher_ctx;

    memcpy(info.iv, iv, TLS_CIPHER_AES_GCM_128_IV_SIZE);
    memcpy(info.rec_seq, rec_seq, TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);
    memcpy(info.key, aes_ctx->rk, TLS_CIPHER_AES_GCM_128_KEY_SIZE);
    memcpy(info.salt, salt, TLS_CIPHER_AES_GCM_128_SALT_SIZE);

    if (UNLIKELY(setsockopt(fd, SOL_TLS, rx_or_tx, &info, sizeof(info)) < 0)) {
        lwan_status_perror("Could not set %s kTLS keys for fd %d",
                           rx_or_tx == TLS_TX ? "transmission" : "reception",
                           fd);
        lwan_always_bzero(&info, sizeof(info));
        return false;
    }

    lwan_always_bzero(&info, sizeof(info));
    return true;
}

__attribute__((format(printf, 2, 3)))
__attribute__((noinline, cold))
static void lwan_status_mbedtls_error(int error_code, const char *fmt, ...)
{
    char *formatted;
    va_list ap;
    int r;

    va_start(ap, fmt);
    r = vasprintf(&formatted, fmt, ap);
    if (r >= 0) {
        char mbedtls_errbuf[128];

        mbedtls_strerror(error_code, mbedtls_errbuf, sizeof(mbedtls_errbuf));
        lwan_status_error("%s: %s", formatted, mbedtls_errbuf);
        free(formatted);
    }
    va_end(ap);
}

static void lwan_setup_tls_free_ssl_context(void *data)
{
    mbedtls_ssl_context *ssl = data;

    mbedtls_ssl_free(ssl);
}

struct lwan_mbedtls_handshake_ctx {
    int fd;
    bool last_was_send;
};

static int lwan_mbedtls_send(void *ctx, const unsigned char *buf, size_t len)
{
    struct lwan_mbedtls_handshake_ctx *hs_ctx = ctx;
    ssize_t r;

    /* We use MSG_MORE -- flushing when we transition from send() to recv()
     * -- rather than buffering on our side because this contains key
     * material that we would need to only copy, but also zero out after
     * finishing the handshake.  */

    r = send(hs_ctx->fd, buf, len, MSG_MORE);
    if (UNLIKELY(r < 0)) {
        switch (errno) {
        case EINTR:
        case EAGAIN:
            return MBEDTLS_ERR_SSL_WANT_WRITE;

        default:
            /* It's not an internal error here, but this seemed the least
             * innapropriate error code for this situation.  lwan_setup_tls()
             * doesn't care. */
            return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        }
    }

    if (UNLIKELY((ssize_t)(int)r != r))
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;

    hs_ctx->last_was_send = true;
    return (int)r;
}

static void flush_pending_output(int fd)
{
    int zero = 0;
    setsockopt(fd, SOL_TCP, TCP_CORK, &zero, sizeof(zero));
}

static int lwan_mbedtls_recv(void *ctx, unsigned char *buf, size_t len)
{
    struct lwan_mbedtls_handshake_ctx *hs_ctx = ctx;
    ssize_t r;

    if (hs_ctx->last_was_send) {
        flush_pending_output(hs_ctx->fd);
        hs_ctx->last_was_send = false;
    }

    r = recv(hs_ctx->fd, buf, len, 0);
    if (UNLIKELY(r < 0)) {
        switch (errno) {
        case EINTR:
        case EAGAIN:
            return MBEDTLS_ERR_SSL_WANT_READ;

        default:
            return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        }
    }

    if (UNLIKELY((ssize_t)(int)r != r))
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;

    return (int)r;
}

static bool lwan_setup_tls(const struct lwan *l, struct lwan_connection *conn)
{
    mbedtls_ssl_context ssl;
    bool retval = false;
    int r;

    mbedtls_ssl_init(&ssl);

    r = mbedtls_ssl_setup(&ssl, &l->tls->config);
    if (UNLIKELY(r != 0)) {
        lwan_status_mbedtls_error(r, "Could not setup TLS context");
        return false;
    }

    /* Yielding the coroutine during the handshake enables the I/O loop to
     * destroy this coro (e.g.  on connection hangup) before we have the
     * opportunity to free the SSL context.  Defer this call for these
     * cases. */
    coro_deferred defer =
        coro_defer(conn->coro, lwan_setup_tls_free_ssl_context, &ssl);

    if (UNLIKELY(!defer)) {
        lwan_status_error("Could not defer cleanup of the TLS context");
        return false;
    }

    int fd = lwan_connection_get_fd(l, conn);

    struct lwan_mbedtls_handshake_ctx ctx = { .fd = fd };
    mbedtls_ssl_set_bio(&ssl, &ctx, lwan_mbedtls_send,
                        lwan_mbedtls_recv, NULL);

    while (true) {
        switch (mbedtls_ssl_handshake(&ssl)) {
        case 0:
            flush_pending_output(fd);
            goto enable_tls_ulp;
        case MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS:
        case MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS:
        case MBEDTLS_ERR_SSL_WANT_READ:
            coro_yield(conn->coro, CONN_CORO_WANT_READ);
            break;
        case MBEDTLS_ERR_SSL_WANT_WRITE:
            coro_yield(conn->coro, CONN_CORO_WANT_WRITE);
            break;
        default:
            goto fail;
        }
    }

enable_tls_ulp:
    if (UNLIKELY(setsockopt(fd, SOL_TCP, TCP_ULP, "tls", sizeof("tls")) < 0))
        goto fail;
    if (UNLIKELY(!lwan_setup_tls_keys(fd, &ssl, TLS_RX)))
        goto fail;
    if (UNLIKELY(!lwan_setup_tls_keys(fd, &ssl, TLS_TX)))
        goto fail;

    retval = true;

fail:
    coro_defer_disarm(conn->coro, defer);
    mbedtls_ssl_free(&ssl);
    return retval;
}
#endif

__attribute__((cold))
static bool send_buffer_without_coro(int fd, const char *buf, size_t buf_len, int flags)
{
    size_t total_sent = 0;

    for (int try = 0; try < 10; try++) {
        size_t to_send = buf_len - total_sent;
        if (!to_send)
            return true;

        ssize_t sent = send(fd, buf + total_sent, to_send, flags);
        if (sent <= 0) {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN)
                continue;
            break;
        }

        total_sent += (size_t)sent;
    }

    return false;
}

__attribute__((cold))
static bool send_string_without_coro(int fd, const char *str, int flags)
{
    return send_buffer_without_coro(fd, str, strlen(str), flags);
}

__attribute__((cold)) static void
send_last_response_without_coro(const struct lwan *l,
                                const struct lwan_connection *conn,
                                enum lwan_http_status status)
{
    int fd = lwan_connection_get_fd(l, conn);

    if (conn->flags & CONN_TLS) {
        /* There's nothing that can be done here if a client is expecting a
         * TLS connection: the TLS handshake requires a coroutine as it
         * might yield.  (In addition, the TLS handshake might allocate
         * memory, and if you couldn't create a coroutine at this point,
         * it's unlikely you'd be able to allocate memory for the TLS
         * context anyway.) */
        goto shutdown_and_close;
    }

    if (!send_string_without_coro(fd, "HTTP/1.0 ", MSG_MORE))
        goto shutdown_and_close;

    if (!send_string_without_coro(
            fd, lwan_http_status_as_string_with_code(status), MSG_MORE))
        goto shutdown_and_close;

    if (!send_string_without_coro(fd, "\r\nConnection: close", MSG_MORE))
        goto shutdown_and_close;

    if (!send_string_without_coro(fd, "\r\nContent-Type: text/html", MSG_MORE))
        goto shutdown_and_close;

    if (send_buffer_without_coro(fd, l->headers.value, l->headers.len,
                                 MSG_MORE)) {
        struct lwan_strbuf buffer;

        lwan_strbuf_init(&buffer);
        lwan_fill_default_response(&buffer, status);

        send_buffer_without_coro(fd, lwan_strbuf_get_buffer(&buffer),
                                 lwan_strbuf_get_length(&buffer), 0);

        lwan_strbuf_free(&buffer);
    }

shutdown_and_close:
    shutdown(fd, SHUT_RDWR);
    close(fd);
}

__attribute__((noreturn)) static int process_request_coro(struct coro *coro,
                                                          void *data)
{
    /* NOTE: This function should not return; coro_yield should be used
     * instead.  This ensures the storage for `strbuf` is alive when the
     * coroutine ends and lwan_strbuf_free() is called. */
    char *header_start[N_HEADER_START];
    struct lwan_connection *conn = data;
    struct lwan *lwan = conn->thread->lwan;
    int fd = lwan_connection_get_fd(lwan, conn);
    enum lwan_request_flags flags = lwan->config.request_flags;
    const size_t request_buffer_size = lwan->config.request_buffer_size;
    const int error_when_n_packets = lwan_calculate_n_packets(request_buffer_size);
    struct lwan_strbuf strbuf = LWAN_STRBUF_STATIC_INIT;
    struct lwan_value buffer;
    char *next_request = NULL;
    struct lwan_proxy proxy;
    size_t init_gen;

    coro_defer(coro, lwan_strbuf_free_defer, &strbuf);

#if defined(LWAN_HAVE_MBEDTLS)
    if (conn->flags & CONN_TLS) {
        if (UNLIKELY(!lwan_setup_tls(lwan, conn))) {
            coro_yield(conn->coro, CONN_CORO_ABORT);
            __builtin_unreachable();
        }
    }
#else
    assert(!(conn->flags & CONN_TLS));
#endif

    if (request_buffer_size > DEFAULT_BUFFER_SIZE) {
        buffer = (struct lwan_value){
            .value = coro_malloc_full(conn->coro, request_buffer_size, free),
            .len = request_buffer_size,
        };

        if (UNLIKELY(!buffer.value)) {
            /* If CONN_TLS is set at this point, we can send responses just
             * fine and they'll be encrypted by the kernel.  However,
             * send_last_response_without_coro() can't send the response if
             * this bit is set as it has been designed to be used in cases
             * where coroutines were not created yet.  */
            conn->flags &= ~CONN_TLS;

            send_last_response_without_coro(lwan, conn, HTTP_UNAVAILABLE);

            coro_yield(conn->coro, CONN_CORO_ABORT);
            __builtin_unreachable();
        }

        init_gen = 2;
    } else {
        buffer = (struct lwan_value){
            .value = alloca(DEFAULT_BUFFER_SIZE),
            .len = DEFAULT_BUFFER_SIZE,
        };

        init_gen = 1;
    }

    while (true) {
        struct lwan_request_parser_helper helper = {
            .buffer = &buffer,
            .next_request = next_request,
            .error_when_n_packets = error_when_n_packets,
            .header_start = header_start,
        };
        struct lwan_request request = {.conn = conn,
                                       .global_response_headers = &lwan->headers,
                                       .fd = fd,
                                       .response = {.buffer = &strbuf},
                                       .flags = flags,
                                       .proxy = &proxy,
                                       .helper = &helper};

        lwan_process_request(lwan, &request);

        /* Run the deferred instructions now (except those used to initialize
         * the coroutine), so that if the connection is gracefully closed,
         * the storage for ``helper'' is still there. */
        coro_deferred_run(coro, init_gen);

        if (UNLIKELY(!(conn->flags & CONN_IS_KEEP_ALIVE))) {
            graceful_close(lwan, conn);
            break;
        }

        if (next_request && *next_request) {
            conn->flags |= CONN_CORK;

            if (!(conn->flags & CONN_EVENTS_WRITE))
                coro_yield(coro, CONN_CORO_WANT_WRITE);
        } else {
            conn->flags &= ~CONN_CORK;
            coro_yield(coro, CONN_CORO_WANT_READ);
        }

        /* Ensure string buffer is reset between requests, and that the backing
         * store isn't over 2KB. */
        lwan_strbuf_reset_trim(&strbuf, 2048);

        /* Only allow flags from config. */
        flags = request.flags & (REQUEST_PROXIED | REQUEST_ALLOW_CORS | REQUEST_WANTS_HSTS_HEADER);
        next_request = helper.next_request;
    }

    coro_yield(coro, CONN_CORO_ABORT);
    __builtin_unreachable();
}

#define EPOLL_EVENTS(flags) (((uint32_t)flags) >> CONN_EPOLL_EVENT_SHIFT)
#define LWAN_EVENTS(flags) (((uint32_t)flags) & CONN_EPOLL_EVENT_MASK)

static ALWAYS_INLINE uint32_t
conn_flags_to_epoll_events(enum lwan_connection_flags flags)
{
    assert((EPOLL_EVENTS(flags) &
            (uint32_t) ~(EPOLLIN | EPOLLOUT | EPOLLRDHUP)) == 0);
    return EPOLL_EVENTS(flags);
}

static int update_epoll_flags(const struct lwan *lwan,
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
        [CONN_CORO_SUSPEND] = CONN_SUSPENDED,

        /* Ideally, when suspending a coroutine, the current flags&CONN_EVENTS_MASK
         * would have to be stored and restored -- however, resuming as if the
         * client coroutine is interested in a write event always guarantees that
         * they'll be resumed as they're TCP sockets.  There's a good chance that
         * trying to read from a socket after resuming a coroutine will succeed,
         * but if it doesn't because read() returns -EAGAIN, the I/O wrappers will
         * yield with CONN_CORO_WANT_READ anyway.  */
        [CONN_CORO_RESUME] = CONN_EVENTS_WRITE,
    };
    static const enum lwan_connection_flags and_mask[CONN_CORO_MAX] = {
        [CONN_CORO_YIELD] = ~0,

        [CONN_CORO_WANT_READ_WRITE] = ~0,
        [CONN_CORO_WANT_READ] = ~CONN_EVENTS_WRITE,
        [CONN_CORO_WANT_WRITE] = ~CONN_EVENTS_READ,

        [CONN_CORO_SUSPEND] = ~CONN_EVENTS_READ_WRITE,
        [CONN_CORO_RESUME] = ~CONN_SUSPENDED,
    };
    enum lwan_connection_flags prev_flags = conn->flags;

    conn->flags |= or_mask[yield_result];
    conn->flags &= and_mask[yield_result];

    assert(!(conn->flags & CONN_LISTENER));
    assert((conn->flags & CONN_TLS) == (prev_flags & CONN_TLS));

    if (LWAN_EVENTS(conn->flags) == LWAN_EVENTS(prev_flags))
        return 0;

    struct epoll_event event = {.events = conn_flags_to_epoll_events(conn->flags),
                                .data.ptr = conn};
    int fd = lwan_connection_get_fd(lwan, conn);
    return epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &event);
}

static void unasync_await_conn(void *data1, void *data2)
{
    struct lwan_connection *async_fd_conn = data1;

    async_fd_conn->flags &=
        ~(CONN_ASYNC_AWAIT | CONN_HUNG_UP | CONN_ASYNC_AWAITV);
    assert(async_fd_conn->parent);
    async_fd_conn->parent->flags &= ~CONN_ASYNC_AWAITV;

    async_fd_conn->thread = data2;

    /* If this file descriptor number is used again in the future as an HTTP
     * connection, we need the coro pointer to be NULL so a new coroutine is
     * created!  */
    async_fd_conn->coro = NULL;

    /* While not strictly necessary, make sure that prev/next point to
     * something valid rather than whatever junk was left from when their
     * storage was used for the parent pointer.  */
    async_fd_conn->prev = -1;
    async_fd_conn->next = -1;
}

static int prepare_await(const struct lwan *l,
                         enum lwan_connection_coro_yield yield_result,
                         int await_fd,
                         struct lwan_connection *conn,
                         int epoll_fd)
{
    static const enum lwan_connection_flags to_connection_flags[] = {
        [CONN_CORO_WANT_READ] = CONN_EVENTS_READ,
        [CONN_CORO_WANT_WRITE] = CONN_EVENTS_WRITE,
        [CONN_CORO_WANT_READ_WRITE] = CONN_EVENTS_READ_WRITE,
    };
    enum lwan_connection_flags flags;
    int op;

    assert(await_fd >= 0);
    assert(yield_result >= CONN_CORO_WANT_READ &&
           yield_result <= CONN_CORO_WANT_READ_WRITE);

    flags = to_connection_flags[yield_result];

    struct lwan_connection *await_fd_conn = &l->conns[await_fd];
    if (LIKELY(await_fd_conn->flags & CONN_ASYNC_AWAIT)) {
        if (LIKELY(LWAN_EVENTS(await_fd_conn->flags) == LWAN_EVENTS(flags))) {
            return 0;
        }

        op = EPOLL_CTL_MOD;
    } else {
        await_fd_conn->parent = conn;

        /* We assert() in the timeout queue that we're not freeing a
         * coroutine when CONN_ASYNC_AWAIT is set in the connection, and are
         * careful to not ever do that.  This makes us get away with struct
         * coro not being refcounted, even though this kinda feels like
         * running with scissors.  */
        assert(!await_fd_conn->coro);
        await_fd_conn->coro = conn->coro;

        /* Since scheduling is performed during startup, we gotta take note
         * of which thread was originally supposed to handle this particular
         * file descriptor once we're done borrowing this lwan_connection
         * for the awaited file descriptor.  */
        struct lwan_thread *old_thread = await_fd_conn->thread;
        await_fd_conn->thread = conn->thread;

        op = EPOLL_CTL_ADD;
        flags |= CONN_ASYNC_AWAIT;

        coro_defer2(conn->coro, unasync_await_conn, await_fd_conn, old_thread);
    }

    struct epoll_event event = {.events = conn_flags_to_epoll_events(flags),
                                .data.ptr = await_fd_conn};
    if (LIKELY(!epoll_ctl(epoll_fd, op, await_fd, &event))) {
        await_fd_conn->flags &= ~CONN_EVENTS_MASK;
        await_fd_conn->flags |= flags;
        return 0;
    }

    return -errno;
}

static void clear_awaitv_flags(struct lwan_connection *conns, va_list ap_orig)
{
    va_list ap;

    va_copy(ap, ap_orig);
    for (int fd = va_arg(ap, int); fd >= 0; fd = va_arg(ap, int)) {
        conns[fd].flags &= ~CONN_ASYNC_AWAITV;
        LWAN_NO_DISCARD(va_arg(ap, enum lwan_connection_coro_yield));
    }
    va_end(ap);
}

struct awaitv_state {
    unsigned int num_awaiting;
    enum lwan_connection_coro_yield request_conn_yield;
};

static int prepare_awaitv(struct lwan_request *r,
                          struct lwan *l,
                          va_list ap,
                          struct awaitv_state *state)
{
    int epoll_fd = r->conn->thread->epoll_fd;

    *state = (struct awaitv_state){
        .num_awaiting = 0,
        .request_conn_yield = CONN_CORO_SUSPEND,
    };

    clear_awaitv_flags(l->conns, ap);

    for (int await_fd = va_arg(ap, int); await_fd >= 0;
         await_fd = va_arg(ap, int)) {
        struct lwan_connection *conn = &l->conns[await_fd];
        enum lwan_connection_coro_yield events =
            va_arg(ap, enum lwan_connection_coro_yield);

        if (UNLIKELY(events < CONN_CORO_WANT_READ ||
                     events > CONN_CORO_WANT_READ_WRITE)) {
            return -EINVAL;
        }
        if (UNLIKELY(conn->flags & CONN_ASYNC_AWAITV)) {
            lwan_status_debug("ignoring second awaitv call on same fd: %d",
                              await_fd);
            continue;
        }

        conn->flags |= CONN_ASYNC_AWAITV;
        state->num_awaiting++;

        if (await_fd == r->fd) {
            state->request_conn_yield = events;
            continue;
        }

        int ret = prepare_await(l, events, await_fd, r->conn, epoll_fd);
        if (UNLIKELY(ret < 0)) {
            errno = -ret;
            lwan_status_perror("prepare_await(%d)", await_fd);
            return ret;
        }
    }

    return 0;
}

int lwan_request_awaitv_any(struct lwan_request *r, ...)
{
    struct lwan *l = r->conn->thread->lwan;
    struct awaitv_state state;
    va_list ap;

    va_start(ap, r);
    int ret = prepare_awaitv(r, l, ap, &state);
    va_end(ap);

    if (UNLIKELY(ret < 0)) {
        errno = -ret;
        lwan_status_perror("prepare_awaitv()");
        coro_yield(r->conn->coro, CONN_CORO_ABORT);
        __builtin_unreachable();
    }

    while (true) {
        int64_t v = coro_yield(r->conn->coro, state.request_conn_yield);
        struct lwan_connection *conn = (struct lwan_connection *)(uintptr_t)v;

        if (conn->flags & CONN_ASYNC_AWAITV) {
            /* Ensure flags are unset in case awaitv_any() is called with
             * a different set of file descriptors. */
            va_start(ap, r);
            clear_awaitv_flags(l->conns, ap);
            va_end(ap);

            int fd = lwan_connection_get_fd(l, conn);
            return UNLIKELY(conn->flags & CONN_HUNG_UP) ? -fd : fd;
        }
    }
}

int lwan_request_awaitv_all(struct lwan_request *r, ...)
{
    struct lwan *l = r->conn->thread->lwan;
    struct awaitv_state state;
    va_list ap;

    va_start(ap, r);
    int ret = prepare_awaitv(r, l, ap, &state);
    va_end(ap);

    if (UNLIKELY(ret < 0)) {
        errno = -ret;
        lwan_status_perror("prepare_awaitv()");
        coro_yield(r->conn->coro, CONN_CORO_ABORT);
        __builtin_unreachable();
    }

    while (state.num_awaiting) {
        int64_t v = coro_yield(r->conn->coro, state.request_conn_yield);
        struct lwan_connection *conn = (struct lwan_connection *)(uintptr_t)v;

        if (conn->flags & CONN_ASYNC_AWAITV) {
            conn->flags &= ~CONN_ASYNC_AWAITV;

            if (UNLIKELY(conn->flags & CONN_HUNG_UP)) { 
                /* Ensure flags are unset in case awaitv_any() is called with
                 * a different set of file descriptors. */
                va_start(ap, r);
                clear_awaitv_flags(l->conns, ap);
                va_end(ap);

                return lwan_connection_get_fd(l, conn);
            }

            state.num_awaiting--;
        }
    }

    return -EISCONN;
}

static inline int async_await_fd(struct lwan_request *request,
                                 int fd,
                                 enum lwan_connection_coro_yield events)
{
    struct lwan_thread *thread = request->conn->thread;
    struct lwan *lwan = thread->lwan;
    struct lwan_connection *awaited = &lwan->conns[fd];

    if (request->conn != awaited) {
        int r =
            prepare_await(lwan, events, fd, request->conn, thread->epoll_fd);
        if (UNLIKELY(r < 0))
            return r;

        events = CONN_CORO_SUSPEND;
    }

    while (true) {
        int64_t from_coro = coro_yield(request->conn->coro, events);

        if ((struct lwan_connection *)(intptr_t)from_coro == awaited) {
            return UNLIKELY(awaited->flags & CONN_HUNG_UP)
                       ? -ECONNRESET
                       : lwan_connection_get_fd(lwan, awaited);
        }
    }
}

int lwan_request_await_read(struct lwan_request *r, int fd)
{
    return async_await_fd(r, fd, CONN_CORO_WANT_READ);
}

int lwan_request_await_write(struct lwan_request *r, int fd)
{
    return async_await_fd(r, fd, CONN_CORO_WANT_WRITE);
}

int lwan_request_await_read_write(struct lwan_request *r, int fd)
{
    return async_await_fd(r, fd, CONN_CORO_WANT_READ_WRITE);
}

static void resume_coro(struct timeout_queue *tq,
                        struct lwan_connection *conn_to_resume,
                        struct lwan_connection *conn_to_yield,
                        int epoll_fd)
{
    assert(conn_to_resume->coro);
    assert(conn_to_yield->coro);

    int64_t from_coro = coro_resume_value(conn_to_resume->coro,
                                          (int64_t)(intptr_t)conn_to_yield);
    if (UNLIKELY(from_coro == CONN_CORO_ABORT)) {
        timeout_queue_expire(tq, conn_to_resume);
        return;
    }

    enum lwan_connection_coro_yield yield = (uint32_t)from_coro;
    int r = update_epoll_flags(tq->lwan, conn_to_resume, epoll_fd, yield);
    if (LIKELY(!r))
        timeout_queue_move_to_last(tq, conn_to_resume);
}

static void update_date_cache(struct lwan_thread *thread)
{
    time_t now = time(NULL);

    lwan_format_rfc_time(now, thread->date.date);
    lwan_format_rfc_time(now + (time_t)thread->lwan->config.expires,
                         thread->date.expires);
}

static bool spawn_coro(struct lwan_connection *conn,
                       coro_context *switcher,
                       struct timeout_queue *tq)
{
    struct lwan_thread *t = conn->thread;
#if defined(LWAN_HAVE_MBEDTLS)
    const enum lwan_connection_flags flags_to_keep = conn->flags & CONN_TLS;
#else
    const enum lwan_connection_flags flags_to_keep = 0;
#endif

    assert(!conn->coro);
    assert(!(conn->flags & (CONN_ASYNC_AWAITV | CONN_ASYNC_AWAIT | CONN_HUNG_UP)));
    assert(!(conn->flags & CONN_LISTENER));
    assert(t);
    assert((uintptr_t)t >= (uintptr_t)tq->lwan->thread.threads);
    assert((uintptr_t)t <
           (uintptr_t)(tq->lwan->thread.threads + tq->lwan->thread.count));

    *conn = (struct lwan_connection){
        .coro = coro_new(switcher, process_request_coro, conn),
        .flags = CONN_EVENTS_READ | flags_to_keep,
        .time_to_expire = tq->current_time + tq->move_to_last_bump,
        .thread = t,
    };
    if (LIKELY(conn->coro)) {
        timeout_queue_insert(tq, conn);
        return true;
    }

    conn->flags = 0;

    int fd = lwan_connection_get_fd(tq->lwan, conn);

    lwan_status_error("Couldn't spawn coroutine for file descriptor %d", fd);

    send_last_response_without_coro(tq->lwan, conn, HTTP_UNAVAILABLE);
    return false;
}

static bool process_pending_timers(struct timeout_queue *tq,
                                   struct lwan_thread *t,
                                   int epoll_fd)
{
    struct timeout *timeout;
    bool should_expire_timers = false;

    while ((timeout = timeouts_get(t->wheel))) {
        if (timeout == &tq->timeout) {
            should_expire_timers = true;
            continue;
        }

        struct lwan_request *request =
            container_of(timeout, struct lwan_request, timeout);
        int r = update_epoll_flags(tq->lwan, request->conn, epoll_fd,
                                   CONN_CORO_RESUME);
        if (UNLIKELY(r < 0)) {
            timeout_queue_expire(tq, request->conn);
        }
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
    const int infinite_timeout = -1;
    timeout_t wheel_timeout;
    struct timespec now;

    if (UNLIKELY(clock_gettime(monotonic_clock_id, &now) < 0))
        lwan_status_critical("Could not get monotonic time");

    timeouts_update(t->wheel,
                    (timeout_t)(now.tv_sec * 1000 + now.tv_nsec / 1000000));

    /* Check if there's an expired timer. */
    wheel_timeout = timeouts_timeout(t->wheel);
    if (wheel_timeout > 0) {
        return (int)wheel_timeout; /* No, but will soon. Wake us up in
                                      wheel_timeout ms. */
    }

    if (UNLIKELY((int64_t)wheel_timeout < 0))
        return infinite_timeout; /* None found. */

    if (!process_pending_timers(tq, t, epoll_fd))
        return infinite_timeout; /* No more timers to process. */

    /* After processing pending timers, determine when to wake up. */
    return (int)timeouts_timeout(t->wheel);
}

static bool accept_waiting_clients(const struct lwan_thread *t,
                                   const struct lwan_connection *listen_socket,
                                   coro_context *switcher,
                                   struct timeout_queue *tq)
{
    const uint32_t read_events = conn_flags_to_epoll_events(CONN_EVENTS_READ);
    struct lwan_connection *conns = t->lwan->conns;
    int listen_fd = (int)(intptr_t)(listen_socket - conns);
    enum lwan_connection_flags new_conn_flags = listen_socket->flags & CONN_TLS;

#if !defined(NDEBUG)
# if defined(LWAN_HAVE_MBEDTLS)
    if (listen_socket->flags & CONN_TLS) {
        assert(listen_fd == t->tls_listen_fd);
    } else {
        assert(listen_fd == t->listen_fd);
    }
# else
    assert(!(new_conn_flags & CONN_TLS));
# endif
#endif

    while (true) {
        int fd = accept4(listen_fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);

        if (LIKELY(fd >= 0)) {
            struct lwan_connection *conn = &conns[fd];
            struct epoll_event ev = {.data.ptr = conn, .events = read_events};
            int r;

            conn->flags = new_conn_flags;

            r = epoll_ctl(conn->thread->epoll_fd, EPOLL_CTL_ADD, fd, &ev);
            if (UNLIKELY(r < 0)) {
                lwan_status_perror("Could not add file descriptor %d to epoll "
                                   "set %d. Dropping connection",
                                   fd, conn->thread->epoll_fd);
                send_last_response_without_coro(t->lwan, conn, HTTP_UNAVAILABLE);
                conn->flags = 0;
            }

            if (UNLIKELY(!spawn_coro(conn, switcher, tq))) {
                send_last_response_without_coro(t->lwan, conn, HTTP_UNAVAILABLE);
                conn->flags = 0;
            }

            continue;
        }

        switch (errno) {
        default:
            lwan_status_perror("Unexpected error while accepting connections");
            /* fallthrough */

        case EAGAIN:
            return true;

        case EBADF:
        case ECONNABORTED:
        case EINVAL:
            lwan_status_info("Listening socket closed");
            return false;
        }
    }

    __builtin_unreachable();
}

static int create_listen_socket(struct lwan_thread *t,
                                unsigned int num,
                                bool tls)
{
    const struct lwan *lwan = t->lwan;
    int listen_fd;

    listen_fd = lwan_create_listen_socket(lwan, num == 0, tls);
    if (listen_fd < 0)
        lwan_status_critical("Could not create listen_fd");

    /* Ignore errors here, as this is just a hint */
#if defined(LWAN_HAVE_SO_ATTACH_REUSEPORT_CBPF)
    /* FIXME: this doesn't seem to work as expected.  if the program returns
     * a fixed number, sockets are always accepted by a thread pinned to
     * that particular CPU; if SKF_AD_CPU is used, sockets are accepted by
     * random threads as if this BPF script weren't installed at all.  */

    /* From socket(7): "These  options may be set repeatedly at any time on
     * any socket in the group to replace the current BPF program used by
     * all sockets in the group." */
    if (num == 0) {
        /* From socket(7): "The  BPF program must return an index between 0
         * and N-1 representing the socket which should receive the packet
         * (where N is the number of sockets in the group)."
         *
         * This should work because sockets are created in the same
         * reuseport group, in the same order as the logical CPU#, and the
         * worker threads for these sockets are pinned to the same CPU#. The
         * MOD operation is there for cases where we have more CPUs than
         * threads (e.g. by setting the "threads" setting in the configuration
         * file); this isn't strictly necessary as any invalid value returned
         * by this program will direct the connection to a random socket in
         * the group.
         *
         * Unfortunately, this program doesn't work that way.  Sockets seem
         * to be delivered to a different thread every time.  Maybe if we
         * change this to eBPF, we'll be able to fetch the file descriptor
         * and feed that into our scheduling table. */
        const uint32_t cpu_ad_cpu = (uint32_t)SKF_AD_OFF + SKF_AD_CPU;
        const uint32_t n_sockets = lwan->thread.count;
        struct sock_filter filter[] = {
            {BPF_LD | BPF_W | BPF_ABS, 0, 0, cpu_ad_cpu}, /* A = current_cpu_idx */
            {BPF_ALU | BPF_MOD, 0, 0, n_sockets},         /* A %= socket_count */
            {BPF_RET | BPF_A, 0, 0, 0},                   /* return A */
        };
        struct sock_fprog fprog = {.filter = filter, .len = N_ELEMENTS(filter)};

        if (n_sockets > 1 && (n_sockets & (n_sockets - 1)) == 0) {
            /* Not sure if the kernel will perform strength reduction
             * on CBPF, so do it here.  This is a common case. */
            assert(filter[1].code == (BPF_ALU | BPF_MOD));
            assert(filter[1].k == n_sockets);

            filter[1].code = BPF_ALU | BPF_AND;
            filter[1].k = n_sockets - 1;
        }

        (void)setsockopt(listen_fd, SOL_SOCKET, SO_ATTACH_REUSEPORT_CBPF,
                         &fprog, sizeof(fprog));
        (void)setsockopt(listen_fd, SOL_SOCKET, SO_LOCK_FILTER, (int[]){1},
                         sizeof(int));
    }
#elif defined(LWAN_HAVE_SO_INCOMING_CPU) && defined(__x86_64__)
    (void)setsockopt(listen_fd, SOL_SOCKET, SO_INCOMING_CPU, &t->cpu,
                     sizeof(t->cpu));
#endif

    struct epoll_event event = {
        .events = EPOLLIN | EPOLLET | EPOLLERR,
        .data.ptr = &lwan->conns[listen_fd],
    };
    if (epoll_ctl(t->epoll_fd, EPOLL_CTL_ADD, listen_fd, &event) < 0)
        lwan_status_critical_perror("Could not add socket to epoll");

    return listen_fd;
}

static void *thread_io_loop(void *data)
{
    struct lwan_thread *t = data;
    int epoll_fd = t->epoll_fd;
    const int max_events = LWAN_MIN((int)t->lwan->thread.max_fd, 1024);
    struct lwan *lwan = t->lwan;
    struct epoll_event *events;
    coro_context switcher;
    struct timeout_queue tq;

    if (t->cpu == UINT_MAX) {
        lwan_status_debug("Worker thread #%zd starting",
                          t - t->lwan->thread.threads + 1);
    } else {
        lwan_status_debug("Worker thread #%zd starting on CPU %d",
                          t - t->lwan->thread.threads + 1, t->cpu);
    }

    lwan_set_thread_name("worker");

    events = calloc((size_t)max_events, sizeof(*events));
    if (UNLIKELY(!events))
        lwan_status_critical("Could not allocate memory for events");

    update_date_cache(t);

    timeout_queue_init(&tq, lwan);

    lwan_random_seed_prng_for_thread(t);

    pthread_barrier_wait(&lwan->thread.barrier);

    for (;;) {
        int timeout = turn_timer_wheel(&tq, t, epoll_fd);
        int n_fds = epoll_wait(epoll_fd, events, max_events, timeout);
        bool created_coros = false;

        if (UNLIKELY(n_fds < 0)) {
            if (errno == EBADF || errno == EINVAL)
                break;
            continue;
        }

        for (struct epoll_event *event = events; n_fds--; event++) {
            struct lwan_connection *conn = event->data.ptr;

            if (conn->flags & (CONN_ASYNC_AWAIT | CONN_LISTENER)) {
                if (conn->flags & CONN_ASYNC_AWAIT) {
                    /* Assert that the connection is part of the conns array,
                     * since the storage for conn->parent is shared with
                     * prev/next. */
                    assert(conn->parent >= lwan->conns);
                    assert(conn->parent <= &lwan->conns[lwan->thread.max_fd]);

                    /* Also validate that conn->parent is in fact a HTTP client
                     * connection and not an awaited fd! */
                    assert(!(conn->parent->flags & CONN_ASYNC_AWAIT));

                    /* CONN_ASYNC_AWAIT conns *must* have a coro and thread as
                     * it's the same as the HTTP client coro for API
                     * consistency, as struct lwan_connection isn't opaque.  (If
                     * it were opaque, or at least a private API, though, we
                     * might be able to get away with reusing the space for
                     * these two pointers for something else in some cases.
                     * This has not been necessary yet, but might become useful
                     * in the future.) */
                    assert(conn->coro);
                    assert(conn->coro == conn->parent->coro);
                    assert(conn->thread == conn->parent->thread);

                    if (UNLIKELY(events->events & (EPOLLRDHUP | EPOLLHUP)))
                        conn->flags |= CONN_HUNG_UP;

                    resume_coro(&tq, conn->parent, conn, epoll_fd);

                    continue;
                }

                if (LIKELY(accept_waiting_clients(t, conn, &switcher, &tq))) {
                    created_coros = true;
                    continue;
                }

                close(epoll_fd);
                epoll_fd = -1;
                break;
            }

            if (UNLIKELY(event->events & (EPOLLRDHUP | EPOLLHUP))) {
                timeout_queue_expire(&tq, conn);
                continue;
            }

            resume_coro(&tq, conn, conn, epoll_fd);
        }

        if (created_coros)
            timeouts_add(t->wheel, &tq.timeout, 1000);
    }

    pthread_barrier_wait(&lwan->thread.barrier);

    timeout_queue_expire_all(&tq);
    free(events);

    return NULL;
}

static void create_thread(struct lwan *l, struct lwan_thread *thread)
{
    int ignore;
    pthread_attr_t attr;

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

    if (pthread_create(&thread->self, &attr, thread_io_loop, thread))
        lwan_status_critical_perror("pthread_create");

    if (pthread_attr_destroy(&attr))
        lwan_status_critical_perror("pthread_attr_destroy");
}

#if defined(__linux__) && defined(__x86_64__)
static bool read_cpu_topology(struct lwan *l, uint32_t siblings[])
{
    char path[PATH_MAX];

    for (uint32_t i = 0; i < l->available_cpus; i++)
        siblings[i] = 0xbebacafe;

    for (unsigned int i = 0; i < l->available_cpus; i++) {
        FILE *sib;
        uint32_t id, sibling;
        char separator;

        snprintf(path, sizeof(path),
                 "/sys/devices/system/cpu/cpu%d/topology/thread_siblings_list",
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

    /* Perform some validation here, as some systems seem to filter out the
     * result of sysconf() to obtain the number of configured and online
     * CPUs but don't bother changing what's available through sysfs as far
     * as the CPU topology information goes.  It's better to fall back to a
     * possibly non-optimal setup than just crash during startup while
     * trying to perform an out-of-bounds array access.  */
    for (unsigned int i = 0; i < l->available_cpus; i++) {
        if (siblings[i] == 0xbebacafe) {
            lwan_status_warning("Could not determine sibling for CPU %d", i);
            return false;
        }

        if (siblings[i] >= l->available_cpus) {
            lwan_status_warning("CPU information topology says CPU %d exists, "
                                "but max available CPUs is %d (online CPUs: %d). "
                                "Is Lwan running in a (broken) container?",
                                siblings[i], l->available_cpus, l->online_cpus);
            return false;
        }
    }

    return true;
}

static void
siblings_to_schedtbl(struct lwan *l, uint32_t siblings[], uint32_t schedtbl[])
{
    int32_t *seen = calloc(l->available_cpus, sizeof(int32_t));
    unsigned int n_schedtbl = 0;

    if (!seen)
        lwan_status_critical("Could not allocate the seen array");

    for (uint32_t i = 0; i < l->available_cpus; i++)
        seen[i] = -1;

    for (uint32_t i = 0; i < l->available_cpus; i++) {
        if (seen[siblings[i]] < 0) {
            seen[siblings[i]] = (int32_t)i;
        } else {
            schedtbl[n_schedtbl++] = (uint32_t)seen[siblings[i]];
            schedtbl[n_schedtbl++] = i;
        }
    }

    for (uint32_t i = 0; i < l->available_cpus && n_schedtbl < l->available_cpus; i++) {
        if (seen[i] == -1) {
            schedtbl[n_schedtbl++] = i;
        }
    }

    free(seen);
}

static bool
topology_to_schedtbl(struct lwan *l, uint32_t schedtbl[], uint32_t n_threads)
{
    uint32_t *siblings = calloc(l->available_cpus, sizeof(uint32_t));
    bool ret = false;

    if (siblings) {
        if (read_cpu_topology(l, siblings)) {
            siblings_to_schedtbl(l, siblings, schedtbl);
            ret = true;
        } else {
            for (uint32_t i = 0; i < n_threads; i++)
                schedtbl[i] = (i / 2) % l->thread.count;
        }

        free(siblings);
    }

    return ret;
}

static void
adjust_thread_affinity(const struct lwan_thread *thread)
{
    cpu_set_t set;

    CPU_ZERO(&set);
    CPU_SET(thread->cpu, &set);

    if (pthread_setaffinity_np(thread->self, sizeof(set), &set))
        lwan_status_warning("Could not set thread affinity");
}
#else
#define adjust_thread_affinity(...)
#endif

#if defined(LWAN_HAVE_MBEDTLS)
static bool is_tls_ulp_supported(void)
{
    FILE *available_ulp = fopen("/proc/sys/net/ipv4/tcp_available_ulp", "re");
    char buffer[512];
    bool available = false;

    if (!available_ulp)
        return false;

    if (fgets(buffer, 512, available_ulp)) {
        if (strstr(buffer, "tls"))
            available = true;
    }

    fclose(available_ulp);
    return available;
}

static bool lwan_init_tls(struct lwan *l)
{
    static const int aes128_ciphers[] = {
        /* Only allow Ephemeral Diffie-Hellman key exchange, so Perfect
         * Forward Secrecy is possible.  */
        MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        MBEDTLS_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
        MBEDTLS_TLS_DHE_PSK_WITH_AES_128_GCM_SHA256,

        /* FIXME: Other ciphers are supported by kTLS, notably AES256 and
         * ChaCha20-Poly1305.  Add those here and patch
         * lwan_setup_tls_keys() to match.  */

        /* FIXME: Maybe allow this to be user-tunable like other servers do?  */
        0,
    };
    int r;

    if (!l->config.ssl.cert || !l->config.ssl.key)
        return false;

    if (!is_tls_ulp_supported()) {
        lwan_status_critical(
            "TLS ULP not loaded. Try running `modprobe tls` as root.");
    }

    l->tls = calloc(1, sizeof(*l->tls));
    if (!l->tls)
        lwan_status_critical("Could not allocate memory for SSL context");

    lwan_status_debug("Initializing mbedTLS");

    mbedtls_ssl_config_init(&l->tls->config);
    mbedtls_x509_crt_init(&l->tls->server_cert);
    mbedtls_pk_init(&l->tls->server_key);
    mbedtls_entropy_init(&l->tls->entropy);
    mbedtls_ctr_drbg_init(&l->tls->ctr_drbg);

    r = mbedtls_x509_crt_parse_file(&l->tls->server_cert, l->config.ssl.cert);
    if (r) {
        lwan_status_mbedtls_error(r, "Could not parse certificate at %s",
                                  l->config.ssl.cert);
        abort();
    }

    r = mbedtls_pk_parse_keyfile(&l->tls->server_key, l->config.ssl.key, NULL);
    if (r) {
        lwan_status_mbedtls_error(r, "Could not parse key file at %s",
                                  l->config.ssl.key);
        abort();
    }

    /* Even though this points to files that will probably be outside
     * the reach of the server (if straightjackets are used), wipe this
     * struct to get rid of the paths to these files. */
    lwan_always_bzero(l->config.ssl.cert, strlen(l->config.ssl.cert));
    free(l->config.ssl.cert);
    lwan_always_bzero(l->config.ssl.key, strlen(l->config.ssl.key));
    free(l->config.ssl.key);
    lwan_always_bzero(&l->config.ssl, sizeof(l->config.ssl));

    mbedtls_ssl_conf_ca_chain(&l->tls->config, l->tls->server_cert.next, NULL);
    r = mbedtls_ssl_conf_own_cert(&l->tls->config, &l->tls->server_cert,
                                  &l->tls->server_key);
    if (r) {
        lwan_status_mbedtls_error(r, "Could not set cert/key");
        abort();
    }

    r = mbedtls_ctr_drbg_seed(&l->tls->ctr_drbg, mbedtls_entropy_func,
                              &l->tls->entropy, NULL, 0);
    if (r) {
        lwan_status_mbedtls_error(r, "Could not seed ctr_drbg");
        abort();
    }

    r = mbedtls_ssl_config_defaults(&l->tls->config, MBEDTLS_SSL_IS_SERVER,
                                    MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT);
    if (r) {
        lwan_status_mbedtls_error(r, "Could not set mbedTLS default config");
        abort();
    }

    mbedtls_ssl_conf_rng(&l->tls->config, mbedtls_ctr_drbg_random,
                         &l->tls->ctr_drbg);
    mbedtls_ssl_conf_ciphersuites(&l->tls->config, aes128_ciphers);

    mbedtls_ssl_conf_renegotiation(&l->tls->config,
                                   MBEDTLS_SSL_RENEGOTIATION_DISABLED);
    mbedtls_ssl_conf_legacy_renegotiation(&l->tls->config,
                                          MBEDTLS_SSL_LEGACY_NO_RENEGOTIATION);

#if defined(MBEDTLS_SSL_ALPN)
    static const char *alpn_protos[] = {"http/1.1", NULL};
    mbedtls_ssl_conf_alpn_protocols(&l->tls->config, alpn_protos);
#endif

    return true;
}
#endif

void lwan_thread_init(struct lwan *l)
{
    const unsigned int total_conns = l->thread.max_fd * l->thread.count;
#if defined(LWAN_HAVE_MBEDTLS)
    const bool tls_initialized = lwan_init_tls(l);
#else
    const bool tls_initialized = false;
#endif

    lwan_status_debug("Initializing threads");

    l->thread.threads =
        calloc((size_t)l->thread.count, sizeof(struct lwan_thread));
    if (!l->thread.threads)
        lwan_status_critical("Could not allocate memory for threads");

    for (unsigned int i = 0; i < l->thread.count; i++)
        l->thread.threads[i].cpu = UINT_MAX;

    uint32_t *schedtbl;

#if defined(__x86_64__) && defined(__linux__)
    if (l->online_cpus > 1) {
        static_assert(sizeof(struct lwan_connection) == 32,
                      "Two connections per cache line");
#ifdef _SC_LEVEL1_DCACHE_LINESIZE
        assert(sysconf(_SC_LEVEL1_DCACHE_LINESIZE) == 64);
#endif
        lwan_status_debug("%d CPUs of %d are online. "
                          "Reading topology to pre-schedule clients",
                          l->online_cpus, l->available_cpus);
        /*
         * Pre-schedule each file descriptor, to reduce some operations in the
         * fast path.
         *
         * Since struct lwan_connection is guaranteed to be 32-byte long, two of
         * them can fill up a cache line.  Assume siblings share cache lines and
         * use the CPU topology to group two connections per cache line in such
         * a way that false sharing is avoided.
         */
        schedtbl = calloc(l->thread.count, sizeof(uint32_t));
        bool adjust_affinity = topology_to_schedtbl(l, schedtbl, l->thread.count);

        for (unsigned int i = 0; i < total_conns; i++) {
            unsigned int thread_id = schedtbl[i % l->thread.count];
            l->conns[i].thread = &l->thread.threads[thread_id];
        }

        if (!adjust_affinity) {
            free(schedtbl);
            schedtbl = NULL;
        }
    } else
#endif /* __x86_64__ && __linux__ */
    {
        lwan_status_debug("Using round-robin to preschedule clients");

        for (unsigned int i = 0; i < l->thread.count; i++)
            l->thread.threads[i].cpu = i % l->online_cpus;
        for (unsigned int i = 0; i < total_conns; i++)
            l->conns[i].thread = &l->thread.threads[i % l->thread.count];

        schedtbl = NULL;
    }

    for (unsigned int i = 0; i < l->thread.count; i++) {
        struct lwan_thread *thread;

        if (schedtbl) {
            /* For SO_ATTACH_REUSEPORT_CBPF to work with the program
             * we provide the kernel, sockets have to be added to the
             * reuseport group in an order consistent with the
             * CPU ID (SKF_AD_CPU field): so group the threads
             * according to the CPU topology to avoid false sharing
             * the connections array, and pin the N-th thread to the
             * N-th CPU. */

            /* FIXME: I don't know why this isn't working as I intended:
             * clients are still accepted by a thread that's not the
             * worker thread that's supposed to handle that particular
             * file descriptor.  According to socket(7), the plain
             * SO_REUSEPORT mechanism might be used if the returned
             * index is wrong, so maybe that's what's happening?  I don't
             * know, gotta debug the kernel to figure this out. */
            thread = &l->thread.threads[schedtbl[i]];

            /* FIXME: figure out which CPUs are actually online */
            thread->cpu = i;
        } else {
            thread = &l->thread.threads[i];
        }

        if (pthread_barrier_init(&l->thread.barrier, NULL, 2))
            lwan_status_critical("Could not create barrier");

        create_thread(l, thread);

        if ((thread->listen_fd = create_listen_socket(thread, i, false)) < 0)
            lwan_status_critical_perror("Could not create listening socket");
        l->conns[thread->listen_fd].flags |= CONN_LISTENER;

        if (tls_initialized) {
            if ((thread->tls_listen_fd = create_listen_socket(thread, i, true)) < 0)
                lwan_status_critical_perror("Could not create TLS listening socket");
            l->conns[thread->tls_listen_fd].flags |= CONN_LISTENER | CONN_TLS;
        } else {
            thread->tls_listen_fd = -1;
        }

        if (schedtbl)
            adjust_thread_affinity(thread);

        pthread_barrier_wait(&l->thread.barrier);
    }

    lwan_status_debug("Worker threads created and ready to serve");

    free(schedtbl);
}

void lwan_thread_shutdown(struct lwan *l)
{
    lwan_status_debug("Shutting down threads");

    for (unsigned int i = 0; i < l->thread.count; i++) {
        struct lwan_thread *t = &l->thread.threads[i];
        int epoll_fd = t->epoll_fd;
        int listen_fd = t->listen_fd;

        t->listen_fd = -1;
        t->epoll_fd = -1;
        close(epoll_fd);
        close(listen_fd);
    }

    pthread_barrier_wait(&l->thread.barrier);
    pthread_barrier_destroy(&l->thread.barrier);

    for (unsigned int i = 0; i < l->thread.count; i++) {
        struct lwan_thread *t = &l->thread.threads[i];

        pthread_join(l->thread.threads[i].self, NULL);
        timeouts_close(t->wheel);
    }

    free(l->thread.threads);

#if defined(LWAN_HAVE_MBEDTLS)
    if (l->tls) {
        mbedtls_ssl_config_free(&l->tls->config);
        mbedtls_x509_crt_free(&l->tls->server_cert);
        mbedtls_pk_free(&l->tls->server_key);
        mbedtls_entropy_free(&l->tls->entropy);
        mbedtls_ctr_drbg_free(&l->tls->ctr_drbg);
        free(l->tls);
    }
#endif
}
