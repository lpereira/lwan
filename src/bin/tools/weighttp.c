/*
 * weighttp - a lightweight and simple webserver benchmarking tool
 *
 * Copyright (c) 2016, Glue Logic LLC. All rights reserved. code()gluelogic.com
 *
 * This rewrite is based on weighttp by Thomas Porzelt
 *     Copyright (c) 2009-2011 Thomas Porzelt
 *   git://git.lighttpd.net/weighttp
 *   https://github.com/lighttpd/weighttp/
 *
 * License:
 *     MIT, see COPYING.weighttp file
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wvla"

#include <sys/types.h>
#include <sys/socket.h>/* socket() connect() SOCK_NONBLOCK sockaddr_storage */
#include <sys/stat.h>  /* fstat() */
#include <sys/time.h>  /* gettimeofday() */
#include <errno.h>     /* errno EINTR EAGAIN EWOULDBLOCK EINPROGRESS EALREADY */
#include <fcntl.h>     /* open() fcntl() pipe2() F_SETFL (O_* flags) */
#include <inttypes.h>  /* PRIu64 PRId64 */
#include <limits.h>    /* USHRT_MAX */
#include <locale.h>    /* setlocale() */
#include <netdb.h>     /* getaddrinfo() freeaddrinfo() */
#include <poll.h>      /* poll() POLLIN POLLOUT POLLERR POLLHUP */
#include <pthread.h>   /* pthread_create() pthread_join() */
#include <stdarg.h>    /* va_start() va_end() vfprintf() */
#include <stdio.h>
#include <stdlib.h>    /* calloc() free() exit() strtoul() strtoull() */
#include <stdint.h>    /* UINT32_MAX */
#include <signal.h>    /* signal() */
#include <string.h>
#include <strings.h>   /* strcasecmp() strncasecmp() */
#include <unistd.h>    /* read() write() close() getopt() optarg optind optopt*/

#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <sys/un.h>

#ifndef MSG_DONTWAIT
#define MSG_DONTWAIT 0
#endif
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
#ifndef SOCK_NONBLOCK
#define SOCK_NONBLOCK 0
#endif

#ifndef PACKAGE_VERSION
#define PACKAGE_VERSION ""
#endif


/*(oversimplified; these attributes are supported by some other compilers)*/
#if defined(__GNUC__) || defined(__clang__)
#ifndef __attribute_cold__
#define __attribute_cold__       __attribute__((__cold__))
#endif
#ifndef __attribute_hot__
#define __attribute_hot__        __attribute__((__hot__))
#endif
#ifndef __attribute_noinline__
#define __attribute_noinline__   __attribute__((__noinline__))
#endif
#ifndef __attribute_nonnull__
#define __attribute_nonnull__    __attribute__((__nonnull__))
#endif
#ifndef __attribute_noreturn__
#define __attribute_noreturn__   __attribute__((__noreturn__))
#endif
#ifndef __attribute_pure__
#define __attribute_pure__       __attribute__((__pure__))
#endif
#ifndef __attribute_format__
#define __attribute_format__(x)  __attribute__((__format__ x))
#endif
#else
#ifndef __builtin_expect
#define __builtin_expect(x, y) (x)
#endif
#ifndef __attribute_cold__
#define __attribute_cold__
#endif
#ifndef __attribute_hot__
#define __attribute_hot__
#endif
#ifndef __attribute_noinline__
#define __attribute_noinline__
#endif
#ifndef __attribute_nonnull__
#define __attribute_nonnull__
#endif
#ifndef __attribute_noreturn__
#define __attribute_noreturn__
#endif
#ifndef __attribute_pure__
#define __attribute_pure__
#endif
#ifndef __attribute_format__
#define __attribute_format__(x)
#endif
#endif


__attribute_cold__
__attribute_noinline__
static void
show_version (void)
{
    puts("\nweighttp " PACKAGE_VERSION
         " - a lightweight and simple webserver benchmarking tool\n");
}


__attribute_cold__
__attribute_noinline__
static void
show_help (void)
{
    puts(
      "weighttp <options> <URI>\n"
      "  -n num     number of requests      (mandatory)\n"
      "  -t num     thread count            (default: 1)\n"
      "  -c num     concurrent clients      (default: 1)\n"
      "  -k         keep alive              (default: no)\n"
      "  -K num     num pipelined requests  (default: 1)\n"
      "  -6         use ipv6                (default: no)\n"
      "  -i         use HTTP HEAD method    (default: GET)\n"
      "  -m method  use custom HTTP method  (default: GET)\n"
      "  -H str     add header to request (\"label: value\"); repeatable\n"
      "  -b size    socket buffer sizes (SO_SNDBUF, SO_RCVBUF)\n"
      "  -B addr    local address to bind to when making outgoing connections\n"
      "  -C cookie  add cookie to request (\"cookie-name=value\"); repeatable\n"
      "  -F         use TCP Fast Open (RFC 7413)\n"
      "  -T type    Content-Type header to use for POST/PUT data,\n"
      "             e.g. application/x-www-form-urlencoded\n"
      "                                     (default: text/plain)\n"
      "  -A string  add Basic WWW Authorization   (str is username:password)\n"
      "  -P string  add Basic Proxy-Authorization (str is username:password)\n"
      "  -X proxy   proxy:port or unix domain socket path beginning w/ '/'\n"
      "  -p file    make HTTP POST request using file contents for body\n"
      "  -u file    make HTTP PUT request using file contents for body\n"
      "  -d         (ignored; compatibility with Apache Bench (ab))\n"
      "  -l         (ignored; compatibility with Apache Bench (ab))\n"
      "  -r         (ignored; compatibility with Apache Bench (ab))\n"
      "  -q         quiet: do not show version header or progress\n"
      "  -h         show help and exit\n"
      "  -V         show version and exit\n\n"
      "example: \n"
      "  weighttpd -n 500000 -c 100 -t 2 -K 64 http://localhost/index.html\n");
}

/* Notes regarding pipelining
 * Enabling pipelining (-p x where x > 1) results in extra requests being sent
 * beyond the precise number requested on the command line.  Subsequently,
 * extra bytes might be read and reported in stats at the end of the test run.
 * Additionally, the extra requests are dropped once the req_todo amount is
 * reached, and so the target web server(s) might report errors that client
 * dropped connection (client disconnect) for those final requests.
 *
 * The benefits of pipelining include reduced latency between request/response,
 * as well as potentially fewer socket read()s for data if multiple requests or
 * multiple responses are available to be read by server or client, respectively
 */

#define CLIENT_BUFFER_SIZE 32 * 1024


struct Stats;
typedef struct Stats Stats;
struct Client;
typedef struct Client Client;
struct Worker;
typedef struct Worker Worker;
struct Config;
typedef struct Config Config;
struct Worker_Config;
typedef struct Worker_Config Worker_Config;


struct Stats {
    uint64_t req_todo;      /* total num of requests to do */
    uint64_t req_started;   /* total num of requests started */
    uint64_t req_done;      /* total num of requests done */
    uint64_t req_success;   /* total num of successful requests */
    uint64_t req_failed;    /* total num of failed requests */
    uint64_t req_error;     /* total num of errored requests */
    uint64_t bytes_total;   /* total num of bytes received (headers+body) */
    uint64_t bytes_headers; /* total num of bytes received (headers) */
    uint64_t req_2xx;
    uint64_t req_3xx;
    uint64_t req_4xx;
    uint64_t req_5xx;
};

struct Client {
    int revents;
    enum {
        PARSER_CONNECT,
        PARSER_START,
        PARSER_HEADER,
        PARSER_BODY
    } parser_state;

    uint32_t buffer_offset;  /* pos in buffer  (size of data in buffer) */
    uint32_t parser_offset;  /* pos in parsing (behind buffer_offset) */
    uint32_t request_offset; /* pos in sending request */
    int chunked;
    int64_t content_length;
    int64_t chunk_size;
    int64_t chunk_received;
    int http_status_success;
    int config_keepalive;
    int keepalive;
    int keptalive;
    int pipelined;
    int pipeline_max;
    int tcp_fastopen;
    int http_head;
    int so_bufsz;

    uint32_t request_size;
    const char *request;
    struct pollfd *pfd;
    Stats *stats;
    const struct addrinfo *raddr;
    const struct addrinfo *laddr;
    char buffer[CLIENT_BUFFER_SIZE];
};

struct Worker {
    struct pollfd *pfds;
    Client *clients;
    Stats stats;
    struct addrinfo raddr;
    struct addrinfo laddr;
    struct sockaddr_storage raddr_storage;
    struct sockaddr_storage laddr_storage;
};

struct Worker_Config {
    const Config *config;
    int id;
    int num_clients;
    uint64_t num_requests;
    Stats stats;
    /* pad struct Worker_Config for cache line separation between threads.
     * Round up to 256 to avoid chance of false sharing between threads.
     * Alternatively, could memalign the allocation of struct Worker_Config
     * list to cache line size (e.g. 128 bytes) */
    uint64_t padding[(256 - (1*sizeof(void *))
                          - (2*sizeof(int))
                          - (1*sizeof(uint64_t))
                          - sizeof(Stats))
                      / sizeof(uint64_t)];
};

struct Config {
    Worker_Config *wconfs;
    char *proxy;
    struct timeval ts_start;
    struct timeval ts_end;

    uint64_t req_count;
    int thread_count;
    int keep_alive;
    int concur_count;
    int pipeline_max;
    int tcp_fastopen;
    int http_head;
    int so_bufsz;

    int quiet;
    uint32_t request_size;
    char *request;
    char buf[16384]; /*(used for simple 8k memaligned request buffer on stack)*/
    struct addrinfo raddr;
    struct addrinfo laddr;
    struct sockaddr_storage raddr_storage;
    struct sockaddr_storage laddr_storage;
    struct laddrs {
        struct addrinfo **addrs;
        int num;
    } laddrs;
};


__attribute_cold__
__attribute_nonnull__
static void
client_init (Worker * const restrict worker,
             const Config * const restrict config,
             const int i)
{
    Client * const restrict client = worker->clients+i;
    client->pfd = worker->pfds+i;
    client->pfd->fd = -1;
    client->parser_state = PARSER_CONNECT;

    client->stats = &worker->stats;
    client->raddr = &worker->raddr;
    client->laddr = config->laddrs.num > 0
                  ? config->laddrs.addrs[(i % config->laddrs.num)]
                  : (0 != worker->laddr.ai_addrlen) ? &worker->laddr : NULL;
    client->config_keepalive = config->keep_alive;
    client->pipeline_max     = config->pipeline_max;
    client->tcp_fastopen     = config->tcp_fastopen;
    client->http_head        = config->http_head;
    client->so_bufsz         = config->so_bufsz;
    client->request_size     = config->request_size;
    client->request          = config->request;
    /* future: might copy config->request to new allocation in Worker
     * so that all memory accesses during benchmark execution are to
     * independent, per-thread allocations */
}


__attribute_cold__
__attribute_nonnull__
static void
client_delete (const Client * const restrict client)
{
    if (-1 != client->pfd->fd)
        close(client->pfd->fd);
}


__attribute_cold__
__attribute_nonnull__
__attribute_noinline__
static void
worker_init (Worker * const restrict worker,
             Worker_Config * const restrict wconf)
{
    const Config * const restrict config = wconf->config;
    memset(worker, 0, sizeof(Worker));
    memcpy(&worker->laddr, &config->laddr, sizeof(config->laddr));
    memcpy(&worker->raddr, &config->raddr, sizeof(config->raddr));
    if (config->laddr.ai_addrlen)
        worker->laddr.ai_addr = (struct sockaddr *)
          memcpy(&worker->laddr_storage,
                 &config->laddr_storage, config->laddr.ai_addrlen);
    worker->raddr.ai_addr = (struct sockaddr *)
      memcpy(&worker->raddr_storage,
             &config->raddr_storage, config->raddr.ai_addrlen);
    const int num_clients = wconf->num_clients;
    worker->stats.req_todo = wconf->num_requests;
    worker->pfds = (struct pollfd *)calloc(num_clients, sizeof(struct pollfd));
    worker->clients = (Client *)calloc(num_clients, sizeof(Client));
    for (int i = 0; i < num_clients; ++i)
        client_init(worker, wconf->config, i);
}


__attribute_cold__
__attribute_nonnull__
__attribute_noinline__
static void
worker_delete (Worker * const restrict worker,
               Worker_Config * const restrict wconf)
{
    int i;
    const int num_clients = wconf->num_clients;

    /* adjust bytes_total to discard count of excess responses
     * (> worker->stats.req_todo) */
    if (worker->clients[0].pipeline_max > 1) {
        for (i = 0; i < num_clients; ++i) {
            worker->stats.bytes_total -= ( worker->clients[i].buffer_offset
                                         - worker->clients[i].parser_offset );
        }
    }

    memcpy(&wconf->stats, &worker->stats, sizeof(Stats));
    for (i = 0; i < num_clients; ++i)
        client_delete(worker->clients+i);
    free(worker->clients);
    free(worker->pfds);
}


__attribute_cold__
__attribute_noinline__
__attribute_nonnull__
static void
wconfs_init (Config * const restrict config)
{
    /* create Worker_Config data structures for each (future) thread */
    Worker_Config * const restrict wconfs =
      (Worker_Config *)calloc(config->thread_count, sizeof(Worker_Config));

    uint32_t rest_concur = config->concur_count % config->thread_count;
    uint32_t rest_req = config->req_count % config->thread_count;

    for (int i = 0; i < config->thread_count; ++i) {
        uint64_t reqs = config->req_count / config->thread_count;
        int concur = config->concur_count / config->thread_count;

        if (rest_concur) {
            concur += 1;
            rest_concur -= 1;
        }

        if (rest_req) {
            reqs += 1;
            rest_req -= 1;
        }

        if (!config->quiet)
            printf("spawning thread #%d: %d concurrent requests, "
                   "%"PRIu64" total requests\n", i+1, concur, reqs);

        wconfs[i].config = config;
        wconfs[i].id = i;
        wconfs[i].num_clients = concur;
        wconfs[i].num_requests = reqs;
    }

    config->wconfs = wconfs;
}


__attribute_cold__
__attribute_noinline__
__attribute_nonnull__
static void
wconfs_delete (const Config * const restrict config)
{
    free(config->wconfs);
    if (config->request < config->buf
        || config->buf+sizeof(config->buf) <= config->request)
        free(config->request);

    if (config->laddrs.num > 0) {
        for (int i = 0; i < config->laddrs.num; ++i)
            freeaddrinfo(config->laddrs.addrs[i]);
        free(config->laddrs.addrs);
    }
}


__attribute_hot__
__attribute_nonnull__
static void
client_reset (Client * const restrict client, const int success)
{
    /* update worker stats */
    Stats * const restrict stats = client->stats;

    ++stats->req_done;
    if (__builtin_expect( (0 != success), 1))
        ++stats->req_success;
    else
        ++stats->req_failed;

    client->revents = (stats->req_started < stats->req_todo) ? POLLOUT : 0;
    if (client->revents && client->keepalive) {
        /*(assumes writable; will find out soon if not and register interest)*/
        ++stats->req_started;
        client->parser_state = PARSER_START;
        client->keptalive = 1;
        if (client->parser_offset == client->buffer_offset) {
            client->parser_offset = 0;
            client->buffer_offset = 0;
        }
      #if 0
        else if (client->parser_offset > (CLIENT_BUFFER_SIZE/2)) {
            memmove(client->buffer, client->buffer+client->parser_offset,
                    client->buffer_offset - client->parser_offset + 1);
            client->buffer_offset -= client->parser_offset;
            client->parser_offset = 0;
        }
        /* future: if we tracked size of headers for first successful response,
         * we might use that size to determine whether or not to memmove()
         * any remaining contents in client->buffer to the beginning of buffer,
         * e.g. if parser_offset + expected_response_len exceeds buffer size
         * On the size, if we expect to already have completed response fully
         * received in buffer, then skip the memmove(). */
      #endif
        if (--client->pipelined && client->buffer_offset)
            client->revents |= POLLIN;
    }
    else {
        close(client->pfd->fd);
        client->pfd->fd = -1;
        client->pfd->events = 0;
        /*client->pfd->revents = 0;*/
        client->parser_state = PARSER_CONNECT;
    }
}


__attribute_cold__
__attribute_noinline__
__attribute_nonnull__
static void
client_error (Client * const restrict client)
{
    ++client->stats->req_error;
    if (client->parser_state != PARSER_BODY) {
        /*(might include subsequent responses to pipelined requests, but
         * some sort of invalid response received if client_error() called)*/
        client->stats->bytes_headers +=
          (client->buffer_offset - client->parser_offset);
        client->buffer_offset = 0;
        client->parser_offset = 0;
    }
    client->keepalive = 0;
    client_reset(client, 0);
}


__attribute_cold__
__attribute_noinline__
__attribute_nonnull__
static void
client_perror (Client * const restrict client, const char * const restrict tag)
{
    const int errnum = errno;
    client->buffer[0] = '\0';
  #if defined(_GNU_SOURCE) && defined(__GLIBC__)
    const char * const errstr =
      strerror_r(errnum, client->buffer, sizeof(client->buffer));
  #else /* XSI-compliant strerror_r() */
    const char * const errstr = client->buffer;
    strerror_r(errnum, client->buffer, sizeof(client->buffer));
  #endif
    fprintf(stderr, "error: %s failed: (%d) %s\n", tag, errnum, errstr);
    client_error(client);
}


__attribute_nonnull__
static void
client_connected (Client * const restrict client)
{
    client->request_offset = 0;
    client->buffer_offset = 0;
    client->parser_offset = 0;
    client->parser_state = PARSER_START;
    client->pipelined = 0;
    client->keepalive = client->config_keepalive;
    client->keptalive = 0;
    /*client->success = 0;*/
}


__attribute_noinline__
__attribute_nonnull__
static int
client_connect (Client * const restrict client)
{
    const struct addrinfo * const restrict raddr = client->raddr;
    int fd = client->pfd->fd;
    int opt;

    if (-1 == fd) {
        ++client->stats->req_started;

        do {
            fd = socket(raddr->ai_family,raddr->ai_socktype,raddr->ai_protocol);
        } while (__builtin_expect( (-1 == fd), 0) && errno == EINTR);

        if (fd >= 0) {
          #if !SOCK_NONBLOCK
            fcntl(fd, F_SETFL, O_NONBLOCK | O_RDWR); /* set non-blocking */
          #endif
            client->pfd->fd = fd;
        }
        else {
            client_perror(client, "socket()");
            return 0;
        }

        if (1 == client->pipeline_max && raddr->ai_family != AF_UNIX) {
            /* disable Nagle if not pipelining requests and not AF_UNIX
             * (pipelining enables keepalive, but if not pipelining but
             *  keepalive enabled, still want to disable Nagle to reduce latency
             *  when sending next keepalive request after receiving response) */
            opt = 1;
            setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
        }

        if (0 != client->so_bufsz) {
            opt = client->so_bufsz;
            if (0 != setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &opt, sizeof(opt)))
                client_perror(client, "setsockopt() SO_SNDBUF");
            if (0 != setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt)))
                client_perror(client, "setsockopt() SO_RCVBUF");
        }

        if (raddr->ai_family != AF_UNIX) {
            /*(might not be correct for real clients, but ok for load test)*/
            struct linger l = { .l_onoff = 1, .l_linger = 0 };
            if (0 != setsockopt(fd, SOL_SOCKET, SO_LINGER, &l, sizeof(l)))
                client_perror(client, "setsockopt() SO_LINGER");
        }

        if (NULL != client->laddr) {
            if (0 != bind(fd,client->laddr->ai_addr,client->laddr->ai_addrlen)){
                client_perror(client, "bind() (local addr)");
                return 0;
            }
        }

        int rc;
      #if defined(TCP_FASTOPEN) && ! defined(__APPLE__)
        ssize_t wr = 0;
        if (client->tcp_fastopen) {/*(disabled if config->proxy is AF_UNIX)*/
            wr = sendto(fd, client->request, client->request_size,
                        MSG_FASTOPEN | MSG_DONTWAIT | MSG_NOSIGNAL,
                        raddr->ai_addr, raddr->ai_addrlen);
            if (wr > 0) {
                client_connected(client);
                if (client->request_size == (uint32_t)wr) {
                    client->pfd->events |= POLLIN;
                    if (++client->pipelined == client->pipeline_max) {
                        client->revents &= ~POLLOUT;
                        client->pfd->events &= ~POLLOUT;
                    }
                }
                else
                    client->request_offset = (uint32_t)wr;
                return 1;
            }
            else if (-1 == wr && errno == EOPNOTSUPP)
                wr = 0;
            else {
                /*(0 == wr with sendto() should not happen
                 * with MSG_FASTOPEN and non-zero request_size)*/
                wr = -1;
                rc = -1;
            }
        }
        if (0 == wr)
      #endif
        do {
            rc = connect(fd, raddr->ai_addr, raddr->ai_addrlen);
        } while (__builtin_expect( (-1 == rc), 0) && errno == EINTR);

        if (0 != rc) {
            switch (errno) {
              case EINPROGRESS:
              case EALREADY:
                /* async connect now in progress */
                client->revents &= ~POLLOUT;
                client->pfd->events |= POLLOUT;
                return 0;
              default:
                client_perror(client, "connect()");
                return 0;
            }
        }
    }
    else {
        opt = 0;
        socklen_t optlen = sizeof(opt);
        if (0 != getsockopt(fd,SOL_SOCKET,SO_ERROR,&opt,&optlen) || 0 != opt) {
            if (0 != opt) errno = opt;
            client_perror(client, "connect() getsockopt()");
            return 0; /* error connecting */
        }
    }

    /* successfully connected */
    client_connected(client);
    return 1;
}


__attribute_nonnull__
static int
client_parse_chunks (Client * const restrict client)
{
    do {
        char *str = client->buffer+client->parser_offset;

        if (-1 == client->chunk_size) {
            /* read chunk size */
            /*char *end = strchr(str, '\n');*/
            char *end =
              memchr(str, '\n', client->buffer_offset - client->parser_offset);
            if (!end) /* partial line */
                return 1;
            ++end;

            /* assume server sends valid chunked header
             * (not validating; (invalid) chunked header without any
             *  hex digits is treated as 0-chunk, ending input) */
            client->chunk_size = 0;
            do {
                int c = *str;
                client->chunk_size <<= 4;
                if (c >= '0' && c <= '9')
                    client->chunk_size |= (c - '0');
                else if ((c |= 0x20) >= 'a' && c <= 'f')
                    client->chunk_size |= (c - 'a' + 10);
                else {
                    if (c=='\r' || c=='\n' || c==' ' || c=='\t' || c==';')
                        break;
                    client_error(client);
                    return 0;
                }
            } while (*++str != '\r' && *str != '\n');

            if (0 == client->chunk_size) {
                /* chunk of size 0 marks end of content body
                 * check for final "\r\n" ending response
                 * (not handling trailers if user supplied -H "TE: trailers") */
                if (end + 2 > client->buffer + client->buffer_offset) {
                    client->chunk_size = -1;
                    return 1; /* final "\r\n" not yet received */
                }
                if (end[0] == '\r' && end[1] == '\n')
                    client->stats->bytes_headers += 2;
                else
                    client->keepalive = 0; /*(just close con if trailers)*/
                client->parser_offset = end - client->buffer + 2;
                client_reset(client, client->http_status_success);
                return 0; /*(trigger loop continue in caller)*/
            }

            client->parser_offset = end - client->buffer;
            client->chunk_received = 0;
            client->chunk_size += 2; /*(for chunk "\r\n" end)*/
        }

        /* consume chunk until chunk_size is reached */
        const int rd = client->buffer_offset - client->parser_offset;
        int chunk_remain = client->chunk_size - client->chunk_received;
        if (rd >= chunk_remain) {
            client->chunk_received += chunk_remain;
            client->parser_offset += chunk_remain;

            if (client->buffer[client->parser_offset-1] != '\n') {
                client_error(client);
                return 0;
            }

            /* got whole chunk, next! */
            client->chunk_size = -1;
            client->chunk_received = 0;
        }
        else {
            client->chunk_received += rd;
            client->parser_offset += rd;
        }

    } while (client->parser_offset != client->buffer_offset);/* more to parse */

    client->parser_offset = 0;
    client->buffer_offset = 0;
    return 1;
}


__attribute_hot__
__attribute_nonnull__
__attribute_pure__
static uint64_t
client_parse_uint64 (const char * const restrict str)
{
    /* quick-n-dirty conversion of numerical string to integral number
     * Note: not validating field and not checking for valid number
     * (weighttp not intended for use with requests > 2 GB, as transfer
     *  of body would take the majority of the time in that case)*/
    uint64_t x = 0;
    for (int i = 0; (unsigned int)(str[i] - '0') < 10u; ++i) {
        x *= 10;
        x += (unsigned int)(str[i] - '0');
    }
    return x;
}


__attribute_hot__
__attribute_noinline__
__attribute_nonnull__
static int
client_parse (Client * const restrict client)
{
    char *end;
    uint32_t len;

    /* future: might combine PARSER_START and PARSER_HEADER states by
     * collecting entire set of headers (reading until "\r\n\r\n")
     * prior to parsing */

    switch (client->parser_state) {

      case PARSER_START:
        /* look for HTTP/1.1 200 OK (though also accept HTTP/1.0 200)
         * Note: does not support 1xx intermediate messages */
        /* Note: not validating response line; assume valid */
        /*end = strchr(client->buffer+client->parser_offset, '\n');*/
        end = memchr(client->buffer+client->parser_offset, '\n',
                     client->buffer_offset - client->parser_offset);
        if (NULL != end) {
            len = (uint32_t)(end - client->buffer - client->parser_offset + 1);
            if (len < sizeof("HTTP/1.1 200\r\n")-1) {
                client_error(client);
                return 0;
            }
        }
        else /*(partial response line; incomplete)*/
            return 1;

        client->content_length = -1;
        client->chunked = 0;
        client->http_status_success = 1;
        switch (client->buffer[client->parser_offset + sizeof("HTTP/1.1 ")-1]
                - '0') {
          case 2:
            ++client->stats->req_2xx;
            break;
          case 3:
            ++client->stats->req_3xx;
            break;
          case 4:
            client->http_status_success = 0;
            ++client->stats->req_4xx;
            break;
          case 5:
            client->http_status_success = 0;
            ++client->stats->req_5xx;
            break;
          default:
            /* invalid status code */
            client_error(client);
            return 0;
        }
        client->stats->bytes_headers += len;
        client->parser_offset += len;
        client->parser_state = PARSER_HEADER;
        /* fall through */

      case PARSER_HEADER:
        /* minimally peek at Content-Length, Connection, Transfer-Encoding */
        do {
            const char *str = client->buffer+client->parser_offset;
            /*end = strchr(str, '\n');*/
            end =
              memchr(str, '\n', client->buffer_offset - client->parser_offset);
            if (NULL == end)
                return 1;
            len = (uint32_t)(end - str + 1);
            client->stats->bytes_headers += len;
            client->parser_offset += len;

            /* minimum lengths for us to check for ':' in the following:
             *   "Content-Length:0\r\n"
             *   "Connection:close\r\n"
             *   "Transfer-Encoding:chunked\r\n"*/
            if (end - str < 17)
                continue;

            if (str[14] == ':'
                && (0 == memcmp(str, "Content-Length",
                                sizeof("Content-Length")-1)
                    || 0 == strncasecmp(str, "Content-Length",
                                        sizeof("Content-Length")-1))) {
                str += sizeof("Content-Length:")-1;
                if (__builtin_expect( (*str == ' '), 1))
                    ++str;
                while (__builtin_expect( (*str == ' '), 0)
                       || __builtin_expect( (*str == '\t'), 0))
                    ++str;
                client->content_length = client_parse_uint64(str);
            }
            else if (str[10] == ':'
                     && (0 == memcmp(str, "Connection",
                                     sizeof("Connection")-1)
                         || 0 == strncasecmp(str, "Connection",
                                             sizeof("Connection")-1))) {
                str += sizeof("Connection:")-1;
                if (__builtin_expect( (*str == ' '), 1))
                    ++str;
                while (__builtin_expect( (*str == ' '), 0)
                       || __builtin_expect( (*str == '\t'), 0))
                    ++str;
                if ((*str | 0x20) == 'c')  /*(assume "close")*/
                    client->keepalive = 0;
            }
            else if (str[17] == ':'
                     && (0 == memcmp(str, "Transfer-Encoding",
                                     sizeof("Transfer-Encoding")-1)
                         || 0 == strncasecmp(str, "Transfer-Encoding",
                                             sizeof("Transfer-Encoding")-1))) {
                client->chunked = 1; /*(assume "chunked")*/
                client->chunk_size = -1;
                client->chunk_received = 0;
            }

        } while (end[1] != '\r' || end[2] != '\n');

        /* body reached */
        client->stats->bytes_headers += 2;
        client->parser_offset += 2;
        client->parser_state = PARSER_BODY;
        if (client->http_head)
            client->content_length = 0;
        else if (!client->chunked && -1 == client->content_length)
            client->keepalive = 0;
        /* fall through */

      case PARSER_BODY:
        /* consume and discard response body */

        if (client->chunked)
            return client_parse_chunks(client);
        else {
            /* consume all data until content-length reached (or EOF) */
            if (-1 != client->content_length) {
                uint32_t rd = client->buffer_offset - client->parser_offset;
                if (client->content_length > rd)
                    client->content_length -= rd;
                else { /* full response received */
                    client->parser_offset += client->content_length;
                    client_reset(client, client->http_status_success);
                    return 0; /*(trigger loop continue in caller)*/
                }
            }

            client->buffer_offset = 0;
            client->parser_offset = 0;
            return 1;
        }

      case PARSER_CONNECT: /*(should not happen here)*/
        break;
    }

    return 1;
}


__attribute_nonnull__
static void
client_revents (Client * const restrict client)
{
    while (client->revents & POLLIN) {
        /* parse pipelined responses */
        if (client->buffer_offset && !client_parse(client))
            continue;

        ssize_t r;
        do {
            r = recv(client->pfd->fd, client->buffer+client->buffer_offset,
                     sizeof(client->buffer) - client->buffer_offset - 1,
                     MSG_DONTWAIT);
        } while (__builtin_expect( (-1 == r), 0) && errno == EINTR);
        if (__builtin_expect( (r > 0), 1)) {
            if (r < (ssize_t)(sizeof(client->buffer)-client->buffer_offset-1))
                client->revents &= ~POLLIN;
            client->buffer[(client->buffer_offset += (uint32_t)r)] = '\0';
            client->stats->bytes_total += r;

            if (!client_parse(client))
                continue;

            /* PARSER_BODY handling consumes data, so buffer full might happen
             * only when parsing response header line or chunked header line.
             * If buffer is full, then line is *way* too long.  However, if
             * client->parser_offset is non-zero, then move data to beginning
             * of buffer and attempt to read() more */
            if (__builtin_expect(
                  (client->buffer_offset == sizeof(client->buffer)-1), 0)) {
                if (0 == client->parser_offset) {
                    client_error(client); /* response header too big */
                    break;
                }
                else {
                    memmove(client->buffer,client->buffer+client->parser_offset,
                            client->buffer_offset - client->parser_offset + 1);
                    client->buffer_offset -= client->parser_offset;
                    client->parser_offset = 0;
                }
            }
        }
        else {
            if (-1 == r) { /* error */
                if (errno == EAGAIN
                   #if EAGAIN != EWOULDBLOCK
                    || errno == EWOULDBLOCK
                   #endif
                   ) {
                    client->revents &= ~POLLIN;
                    client->pfd->events |= POLLIN;
                    break;
                }
                else
                    client_perror(client, "read()");
            }
            else { /* disconnect; evaluate if end-of-response or error */
                if (client->http_status_success
                    && client->parser_state == PARSER_BODY
                    && !client->chunked && -1 == client->content_length) {
                    client->keepalive = 0;
                    client_reset(client, 1);
                }
                else {
                    if (client->keptalive
                        && client->parser_state == PARSER_START
                        && 0 == client->buffer_offset) {
                        /* (server might still read and discard request,
                         *  but has initiated connection close)
                         * (decrement counters to redo request, including
                         *  decrementing counters that will be incremented
                         *  by call to client_error() directly below) */
                        --client->stats->req_started;
                        --client->stats->req_failed;
                        --client->stats->req_error;
                        --client->stats->req_done;
                    }
                    client_error(client);
                }
            }
        }
    }

    if (__builtin_expect( (client->revents & (POLLERR|POLLHUP)), 0)) {
        client->keepalive = 0;
        client_reset(client, 0);
    }

    while (client->revents & POLLOUT) {
        ssize_t r;
        if (client->parser_state == PARSER_CONNECT && !client_connect(client))
            continue;

        do {
            r = send(client->pfd->fd,
                     client->request+client->request_offset,
                     client->request_size - client->request_offset,
                     MSG_DONTWAIT | MSG_NOSIGNAL);
        } while (__builtin_expect( (-1 == r), 0) && errno == EINTR);
        if (__builtin_expect( (r > 0), 1)) {
            if (client->request_size == (uint32_t)r
                || client->request_size==(client->request_offset+=(uint32_t)r)){
                /* request sent; register read interest for response */
                client->request_offset = 0;
                client->pfd->events |= POLLIN;
                if (++client->pipelined < client->pipeline_max)
                    continue;
                else {
                    client->revents &= ~POLLOUT; /*(trigger write() loop exit)*/
                    client->pfd->events &= ~POLLOUT;
                }
            }
            else {
                client->revents &= ~POLLOUT; /*(trigger write() loop exit)*/
                client->pfd->events |= POLLOUT;
            }
        }
        else {
            if (-1 == r) { /* error */
                if (errno == EAGAIN
                   #if EAGAIN != EWOULDBLOCK
                    || errno == EWOULDBLOCK
                   #endif
                   ) {
                    client->revents &= ~POLLOUT;
                    client->pfd->events |= POLLOUT;
                    break;
                }
                else
                    client_perror(client, "write()");
            }
            else { /* (0 == r); not expected; not attempting to write 0 bytes */
                client->keepalive = 0;
                client_reset(client, 0);
            }
        }
    }
}


__attribute_nonnull__
static void *
worker_thread (void * const arg)
{
    Worker worker;
    int i, nready;
    Worker_Config * const restrict wconf = (Worker_Config *)arg;
    worker_init(&worker, wconf);

    const int num_clients = wconf->num_clients;
    const int progress =
      (0==wconf->id && !wconf->config->quiet); /* report only in first thread */
    const uint64_t progress_interval =         /* print every 10% done */
     (worker.stats.req_todo > 10) ? worker.stats.req_todo / 10 : 1;
    uint64_t progress_next = progress_interval;

    /* start all clients */
    for (i = 0; i < num_clients; ++i) {
        if (worker.stats.req_started < worker.stats.req_todo) {
            worker.clients[i].revents = POLLOUT;
            client_revents(worker.clients+i);
        }
    }

    while (worker.stats.req_done < worker.stats.req_todo) {
        do {                                 /*(infinite wait)*/
            nready = poll(worker.pfds, (nfds_t)num_clients, -1);
        } while (__builtin_expect( (-1 == nready), 0) && errno == EINTR);
        if (__builtin_expect( (-1 == nready), 0)) {
            /*(repurpose client_perror(); use client buffer for strerror_r())*/
            client_perror(worker.clients+0, "poll()"); /* fatal; ENOMEM */
            return NULL;
        }

        i = 0;
        do {
            while (0 == worker.pfds[i].revents)
                ++i;
            worker.clients[i].revents |= worker.pfds[i].revents;
            worker.pfds[i].revents = 0;
            client_revents(worker.clients+i);
        } while (--nready);

        if (progress) {
            /*(assume progress of one thread approximates that of all threads)*/
            /*(RFE: main thread could poll and report progress of all workers)*/
            while (__builtin_expect( worker.stats.req_done >= progress_next,0)){
                printf("progress: %3d%% done\n", (int)
                       (worker.stats.req_done * 100 / worker.stats.req_todo));
                if (progress_next == worker.stats.req_todo)
                    break;
                progress_next += progress_interval;
                if (__builtin_expect( progress_next > worker.stats.req_todo, 0))
                    progress_next = worker.stats.req_todo;
            }
        }
    }

    worker_delete(&worker, wconf);
    return NULL;
}


__attribute_cold__
__attribute_noinline__
__attribute_nonnull__
static void
config_error_diagnostic (const char * const restrict errfmt,
                         const int perr, va_list ap)
{
    const int errnum = errno;
    show_version();
    show_help();
    fflush(stdout);

    fprintf(stderr, "\nerror: ");
    vfprintf(stderr, errfmt, ap);

    if (!perr)
        fprintf(stderr, "\n\n");
    else {
        char buf[1024];
        buf[0] = '\0';
      #if defined(_GNU_SOURCE) && defined(__GLIBC__)
        const char * const errstr = strerror_r(errnum, buf, sizeof(buf));
      #else /* XSI-compliant strerror_r() */
        const char * const errstr = buf;
        strerror_r(errnum, buf, sizeof(buf));
      #endif

        fprintf(stderr, ": (%d) %s\n\n", errnum, errstr);
    }
}


__attribute_cold__
__attribute_format__((__printf__, 1, 2))
__attribute_noinline__
__attribute_nonnull__
__attribute_noreturn__
static void
config_error (const char * const restrict errfmt, ...)
{
    va_list ap;
    va_start(ap, errfmt);
    config_error_diagnostic(errfmt, 0, ap);
    va_end(ap);
    exit(1);
}


__attribute_cold__
__attribute_format__((__printf__, 1, 2))
__attribute_noinline__
__attribute_nonnull__
__attribute_noreturn__
static void
config_perror (const char * const restrict errfmt, ...)
{
    va_list ap;
    va_start(ap, errfmt);
    config_error_diagnostic(errfmt, 1, ap);
    va_end(ap);
    exit(1);
}


typedef struct config_params {
  const char *method;
  const char *uri;
        char *laddrstr;
  int use_ipv6;
  int headers_num;
  int cookies_num;
  const char *headers[64];
  const char *cookies[64];
  const char *body_content_type;
  const char *body_filename;
  const char *authorization;
  const char *proxy_authorization;
} config_params;


__attribute_cold__
__attribute_nonnull__
static int
config_laddr (Config * const restrict config,
              const char * const restrict laddrstr)
{
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    /*hints.ai_flags |= AI_NUMERICHOST;*/
    hints.ai_family   = config->raddr.ai_family;
    hints.ai_socktype = SOCK_STREAM;

    if (0 != getaddrinfo(laddrstr, NULL, &hints, &res) || NULL == res)
        return 0;

    config->laddr.ai_family   = res->ai_family;
    config->laddr.ai_socktype = res->ai_socktype;
    config->laddr.ai_protocol = res->ai_protocol;
    config->laddr.ai_addrlen  = res->ai_addrlen;
    config->laddr.ai_addr     = (struct sockaddr *)
      memcpy(&config->laddr_storage, res->ai_addr, res->ai_addrlen);

    freeaddrinfo(res);
    return 1;
}


__attribute_cold__
__attribute_nonnull__
static int
config_laddrs (Config * const restrict config,
               char * const restrict laddrstr)
{
    char *s;
    int num = 1;
    for (s = laddrstr; NULL != (s = strchr(s, ',')); s = s+1) ++num;
    if (1 == num) return config_laddr(config, laddrstr);

    struct addrinfo hints, **res;
    memset(&hints, 0, sizeof(hints));
    /*hints.ai_flags |= AI_NUMERICHOST;*/
    hints.ai_family   = config->raddr.ai_family;
    hints.ai_socktype = SOCK_STREAM;

    config->laddrs.num = num;
    config->laddrs.addrs = res =
      (struct addrinfo **)calloc((size_t)num, sizeof(struct addrinfo *));

    s = laddrstr;
    for (int i = 0; i < num; ++i, ++res) {
        char *e = strchr(s, ',');
        if (NULL != e) *e = '\0';

        *res = NULL;
        if (0 != getaddrinfo(s, NULL, &hints, res) || NULL == *res)
            return 0; /*(leave laddrstr modified so last addr is one w/ error)*/

        if (NULL == e) break;
        *e = ',';
        s = e+1;
    }

    return 1;
}


__attribute_cold__
__attribute_nonnull__
static void
config_raddr (Config * const restrict config,
              const char * restrict hostname, uint16_t port, const int use_ipv6)
{
    if (config->proxy && config->proxy[0] == '/') {
        #ifndef UNIX_PATH_MAX
        #define UNIX_PATH_MAX 108
        #endif
        const size_t len = strlen(config->proxy);
        if (len >= UNIX_PATH_MAX)
            config_error("socket path too long: %s", config->proxy);

        config->raddr.ai_family   = AF_UNIX;
        config->raddr.ai_socktype = SOCK_STREAM | SOCK_NONBLOCK;
        config->raddr.ai_protocol = 0;
        /* calculate effective SUN_LEN(); macro not always available)*/
        config->raddr.ai_addrlen  =
          (socklen_t)((size_t)(((struct sockaddr_un *) 0)->sun_path) + len);
        config->raddr.ai_addr     = (struct sockaddr *)&config->raddr_storage;
        memset(&config->raddr_storage, 0, sizeof(config->raddr_storage));
        config->raddr_storage.ss_family = AF_UNIX;
        memcpy(((struct sockaddr_un *)&config->raddr_storage)->sun_path,
               config->proxy, len+1);
        return;
    }

    char host[1024]; /*(host should be < 256 chars)*/
    if (config->proxy) { /* (&& config->proxy[0] != '/') */
        char * const colon = strrchr(config->proxy, ':');
        if (colon) {
            char *endptr;
            unsigned long i = strtoul(colon+1, &endptr, 10);
            if (*endptr == '\0' && 0 != i && i <= USHRT_MAX)
                port = (unsigned short)i;
            else /*(might mis-parse IPv6 addr which omitted port)*/
                config_error("could not parse -X proxy: %s", config->proxy);

            const size_t len = (size_t)(colon - config->proxy);
            if (len >= sizeof(host))
                config_error("proxy host path too long: %s", config->proxy);
            memcpy(host, config->proxy, len);
            host[len] = '\0';
            hostname = host;
        }
        else {
            hostname = config->proxy;
            port = 80; /* default HTTP port */
        }
    }

    struct addrinfo hints, *res, *res_first;
    memset(&hints, 0, sizeof(hints));
    hints.ai_flags |= AI_NUMERICSERV;
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%hu", port);

    if (0 != getaddrinfo(hostname, port_str, &hints, &res_first))
        config_error("could not resolve hostname: %s", hostname);

    for (res = res_first; res != NULL; res = res->ai_next) {
        if (res->ai_family == (use_ipv6 ? AF_INET6 : AF_INET)) {
            config->raddr.ai_family   = res->ai_family;
            config->raddr.ai_socktype = res->ai_socktype | SOCK_NONBLOCK;
            config->raddr.ai_protocol = res->ai_protocol;
            config->raddr.ai_addrlen  = res->ai_addrlen;
            config->raddr.ai_addr     = (struct sockaddr *)
              memcpy(&config->raddr_storage, res->ai_addr, res->ai_addrlen);
            break;
        }
    }

    freeaddrinfo(res_first);
    if (NULL == res)
        config_error("could not resolve hostname: %s", hostname);
}


__attribute_cold__
__attribute_nonnull__
static int
config_base64_encode_pad (char * const restrict dst, const size_t dstsz,
                          const char * const restrict ssrc)
{
    static const char base64_table[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

    const size_t srclen = strlen(ssrc);
    const int rem    = (int)(srclen % 3);
    const int tuples = (int)(srclen / 3);
    const int tuplen = (int)(srclen - (size_t)rem);
    if (srclen > INT_MAX/2)  /*(ridiculous size; prevent integer overflow)*/
        return -1;
    if (dstsz < (size_t)(4*tuples + (rem ? 4 : 0) + 1))
        return -1;

    int s = 0, d = 0;
    unsigned int v;
    const unsigned char * const src = (const unsigned char *)ssrc;
    for (; s < tuplen; s += 3, d += 4) {
        v = (src[s+0] << 16) | (src[s+1] << 8) | src[s+2];
        dst[d+0] = base64_table[(v >> 18) & 0x3f];
        dst[d+1] = base64_table[(v >> 12) & 0x3f];
        dst[d+2] = base64_table[(v >>  6) & 0x3f];
        dst[d+3] = base64_table[(v      ) & 0x3f];
    }

    if (rem) {
        if (1 == rem) {
            v = (src[s+0] << 4);
            dst[d+2] = base64_table[64]; /* pad */
        }
        else { /*(2 == rem)*/
            v = (src[s+0] << 10) | (src[s+1] << 2);
            dst[d+2] = base64_table[v & 0x3f]; v >>= 6;
        }
        dst[d+0] = base64_table[(v >> 6) & 0x3f];
        dst[d+1] = base64_table[(v     ) & 0x3f];
        dst[d+3] = base64_table[64]; /* pad */
        d += 4;
    }

    dst[d] = '\0';
    return d; /*(base64-encoded string length; might be 0)*/
}


__attribute_cold__
__attribute_nonnull__
static void
config_request (Config * const restrict config,
                const config_params * const restrict params)
{
    const char * restrict uri = params->uri;
    uint16_t port = 80;
    uint16_t default_port = 80;
    char host[1024]; /*(host should be < 256 chars)*/

    if (0 == strncmp(uri, "http://", sizeof("http://")-1))
        uri += 7;
    else if (0 == strncmp(uri, "https://", sizeof("https://")-1)) {
        uri += 8;
        port = default_port = 443;
        config_error("no ssl support yet");
    }

    /* XXX: note that this is not a fully proper URI parse */
    const char *c;
    if ((c = strchr(uri, ':'))) { /* found ':' => host:port */
        if (c - uri + 1 > (int)sizeof(host))
            config_error("host name in URI is too long");
        memcpy(host, uri, c - uri);
        host[c - uri] = '\0';

        char *endptr;
        unsigned long i = strtoul(c+1, &endptr, 10);
        if (0 != i && i <= USHRT_MAX) {
            port = (unsigned short)i;
            uri = endptr;
        }
        else
            config_error("could not parse URI");
    }
    else {
        if ((c = strchr(uri, '/'))) {
            if (c - uri + 1 > (int)sizeof(host))
                config_error("host name in URI is too long");
            memcpy(host, uri, c - uri);
            host[c - uri] = '\0';
            uri = c;
        }
        else {
            size_t len = strlen(uri);
            if (len + 1 > (int)sizeof(host))
                config_error("host name in URI is too long");
            memcpy(host, uri, len);
            host[len] = '\0';
            uri += len;
        }
    }

    /* resolve hostname to sockaddr */
    config_raddr(config, host, port, params->use_ipv6);

    int idx_host = -1;
    int idx_user_agent = -1;
    int idx_content_type = -1;
    int idx_content_length = -1;
    int idx_transfer_encoding = -1;
    const char * const * const restrict headers = params->headers;
    for (int i = 0; i < params->headers_num; i++) {
        if (0 == strncasecmp(headers[i],"Host:",sizeof("Host:")-1)) {
            if (-1 != idx_host)
                config_error("duplicate Host header");
            idx_host = i;
        }
        if (0 == strncasecmp(headers[i],"User-Agent:",sizeof("User-Agent:")-1))
            idx_user_agent = i;
        if (0 == strncasecmp(headers[i],"Connection:",sizeof("Connection:")-1))
            config_error("Connection request header not allowed; "
                         "use -k param to enable keep-alive");
        if (0 == strncasecmp(headers[i],"Content-Type:",
                                 sizeof("Content-Type:")-1))
            idx_content_type = i;
        if (0 == strncasecmp(headers[i],"Content-Length:",
                                 sizeof("Content-Length:")-1))
            idx_content_length = i;
        if (0 == strncasecmp(headers[i],"Transfer-Encoding:",
                                 sizeof("Transfer-Encoding:")-1))
            idx_transfer_encoding = i;
    }

    /*(simple 8k memaligned request buffer (part of struct Config))*/
    config->request =
      (char *)((uintptr_t)(config->buf + (8*1024-1)) & ~(uintptr_t)(8*1024-1));
    char * const restrict req = config->request;
    const size_t sz = sizeof(config->buf) >> 1;
    int offset = snprintf(req, sz, "%s %s HTTP/1.1\r\n", params->method,
                          config->proxy && config->proxy[0] != '/'
                            ? params->uri /*(provide full URI to proxy host)*/
                            : *uri != '\0' ? uri : "/");
    if (offset >= (int)sz)
        config_error("request too large");

    int len = (-1 != idx_host)
      ? snprintf(req+offset, sz-offset, "%s\r\n", headers[idx_host])
      : (port == default_port)
        ? snprintf(req+offset, sz-offset, "Host: %s\r\n", host)
        : snprintf(req+offset, sz-offset, "Host: %s:%hu\r\n", host, port);
    if (len >= (int)sz - offset)
        config_error("request too large");
    offset += len;

    if (!config->keep_alive) {
        len = sizeof("Connection: close\r\n")-1;
        if (len >= (int)sz - offset)
            config_error("request too large");
        memcpy(req+offset, "Connection: close\r\n", len);
        offset += len;
    }

    int fd = -1;
    off_t fsize = 0;
    if (params->body_filename) {
        #ifndef O_BINARY
        #define O_BINARY 0
        #endif
        #ifndef O_LARGEFILE
        #define O_LARGEFILE 0
        #endif
        #ifndef O_NOATIME
        #define O_NOATIME 0
        #endif
        fd = open(params->body_filename,
                  O_RDONLY|O_BINARY|O_LARGEFILE|O_NOATIME|O_NONBLOCK, 0);
        if (-1 == fd)
            config_perror("open(%s)", params->body_filename);
        struct stat st;
        if (0 != fstat(fd, &st))
            config_perror("fstat(%s)", params->body_filename);
        fsize = st.st_size;
        if (fsize > UINT32_MAX - (8*1024))
            config_error("file size too large (not supported > ~4GB) (%s)",
                         params->body_filename);

        /* If user specified Transfer-Encoding, trust that it is proper,
         * e.g. chunked, and that body_filename contains already-chunked data */
        if (-1 == idx_transfer_encoding) {
            if (-1 == idx_content_length) {
                len = snprintf(req+offset, sz-offset,
                               "Content-Length: %"PRId64"\r\n", (int64_t)fsize);
                if (len >= (int)sz - offset)
                    config_error("request too large");
                offset += len;
            } /*(else trust user specified length matching body_filename size)*/
        }
        else if (-1 != idx_content_length)
            config_error("Content-Length must be omitted "
                         "if Transfer-Encoding provided");

        if (params->body_content_type) {
            if (-1 == idx_content_type)
                config_error("Content-Type duplicated in -H and -T params");
            len = snprintf(req+offset, sz-offset,
                           "Content-Type: %s\r\n", params->body_content_type);
            if (len >= (int)sz - offset)
                config_error("request too large");
            offset += len;
        }
        else if (-1 == idx_content_type) {
            len = sizeof("Content-Type: text/plain\r\n")-1;
            if (len >= (int)sz - offset)
                config_error("request too large");
            memcpy(req+offset, "Content-Type: text/plain\r\n", len);
            offset += len;
        }
    }

    for (int i = 0; i < params->headers_num; ++i) {
        if (i == idx_host)
            continue;
        len = snprintf(req+offset, sz-offset, "%s\r\n", headers[i]);
        if (len >= (int)sz - offset)
            config_error("request too large");
        offset += len;
    }

    if (params->authorization) {
        len = snprintf(req+offset, sz-offset, "Authorization: Basic ");
        if (len >= (int)sz - offset)
            config_error("request too large");
        offset += len;

        len = config_base64_encode_pad(req+offset, sz-offset,
                                       params->authorization);
        if (len < 0)
            config_error("request too large");
        offset += len;

        if (2 >= (int)sz - offset)
            config_error("request too large");
        memcpy(req+offset, "\r\n", 3);
        offset += 2;
    }

    if (params->proxy_authorization) {
        len = snprintf(req+offset, sz-offset, "Proxy-Authorization: Basic ");
        if (len >= (int)sz - offset)
            config_error("request too large");
        offset += len;

        len = config_base64_encode_pad(req+offset, sz-offset,
                                       params->proxy_authorization);
        if (len < 0)
            config_error("request too large");
        offset += len;

        if (2 >= (int)sz - offset)
            config_error("request too large");
        memcpy(req+offset, "\r\n", 3);
        offset += 2;
    }

    if (-1 == idx_user_agent) {
        len = sizeof("User-Agent: weighttp/" PACKAGE_VERSION "\r\n")-1;
        if (len >= (int)sz - offset)
            config_error("request too large");
        memcpy(req+offset,
               "User-Agent: weighttp/" PACKAGE_VERSION "\r\n", len);
        offset += len;
    }

    const char * const * const restrict cookies = params->cookies;
    for (int i = 0; i < params->cookies_num; ++i) {
        len = snprintf(req+offset, sz-offset, "Cookie: %s\r\n",cookies[i]);
        if (len >= (int)sz - offset)
            config_error("request too large");
        offset += len;
    }

    if (3 > (int)sz - offset)
        config_error("request too large");
    memcpy(req+offset, "\r\n", 3); /*(including terminating '\0')*/
    offset += 2;               /*(not including terminating '\0')*/

    config->request_size = (uint32_t)(offset + fsize);

    if (-1 != fd && 0 != fsize) {
        /*(not checking if file changed between fstat() and read())*/
        /*(not using mmap() since we expect benchmark test file to be smallish
         * and able to fit in memory, or */
        config->request = malloc(config->request_size);
        memcpy(config->request, req, (size_t)offset);
        off_t reqsz = offset;
        ssize_t rd;
        do {
            rd = read(fd, config->request+reqsz, config->request_size-reqsz);
        } while (rd > 0 ? (reqsz += rd) < config->request_size
                        : (rd < 0 && errno == EINTR));
        if (reqsz != config->request_size)
            config_perror("read(%s)", params->body_filename);
    }
}


__attribute_cold__
__attribute_noinline__
__attribute_nonnull__
static void
weighttp_setup (Config * const restrict config, const int argc, char *argv[])
{
    int opt_show_help = 0;
    int opt_show_version = 0;
    config_params params;
    memset(&params, 0, sizeof(params));

    /* default settings */
    config->thread_count = 1;
    config->concur_count = 1;
    config->req_count = 0;
    config->keep_alive = 0;
    config->proxy = NULL;
    config->pipeline_max = 0;
    config->tcp_fastopen = 0;
    config->http_head = 0;
    config->so_bufsz = 0;
    config->quiet = 0;

    setlocale(LC_ALL, "C");
    signal(SIGPIPE, SIG_IGN);

    const char * const optstr = ":hVikqdlr6Fm:n:t:c:b:p:u:A:B:C:H:K:P:T:X:";
    int opt;
    while (-1 != (opt = getopt(argc, argv, optstr))) {
        switch (opt) {
          case '6':
            params.use_ipv6 = 1;
            break;
          case 'A':
            params.authorization = optarg;
            break;
          case 'B':
            params.laddrstr = optarg;
            break;
          case 'C':
            if (params.cookies_num == sizeof(params.cookies)/sizeof(char *))
                config_error("too many cookies");
            params.cookies[params.cookies_num++] = optarg;
            break;
          case 'F':
            config->tcp_fastopen = 1;
            break;
          case 'H':
            if (params.headers_num == sizeof(params.headers)/sizeof(char *))
                config_error("too many headers");
            params.headers[params.headers_num++] = optarg;
            break;
          case 'K':
            config->pipeline_max = (int)strtoul(optarg, NULL, 10);
            if (config->pipeline_max >= 2)
                config->keep_alive = 1;
            break;
          case 'P':
            params.proxy_authorization = optarg;
            break;
          case 'T':
            params.body_content_type = optarg;
            break;
          case 'X':
            config->proxy = optarg;
            break;
          case 'b':
            config->so_bufsz = (int)strtoul(optarg, NULL, 10);
            break;
          case 'c':
            config->concur_count = (int)strtoul(optarg, NULL, 10);
            break;
          case 'i':
            config->http_head = 1;
            break;
          case 'k':
            config->keep_alive = 1;
            break;
          case 'm':
            params.method = optarg;
            config->http_head = (0 == strcasecmp(optarg, "HEAD"));
            break;
          case 'n':
            config->req_count = strtoull(optarg, NULL, 10);
            break;
          case 'p':
            params.body_filename = optarg;
            params.method = "POST";
            config->http_head = 0;
            break;
          case 'q':
            config->quiet = 1;
            break;
          case 'd':
          case 'l':
          case 'r':
            /*(ignored; compatibility with Apache Bench (ab))*/
            break;
          case 't':
            config->thread_count = (int)strtoul(optarg, NULL, 10);
            break;
          case 'u':
            params.body_filename = optarg;
            params.method = "PUT";
            config->http_head = 0;
            break;
          case ':':
            config_error("option requires an argument: -%c", optopt);
          case '?':
            if ('?' != optopt)
                config_error("unknown option: -%c", optopt);
            /* fall through */
          case 'h':
            opt_show_help = 1;
            /* fall through */
          case 'V':
            opt_show_version = 1;
            break;
        }
    }

    if (opt_show_version || !config->quiet)
        show_version();

    if (opt_show_help)
        show_help();

    if (opt_show_version)
        exit(0);

    if ((argc - optind) < 1)
        config_error("missing URI argument");
    else if ((argc - optind) > 1)
        config_error("too many arguments");
    params.uri = argv[optind];

    /* check for sane arguments */
    if (!config->req_count)
        config_error("num of requests has to be > 0");
    if (config->req_count == UINT64_MAX)
        config_error("invalid req_count");
    if (!config->thread_count)
        config_error("thread count has to be > 0");
    if ((uint64_t)config->thread_count > config->req_count)
        config_error("thread_count > req_count");
    if (!config->concur_count)
        config_error("num of concurrent clients has to be > 0");
    if ((uint64_t)config->concur_count > config->req_count)
        config_error("concur_count > req_count");
    if (config->thread_count > config->concur_count)
        config_error("thread_count > concur_count");
    if (config->pipeline_max < 1)
        config->pipeline_max = 1;
    if (NULL == params.method)
        params.method = config->http_head ? "HEAD" : "GET";

    config_request(config, &params);

    config->laddr.ai_addrlen = 0;
    config->laddrs.addrs = NULL;
    config->laddrs.num = 0;
    if (params.laddrstr && !config_laddrs(config, params.laddrstr))
        config_error("could not resolve local bind address: %s",
                     params.laddrstr);

    if (config->concur_count > 32768 && config->raddr.ai_family != AF_UNIX) {
        int need = config->concur_count;
        int avail = 32768;
        int fd = open("/proc/sys/net/ipv4/ip_local_port_range",
                      O_RDONLY|O_BINARY|O_LARGEFILE|O_NONBLOCK, 0);
        if (fd >= 0) {
            char buf[32];
            ssize_t rd = read(fd, buf, sizeof(buf));
            if (rd >= 3 && rd < (ssize_t)sizeof(buf)) {
                long lb, ub;
                char *e;
                buf[rd] = '\0';
                lb = strtoul(buf, &e, 10);
                if (lb > 0 && lb < USHRT_MAX && *e) {
                    ub = strtoul(e, &e, 10);
                    if (ub > 0 && ub <= USHRT_MAX && (*e=='\0' || *e=='\n')) {
                        if (lb <= ub)
                            avail = ub - lb + 1;
                    }
                }
            }
            close(fd);
        }
        if (config->laddrs.num)
            need = (need + config->laddrs.num - 1) / config->laddrs.num;
        if (need > avail)
            config_error("not enough local ports for concurrency\n"
                         "Reduce concur or provide -B addr,addr,addr "
                         "to specify multiple local bind addrs");
    }

    /* (see [RFC7413] 4.1.3. Client Cookie Handling) */
    if ((config->proxy && config->proxy[0] == '/')
        || config->request_size > (params.use_ipv6 ? 1440 : 1460))
        config->tcp_fastopen = 0;
}


__attribute_cold__
__attribute_noinline__
__attribute_nonnull__
static void
weighttp_report (const Config * const restrict config)
{
    /* collect worker stats and releaes resources */
    Stats stats;
    memset(&stats, 0, sizeof(stats));
    for (int i = 0; i < config->thread_count; ++i) {
        const Stats * const restrict wstats = &config->wconfs[i].stats;

        stats.req_started   += wstats->req_started;
        stats.req_done      += wstats->req_done;
        stats.req_success   += wstats->req_success;
        stats.req_failed    += wstats->req_failed;
        stats.bytes_total   += wstats->bytes_total;
        stats.bytes_headers += wstats->bytes_headers;
        stats.req_2xx       += wstats->req_2xx;
        stats.req_3xx       += wstats->req_3xx;
        stats.req_4xx       += wstats->req_4xx;
        stats.req_5xx       += wstats->req_5xx;
    }

    /* report cumulative stats */
    struct timeval tdiff;
    tdiff.tv_sec  = config->ts_end.tv_sec  - config->ts_start.tv_sec;
    tdiff.tv_usec = config->ts_end.tv_usec - config->ts_start.tv_usec;
    if (tdiff.tv_usec < 0) {
        --tdiff.tv_sec;
        tdiff.tv_usec += 1000000;
    }
    const uint64_t total_usecs = tdiff.tv_sec * 1000000 + tdiff.tv_usec;
    const uint64_t rps = stats.req_done * 1000000 / total_usecs;
    const uint64_t kbps= stats.bytes_total / 1024 * 1000000 / total_usecs;
  #if 1  /* JSON-style formatted output */
    printf("{\n"
           "  \"reqs_per_sec\": %"PRIu64",\n"
           "  \"kBps_per_sec\": %"PRIu64",\n"
           "  \"secs_elapsed\": %01d.%06ld,\n",
           rps, kbps, (int)tdiff.tv_sec, (long)tdiff.tv_usec);
    printf("  \"request_counts\": {\n"
           "    \"started\": %"PRIu64",\n"
           "    \"retired\": %"PRIu64",\n"
           "    \"total\":   %"PRIu64"\n"
           "  },\n",
           stats.req_started, stats.req_done, config->req_count);
    printf("  \"response_counts\": {\n"
           "    \"pass\": %"PRIu64",\n"
           "    \"fail\": %"PRIu64",\n"
           "    \"errs\": %"PRIu64"\n"
           "  },\n",
           stats.req_success, stats.req_failed, stats.req_error);
    printf("  \"status_codes\": {\n"
           "    \"2xx\":  %"PRIu64",\n"
           "    \"3xx\":  %"PRIu64",\n"
           "    \"4xx\":  %"PRIu64",\n"
           "    \"5xx\":  %"PRIu64"\n"
           "  },\n",
           stats.req_2xx, stats.req_3xx, stats.req_4xx, stats.req_5xx);
    printf("  \"traffic\": {\n"
           "    \"bytes_total\":   %12."PRIu64",\n"
           "    \"bytes_headers\": %12."PRIu64",\n"
           "    \"bytes_body\":    %12."PRIu64"\n"
           "  }\n"
           "}\n",
           stats.bytes_total, stats.bytes_headers,
           stats.bytes_total - stats.bytes_headers);
  #else
    printf("\nfinished in %01d.%06ld sec, %"PRIu64" req/s, %"PRIu64" kbyte/s\n",
           (int)tdiff.tv_sec, (long)tdiff.tv_usec, rps, kbps);

    printf("requests:  %"PRIu64" started, %"PRIu64" done, %"PRIu64" total\n"
           "responses: %"PRIu64" success, %"PRIu64" fail, %"PRIu64" error\n",
           stats.req_started, stats.req_done, config->req_count,
           stats.req_success, stats.req_failed, stats.req_error);

    printf("status codes: "
           "%"PRIu64" 2xx, %"PRIu64" 3xx, %"PRIu64" 4xx, %"PRIu64" 5xx\n",
           stats.req_2xx, stats.req_3xx, stats.req_4xx, stats.req_5xx);

    printf("traffic: %"PRIu64" bytes total, %"PRIu64" bytes headers, "
           "%"PRIu64" bytes body\n", stats.bytes_total,
           stats.bytes_headers, stats.bytes_total - stats.bytes_headers);
  #endif
}


int main (int argc, char *argv[])
{
    Config config;
    weighttp_setup(&config, argc, argv); /* exits if error (or done) */
    wconfs_init(&config);
  #if defined(__STDC_VERSION__) && __STDC_VERSION__-0 >= 199901L /* C99 */
    pthread_t threads[config.thread_count]; /*(C99 dynamic array)*/
  #else
    pthread_t * const restrict threads =
      (pthread_t *)calloc(config.thread_count, sizeof(pthread_t));
  #endif

    if (!config.quiet)
        puts("starting benchmark...");
    gettimeofday(&config.ts_start, NULL);

    for (int i = 0; i < config.thread_count; ++i) {
        int err = pthread_create(threads+i, NULL,
                                 worker_thread, (void*)(config.wconfs+i));
        if (__builtin_expect( (0 != err), 0)) {
            fprintf(stderr, "error: failed spawning thread (%d)\n", err);
            /*(XXX: leaks resources and does not attempt pthread_cancel())*/
            return 2; /* (unexpected) fatal error */
        }
    }

    for (int i = 0; i < config.thread_count; ++i) {
        int err = pthread_join(threads[i], NULL);
        if (__builtin_expect( (0 != err), 0)) {
            fprintf(stderr, "error: failed joining thread (%d)\n", err);
            /*(XXX: leaks resources and does not attempt pthread_cancel())*/
            return 3; /* (unexpected) fatal error */
        }
    }

    gettimeofday(&config.ts_end, NULL);

  #if !(defined(__STDC_VERSION__) && __STDC_VERSION__-0 >= 199901L) /* !C99 */
    free(threads);
  #endif
    weighttp_report(&config);
    wconfs_delete(&config);

    return 0;
}
