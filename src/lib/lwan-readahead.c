/*
 * lwan - web server
 * Copyright (c) 2018 L. A. F. Pereira <l@tia.mat.br>
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
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <ioprio.h>
#include <sys/mman.h>

#include "lwan-private.h"

#if defined(__linux__) && defined(O_DIRECT) && O_DIRECT
#define PIPE_DIRECT_FLAG O_DIRECT
#else
#define PIPE_DIRECT_FLAG 0
#endif

enum readahead_cmd {
    READAHEAD,
    MADVISE,
    SHUTDOWN,
};

struct lwan_readahead_cmd {
    enum readahead_cmd cmd;
    union {
        struct {
            size_t size;
            off_t off;
            int fd;
        } readahead;
        struct {
            void *addr;
            size_t length;
        } madvise;
    };
} __attribute__((packed));

static int readahead_pipe_fd[2] = {-1, -1};
static pthread_t readahead_self;
static long page_size = PAGE_SIZE;

#ifdef _SC_PAGESIZE
LWAN_CONSTRUCTOR(get_page_size, 0)
{
    long ps = sysconf(_SC_PAGESIZE);

    if (ps >= 0)
        page_size = ps;
}
#endif

void lwan_readahead_shutdown(void)
{
    struct lwan_readahead_cmd cmd = {
        .cmd = SHUTDOWN,
    };

    if (readahead_pipe_fd[0] == readahead_pipe_fd[1] &&
        readahead_pipe_fd[0] == -1)
        return;

    lwan_status_debug("Shutting down readahead thread");

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"
    write(readahead_pipe_fd[1], &cmd, sizeof(cmd));
#pragma GCC diagnostic pop
    pthread_join(readahead_self, NULL);

    close(readahead_pipe_fd[0]);
    close(readahead_pipe_fd[1]);
    readahead_pipe_fd[0] = readahead_pipe_fd[1] = -1;
}

void lwan_readahead_queue(int fd, off_t off, size_t size)
{
    if (size < (size_t)page_size)
        return;

    struct lwan_readahead_cmd cmd = {
        .readahead = {.size = size, .fd = fd, .off = off},
        .cmd = READAHEAD,
    };

    /* Readahead is just a hint.  Failing to write is not an error. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"
    write(readahead_pipe_fd[1], &cmd, sizeof(cmd));
#pragma GCC diagnostic pop
}

void lwan_madvise_queue(void *addr, size_t length)
{
    if (length < (size_t)page_size)
        return;

    struct lwan_readahead_cmd cmd = {
        .madvise = {.addr = addr, .length = length},
        .cmd = MADVISE,
    };

    /* Madvise is just a hint.  Failing to write is not an error. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"
    write(readahead_pipe_fd[1], &cmd, sizeof(cmd));
#pragma GCC diagnostic pop
}

static void *lwan_readahead_loop(void *data __attribute__((unused)))
{
    /* Idle priority for the calling thread.   Magic value of `7` obtained from
     * sample program in linux/Documentation/block/ioprio.txt.  This is a no-op
     * on anything but Linux.  */
    ioprio_set(IOPRIO_WHO_PROCESS, 0, IOPRIO_PRIO_VALUE(IOPRIO_CLASS_IDLE, 7));

    lwan_set_thread_name("readahead");

    while (true) {
        struct lwan_readahead_cmd cmd[16];
        ssize_t n_bytes = read(readahead_pipe_fd[0], cmd, sizeof(cmd));
        ssize_t cmds;

        if (UNLIKELY(n_bytes < 0)) {
            if (errno == EAGAIN || errno == EINTR)
                continue;
            lwan_status_perror("Ignoring error while reading from pipe (%d)",
                               readahead_pipe_fd[0]);
            continue;
#if PIPE_DIRECT_FLAG
        } else if (UNLIKELY(n_bytes % (ssize_t)sizeof(cmd[0]))) {
            lwan_status_warning("Ignoring readahead packet read of %zd bytes",
                                n_bytes);
            continue;
#endif
        }

        cmds = n_bytes / (ssize_t)sizeof(struct lwan_readahead_cmd);
        for (ssize_t i = 0; i < cmds; i++) {
            switch (cmd[i].cmd) {
            case READAHEAD:
                readahead(cmd[i].readahead.fd, cmd[i].readahead.off,
                          cmd[i].readahead.size);
                break;
            case MADVISE:
                madvise(cmd[i].madvise.addr, cmd[i].madvise.length,
                        MADV_WILLNEED);

                if (cmd[i].madvise.length >= 10 * 1024) {
                    /* On Linux, SO_ZEROCOPY is only useful to transmit
                     * 10kB or more because it uses page pinning (what
                     * mlock(2) does!), so consider the same threshold
                     * here.  */
                    mlock(cmd[i].madvise.addr, cmd[i].madvise.length);
                }

                break;
            case SHUTDOWN:
                goto out;
            }
        }
    }

out:
    return NULL;
}

void lwan_readahead_init(void)
{
    int flags;

    if (readahead_pipe_fd[0] != readahead_pipe_fd[1])
        return;

    lwan_status_debug("Initializing low priority readahead thread");

    if (pipe2(readahead_pipe_fd, O_CLOEXEC | PIPE_DIRECT_FLAG) < 0) {
        lwan_status_warning("Could not create pipe for readahead queue");
        goto disable_readahead;
    }

    /* Only write side should be non-blocking. */
    flags = fcntl(readahead_pipe_fd[1], F_GETFL);
    if (flags < 0) {
        lwan_status_warning(
            "Could not get flags for readahead pipe write side");
        goto disable_readahead_close_pipe;
    }
    if (fcntl(readahead_pipe_fd[1], F_SETFL, flags | O_NONBLOCK) < 0) {
        lwan_status_warning(
            "Could not set readahead write side to be no-blocking");
        goto disable_readahead_close_pipe;
    }

    if (pthread_create(&readahead_self, NULL, lwan_readahead_loop, NULL)) {
        lwan_status_warning("Could not create low-priority readahead thread");
        goto disable_readahead_close_pipe;
    }

#ifdef SCHED_IDLE
    struct sched_param sched_param = {.sched_priority = 0};
    if (pthread_setschedparam(readahead_self, SCHED_IDLE, &sched_param) < 0)
        lwan_status_perror(
            "Could not set scheduling policy of readahead thread to idle");
#endif /* SCHED_IDLE */

    return;

disable_readahead_close_pipe:
    close(readahead_pipe_fd[0]);
    close(readahead_pipe_fd[1]);

disable_readahead:
    /* Set these to -1 just to ensure that even if the page_size check inside
     * the enqueuing functions fail, we don't write stuff to a file descriptor
     * that's not the readahead queue. */
    readahead_pipe_fd[0] = readahead_pipe_fd[1] = -1;

    /* If page_size is 0, then the enqueuing functions won't write to the pipe.
     * This way, we don't need to introduce new checks there for
     * this corner case of not being able to create/set up the pipe. */
    page_size = 0;

    lwan_status_warning("Readahead thread has been disabled");
}
