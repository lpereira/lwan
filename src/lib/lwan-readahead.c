/*
 * lwan - simple web server
 * Copyright (c) 2018 Leandro A. F. Pereira <leandro@hardinfo.org>
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

#include "lwan-private.h"

struct lwan_readahead_cmd {
    size_t size;
    int fd;
} __attribute__((packed));

static int readahead_pipe_fd[2];
static pthread_t readahead_self;

void lwan_readahead_shutdown(void)
{
    unsigned char quit_cmd = 0;

    if (readahead_pipe_fd[0] != readahead_pipe_fd[1]) {
        lwan_status_debug("Shutting down readahead thread");

        /* Writing only 1 byte will signal the thread to end. */
        write(readahead_pipe_fd[1], &quit_cmd, sizeof(quit_cmd));
        pthread_join(readahead_self, NULL);

        close(readahead_pipe_fd[0]);
        close(readahead_pipe_fd[1]);
        readahead_pipe_fd[0] = readahead_pipe_fd[1] = 0;
    }
}

void lwan_readahead_queue(int fd, size_t size)
{
    struct lwan_readahead_cmd cmd = {.size = size, .fd = fd};

    /* Readahead is just a hint.  Failing to write is not an error. */
    write(readahead_pipe_fd[1], &cmd, sizeof(cmd));
}

static void *lwan_readahead_loop(void *data __attribute__((unused)))
{
    /* Idle priority for the calling thread.   Magic value of `7` obtained from
     * sample program in linux/Documentation/block/ioprio.txt.  This is a no-op
     * on anything but Linux.  */
    ioprio_set(IOPRIO_WHO_PROCESS, 0, IOPRIO_PRIO_VALUE(IOPRIO_CLASS_IDLE, 7));

    while (true) {
        struct lwan_readahead_cmd cmd;
        ssize_t n_bytes = read(readahead_pipe_fd[0], &cmd, sizeof(cmd));

        if (LIKELY(n_bytes == (ssize_t)sizeof(cmd))) {
            lwan_status_debug("Got request to readahead fd %d, size %zu",
                              cmd.fd, cmd.size);
            readahead(cmd.fd, 0, cmd.size);
        } else if (UNLIKELY(n_bytes == 1)) {
            /* Shutdown request received. */
            break;
        }
    }

    return NULL;
}

void lwan_readahead_init(void)
{
    int flags;

    if (readahead_pipe_fd[0] != readahead_pipe_fd[1])
        return;

    lwan_status_debug("Initializing low priority readahead thread");

    if (pipe2(readahead_pipe_fd, O_CLOEXEC) < 0)
        lwan_status_critical_perror("pipe2");

    /* Only write side should be non-blocking. */
    flags = fcntl(readahead_pipe_fd[1], F_GETFL);
    if (flags < 0)
        lwan_status_critical_perror("fcntl");
    if (fcntl(readahead_pipe_fd[1], F_SETFL, flags | O_NONBLOCK) < 0)
        lwan_status_critical_perror("fcntl");

    if (pthread_create(&readahead_self, NULL, lwan_readahead_loop, NULL))
        lwan_status_critical_perror("pthread_create");

#ifdef SCHED_IDLE
    struct sched_param sched_param = {.sched_priority = 0};
    if (pthread_setschedparam(readahead_self, SCHED_IDLE, &sched_param) < 0)
        lwan_status_perror("pthread_setschedparam");
#endif /* SCHED_IDLE */
}
