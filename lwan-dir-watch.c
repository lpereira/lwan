/*
 * lwan - simple web server
 * Copyright (c) 2012 Leandro A. F. Pereira <leandro@hardinfo.org>
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

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <unistd.h>

#include "lwan.h"
#include "lwan-dir-watch.h"
#include "hash.h"

struct dir_watch_priv {
    int fd;
    struct hash *wd_table;
    int init_count;
};

static struct dir_watch_priv self = {
    .init_count = 0
};

struct lwan_dir_watch_t_ {
   void (*cb)(char *name, char *root, lwan_dir_watch_event_t event, void *data);
   void *data;
   char *path;
   int wd;
};

bool
lwan_dir_watch_init()
{
    if (self.init_count)
        goto increment_init_count;

    self.fd = inotify_init1(IN_NONBLOCK);
    if (self.fd < 0)
        return false;

    self.wd_table = hash_int_new(128, NULL, NULL);
    if (!self.wd_table) {
        close(self.fd);
        return false;
    }

increment_init_count:
    ++self.init_count;
    return true;
}

void
lwan_dir_watch_shutdown()
{
    if (--self.init_count)
        return;

    close(self.fd);
    hash_free(self.wd_table);
}

int
lwan_dir_watch_get_fd()
{
    return self.fd;
}

lwan_dir_watch_t *
lwan_dir_watch_add(const char *pathname,
                   void (*cb)(char *name, char *root, lwan_dir_watch_event_t event, void *data),
                   void *data)
{
    lwan_dir_watch_t *dw;

    if (UNLIKELY(!cb))
        return NULL;

    dw = calloc(1, sizeof(*dw));
    if (UNLIKELY(!dw))
        return NULL;

    dw->wd = inotify_add_watch(self.fd, pathname,
            IN_CREATE | IN_DELETE | IN_DELETE_SELF | IN_MODIFY);
    if (UNLIKELY(dw->wd < 0)) {
        free(dw);
        return NULL;
    }

    dw->cb = cb;
    dw->data = data;
    dw->path = strdup(pathname);

    hash_add(self.wd_table, (const void *)(long)dw->wd, dw);

    return dw;
}

void
lwan_dir_watch_del(lwan_dir_watch_t *dw)
{
    hash_del(self.wd_table, (const void *)(long)dw->wd);
    inotify_rm_watch(self.fd, dw->wd);
    free(dw->path);
    free(dw);
}

void
lwan_dir_watch_process_events()
{
    struct inotify_event events[16];
    struct inotify_event *event = events;
    ssize_t length;

    length = read(self.fd, events, sizeof(events));
    if (UNLIKELY(length <= 0))
        return;

    do {
        lwan_dir_watch_t *dw = hash_find(self.wd_table, (const void *)(long)event->wd);

        if (!dw)
            goto next_event;

        if (event->mask & IN_CREATE)
            dw->cb(event->name, dw->path, DIR_WATCH_ADD, dw->data);
        else if (event->mask & IN_DELETE)
            dw->cb(event->name, dw->path, DIR_WATCH_DEL, dw->data);
        else if (event->mask & IN_MODIFY)
            dw->cb(event->name, dw->path, DIR_WATCH_MOD, dw->data);
        else if (event->mask & IN_DELETE_SELF)
            lwan_dir_watch_del(dw);

next_event:
        ++event;
    } while (length -= sizeof(struct inotify_event));
}
