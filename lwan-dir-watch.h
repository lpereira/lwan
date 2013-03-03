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

#ifndef LWAN_DIR_WATCH_H
#define LWAN_DIR_WATCH_H

#include <stdbool.h>

typedef struct lwan_dir_watch_t_ lwan_dir_watch_t;

typedef enum {
    DIR_WATCH_ADD,
    DIR_WATCH_DEL,
    DIR_WATCH_DEL_SELF,
    DIR_WATCH_MOD
} lwan_dir_watch_event_t;

bool lwan_dir_watch_init(void);
void lwan_dir_watch_shutdown(void);

int lwan_dir_watch_get_fd(void);
lwan_dir_watch_t *lwan_dir_watch_add(const char *pathname,
                                     void (*cb)(char *name, char *root, lwan_dir_watch_event_t event, void *data),
                                     void *data);
void lwan_dir_watch_del(lwan_dir_watch_t *dw);
void lwan_dir_watch_process_events(void);

#endif
