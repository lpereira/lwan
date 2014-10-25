/*
 * lwan - simple web server
 * Copyright (c) 2014 Leandro A. F. Pereira <leandro@hardinfo.org>
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

#ifndef __DATABASE_H__
#define __DATABASE_H__

#include <stdbool.h>

struct db_row {
    union {
        char *s;
        int i;
    } u;
    char kind; /* 's' = string, 'i' = 'int', '\0' = last */
    size_t buffer_length;
};

struct db_stmt {
    bool (*bind)(const struct db_stmt *stmt, struct db_row *rows, size_t n_rows);
    bool (*step)(const struct db_stmt *stmt, struct db_row *row);
    void (*finalize)(struct db_stmt *stmt);
};

struct db {
    void (*disconnect)(struct db *db);
    struct db_stmt *(*prepare)(const struct db *db, const char *sql, const size_t sql_len);
};

struct db *db_connect_sqlite(const char *path, bool read_only, const char *pragmas[]);
struct db *db_connect_mysql(const char *host, const char *user, const char *pass, const char *database);

#endif /* __DATABASE_H__ */
