/*
 * lwan - web server
 * Copyright (c) 2014 L. A. F. Pereira <l@tia.mat.br>
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

#pragma once

#include <stdbool.h>

struct db;
struct db_stmt;

struct db_row {
    union {
        char *s;
        int i;
    } u;
    size_t buffer_length;
};


struct db_stmt *db_prepare_stmt_ctx(const struct db *db,
                                void *ctx,
                                const char *sql,
                                const char *param_signature,
                                const char *result_signature);

static inline struct db_stmt *db_prepare_stmt(const struct db *db,
                                              const char *sql,
                                              const char *param_signature,
                                              const char *result_signature)
{
    return db_prepare_stmt_ctx(db, NULL, sql, param_signature,
                               result_signature);
}

void db_stmt_finalize(struct db_stmt *stmt);

bool db_stmt_bind(const struct db_stmt *stmt, struct db_row *rows);
bool db_stmt_step(const struct db_stmt *stmt, ...);

struct db *db_connect_sqlite(const char *path,
                             bool read_only,
                             const char *pragmas[]);
struct db *db_connect_mysql(const char *host,
                            const char *user,
                            const char *pass,
                            const char *database);
void db_disconnect(struct db *db);
