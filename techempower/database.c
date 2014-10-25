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

#include <mysql.h>
#include <sqlite3.h>
#include <stddef.h>
#include <stdlib.h>

#include "database.h"

/* MySQL */

struct db_mysql {
    struct db base;
    MYSQL *con;
};

struct db_stmt_mysql {
    struct db_stmt base;
    MYSQL_STMT *stmt;
    MYSQL_BIND *param_bind;
    MYSQL_BIND *result_bind;
};

static bool db_stmt_bind_mysql(const struct db_stmt *stmt,
        struct db_row *rows, size_t n_rows)
{
    struct db_stmt_mysql *stmt_mysql = (struct db_stmt_mysql *)stmt;

    stmt_mysql->param_bind = calloc(n_rows, sizeof(*stmt_mysql->param_bind));
    if (!stmt_mysql->param_bind)
        return false;

    for (size_t row = 0; row < n_rows; row++) {
        if (rows[row].kind == '\0') break;

        MYSQL_BIND *param = &stmt_mysql->param_bind[row];
        if (rows[row].kind == 's') {
            param->buffer_type = MYSQL_TYPE_STRING;
            param->buffer = rows[row].u.s;
        } else if (rows[row].kind == 'i') {
            param->buffer_type = MYSQL_TYPE_LONG;
            param->buffer = &rows[row].u.i;
        }
        param->is_null = false;
        param->length = 0;
    }

    return !mysql_stmt_bind_param(stmt_mysql->stmt, stmt_mysql->param_bind);
}

static bool db_stmt_step_mysql(const struct db_stmt *stmt, struct db_row *row)
{
    struct db_stmt_mysql *stmt_mysql = (struct db_stmt_mysql *)stmt;

    if (!stmt_mysql->result_bind) {
        if (mysql_stmt_execute(stmt_mysql->stmt))
            return false;

        size_t n_rows = 0;
        for (struct db_row *r = row; r->kind != '\0'; r++)
            n_rows++;

        stmt_mysql->result_bind = calloc(n_rows, sizeof(*stmt_mysql->result_bind));
        if (!stmt_mysql->result_bind)
            return false;

        stmt_mysql->param_bind = calloc(n_rows, sizeof(*stmt_mysql->param_bind));
        if (!stmt_mysql->param_bind) {
            free(stmt_mysql->param_bind);
            return false;
        }

        MYSQL_BIND *result = stmt_mysql->result_bind;
        for (size_t r = 0; r < n_rows; r++) {
            if (row[r].kind == 's') {
                result[r].buffer_type = MYSQL_TYPE_STRING;
                result[r].buffer = row[r].u.s;
            } else if (row[r].kind == 'i') {
                result[r].buffer_type = MYSQL_TYPE_LONG;
                result[r].buffer = &row[r].u.i;
            } else {
                return false;
            }

            result[r].is_null = false;
            result[r].buffer_length = row[r].buffer_length;
        }

        if (mysql_stmt_bind_result(stmt_mysql->stmt, result))
            return false;
    }

    return !mysql_stmt_fetch(stmt_mysql->stmt);
}

static void db_stmt_finalize_mysql(struct db_stmt *stmt)
{
    struct db_stmt_mysql *stmt_mysql = (struct db_stmt_mysql *)stmt;

    mysql_stmt_close(stmt_mysql->stmt);
    free(stmt_mysql->result_bind);
    free(stmt_mysql->param_bind);
    free(stmt_mysql);
}

static struct db_stmt *db_prepare_mysql(const struct db *db, const char *sql,
        const size_t sql_len)
{
    const struct db_mysql *db_mysql = (const struct db_mysql *)db;
    struct db_stmt_mysql *stmt_mysql = malloc(sizeof(*stmt_mysql));

    if (!stmt_mysql)
        return NULL;

    stmt_mysql->stmt = mysql_stmt_init(db_mysql->con);
    if (!stmt_mysql->stmt) {
        free(stmt_mysql);
        return NULL;
    }

    if (mysql_stmt_prepare(stmt_mysql->stmt, sql, sql_len)) {
        mysql_stmt_close(stmt_mysql->stmt);
        free(stmt_mysql);
        return NULL;
    }

    stmt_mysql->base.bind = db_stmt_bind_mysql;
    stmt_mysql->base.step = db_stmt_step_mysql;
    stmt_mysql->base.finalize = db_stmt_finalize_mysql;
    stmt_mysql->result_bind = NULL;
    stmt_mysql->param_bind = NULL;

    return (struct db_stmt*)stmt_mysql;
}

static void db_disconnect_mysql(struct db *db)
{
    struct db_mysql *db_mysql = (struct db_mysql *)db;

    mysql_close(db_mysql->con);
    free(db);
}

struct db *db_connect_mysql(const char *host, const char *user, const char *pass)
{
    struct db_mysql *db_mysql = malloc(sizeof(*db_mysql));

    if (!db_mysql)
        return NULL;

    db_mysql->con = mysql_init(NULL);
    if (!db_mysql->con) {
        free(db_mysql);
        return NULL;
    }

    if (!mysql_real_connect(db_mysql->con, host, user, pass, NULL, 0, NULL, 0)) {
        mysql_close(db_mysql->con);
        free(db_mysql);
        return NULL;
    }

    db_mysql->base.disconnect = db_disconnect_mysql;
    db_mysql->base.prepare = db_prepare_mysql;

    return (struct db *)db_mysql;
}

/* SQLite */

struct db_sqlite {
    struct db base;
    sqlite3 *sqlite;
};

struct db_stmt_sqlite {
    struct db_stmt base;
    sqlite3_stmt *sqlite;
};

static bool db_stmt_bind_sqlite(const struct db_stmt *stmt, struct db_row *rows, size_t n_rows)
{
    const struct db_stmt_sqlite *stmt_sqlite = (const struct db_stmt_sqlite *)stmt;
    const struct db_row *rows_1_based = rows - 1;

    for (size_t row = 1; row <= n_rows; row++) {
        const struct db_row *r = &rows_1_based[row];
        if (r->kind == '\0') break;

        if (r->kind == 's') {
            if (sqlite3_bind_text(stmt_sqlite->sqlite, (int)row, r->u.s, -1, NULL) != SQLITE_OK)
                return false;
        } else if (r->kind == 'i') {
            if (sqlite3_bind_int(stmt_sqlite->sqlite, (int)row, r->u.i) != SQLITE_OK)
                return false;
        } else {
            return false;
        }
    }

    return true;
}

static bool db_stmt_step_sqlite(const struct db_stmt *stmt, struct db_row *row)
{
    const struct db_stmt_sqlite *stmt_sqlite = (const struct db_stmt_sqlite *)stmt;

    if (sqlite3_step(stmt_sqlite->sqlite) != SQLITE_ROW)
        return false;

    int column_id = 0;
    for (struct db_row *r = row; r->kind != '\0'; r++, column_id++) {
        if (r->kind == 'i') {
            r->u.i = sqlite3_column_int(stmt_sqlite->sqlite, column_id);
        } else if (r->kind == 's') {
            r->u.s = (char *)sqlite3_column_text(stmt_sqlite->sqlite, column_id);
        } else {
            return false;
        }
    }

    return true;
}

static void db_stmt_finalize_sqlite(struct db_stmt *stmt)
{
    struct db_stmt_sqlite *stmt_sqlite = (struct db_stmt_sqlite *)stmt;

    sqlite3_finalize(stmt_sqlite->sqlite);
    free(stmt_sqlite);
}

static struct db_stmt *db_prepare_sqlite(const struct db *db, const char *sql,
        const size_t sql_len)
{
    const struct db_sqlite *db_sqlite = (const struct db_sqlite *)db;
    struct db_stmt_sqlite *stmt_sqlite = malloc(sizeof(*stmt_sqlite));

    if (!stmt_sqlite)
        return NULL;

    int ret = sqlite3_prepare(db_sqlite->sqlite, sql, (int)sql_len, &stmt_sqlite->sqlite, NULL);
    if (ret != SQLITE_OK) {
        free(stmt_sqlite);
        return NULL;
    }

    stmt_sqlite->base.bind = db_stmt_bind_sqlite;
    stmt_sqlite->base.step = db_stmt_step_sqlite;
    stmt_sqlite->base.finalize = db_stmt_finalize_sqlite;

    return (struct db_stmt *)stmt_sqlite;
}

static void db_disconnect_sqlite(struct db *db)
{
    struct db_sqlite *db_sqlite = (struct db_sqlite *)db;

    sqlite3_close(db_sqlite->sqlite);
    free(db);
}

struct db *db_connect_sqlite(const char *path, bool read_only, const char *pragmas[])
{
    struct db_sqlite *db_sqlite = malloc(sizeof(*db_sqlite));

    if (!db_sqlite)
        return NULL;

    int flags = read_only ? SQLITE_OPEN_READONLY : 0;
    int ret = sqlite3_open_v2(path, &db_sqlite->sqlite, flags, NULL);
    if (ret != SQLITE_OK) {
        free(db_sqlite);
        return NULL;
    }

    if (pragmas) {
        for (size_t p = 0; pragmas[p]; p++)
            sqlite3_exec(db_sqlite->sqlite, pragmas[p], NULL, NULL, NULL);
    }

    db_sqlite->base.disconnect = db_disconnect_sqlite;
    db_sqlite->base.prepare = db_prepare_sqlite;

    return (struct db *)db_sqlite;
}
