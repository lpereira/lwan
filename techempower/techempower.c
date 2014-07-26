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

#include <stdlib.h>
#include <sqlite3.h>

#include "lwan.h"
#include "lwan-config.h"
#include "json.h"

static const char hello_world[] = "Hello, World!";

static sqlite3 *database = NULL;

static lwan_http_status_t
json_response(lwan_response_t *response, JsonNode *node)
{
    size_t length;
    char *serialized;

    serialized = json_stringify_length(node, NULL, &length);
    json_delete(node);
    if (UNLIKELY(!serialized))
        return HTTP_INTERNAL_ERROR;

    strbuf_set(response->buffer, serialized, length);
    free(serialized);

    response->mime_type = "application/json";
    return HTTP_OK;
}

static lwan_http_status_t
json(lwan_request_t *request __attribute__((unused)),
     lwan_response_t *response,
     void *data __attribute__((unused)))
{
    JsonNode *hello = json_mkobject();
    if (UNLIKELY(!hello))
        return HTTP_INTERNAL_ERROR;

    json_append_member(hello, "message", json_mkstring(hello_world));

    return json_response(response, hello);
}

static JsonNode *
db_query(void)
{
    static const char world_query[] = "SELECT randomNumber FROM World WHERE id=?";
    JsonNode *object = NULL;
    sqlite3_stmt *stmt;
    int id = rand() % 10000;

    if (UNLIKELY(sqlite3_prepare(database, world_query, sizeof(world_query) - 1,
        &stmt, NULL) != SQLITE_OK))
        return NULL;

    if (UNLIKELY(sqlite3_bind_int(stmt, 1, id) != SQLITE_OK))
        goto out;

    if (UNLIKELY(sqlite3_step(stmt) != SQLITE_ROW))
        goto out;

    object = json_mkobject();
    if (UNLIKELY(!object))
        goto out;

    json_append_member(object, "id", json_mknumber(id));
    json_append_member(object, "randomNumber",
        json_mknumber(sqlite3_column_int(stmt, 0)));

out:
    sqlite3_finalize(stmt);

    return object;
}

static lwan_http_status_t
db(lwan_request_t *request __attribute__((unused)),
   lwan_response_t *response,
   void *data __attribute__((unused)))
{
    JsonNode *object = db_query();
    if (UNLIKELY(!object))
        return HTTP_INTERNAL_ERROR;

    return json_response(response, object);
}

static lwan_http_status_t
queries(lwan_request_t *request,
        lwan_response_t *response,
        void *data __attribute__((unused)))
{
    const char *queries_str = lwan_request_get_query_param(request, "queries");

    if (UNLIKELY(!queries_str))
        return HTTP_BAD_REQUEST;

    long queries = parse_long(queries_str, -1);
    if (UNLIKELY(queries < 0))
        return HTTP_BAD_REQUEST;

    JsonNode *array = json_mkarray();
    if (UNLIKELY(!array))
        return HTTP_INTERNAL_ERROR;

    while (queries--) {
        JsonNode *object = db_query();
        
        if (UNLIKELY(!object)) {
            json_delete(array);
            return HTTP_INTERNAL_ERROR;
        }

        json_append_element(array, object);
    }

    return json_response(response, array);
}

static lwan_http_status_t
plaintext(lwan_request_t *request __attribute__((unused)),
          lwan_response_t *response,
          void *data __attribute__((unused)))
{
    strbuf_set_static(response->buffer, hello_world, sizeof(hello_world) - 1);

    response->mime_type = "text/plain";
    return HTTP_OK;
}

static void
database_init()
{
    if (sqlite3_open_v2("world.db", &database, SQLITE_OPEN_READONLY,
            NULL) != SQLITE_OK)
        lwan_status_critical("Could not open database: %s",
                             sqlite3_errmsg(database));
}

static const lwan_url_map_t url_map[] = {
    { .prefix = "/json", .callback = json },
    { .prefix = "/db", .callback = db },
    { .prefix = "/queries", .callback = queries },
    { .prefix = "/plaintext", .callback = plaintext },
    { .prefix = NULL }
};

int
main(void)
{
    lwan_t l;

    lwan_init(&l);

    srand((unsigned int)time(NULL));

    database_init();

    lwan_set_url_map(&l, url_map);
    lwan_main_loop(&l);
    lwan_shutdown(&l);

    return 0;
}
