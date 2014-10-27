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
#include <string.h>

#include "lwan.h"
#include "lwan-config.h"
#include "lwan-template.h"

#include "array.h"
#include "database.h"
#include "json.h"

static const char hello_world[] = "Hello, World!";

struct Fortune {
    struct {
        lwan_tpl_list_generator_t generator;

        int id;
        char *message;
    } item;
};

static const char fortunes_template_str[] = "<!DOCTYPE html>" \
"<html>" \
"<head><title>Fortunes</title></head>" \
"<body>" \
"<table>" \
"<tr><th>id</th><th>message</th></tr>" \
"{{#item}}" \
"<tr><td>{{item.id}}</td><td>{{item.message}}</td></tr>" \
"{{/item}}" \
"</table>" \
"</body>" \
"</html>";

static int fortune_list_generator(coro_t *coro);

static const lwan_var_descriptor_t fortune_item_desc[] = {
    TPL_VAR_INT(struct Fortune, item.id),
    TPL_VAR_STR_ESCAPE(struct Fortune, item.message),
    TPL_VAR_SENTINEL
};

static const lwan_var_descriptor_t fortune_desc[] = {
    TPL_VAR_SEQUENCE(struct Fortune, item,
                     fortune_list_generator, fortune_item_desc),
    TPL_VAR_SENTINEL
};

static struct db *database;
static lwan_tpl_t *fortune_tpl;

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
    struct db_stmt *stmt;
    int id = rand() % 10000;

    stmt = db_prepare_stmt(database, world_query, sizeof(world_query) - 1);
    if (UNLIKELY(!stmt))
        return NULL;

    struct db_row rows[1] = {{ .u.i = id, .kind = 'i' }};
    if (UNLIKELY(!db_stmt_bind(stmt, rows, 1)))
        goto out;

    struct db_row results[] = {{ .kind = 'i' }, { .kind = '\0' }};
    if (UNLIKELY(!db_stmt_step(stmt, results)))
        goto out;

    object = json_mkobject();
    if (UNLIKELY(!object))
        goto out;

    json_append_member(object, "id", json_mknumber(id));
    json_append_member(object, "randomNumber", json_mknumber(results[0].u.i));

out:
    db_stmt_finalize(stmt);

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
    if (UNLIKELY(queries <= 0))
        queries = 1;
    else if (UNLIKELY(queries > 500))
        queries = 500;

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

static int fortune_compare(const void *a, const void *b)
{
    const struct Fortune *fortune_a = *(const struct Fortune **)a;
    const struct Fortune *fortune_b = *(const struct Fortune **)b;
    size_t a_len = strlen(fortune_a->item.message);
    size_t b_len = strlen(fortune_b->item.message);

    if (!a_len || !b_len)
        return a_len > b_len;

    size_t min_len = a_len < b_len ? a_len : b_len;
    int cmp = memcmp(fortune_a->item.message, fortune_b->item.message, min_len);
    if (cmp == 0)
        return a_len > b_len;

    return cmp > 0;
}

static bool append_fortune(coro_t *coro, struct array *fortunes,
                           int id, const char *message)
{
    struct Fortune *fortune;

    fortune = coro_malloc(coro, sizeof(*fortune));
    if (UNLIKELY(!fortune))
        return false;

    fortune->item.id = id;
    fortune->item.message = coro_strdup(coro, message);
    if (UNLIKELY(!fortune->item.message))
        return false;

    return array_append(fortunes, fortune) >= 0;
}

static int fortune_list_generator(coro_t *coro)
{
    static const char fortune_query[] = "SELECT * FROM Fortune";
    char fortune_buffer[256];
    struct Fortune *fortune;
    struct array fortunes;
    struct db_stmt *stmt;
    size_t i;

    stmt = db_prepare_stmt(database, fortune_query, sizeof(fortune_query) - 1);
    if (UNLIKELY(!stmt))
        return 0;

    array_init(&fortunes, 16);

    struct db_row results[] = {
        { .kind = 'i' },
        { .kind = 's', .u.s = fortune_buffer, .buffer_length = sizeof(fortune_buffer) },
        { .kind = '\0' }
    };
    while (db_stmt_step(stmt, results)) {
        if (!append_fortune(coro, &fortunes, results[0].u.i, results[1].u.s))
            goto out;
    }

    if (!append_fortune(coro, &fortunes, 0,
                            "Additional fortune added at request time."))
        goto out;

    array_sort(&fortunes, fortune_compare);

    fortune = coro_get_data(coro);
    for (i = 0; i < fortunes.count; i++) {
        struct Fortune *f = fortunes.array[i];
        fortune->item.id = f->item.id;
        fortune->item.message = f->item.message;
        coro_yield(coro, 1);
    }

out:
    array_free_array(&fortunes);
    db_stmt_finalize(stmt);
    return 0;
}

static lwan_http_status_t
fortunes(lwan_request_t *request __attribute__((unused)),
         lwan_response_t *response,
         void *data __attribute__((unused)))
{
    struct Fortune fortune;

    if (UNLIKELY(!lwan_tpl_apply_with_buffer(fortune_tpl,
                                             response->buffer, &fortune)))
       return HTTP_INTERNAL_ERROR;

    response->mime_type = "text/html; charset=UTF-8";
    return HTTP_OK;
}

int
main(void)
{
    static const lwan_url_map_t url_map[] = {
        { .prefix = "/json", .handler = json },
        { .prefix = "/db", .handler = db },
        { .prefix = "/queries", .handler = queries },
        { .prefix = "/plaintext", .handler = plaintext },
        { .prefix = "/fortunes", .handler = fortunes },
        { .prefix = NULL }
    };
    lwan_t l;

    lwan_init(&l);

    srand((unsigned int)time(NULL));

    if (getenv("USE_MYSQL")) {
        const char *user = getenv("MYSQL_USER");
        const char *password = getenv("MYSQL_PASS");
        const char *hostname = getenv("MYSQL_HOST");
        const char *db = getenv("MYSQL_DB");

        if (!user)
            lwan_status_critical("No MySQL user provided");
        if (!password)
            lwan_status_critical("No MySQL password provided");
        if (!hostname)
            lwan_status_critical("No MySQL hostname provided");
        if (!db)
            lwan_status_critical("No MySQL database provided");

        database = db_connect_mysql(hostname, user, password, db);
    } else {
        const char *pragmas[] = {
            "PRAGMA mmap_size=44040192",
            "PRAGMA journal_mode=OFF",
            "PRAGMA locking_mode=EXCLUSIVE",
            NULL
        };
        database = db_connect_sqlite("techempower.db", true, pragmas);
    }

    if (!database)
        lwan_status_critical("Could not connect to the database");

    fortune_tpl = lwan_tpl_compile_string(fortunes_template_str, fortune_desc);
    if (!fortune_tpl)
        lwan_status_critical("Could not compile fortune templates");

    lwan_set_url_map(&l, url_map);
    lwan_main_loop(&l);

    lwan_tpl_free(fortune_tpl);
    db_disconnect(database);
    lwan_shutdown(&l);

    return 0;
}
