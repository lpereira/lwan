/*
 * lwan - simple web server
 * Copyright (c) 2012 Leandro A. F. Pereira <leandro@hardinfo.org>
 *
 * SQL query is copied from freegeoip.go
 * Copyright (c) 2013 Alexandre Fiori
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

#define _BSD_SOURCE
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <sqlite3.h>
#include "lwan.h"
#include "lwan-serve-files.h"
#include "memcache.h"

struct ip_info_t {
    struct {
        char *code;
        char *name;
    } country, region;
    struct {
        char *name;
        char *zip_code;
    } city;
    double latitude, longitude;
    struct {
        char *code, *area;
    } metro;
};

static memcache_t *mc;
static sqlite3 *db;
static const char const ip_to_city_query[] = \
    "SELECT " \
    "   city_location.country_code, country_blocks.country_name," \
    "   city_location.region_code, region_names.region_name," \
    "   city_location.city_name, city_location.postal_code," \
    "   city_location.latitude, city_location.longitude," \
    "   city_location.metro_code, city_location.area_code " \
    "FROM city_blocks " \
    "   NATURAL JOIN city_location " \
    "   INNER JOIN country_blocks ON " \
    "      city_location.country_code = country_blocks.country_code " \
    "   INNER JOIN region_names ON " \
    "      city_location.country_code = region_names.country_code " \
    "      AND " \
    "      city_location.region_code = region_names.region_code " \
    "WHERE city_blocks.ip_start <= ? " \
    "ORDER BY city_blocks.ip_start DESC LIMIT 1";


static void
free_ip_info_t(void *data)
{
    struct ip_info_t *ip_info = data;

    if (!ip_info)
        return;

    free(ip_info->country.code);
    free(ip_info->country.name);
    free(ip_info->region.code);
    free(ip_info->region.code);
    free(ip_info->city.name);
    free(ip_info->city.zip_code);
    free(ip_info->metro.code);
    free(ip_info->metro.area);
    free(ip_info);
}

static ALWAYS_INLINE char *
text_column_helper(sqlite3_stmt *stmt, int index)
{
    const unsigned char *value;

    value = sqlite3_column_text(stmt, index);
    return value ? strdup((char *)value) : NULL;
}

static struct ip_info_t *
geoip_query(unsigned int ip)
{
    sqlite3_stmt *stmt;
    struct ip_info_t *ip_info;
    
    ip_info = NULL;

    if (sqlite3_prepare(db, ip_to_city_query,
                        sizeof(ip_to_city_query) - 1,
                        &stmt, NULL) != SQLITE_OK)
        goto end_no_finalize;

    if (sqlite3_bind_int64(stmt, 1, ntohl(ip)) != SQLITE_OK)
        goto end;

    if (sqlite3_step(stmt) != SQLITE_ROW)
        goto end;

    ip_info = malloc(sizeof(*ip_info));
    if (!ip_info)
        goto end;

#define TEXT_COLUMN(index) text_column_helper(stmt, index)

    ip_info->country.code = TEXT_COLUMN(0);
    ip_info->country.name = TEXT_COLUMN(1);
    ip_info->region.code = TEXT_COLUMN(2);
    ip_info->region.name = TEXT_COLUMN(3);
    ip_info->city.name = TEXT_COLUMN(4);
    ip_info->city.zip_code = TEXT_COLUMN(5);
    ip_info->latitude = sqlite3_column_double(stmt, 6);
    ip_info->longitude = sqlite3_column_double(stmt, 7);
    ip_info->metro.code = TEXT_COLUMN(8);
    ip_info->metro.area = TEXT_COLUMN(9);

#undef TEXT_COLUMN

end:
    sqlite3_finalize(stmt);
end_no_finalize:
    return ip_info;
}

static struct ip_info_t *
internal_query(lwan_request_t *request)
{
    struct ip_info_t *info;
    const char *ip_address;
    struct in_addr addr;

    if (request->url.len == 0)
        ip_address = lwan_request_get_remote_address(request,
                                                     request->buffer,
                                                     INET_ADDRSTRLEN);
    else if (request->url.len < 7)
        ip_address = NULL;
    else
        ip_address = request->url.value;
    if (UNLIKELY(!ip_address))
        return NULL;

    if (UNLIKELY(!inet_aton(ip_address, &addr)))
        return NULL;

    info = memcache_get(mc, (void *)(unsigned long)addr.s_addr);
    if (!info) {
        info = geoip_query(addr.s_addr);
        if (!info)
            return NULL;

        memcache_put(mc, (void *)(unsigned long)addr.s_addr, info);
    }

    return info;
}

static lwan_http_status_t
as_json(lwan_request_t *request,
        lwan_response_t *response,
        void *data __attribute__((unused)))
{
    struct ip_info_t *info;

    info = internal_query(request);
    if (!info)
        return HTTP_NOT_FOUND;

    response->mime_type = "text/plain";
    strbuf_printf(response->buffer,
        "{" \
        "\"country_code\":\"%s\"," \
        "\"country_name\":\"%s\"," \
        "\"region_code\":\"%s\"," \
        "\"region_name\":\"%s\"," \
        "\"city\":\"%s\"," \
        "\"zipcode\":\"%s\"," \
        "\"latitude\":%f," \
        "\"longitude\":%f," \
        "\"metro_code\":\"%s\"," \
        "\"areacode\":\"%s\"" \
        "}",
            info->country.code,
            info->country.name,
            info->region.code,
            info->region.name,
            info->city.name,
            info->city.zip_code,
            info->latitude,
            info->longitude,
            info->metro.code,
            info->metro.area);

    return HTTP_OK;
}

int
main(void)
{
    lwan_url_map_t default_map[] = {
        { .prefix = "/json/", .callback = as_json },
        { .prefix = "/", SERVE_FILES("./static") },
        { .prefix = NULL }
    };

    lwan_t l = {
        .config = {
            .port = 8080,
            .keep_alive_timeout = 15 /*seconds */
        }
    };

    int result = sqlite3_open_v2("./db/ipdb.sqlite", &db,
                                 SQLITE_OPEN_READONLY, NULL);
    if (result != SQLITE_OK) {
        fprintf(stderr, "Could not open database: %s\n",
                    sqlite3_errstr(result));
        return 1;
    }

    mc = memcache_new_int32(256, free_ip_info_t);

    lwan_init(&l);
    lwan_set_url_map(&l, default_map);
    lwan_main_loop(&l);
    lwan_shutdown(&l);

    memcache_free(mc);
    sqlite3_close(db);

    return 0;
}
