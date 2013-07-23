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
#include "lwan-cache.h"
#include "lwan-serve-files.h"
#include "lwan-template.h"

struct ip_info_t {
    struct cache_entry_t base;
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
    char *ip;
};

union ip_to_octet {
    unsigned char octet[sizeof(in_addr_t)];
    in_addr_t ip;
};

struct ip_net_t {
    union ip_to_octet ip;
    union ip_to_octet mask;
};

static struct cache_t *cache;
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

static const char const json_template_str[] = \
    "{" \
    "\"country_code\":\"{{country.code}}\"," \
    "\"country_name\":\"{{country.name}}\"," \
    "\"region_code\":\"{{region.code}}\"," \
    "\"region_name\":\"{{region.name}}\"," \
    "\"city\":\"{{city.name}}\"," \
    "\"zipcode\":\"{{city.zip_code}}\"," \
    "\"latitude\":{{latitude}}," \
    "\"longitude\":{{longitude}}," \
    "\"metro_code\":\"{{metro.code}}\"," \
    "\"areacode\":\"{{metro.area}}\"," \
    "\"ip\":\"{{ip}}\"" \
    "}";

static const char const xml_template_str[] = \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" \
    "<Response>" \
    "<Ip>{{ip}}</Ip>" \
    "<CountryCode>{{country.code}}</CountryCode>" \
    "<CountryName>{{country.name}}</CountryName>" \
    "<RegionCode>{{region.code}}</RegionCode>" \
    "<RegionName>{{region.name}}</RegionName>" \
    "<City>{{city.name}}</City>" \
    "<ZipCode>{{city.zip_code}}</ZipCode>" \
    "<Latitude>{{latitude}}</Latitude>" \
    "<Longitude>{{longitude}}</Longitude>" \
    "<MetroCode>{{metro.code}}</MetroCode>" \
    "<AreaCode>{{metro.area}}</AreaCode>" \
    "</Response>";

static const char const csv_template_str[] = \
    "\"{{ip}}\"," \
    "\"{{country.code}}\"," \
    "\"{{country.name}}\"," \
    "\"{{region.code}}\"," \
    "\"{{region.name}}\"," \
    "\"{{city.name}}\","
    "\"{{city.zip_code}}\"," \
    "\"{{latitude}}\"," \
    "\"{{longitude}}\"," \
    "\"{{metro.code}}\"," \
    "\"{{metro.area}}\"";

/* http://en.wikipedia.org/wiki/Reserved_IP_addresses */
#define ADDRESS(o1, o2, o3, o4) \
    { .octet[0] = o1, .octet[1] = o2, .octet[2] = o3, .octet[3] = o4 }

static const struct ip_net_t reserved_ips[] = {
    {ADDRESS(0, 0, 0, 0), ADDRESS(255, 0, 0, 0)},
    {ADDRESS(10, 0, 0, 0), ADDRESS(255, 0, 0, 0)},
    {ADDRESS(100, 64, 0, 0), ADDRESS(255, 192, 0, 0)},
    {ADDRESS(127, 0, 0, 0), ADDRESS(255, 0, 0, 0)},
    {ADDRESS(169, 254, 0, 0), ADDRESS(255, 255, 0, 0)},
    {ADDRESS(172, 16, 0, 0), ADDRESS(255, 240, 0, 0)},
    {ADDRESS(192, 0, 0, 0), ADDRESS(255, 255, 255, 248)},
    {ADDRESS(192, 0, 2, 0), ADDRESS(255, 255, 255, 0)},
    {ADDRESS(192, 88, 99, 0), ADDRESS(255, 255, 255, 0)},
    {ADDRESS(192, 168, 0, 0), ADDRESS(255, 255, 0, 0)},
    {ADDRESS(198, 18, 0, 0), ADDRESS(255, 254, 0, 0)},
    {ADDRESS(198, 51, 100, 0), ADDRESS(255, 255, 255, 0)},
    {ADDRESS(203, 0, 113, 0), ADDRESS(255, 255, 255, 0)},
    {ADDRESS(224, 0, 0, 0), ADDRESS(240, 0, 0, 0)},
    {ADDRESS(240, 0, 0, 0), ADDRESS(240, 0, 0, 0)},
    {ADDRESS(255, 255, 255, 255), ADDRESS(255, 255, 255, 255)},
};

#undef ADDRESS

static lwan_tpl_t *json_template = NULL;
static lwan_tpl_t *xml_template = NULL;
static lwan_tpl_t *csv_template = NULL;

static bool
net_contains_ip(const struct ip_net_t *net, in_addr_t ip)
{
    union ip_to_octet _ip = { .ip = ip };
    return (net->ip.octet[0] & net->mask.octet[0]) == (_ip.octet[0] & net->mask.octet[0]) && \
        (net->ip.octet[1] & net->mask.octet[1]) == (_ip.octet[1] & net->mask.octet[1]) && \
        (net->ip.octet[2] & net->mask.octet[2]) == (_ip.octet[2] & net->mask.octet[2]) && \
        (net->ip.octet[3] & net->mask.octet[3]) == (_ip.octet[3] & net->mask.octet[3]);
}

static bool
is_reserved_ip(in_addr_t ip)
{
    size_t i;
    for (i = 0; i < (sizeof(reserved_ips) / sizeof(reserved_ips[0])); i++) {
        if (net_contains_ip(&reserved_ips[i], ip))
            return true;
    }
    return false;
}

static void
destroy_ipinfo(struct cache_entry_t *entry,
            void *context __attribute__((unused)))
{
    struct ip_info_t *ip_info = (struct ip_info_t *)entry;

    if (!ip_info)
        return;

    free(ip_info->country.code);
    free(ip_info->country.name);
    free(ip_info->region.code);
    free(ip_info->region.name);
    free(ip_info->city.name);
    free(ip_info->city.zip_code);
    free(ip_info->metro.code);
    free(ip_info->metro.area);
    free(ip_info->ip);
    free(ip_info);
}

static ALWAYS_INLINE char *
text_column_helper(sqlite3_stmt *stmt, int index)
{
    const unsigned char *value;

    value = sqlite3_column_text(stmt, index);
    return value ? strdup((char *)value) : NULL;
}

static struct cache_entry_t *
create_ipinfo(const char *key, void *context __attribute__((unused)))
{
    sqlite3_stmt *stmt;
    struct ip_info_t *ip_info = NULL;
    struct in_addr addr;
    
    if (UNLIKELY(!inet_aton(key, &addr)))
        goto end;

    if (is_reserved_ip(addr.s_addr)) {
        ip_info = calloc(1, sizeof(*ip_info));
        if (LIKELY(ip_info)) {
            ip_info->country.code = strdup("RD");
            ip_info->country.name = strdup("Reserved");
            ip_info->ip = strdup(key);
        }
        goto end_no_finalize;
    }

    if (sqlite3_prepare(db, ip_to_city_query,
                        sizeof(ip_to_city_query) - 1,
                        &stmt, NULL) != SQLITE_OK)
        goto end_no_finalize;

    if (sqlite3_bind_int64(stmt, 1, ntohl(addr.s_addr)) != SQLITE_OK)
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

    ip_info->ip = strdup(key);

end:
    sqlite3_finalize(stmt);
end_no_finalize:
    return (struct cache_entry_t *)ip_info;
}

static struct ip_info_t *
internal_query(lwan_request_t *request)
{
    const char *ip_address;

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

    int error;
    return (struct ip_info_t *)cache_get_and_ref_entry(cache, ip_address, &error);
}

static lwan_http_status_t
templated_output(lwan_request_t *request,
                 lwan_response_t *response,
                 void *data)
{
    struct ip_info_t *info = internal_query(request);
    if (LIKELY(info)) {
        lwan_tpl_t *tpl = data;

        if (data == json_template)
            response->mime_type = "application/json; charset=UTF-8";
        else if (data == xml_template)
            response->mime_type = "application/xml; charset=UTF-8";
        else
            response->mime_type = "text/plain; charset=UTF-8";

        lwan_tpl_apply_with_buffer(tpl, response->buffer, info);
        cache_entry_unref(cache, &info->base);

        return HTTP_OK;
    }

    return HTTP_NOT_FOUND;
}

int
main(void)
{
    static lwan_var_descriptor_t template_descriptor[] = {
        TPL_VAR_STR(struct ip_info_t, country.code),
        TPL_VAR_STR(struct ip_info_t, country.name),
        TPL_VAR_STR(struct ip_info_t, region.code),
        TPL_VAR_STR(struct ip_info_t, region.name),
        TPL_VAR_STR(struct ip_info_t, city.name),
        TPL_VAR_STR(struct ip_info_t, city.zip_code),
        TPL_VAR_DOUBLE(struct ip_info_t, latitude),
        TPL_VAR_DOUBLE(struct ip_info_t, longitude),
        TPL_VAR_STR(struct ip_info_t, metro.code),
        TPL_VAR_STR(struct ip_info_t, metro.area),
        TPL_VAR_STR(struct ip_info_t, ip),
        TPL_VAR_SENTINEL
    };

    json_template = lwan_tpl_compile_string(json_template_str, template_descriptor);
    if (!json_template)
        lwan_status_critical("Could not compile JSON template");
    xml_template = lwan_tpl_compile_string(xml_template_str, template_descriptor);
    if (!xml_template)
        lwan_status_critical("Could not compile XML template");
    csv_template = lwan_tpl_compile_string(csv_template_str, template_descriptor);
    if (!csv_template)
        lwan_status_critical("Could not compile CSV template");

    lwan_t l = {
        .config = {
            .port = 8080,
            .keep_alive_timeout = 15 /*seconds */
        }
    };

    lwan_init(&l);

    int result = sqlite3_open_v2("./db/ipdb.sqlite", &db,
                                 SQLITE_OPEN_READONLY, NULL);
    if (result != SQLITE_OK)
        lwan_status_critical("Could not open database: %s",
                    sqlite3_errstr(result));
    cache = cache_create(create_ipinfo, destroy_ipinfo, NULL, 10);

    lwan_url_map_t default_map[] = {
        { .prefix = "/json/", .callback = templated_output, .data = json_template },
        { .prefix = "/xml/", .callback = templated_output, .data = xml_template },
        { .prefix = "/csv/", .callback = templated_output, .data = csv_template },
        { .prefix = "/", SERVE_FILES("./static") },
        { .prefix = NULL }
    };

    lwan_set_url_map(&l, default_map);
    lwan_main_loop(&l);
    lwan_shutdown(&l);

    unsigned hits, misses, evictions;
    cache_get_stats(cache, &hits, &misses, &evictions);
    lwan_status_info("Cache stats: %d hits, %d misses, %d evictions",
            hits, misses, evictions);

    lwan_tpl_free(json_template);
    lwan_tpl_free(xml_template);
    lwan_tpl_free(csv_template);
    cache_destroy(cache);
    sqlite3_close(db);

    return 0;
}
