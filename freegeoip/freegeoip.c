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

#define _DEFAULT_SOURCE
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <sqlite3.h>

#include "lwan.h"
#include "lwan-cache.h"
#include "lwan-mod-serve-files.h"
#include "lwan-template.h"

/* Set to 0 to disable */
#define QUERIES_PER_HOUR 10000

struct ip_info {
    struct cache_entry base;
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
    const char *callback;
};

struct template_mime {
    struct lwan_tpl *tpl;
    const char *mime_type;
};

static const struct lwan_var_descriptor template_descriptor[] = {
    TPL_VAR_STR(struct ip_info, country.code),
    TPL_VAR_STR(struct ip_info, country.name),
    TPL_VAR_STR(struct ip_info, region.code),
    TPL_VAR_STR(struct ip_info, region.name),
    TPL_VAR_STR(struct ip_info, city.name),
    TPL_VAR_STR(struct ip_info, city.zip_code),
    TPL_VAR_DOUBLE(struct ip_info, latitude),
    TPL_VAR_DOUBLE(struct ip_info, longitude),
    TPL_VAR_STR(struct ip_info, metro.code),
    TPL_VAR_STR(struct ip_info, metro.area),
    TPL_VAR_STR(struct ip_info, ip),
    TPL_VAR_STR(struct ip_info, callback),
    TPL_VAR_SENTINEL
};

static const char json_template_str[] = \
    "{{callback?}}{{callback}}({{/callback?}}" \
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
    "}"
    "{{callback?}});{{/callback?}}";

static const char xml_template_str[] = \
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

static const char csv_template_str[] = \
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


static const char ip_to_city_query[] = \
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


union ip_to_octet {
    unsigned char octet[sizeof(in_addr_t)];
    in_addr_t ip;
};

struct ip_net {
    union ip_to_octet ip;
    union ip_to_octet mask;
};

/* http://en.wikipedia.org/wiki/Reserved_IP_addresses */
#define ADDRESS(o1, o2, o3, o4) \
    { .octet[0] = o1, .octet[1] = o2, .octet[2] = o3, .octet[3] = o4 }

static const struct ip_net reserved_ips[] = {
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


#if QUERIES_PER_HOUR != 0
struct query_limit {
    struct cache_entry base;
    unsigned queries;
};

static struct cache *query_limit;
#endif

static struct cache *cache = NULL;
static sqlite3 *db = NULL;

static bool
net_contains_ip(const struct ip_net *net, in_addr_t ip)
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
    for (i = 0; i < N_ELEMENTS(reserved_ips); i++) {
        if (net_contains_ip(&reserved_ips[i], ip))
            return true;
    }
    return false;
}

static void
destroy_ipinfo(struct cache_entry *entry,
            void *context __attribute__((unused)))
{
    struct ip_info *ip_info = (struct ip_info *)entry;

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
text_column_helper(sqlite3_stmt *stmt, int ind)
{
    const unsigned char *value;

    value = sqlite3_column_text(stmt, ind);
    return value ? strdup((char *)value) : NULL;
}

static struct cache_entry *
create_ipinfo(const char *key, void *context __attribute__((unused)))
{
    sqlite3_stmt *stmt;
    struct ip_info *ip_info = NULL;
    struct in_addr addr;

    if (UNLIKELY(!inet_aton(key, &addr)))
        goto end_no_finalize;

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
    return (struct cache_entry *)ip_info;
}

#if QUERIES_PER_HOUR != 0
static struct cache_entry *
create_query_limit(const char *key __attribute__((unused)),
            void *context __attribute__((unused)))
{
    struct query_limit *entry = malloc(sizeof(*entry));
    if (LIKELY(entry))
        entry->queries = 0;
    return (struct cache_entry *)entry;
}

static void
destroy_query_limit(struct cache_entry *entry,
            void *context __attribute__((unused)))
{
    free(entry);
}
#endif

static struct ip_info *
internal_query(struct lwan_request *request, const char *ip_address)
{
    const char *query;

    if (request->url.len == 0)
        query = ip_address;
    else if (request->url.len < 7)
        query = NULL;
    else
        query = request->url.value;
    if (UNLIKELY(!query))
        return NULL;

    return (struct ip_info *)cache_coro_get_and_ref_entry(cache,
                request->conn->coro, query);
}

#if QUERIES_PER_HOUR != 0
static bool is_rate_limited(const char *ip_address)
{
    bool limited;
    int error;
    struct query_limit *limit;

    limit = (struct query_limit *)
                cache_get_and_ref_entry(query_limit, ip_address, &error);
    if (!limit)
        return true;

    limited = ATOMIC_AAF(&limit->queries, 1) > QUERIES_PER_HOUR;
    cache_entry_unref(query_limit, &limit->base);

    return limited;
}
#endif

static enum lwan_http_status
templated_output(struct lwan_request *request,
                 struct lwan_response *response,
                 void *data)
{
    const struct template_mime *tm = data;
    const char *ip_address;
    struct ip_info *info;
    char ip_address_buf[INET6_ADDRSTRLEN];

    ip_address = lwan_request_get_remote_address(request, ip_address_buf);
    if (UNLIKELY(!ip_address))
        return HTTP_INTERNAL_ERROR;

#if QUERIES_PER_HOUR != 0
    if (UNLIKELY(is_rate_limited(ip_address)))
        return HTTP_FORBIDDEN;
#endif

    info = internal_query(request, ip_address);
    if (UNLIKELY(!info))
        return HTTP_NOT_FOUND;

    const char *callback = lwan_request_get_query_param(request, "callback");
    struct ip_info info_with_callback = *info;
    info_with_callback.callback = callback;

    lwan_tpl_apply_with_buffer(tm->tpl, response->buffer,
                &info_with_callback);
    response->mime_type = tm->mime_type;

    return HTTP_OK;
}

static struct template_mime
compile_template(const char *template, const char *mime_type)
{
    struct lwan_tpl *tpl = lwan_tpl_compile_string(template, template_descriptor);

    if (!tpl) {
        lwan_status_critical("Could not compile template for mime-type %s",
            mime_type);
    }

    return (struct template_mime) { .tpl = tpl, .mime_type = mime_type };
}

int
main(void)
{
    struct lwan l;

    lwan_init(&l);

    struct template_mime json_tpl = compile_template(json_template_str,
        "application/json; charset=UTF-8");
    struct template_mime csv_tpl = compile_template(csv_template_str,
        "application/csv; charset=UTF-8");
    struct template_mime xml_tpl = compile_template(xml_template_str,
        "text/plain; charset=UTF-8");

    int result = sqlite3_open_v2("./db/ipdb.sqlite", &db,
                                 SQLITE_OPEN_READONLY, NULL);
    if (result != SQLITE_OK)
        lwan_status_critical("Could not open database: %s",
                    sqlite3_errmsg(db));
    cache = cache_create(create_ipinfo, destroy_ipinfo, NULL, 10);

#if QUERIES_PER_HOUR != 0
    lwan_status_info("Limiting to %d queries per hour per client",
                QUERIES_PER_HOUR);
    query_limit = cache_create(create_query_limit,
                destroy_query_limit, NULL, 3600);
#else
    lwan_status_info("Rate-limiting disabled");
#endif

    const struct lwan_url_map default_map[] = {
        { .prefix = "/json/", .handler = templated_output, .data = &json_tpl },
        { .prefix = "/xml/", .handler = templated_output, .data = &xml_tpl },
        { .prefix = "/csv/", .handler = templated_output, .data = &csv_tpl },
        { .prefix = "/", SERVE_FILES("./static") },
        { .prefix = NULL }
    };

    lwan_set_url_map(&l, default_map);
    lwan_main_loop(&l);
    lwan_shutdown(&l);

    lwan_tpl_free(json_tpl.tpl);
    lwan_tpl_free(xml_tpl.tpl);
    lwan_tpl_free(csv_tpl.tpl);
#if QUERIES_PER_HOUR != 0
    cache_destroy(query_limit);
#endif
    cache_destroy(cache);
    sqlite3_close(db);

    return 0;
}
