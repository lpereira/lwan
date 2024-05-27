/*
 * lwan - web server
 * Copyright (c) 2024 L. A. F. Pereira <l@tia.mat.br>
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

/*
 * Hastily written to compare results with other languages and
 * frameworks after this Twitter thread:
 *   https://twitter.com/iSeiryu/status/1793830738153889902
 */

#include <stdbool.h>
#include <time.h>

#define ARRAY_SIZE N_ELEMENTS

#include "../techempower/json.h"
#include "lwan.h"

struct address {
    const char *street;
    const char *city;
    const char *state;
    const char *zip;
};

struct account_holder {
    const char *id;
    const char *firstName;
    const char *lastName;
    struct address address;
    const char *email;
};

struct send_money_request {
    struct account_holder from, to;
    int amount;
    const char *sendOn;
};

struct receipt {
    char *from_account;
    char *to_account;
    char *created_on;
    char *to_address;
    int amount;
};

static const struct json_obj_descr receipt_descr[] = {
    JSON_OBJ_DESCR_PRIM(struct receipt, from_account, JSON_TOK_STRING),
    JSON_OBJ_DESCR_PRIM(struct receipt, to_account, JSON_TOK_STRING),
    JSON_OBJ_DESCR_PRIM(struct receipt, amount, JSON_TOK_NUMBER),
    JSON_OBJ_DESCR_PRIM(struct receipt, created_on, JSON_TOK_STRING),
    JSON_OBJ_DESCR_PRIM(struct receipt, to_address, JSON_TOK_STRING),
};

static const struct json_obj_descr address_descr[] = {
    JSON_OBJ_DESCR_PRIM(struct address, street, JSON_TOK_STRING),
    JSON_OBJ_DESCR_PRIM(struct address, city, JSON_TOK_STRING),
    JSON_OBJ_DESCR_PRIM(struct address, state, JSON_TOK_STRING),
    JSON_OBJ_DESCR_PRIM(struct address, zip, JSON_TOK_STRING),
};

static const struct json_obj_descr account_holder_descr[] = {
    JSON_OBJ_DESCR_PRIM(struct account_holder, id, JSON_TOK_STRING),
    JSON_OBJ_DESCR_PRIM(struct account_holder, firstName, JSON_TOK_STRING),
    JSON_OBJ_DESCR_PRIM(struct account_holder, lastName, JSON_TOK_STRING),
    JSON_OBJ_DESCR_PRIM(struct account_holder, email, JSON_TOK_STRING),
    JSON_OBJ_DESCR_OBJECT(struct account_holder, address, address_descr),
};

static const struct json_obj_descr send_money_request_descr[] = {
    JSON_OBJ_DESCR_PRIM(struct send_money_request, amount, JSON_TOK_NUMBER),
    JSON_OBJ_DESCR_PRIM(struct send_money_request, sendOn, JSON_TOK_STRING),
    JSON_OBJ_DESCR_OBJECT(
        struct send_money_request, from, account_holder_descr),
    JSON_OBJ_DESCR_OBJECT(struct send_money_request, to, account_holder_descr),
};

static int append_to_strbuf(const char *bytes, size_t len, void *data)
{
    struct lwan_strbuf *strbuf = data;

    return !lwan_strbuf_append_str(strbuf, bytes, len);
}

static inline struct tm *localtime_now(void)
{
    static __thread struct tm result;
    time_t now = time(NULL);
    return localtime_r(&now, &result);
}

LWAN_HANDLER_ROUTE(send_money, "/send-money")
{
    struct send_money_request smr;
    const struct lwan_value *body;

    if (lwan_request_get_method(request) != REQUEST_METHOD_POST)
        return HTTP_BAD_REQUEST;

    body = lwan_request_get_request_body(request);
    if (!body) {
        return HTTP_BAD_REQUEST;
    }

    if (json_obj_parse(body->value, body->len, send_money_request_descr,
                       N_ELEMENTS(send_money_request_descr),
                       &smr) != (1 << 0 | 1 << 1 | 1 << 2 | 1 << 3)) {
        return HTTP_BAD_REQUEST;
    }

    char formatted_time[25];
    strftime(formatted_time, 25, "%FT%T%z", localtime_now());

    struct receipt r = {
        .from_account = coro_printf(request->conn->coro, "%s %s",
                                    smr.from.firstName, smr.from.lastName),
        .to_account = coro_printf(request->conn->coro, "%s %s",
                                  smr.to.firstName, smr.to.lastName),
        .to_address = coro_printf(request->conn->coro, "%s, %s, %s, %s",
                                  smr.to.address.street, smr.to.address.city,
                                  smr.to.address.state, smr.to.address.zip),
        .created_on = formatted_time,
        .amount = smr.amount,
    };
    if (json_obj_encode_full(receipt_descr, N_ELEMENTS(receipt_descr), &r,
                             append_to_strbuf, response->buffer, false) != 0) {
        return HTTP_INTERNAL_ERROR;
    }

    response->mime_type = "application/json";
    return HTTP_OK;
}

int main(void) { return lwan_main(); }
