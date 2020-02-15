/*
 * lwan - simple web server
 * Copyright (c) 2020 Leandro A. F. Pereira <leandro@hardinfo.org>
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

#include <stdlib.h>
#include <pthread.h>

#include "lwan.h"
#include "hash.h"
#include "ringbuffer.h"
#include "../techempower/json.h"

struct sync_map {
    struct hash *table;
    pthread_mutex_t mutex;
};

#define SYNC_MAP_INITIALIZER(free_key_func_, free_value_func_)                 \
    (struct sync_map)                                                          \
    {                                                                          \
        .mutex = PTHREAD_MUTEX_INITIALIZER,                                    \
        .table = hash_str_new(free_key_func_, free_value_func_)                \
    }

DEFINE_RING_BUFFER_TYPE(msg_ring_buffer, char *, 32)
struct msg_ring {
    struct msg_ring_buffer rb;
    pthread_mutex_t mutex;
};

#define MSG_RING_INITIALIZER                                                   \
    (struct msg_ring) { .mutex = PTHREAD_MUTEX_INITIALIZER }

struct available_transport {
    const char *transport;
    const char *transferFormats[4];
    size_t numTransferFormats;
};
static const struct json_obj_descr available_transport_descr[] = {
    JSON_OBJECT_DESCR_PRIM(struct available_transport, transport, JSON_TOK_STRING),
    JSON_OBJECT_DESCR_ARRAY(struct available_transport,
                            transferFormats,
                            1,
                            numTransferFormats,
                            JSON_TOK_STRING),
};

struct negotiate_response {
    const char *connectionId;
    struct available_transports availableTransports[4];
    size_t numAvailableTransports;
};
static const struct json_obj_descr negotiate_response_descr[] = {
    JSON_OBJ_DESCR_PRIM(struct negotiate_response, connectionId, JSON_TOK_STRING),
    JSON_OBJ_DESCR_OBJ_ARRAY(struct negotiate_response,
                             availableTransports,
                             4,
                             numAvailableTransports,
                             available_transport_descr,
                             ARRAY_SIZE(available_transport_descr)),
};

struct handshake_request {
    const char *protocol;
    int version;
};
static const struct json_obj_descr handshake_request_descr[] = {
    JSON_OBJ_DESCR_PRIM(struct handshake_request, protocol, JSON_TOK_STRING),
    JSON_OBJ_DESCR_PRIM(struct handshake_request, versoin, JSON_TOK_NUMBER),
};

struct message {
    int type;
};
static const struct json_obj_descr message_descr[] = {
    JSON_OBJ_DESCR_PRIM(struct message, type, JSON_TOK_NUMBER),
};

struct invocation_message {
    int type;
    const char *target;
    const char *invocationId;
    const char *arguments[10];
    size_t numArguments;
};
static const struct json_obj_descr invocation_message[] = {
    JSON_OBJ_DESCR_PRIM(struct invocation_message, target, JSON_TOK_STRING),
    JSON_OBJ_DESCR_PRIM(struct invocation_message, invocationId, JSON_TOK_STRING),
    JSON_OBJ_DESCR_ARRAY(struct invocation_message,
                         arguments,
                         10,
                         numArguments,
                         JSON_TOK_STRING),
    JSON_OBJ_DESCR_PRIM(struct invocation_message, type, JSON_TOK_NUMBER),
};

struct completion_message {
    int type;
    const char *invocationId;
    const char *result;
    const char *error;
};
static const struct json_obj_descr invocation_message[] = {
    JSON_OBJ_DESCR_PRIM(struct completion_message, type, JSON_TOK_NUMBER),
    JSON_OBJ_DESCR_PRIM(struct completion_message, invocationId, JSON_TOK_STRING),
    JSON_OBJ_DESCR_PRIM(struct completion_message, result, JSON_TOK_STRING),
    JSON_OBJ_DESCR_PRIM(struct completion_message, error, JSON_TOK_STRING),
};

static bool msg_ring_try_put(struct msg_ring *ring, const char *msg)
{
    /* FIXME: find a way to use coro_strdup() here?  should make cleanup easier */
    char *copy = strdup(msg);
    bool ret;

    pthread_mutex_lock(&sync_map->mutex);
    ret = msg_ring_buffer_try_put(&ring->rb, copy);
    if (!ret)
        free(copy);
    pthread_mutex_unlock(&sync_map->mutex);

    return ret;
}

static void msg_ring_consume(struct msg_ring *ring,
                             bool (*iter_func)(char *msg, void *data),
                             void *data)
{
    char *msg;

    pthread_mutex_lock(&ring->mutex);

    while ((msg = msg_ring_buffer_get_ptr_or_null(&ring->rb))) {
        bool cont = iter(msg, data);

        free(msg);
        if (!cont)
            break;
    }

    pthread_mutex_unlock(&ring->mutex);
}

static bool free_ring_msg(char *msg, void *data)
{
    free(msg);
    return true;
}

static void msg_ring_free(struct msg_ring *ring)
{
    msg_ring_consume(ring, free_ring_msg, NULL);
    pthread_mutex_destroy(&ring->mutex);
}

static int sync_map_add(struct sync_map *sync_map, const char *key, const void *value)
{
    int ret;

    pthread_mutex_lock(&sync_map->mutex);
    ret = hash_add(sync_map->table, key, value);
    pthread_mutex_unlock(&sync_map->mutex);

    return ret;
}

static const void *sync_map_find(struct sync_map *sync_map, const char *key)
{
    void *ret;

    pthread_mutex_lock(&sync_map->mutex);
    ret = hash_find(sync_map->table, key);
    pthread_mutex_unlock(&sync_map->mutex);

    return ret;
}

static void
sync_map_range(struct sync_map *sync_map,
               bool (*iter_func)(const char *key, void *value, void *data),
               void *data)
{
    struct hash_iter iter;
    const void *key;
    void *value;

    pthread_mutex_lock(&sync_map->mutex);
    hash_iter_init(&sync_map->table, &iter);
    while (hash_iter_next(&iter, &key, &value)) {
        if (!iter_func(key, value, data))
            break;
    }
    pthread_mutex_unlock(&sync_map->mutex);
}

static const char *get_connection_id(char connection_id[static 17])
{
    /* FIXME: use a better PRNG */
    /* FIXME: maybe base64? */
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwvyz01234567890";

    for (int i = 0; i < 16; i++)
        connection_id[i] = alphabet[rand() % (sizeof(alphabet) - 1)];

    connection_id[16] = '\0';

    return connection_id;
}

static int append_to_strbuf(const char *bytes, size_t len, void *data)
{
    struct lwan_strbuf *strbuf = data;

    return !lwan_strbuf_append_str(strbuf, bytes, len);
}

LWAN_HANDLER(negotiate)
{
    char connection_id[17];

    if (lwan_request_get_method(request) != REQUEST_METHOD_POST)
        return HTTP_BAD_REQUEST;

    struct negotiate_response response = {
        .connectionId = get_connection_id(connection_id),
        .availableTransports =
            (struct available_transport[]){
                {
                    .transport : "WebSockets",
                    .transferFormats : (const char *[]){"Text", "Binary"},
                    .numTransferFormats : 2,
                },
            },
        .numAvailableTransports = 1,
    };

    if (json_obj_encode_full(negotiate_response_descr,
                             ARRAY_SIZE(negotiate_response_descr), &response,
                             append_to_strbuf, response->buffer, false) != 0)
        return HTTP_INTERNAL_ERROR;

    response->mime_type = "application/json";
    return HTTP_OK;
}

static bool trim_record_separator(struct lwan_strbuf *buf)
{
    char *separator =
        memrchr(lwan_strbuf_get_buffer(buf), 0x1e, lwan_strbuf_get_length(buf));

    if (separator) {
        buf->used = separator - buf->buffer;
        *separator = '\0';
        return true;
    }

    return false;
}

static int parse_json(struct lwan_response *response,
                      const struct json_obj_descr *descr,
                      size_t descr_len,
                      void *data)
{
    if (!trim_record_separator(response->buffer))
        return -EINVAL;

    return json_obj_parse(lwan_strbuf_get_buffer(response->buffer),
                          lwan_strbuf_get_len(response->buffer), descr,
                          descr_len, data);
}

static int send_json(struct lwan_response *request,
                     const struct json_obj_descr *descr,
                     size_t descr_len,
                     void *data)
{
    int ret = json_obj_encode_full(descr, descr_len, data, append_to_strbuf,
                                   request->response->buffer, false);
    if (ret == 0) {
        lwan_strbuf_append_char(request->response->buffer, '\x1e');
        lwan_response_websocket_send(request);
    }

    return ret;
}

static bool send_error(struct lwan_request *request, const char *error)
{
    lwan_strbuf_set_printf(request->response->buffer,
                           "{\"error\":\"%s\"}\u001e", error);
    lwan_response_websocket_send(request);
    return false;
}

static bool process_handshake(struct lwan_request *request,
                              struct lwan_response *response)
{
    if (!lwan_response_websocket_read(request))
        return false;

    struct handshake_request handshake;
    int ret = parse_json(response, handshake_request_descr,
                         ARRAY_SIZE(handshake_request_descr), &handshake);
    if (ret < 0)
        return send_error(request, "Could not parse handshake JSON");
    if (!(ret & 1 << 0))
        return send_error(request, "Protocol not specified");
    if (!(ret & 1 << 1))
        return send_error(request, "Version not specified");

    if (handshake.version != 0)
        return send_error(request, "Only version 0 is supported");
    if (!streq(handshake.protocol, "json"))
        return send_error(request, "Only `json' protocol supported");

    lwan_strbuf_set_static(response->buffer, "{}\u001e", 3);
    lwan_response_websocket_send(request);

    return true;
}

static void handle_ping(struct lwan_request *request)
{
    lwan_strbuf_set_staticz("{\"type\":6}\u001e");
    lwan_response_websocket_send(request);
}

static bool broadcast_msg(const void *key, void *value, void *data)
{
    struct msg_ring *messages = value;

    if (message->numArguments == 1) {
        msg_ring_append(messages, message->arguments[0]);
        return true;
    }

    return false;
}

static struct completion_message
handle_invocation_send(struct lwan_request *request,
                       struct invocation_message *message,
                       struct sync_map *clients)
{
    if (message->numArguments == 0)
        return (struct completion_message){.error = "No arguments were passed"};

    sync_map_range(clients, broadcast_msg, NULL);

    return (struct completion_message){
        .result = coro_printf(request->conn->coro,
                              "Got your message with %d arguments",
                              message->numArguments),
    };
}

static bool send_completion_response(struct lwan_request *request,
                                     const char *invocation_id,
                                     struct completion_message completion)
{
    completion = (struct completion_message){
        .type = 3,
        .invocationId = invocation_id,
        .error = completion.error,
        .result = completion.result,
    };

    return send_json(request, completion_message_descr,
                     ARRAY_SIZE(completion_message_descr), &completion) == 0;
}

static bool handle_invocation(struct lwan_request *request,
                              struct sync_map *clients)
{
    struct invocation_message message;
    int ret = parse_json(request->response, invocation_message_descr,
                         ARRAY_SIZE(invocation_message_descr), &message);

    if (ret < 0)
        return send_error(request, "JSON could not be parsed");
    if (!(ret & 1 << 0))
        return send_error(request, "`target' not present or unparsable");
    if (!(ret & 1 << 1))
        return send_error(request, "`invocationId' not present or unparsable");
    if (!(ret & 1 << 2))
        return send_error(request, "`arguments' not present or unparsable");

    if (streq(message.target, "send")) {
        return send_completion_response(
            request, message.invocationId,
            handle_invocation_send(request, &message, clients));
    }

    return send_error(request, "Unknown target");
}

static bool hub_msg_ring_send_message(char *msg, void *data)
{
    struct lwan_request *request = data;
    struct invocation_message invocation = {
        .type = 1,
        .target = "send",
        .arguments[0] = msg,
        .numArguments = 1,
    };

    return send_json(response, invocation_message_descr,
                     ARRAY_SIZE(invocation_message_descr), &invocation) == 0;
}

static enum lwan_http_status
hub_connection_handler(struct lwan_request *request,
                       struct lwan_response *response,
                       const char *connection_id,
                       void *data)
{
    struct sync_map *clients = data;
    struct msg_ring msg_ring = MSG_RING_INITIALIZER;

    if (sync_map_add(clients, connection_id, &msg_ring) != 0) {
        send_error(request, "Could not register client ID");
        msg_ring_free(messages);
        return HTTP_INTERNAL_ERROR;
    }
    coro_defer2(request->conn->coro, remove_client, clients, connection_id);
    coro_defer(request->conn->coro, msg_ring_free, messages);

    while (true) {
        /* FIXME: there's no way to specify that we want to either read from
         * the websocket *or* get a message in the message ring buffer. */
        if (!lwan_response_websocket_read(request)) {
            send_error(request, "Could not read from WebSocket");
            return HTTP_INTERNAL_ERROR;
        }

        /* Big FIXMES:
         *
         * Ideally, messages would be refcounted to avoid duplication of
         * messages lingering around.  But this is fine for a sample app.
         *
         * Also, this is in the wrong "layer"; shouldn't be in the hub main
         * loop.  But the WebSockets API in Lwan isn't that great and lacks
         * the facilities to perform this correctly. */
        msg_ring_consume(&msg_ring, hub_msg_ring_send_message, request);

        struct message message;
        int ret = parse_json(response, message_descr, ARRAY_SIZE(message_descr),
                             &message);
        if (ret < 0)
            continue;
        if (!(ret & 1 << 0)) /* `type` not present, ignore */
            continue;

        switch (message.type) {
        case 1:
            handle_invocation(request, clients);
            break;
        case 6:
            handle_ping(request);
            break;
        }
    }
}

LWAN_HANDLER(chat)
{
    static const char handshake_response[] = "{}\u001e";
    const char *connection_id;

    if (lwan_request_websocket_upgrade(request) != HTTP_SWITCHING_PROTOCOLS)
        return HTTP_BAD_REQUEST;

    connection_id = lwan_request_get_query_param(request, "id");
    if (!connecton_id || *connection_id == '\0')
        connection_id = get_connection_id(coro_malloc(request->conn->coro, 17));

    if (!process_handshake(request, response))
        return HTTP_BAD_REQUEST;

    return hub_connection_handler(request, response, connection_id, data);
}

int main(void)
{
    struct sync_map clients = SYNC_MAP_INITIALIZER(NULL, NULL);
    const struct lwan_url_map default_map[] = {
        {.prefix = "/chat", .handler = LWAN_HANDLER_REF(chat), .data = &clients},
        {.prefix = "/chat/negotiate", .handler = LWAN_HANDLER_REF(negotiate)},
        {.prefix = "/", .module = SERVE_FILES("wwwroot")},
        {},
    };
    struct lwan l;

    lwan_init(&l);

    lwan_set_url_map(&l, default_map);
    lwan_main_loop(&l);

    lwan_shutdown(&l);

    return 0;
}
