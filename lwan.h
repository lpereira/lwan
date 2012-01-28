#ifndef _LWAN_H__
#define _LWAN_H_

#include <pthread.h>
#include <stdbool.h>

typedef struct lwan_thread_t_		lwan_thread_t;
typedef struct lwan_request_t_		lwan_request_t;
typedef struct lwan_response_t_		lwan_response_t;
typedef struct lwan_url_map_t_		lwan_url_map_t;
typedef struct lwan_t_			lwan_t;

typedef enum {
    HTTP_OK = 200,
    HTTP_BAD_REQUEST = 400,
    HTTP_NOT_FOUND = 404,
    HTTP_FORBIDDEN = 403,
    HTTP_NOT_ALLOWED = 405,
    HTTP_INTERNAL_ERROR = 500,
} lwan_http_status_t;

typedef enum {
    HTTP_GET = 0,
    HTTP_POST
} lwan_http_method_t;

struct lwan_response_t_ {
    char *content;
    char *mime_type;
    int content_length;
};

struct lwan_request_t_ {
    lwan_http_method_t method;
    lwan_response_t *response;
    char *url;
    int url_len;
    int fd;
};

struct lwan_url_map_t_ {
    const char *prefix;
    int prefix_len;
    lwan_http_status_t (*callback)(lwan_request_t *request, void *data);
    void *data;
};

struct lwan_t_ {
    lwan_url_map_t *url_map;
    int main_socket;
    int port;

    struct {
        int count;
        int sockets[2];
        pthread_t *ids;
    } thread;
};

void lwan_init(lwan_t *l);
void lwan_shutdown(lwan_t *l);

bool lwan_default_response(lwan_t *l, lwan_request_t *request, lwan_http_status_t status);
void lwan_request_set_response(lwan_request_t *request, lwan_response_t *response);
bool lwan_process_request_from_socket(lwan_t *l, int fd);
void lwan_request_queue_push_fd(lwan_t *l, int fd);
int lwan_request_queue_pop_fd(lwan_t *l);

#endif /* _LWAN_H_ */
