#ifndef __LWAN_PRIVATE_H__
#define __LWAN_PRIVATE_H__

#include "lwan.h"

void lwan_response_init(void);
void lwan_response_shutdown(void);

void lwan_socket_init(lwan_t *l);
void lwan_socket_shutdown(lwan_t *l);

void lwan_thread_init(lwan_t *l);
void lwan_thread_shutdown(lwan_t *l);

void lwan_status_init(lwan_t *l);
void lwan_status_shutdown(lwan_t *l);

void lwan_job_thread_init(void);
void lwan_job_thread_shutdown(void);
void lwan_job_add(bool (*cb)(void *data), void *data);
void lwan_job_del(bool (*cb)(void *data), void *data);

void lwan_tables_init(void);
void lwan_tables_shutdown(void);

#endif /* __LWAN_PRIVATE_H__ */
