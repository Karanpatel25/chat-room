#ifndef SERVER_H
#define SERVER_H
#include <stddef.h>
#include <stdint.h>
#include "http.h"

typedef struct client client_t;

typedef struct {
    int  port;
    char bind_addr[64];
    char datadir[256];
    char webroot[256];
    int  secure_cookie;
    int  trust_proxy;   /* take client IP from the (rightmost) X-Forwarded-For entry */
} server_config_t;

int  server_init(const server_config_t *cfg);   /* 0 on success */
void server_run(void);
void server_stop(void);
void server_cleanup(void);

/* ---- API used by chat.c ---- */
const char *srv_client_user(const client_t *c);
void srv_send_text(client_t *c, const char *s, size_t n);
void srv_send_user(const char *user, const char *s, size_t n);               /* all connections of user */
void srv_broadcast(const char *s, size_t n, const char *except_user);        /* all authenticated clients */
int  srv_user_conn_count(const char *user);
/* Cheap control frames (read receipts) are charged to a separate, larger bucket so they don't
   starve real messages. Returns 0 if that bucket is empty; otherwise refunds the normal token. */
int  srv_light_ok(client_t *c);
#endif
