#ifndef HTTP_H
#define HTTP_H
#include <stddef.h>
#include <stdint.h>
#include "util.h"
#include "auth.h"

#define HTTP_MAX_HEADER 8192
#define HTTP_MAX_BODY   4096

typedef struct {
    char   method[8];
    char   path[128];
    char   host[128], origin[160], cookie[512], ctype[64];
    char   upgrade[32], connection[64], ws_key[64], ws_version[8], xff[128];
    size_t content_length;
    int    has_transfer_encoding;
    const char *body;
    size_t body_len;
    size_t total_len;       /* header + body bytes consumed from the buffer */
} http_req_t;

/* 1 = complete request parsed, 0 = need more data,
   -1 = 400, -2 = 431 (headers too large), -3 = 413 (body too large), -4 = 501 */
int http_parse(const uint8_t *buf, size_t len, http_req_t *rq);

typedef struct {
    const char *webroot;
    int         secure_cookie;   /* add Secure + HSTS (use when behind HTTPS) */
} http_config_t;

typedef struct {
    sb_t    resp;                /* complete HTTP response bytes */
    int     upgrade;             /* 1: WebSocket accepted (resp is the 101 reply) */
    char    user[USERNAME_MAX + 1];
    uint8_t sess[SESSION_HASH_LEN];
    int     kick;                /* logout: close sockets bound to kick_hash */
    uint8_t kick_hash[SESSION_HASH_LEN];
    char    new_user[USERNAME_MAX + 1];   /* set after a successful registration */
} http_result_t;

void http_result_init(http_result_t *r);
void http_result_free(http_result_t *r);
void http_route(const http_req_t *rq, const char *client_ip, const http_config_t *cfg, http_result_t *res);
void http_error_response(sb_t *out, int status);
void http_init_limits(void);
#endif
