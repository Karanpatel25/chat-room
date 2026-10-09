#define _POSIX_C_SOURCE 200809L
#include "server.h"
#include "chat.h"
#include "ws.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#define MAX_CLIENTS        512
#define MAX_PER_IP         20
#define MAX_CONN_PER_USER  8
#define RBUF_SIZE          16384
#define WBUF_MAX           (1u << 20)
#define WS_MAX_PAYLOAD     8192
#define HTTP_TIMEOUT_MS    10000
#define PING_INTERVAL_MS   30000
#define PONG_TIMEOUT_MS    20000
#define CLOSE_GRACE_MS     3000
#define SESSION_CHECK_MS   5000
#define RATE_BURST         8.0
#define RATE_PER_SEC       4.0
#define MAX_VIOLATIONS     30
#define LIGHT_BURST        30.0
#define LIGHT_PER_SEC      15.0

enum { ST_HTTP, ST_WS, ST_CLOSING, ST_DEAD };

struct client {
    int     fd;
    int     state;
    char    peer_ip[INET6_ADDRSTRLEN];
    char    ip[INET6_ADDRSTRLEN];            /* effective client IP (after proxy handling) */
    uint8_t rbuf[RBUF_SIZE];
    size_t  rlen;
    uint8_t *wbuf;
    size_t  wlen, woff, wcap;
    int     close_after_flush;
    int64_t connected_ms, last_recv_ms, last_ping_ms, closing_since_ms, last_session_check_ms;
    int     awaiting_pong;
    char    user[USERNAME_MAX + 1];
    uint8_t sess[SESSION_HASH_LEN];
    uint8_t *frag; size_t fraglen; int frag_active;
    double  tokens; int64_t last_refill_ms; int violations;
    double  ltokens; int64_t last_lrefill_ms;      /* bucket for light control frames (read receipts) */
};

static client_t *g_clients[MAX_CLIENTS];
static int g_n;
static int g_listen = -1;
static volatile int g_running;
static server_config_t g_cfg;
static http_config_t g_http;
static char g_scratch[WS_MAX_PAYLOAD + 1];

/* ---------------------------------------------------------------- buffers */

static void queue_raw(client_t *c, const void *data, size_t n)
{
    if (c->state == ST_DEAD) return;
    if (c->wlen - c->woff + n > WBUF_MAX) { c->state = ST_DEAD; return; }  /* slow consumer */
    if (c->wlen + n > c->wcap) {
        if (c->woff) {
            memmove(c->wbuf, c->wbuf + c->woff, c->wlen - c->woff);
            c->wlen -= c->woff; c->woff = 0;
        }
        if (c->wlen + n > c->wcap) {
            size_t nc = c->wcap ? c->wcap : 4096;
            while (nc < c->wlen + n) nc *= 2;
            uint8_t *p = realloc(c->wbuf, nc);
            if (!p) { c->state = ST_DEAD; return; }
            c->wbuf = p; c->wcap = nc;
        }
    }
    memcpy(c->wbuf + c->wlen, data, n);
    c->wlen += n;
}

static void send_frame(client_t *c, int op, const void *payload, size_t n)
{
    uint8_t hdr[10];
    size_t hl = ws_frame_header(op, n, hdr);
    queue_raw(c, hdr, hl);
    if (n) queue_raw(c, payload, n);
}

static void flush_client(client_t *c)
{
    while (c->woff < c->wlen && c->state != ST_DEAD) {
        ssize_t n = send(c->fd, c->wbuf + c->woff, c->wlen - c->woff, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            c->state = ST_DEAD; return;
        }
        c->woff += (size_t)n;
    }
    if (c->woff == c->wlen) {
        c->woff = c->wlen = 0;
        if (c->wcap > 65536) { free(c->wbuf); c->wbuf = NULL; c->wcap = 0; }
        if (c->close_after_flush) c->state = ST_DEAD;
    }
}

static void ws_close(client_t *c, int code)
{
    uint8_t p[2] = { (uint8_t)(code >> 8), (uint8_t)code };
    send_frame(c, WS_CLOSE, p, 2);
    c->state = ST_CLOSING;
    c->close_after_flush = 1;
    c->closing_since_ms = mono_ms();
}

/* --------------------------------------------------------------- chat API */

const char *srv_client_user(const client_t *c) { return c->user; }

void srv_send_text(client_t *c, const char *s, size_t n)
{
    if (c->state == ST_WS) send_frame(c, WS_TEXT, s, n);
}

void srv_send_user(const char *user, const char *s, size_t n)
{
    for (int i = 0; i < g_n; i++)
        if (g_clients[i]->state == ST_WS && !strcasecmp(g_clients[i]->user, user))
            send_frame(g_clients[i], WS_TEXT, s, n);
}

void srv_broadcast(const char *s, size_t n, const char *except_user)
{
    for (int i = 0; i < g_n; i++) {
        client_t *c = g_clients[i];
        if (c->state != ST_WS) continue;
        if (except_user && !strcasecmp(c->user, except_user)) continue;
        send_frame(c, WS_TEXT, s, n);
    }
}

int srv_light_ok(client_t *c)
{
    int64_t now = mono_ms();
    c->ltokens += (double)(now - c->last_lrefill_ms) * LIGHT_PER_SEC / 1000.0;
    if (c->ltokens > LIGHT_BURST) c->ltokens = LIGHT_BURST;
    c->last_lrefill_ms = now;
    if (c->ltokens < 1.0) return 0;
    c->ltokens -= 1.0;
    c->tokens += 1.0;                                 /* refund the normal-bucket token */
    if (c->tokens > RATE_BURST) c->tokens = RATE_BURST;
    return 1;
}

int srv_user_conn_count(const char *user)
{
    int k = 0;
    for (int i = 0; i < g_n; i++)
        if (g_clients[i]->state == ST_WS && !strcasecmp(g_clients[i]->user, user)) k++;
    return k;
}

/* -------------------------------------------------------------- WebSocket */

static void deliver_text(client_t *c, const uint8_t *data, size_t n)
{
    if (!utf8_valid((const char *)data, n)) { ws_close(c, 1007); return; }

    int64_t now = mono_ms();                         /* token-bucket rate limit */
    c->tokens += (double)(now - c->last_refill_ms) * RATE_PER_SEC / 1000.0;
    if (c->tokens > RATE_BURST) c->tokens = RATE_BURST;
    c->last_refill_ms = now;
    if (c->tokens < 1.0) {
        if (++c->violations >= MAX_VIOLATIONS) { ws_close(c, 1008); return; }
        const char *e = "{\"type\":\"error\",\"message\":\"You are sending messages too fast\"}";
        send_frame(c, WS_TEXT, e, strlen(e));
        return;
    }
    c->tokens -= 1.0;

    memcpy(g_scratch, data, n);
    g_scratch[n] = '\0';
    chat_on_text(c, c->user, g_scratch, n);
}

static void process_ws(client_t *c)
{
    while (c->state == ST_WS && c->rlen > 0) {
        ws_frame_t f; int code = 1002;
        int r = ws_parse(c->rbuf, c->rlen, WS_MAX_PAYLOAD, &f, &code);
        if (r == 0) return;
        if (r < 0) { ws_close(c, code); return; }

        uint8_t *payload = c->rbuf + f.header_len;
        ws_unmask(payload, f.payload_len, f.mask);

        switch (f.opcode) {
        case WS_TEXT:
            if (c->frag_active) { ws_close(c, 1002); break; }
            if (f.fin) deliver_text(c, payload, f.payload_len);
            else {
                c->frag = malloc(WS_MAX_PAYLOAD);
                if (!c->frag) { ws_close(c, 1011); break; }
                memcpy(c->frag, payload, f.payload_len);
                c->fraglen = f.payload_len; c->frag_active = 1;
            }
            break;
        case WS_CONT:
            if (!c->frag_active) { ws_close(c, 1002); break; }
            if (c->fraglen + f.payload_len > WS_MAX_PAYLOAD) { ws_close(c, 1009); break; }
            memcpy(c->frag + c->fraglen, payload, f.payload_len);
            c->fraglen += f.payload_len;
            if (f.fin) {
                size_t n = c->fraglen;
                memcpy(g_scratch, c->frag, n);       /* free before delivering */
                free(c->frag); c->frag = NULL; c->fraglen = 0; c->frag_active = 0;
                uint8_t *tmp = malloc(n ? n : 1);
                if (tmp) { memcpy(tmp, g_scratch, n); deliver_text(c, tmp, n); free(tmp); }
            }
            break;
        case WS_BINARY: ws_close(c, 1003); break;
        case WS_PING:   send_frame(c, WS_PONG, payload, f.payload_len); break;
        case WS_PONG:   c->awaiting_pong = 0; break;
        case WS_CLOSE: {
            int code_out = 1000;
            if (f.payload_len == 1) code_out = 1002;
            ws_close(c, code_out);
            break;
        }
        }
        size_t used = f.header_len + f.payload_len;
        if (c->state != ST_WS) { c->rlen = 0; return; }
        memmove(c->rbuf, c->rbuf + used, c->rlen - used);
        c->rlen -= used;
    }
}

/* ------------------------------------------------------------------- HTTP */

static void set_effective_ip(client_t *c, const http_req_t *rq)
{
    snprintf(c->ip, sizeof c->ip, "%s", c->peer_ip);
    if (g_cfg.trust_proxy && rq->xff[0]) {
        const char *last = strrchr(rq->xff, ',');
        last = last ? last + 1 : rq->xff;
        while (*last == ' ') last++;
        struct in6_addr a6; struct in_addr a4;
        if (inet_pton(AF_INET, last, &a4) == 1 || inet_pton(AF_INET6, last, &a6) == 1)
            snprintf(c->ip, sizeof c->ip, "%.45s", last);
    }
}

static void handle_http(client_t *c)
{
    http_req_t rq;
    int r = http_parse(c->rbuf, c->rlen, &rq);
    if (r == 0) return;
    if (r < 0) {
        sb_t b; sb_init(&b);
        http_error_response(&b, r);
        queue_raw(c, b.data, b.len);
        sb_free(&b);
        c->close_after_flush = 1; c->state = ST_CLOSING; c->closing_since_ms = mono_ms(); c->rlen = 0;
        return;
    }
    set_effective_ip(c, &rq);

    http_result_t res;
    http_result_init(&res);
    http_route(&rq, c->ip, &g_http, &res);

    if (res.upgrade && srv_user_conn_count(res.user) >= MAX_CONN_PER_USER) {
        http_result_free(&res);
        http_result_init(&res);
        static const char tm[] = "HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        sb_append(&res.resp, tm, sizeof tm - 1);
    }

    if (res.resp.oom) { c->state = ST_DEAD; http_result_free(&res); return; }
    queue_raw(c, res.resp.data, res.resp.len);

    if (res.kick) {
        for (int i = 0; i < g_n; i++)
            if (g_clients[i]->state == ST_WS && ct_equal(g_clients[i]->sess, res.kick_hash, SESSION_HASH_LEN))
                ws_close(g_clients[i], 1008);
    }
    if (res.new_user[0]) chat_on_register(res.new_user);

    if (res.upgrade && c->state == ST_HTTP) {
        size_t left = c->rlen - rq.total_len;
        memmove(c->rbuf, c->rbuf + rq.total_len, left);
        c->rlen = left;
        c->state = ST_WS;
        snprintf(c->user, sizeof c->user, "%.24s", res.user);
        memcpy(c->sess, res.sess, SESSION_HASH_LEN);
        c->tokens = RATE_BURST; c->last_refill_ms = mono_ms(); c->last_ping_ms = mono_ms();
        c->ltokens = LIGHT_BURST; c->last_lrefill_ms = mono_ms();
        c->last_session_check_ms = mono_ms();
        chat_on_connect(c, c->user);
        process_ws(c);
    } else {
        c->close_after_flush = 1; c->state = ST_CLOSING; c->closing_since_ms = mono_ms(); c->rlen = 0;
    }
    http_result_free(&res);
}

/* -------------------------------------------------------------- lifecycle */

static void accept_clients(void)
{
    for (;;) {
        struct sockaddr_storage ss; socklen_t sl = sizeof ss;
        int fd = accept(g_listen, (struct sockaddr *)&ss, &sl);
        if (fd < 0) return;                          /* EAGAIN or transient error */

        char ip[INET6_ADDRSTRLEN] = "?";
        if (ss.ss_family == AF_INET) inet_ntop(AF_INET, &((struct sockaddr_in *)&ss)->sin_addr, ip, sizeof ip);
        else if (ss.ss_family == AF_INET6) inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&ss)->sin6_addr, ip, sizeof ip);

        int same = 0;
        for (int i = 0; i < g_n; i++) if (!strcmp(g_clients[i]->peer_ip, ip)) same++;
        if (g_n >= MAX_CLIENTS || (same >= MAX_PER_IP && strcmp(ip, "127.0.0.1") && strcmp(ip, "::1"))) { close(fd); continue; }

        int fl = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, fl | O_NONBLOCK);
        fcntl(fd, F_SETFD, FD_CLOEXEC);
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);

        client_t *c = calloc(1, sizeof *c);
        if (!c) { close(fd); continue; }
        c->fd = fd; c->state = ST_HTTP;
        snprintf(c->peer_ip, sizeof c->peer_ip, "%s", ip);
        snprintf(c->ip, sizeof c->ip, "%s", ip);
        c->connected_ms = c->last_recv_ms = mono_ms();
        g_clients[g_n++] = c;
    }
}

static void read_client(client_t *c)
{
    ssize_t n = recv(c->fd, c->rbuf + c->rlen, RBUF_SIZE - c->rlen, 0);
    if (n == 0) { c->state = ST_DEAD; return; }
    if (n < 0) { if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) c->state = ST_DEAD; return; }
    c->rlen += (size_t)n;
    c->last_recv_ms = mono_ms();
    if (c->state == ST_HTTP) handle_http(c);
    else if (c->state == ST_WS) process_ws(c);
}

static void tick(int64_t now)
{
    for (int i = 0; i < g_n; i++) {
        client_t *c = g_clients[i];
        if (c->state == ST_HTTP && now - c->connected_ms > HTTP_TIMEOUT_MS) c->state = ST_DEAD;
        else if (c->state == ST_CLOSING && now - c->closing_since_ms > CLOSE_GRACE_MS) c->state = ST_DEAD;
        else if (c->state == ST_WS) {
            if (c->awaiting_pong && now - c->last_ping_ms > PONG_TIMEOUT_MS) { c->state = ST_DEAD; continue; }
            if (!c->awaiting_pong && now - c->last_recv_ms > PING_INTERVAL_MS) {
                send_frame(c, WS_PING, "", 0);
                c->awaiting_pong = 1; c->last_ping_ms = now;
            }
            if (now - c->last_session_check_ms > SESSION_CHECK_MS) {   /* enforce logout / expiry on live sockets */
                c->last_session_check_ms = now;
                if (!auth_session_valid(c->sess)) ws_close(c, 1008);
            }
        }
    }
}

static void sweep(void)
{
    char gone[MAX_CLIENTS][USERNAME_MAX + 1];
    int ngone = 0, j = 0;
    for (int i = 0; i < g_n; i++) {
        client_t *c = g_clients[i];
        if (c->state != ST_DEAD) { g_clients[j++] = c; continue; }
        if (c->user[0]) { strcpy(gone[ngone++], c->user); }
        close(c->fd);
        free(c->wbuf); free(c->frag);
        free(c);
    }
    g_n = j;
    for (int i = 0; i < ngone; i++) chat_on_disconnect(gone[i]);
}

int server_init(const server_config_t *cfg)
{
    g_cfg = *cfg;
    g_http.webroot = g_cfg.webroot;
    g_http.secure_cookie = g_cfg.secure_cookie;
    http_init_limits();

    g_listen = socket(AF_INET, SOCK_STREAM, 0);
    if (g_listen < 0) { perror("socket"); return -1; }
    int one = 1;
    setsockopt(g_listen, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)cfg->port);
    if (inet_pton(AF_INET, cfg->bind_addr, &a.sin_addr) != 1) { fprintf(stderr, "Invalid bind address\n"); return -1; }
    if (bind(g_listen, (struct sockaddr *)&a, sizeof a) < 0) { perror("bind"); return -1; }
    if (listen(g_listen, 128) < 0) { perror("listen"); return -1; }
    fcntl(g_listen, F_SETFL, fcntl(g_listen, F_GETFL, 0) | O_NONBLOCK);
    fcntl(g_listen, F_SETFD, FD_CLOEXEC);
    return 0;
}

void server_stop(void) { g_running = 0; }

void server_run(void)
{
    g_running = 1;
    struct pollfd pfds[MAX_CLIENTS + 1];
    client_t *snap[MAX_CLIENTS];

    while (g_running) {
        int n = g_n;
        pfds[0].fd = g_listen; pfds[0].events = POLLIN; pfds[0].revents = 0;
        for (int i = 0; i < n; i++) {
            client_t *c = g_clients[i];
            snap[i] = c;
            pfds[i + 1].fd = c->fd;
            pfds[i + 1].events = (c->state == ST_HTTP || c->state == ST_WS ? POLLIN : 0) |
                                 (c->woff < c->wlen ? POLLOUT : 0);
            pfds[i + 1].revents = 0;
        }
        int pr = poll(pfds, (nfds_t)n + 1, 1000);
        if (pr < 0) { if (errno == EINTR) continue; perror("poll"); break; }

        if (pfds[0].revents & POLLIN) accept_clients();

        for (int i = 0; i < n; i++) {
            client_t *c = snap[i];
            short re = pfds[i + 1].revents;
            if (c->state == ST_DEAD) continue;
            if (re & (POLLERR | POLLNVAL)) { c->state = ST_DEAD; continue; }
            if (re & POLLIN) read_client(c);
            else if (re & POLLHUP) { c->state = ST_DEAD; continue; }
        }
        for (int i = 0; i < g_n; i++) if (g_clients[i]->wlen > g_clients[i]->woff) flush_client(g_clients[i]);

        tick(mono_ms());
        for (int i = 0; i < g_n; i++) if (g_clients[i]->wlen > g_clients[i]->woff) flush_client(g_clients[i]);
        sweep();
    }
}

void server_cleanup(void)
{
    for (int i = 0; i < g_n; i++) {
        close(g_clients[i]->fd);
        free(g_clients[i]->wbuf); free(g_clients[i]->frag);
        free(g_clients[i]);
    }
    g_n = 0;
    if (g_listen >= 0) close(g_listen);
    g_listen = -1;
}
