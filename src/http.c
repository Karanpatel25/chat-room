#define _POSIX_C_SOURCE 200809L
#include "http.h"
#include "json.h"
#include "ws.h"
#include "ratelimit.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

static rl_t g_login_ip, g_login_user, g_register_ip;

void http_init_limits(void)
{
    rl_init(&g_login_ip); rl_init(&g_login_user); rl_init(&g_register_ip);
}

void http_result_init(http_result_t *r) { memset(r, 0, sizeof *r); sb_init(&r->resp); }
void http_result_free(http_result_t *r) { sb_free(&r->resp); }

/* ------------------------------------------------------------------ parsing */

static int set_field(char *dst, size_t cap, const char *val)
{
    size_t n = strlen(val);
    if (n >= cap) return -1;
    memcpy(dst, val, n + 1);
    return 0;
}

int http_parse(const uint8_t *buf, size_t len, http_req_t *rq)
{
    memset(rq, 0, sizeof *rq);

    size_t hend = 0;
    for (size_t i = 0; i + 3 < len && i < HTTP_MAX_HEADER; i++) {
        if (buf[i] == '\r' && buf[i+1] == '\n' && buf[i+2] == '\r' && buf[i+3] == '\n') { hend = i + 4; break; }
    }
    if (!hend) return len >= HTTP_MAX_HEADER ? -2 : 0;

    char *hdr = malloc(hend + 1);
    if (!hdr) return -1;
    memcpy(hdr, buf, hend - 2);            /* keep everything except the final blank line */
    hdr[hend - 2] = '\0';
    if (memchr(buf, 0, hend)) { free(hdr); return -1; }

    int rc = 1;
    char *line = hdr;
    int first = 1, seen_host = 0, seen_cl = 0, seen_origin = 0, seen_ctype = 0, seen_cookie = 0;
    while (line && rc == 1) {
        char *eol = strstr(line, "\r\n");
        if (eol) { *eol = '\0'; }
        if (strchr(line, '\r') || strchr(line, '\n')) { rc = -1; break; }   /* bare CR/LF: smuggling vector */

        if (first) {
            first = 0;
            char *sp1 = strchr(line, ' ');
            char *sp2 = sp1 ? strchr(sp1 + 1, ' ') : NULL;
            if (!sp1 || !sp2 || strchr(sp2 + 1, ' ')) { rc = -1; break; }
            *sp1 = '\0'; *sp2 = '\0';
            char *target = sp1 + 1, *ver = sp2 + 1;
            if (strcmp(ver, "HTTP/1.1") != 0 && strcmp(ver, "HTTP/1.0") != 0) { rc = -1; break; }
            if (set_field(rq->method, sizeof rq->method, line) < 0) { rc = -1; break; }
            if (target[0] != '/') { rc = -1; break; }
            char *q = strpbrk(target, "?#");
            if (q) *q = '\0';
            if (set_field(rq->path, sizeof rq->path, target) < 0) { rc = -1; break; }
            for (const char *c = rq->path; *c; c++) if ((unsigned char)*c < 0x21 || *c == 0x7f) { rc = -1; break; }
        } else if (*line) {
            char *colon = strchr(line, ':');
            if (!colon || colon == line) { rc = -1; break; }
            *colon = '\0';
            for (const char *c = line; *c; c++) if (*c == ' ' || *c == '\t') { rc = -1; break; }
            if (rc != 1) break;
            char *val = str_trim(colon + 1);
            int e = 0;
            if (!strcasecmp(line, "host"))                  { if (seen_host++) rc = -1; else e = set_field(rq->host, sizeof rq->host, val); }
            else if (!strcasecmp(line, "origin"))           { if (seen_origin++) rc = -1; else e = set_field(rq->origin, sizeof rq->origin, val); }
            else if (!strcasecmp(line, "cookie"))           { if (seen_cookie++) rc = -1; else e = set_field(rq->cookie, sizeof rq->cookie, val); }
            else if (!strcasecmp(line, "content-type"))     { if (seen_ctype++) rc = -1; else e = set_field(rq->ctype, sizeof rq->ctype, val); }
            else if (!strcasecmp(line, "upgrade"))          e = set_field(rq->upgrade, sizeof rq->upgrade, val);
            else if (!strcasecmp(line, "connection"))       e = set_field(rq->connection, sizeof rq->connection, val);
            else if (!strcasecmp(line, "sec-websocket-key")) e = set_field(rq->ws_key, sizeof rq->ws_key, val);
            else if (!strcasecmp(line, "sec-websocket-version")) e = set_field(rq->ws_version, sizeof rq->ws_version, val);
            else if (!strcasecmp(line, "x-forwarded-for"))  e = set_field(rq->xff, sizeof rq->xff, val);
            else if (!strcasecmp(line, "transfer-encoding")) rq->has_transfer_encoding = 1;
            else if (!strcasecmp(line, "content-length")) {
                if (seen_cl++) { rc = -1; }
                else {
                    char *end; 
                    if (!*val || strspn(val, "0123456789") != strlen(val) || strlen(val) > 9) rc = -1;
                    else { rq->content_length = (size_t)strtoul(val, &end, 10); }
                }
            }
            if (e < 0) rc = -2;
        }
        line = eol ? eol + 2 : NULL;
    }
    free(hdr);
    if (rc != 1) return rc;
    if (rq->has_transfer_encoding) return -4;
    if (first || !rq->method[0]) return -1;
    if (rq->content_length > HTTP_MAX_BODY) return -3;
    if (len < hend + rq->content_length) return 0;

    rq->body = (const char *)buf + hend;
    rq->body_len = rq->content_length;
    rq->total_len = hend + rq->content_length;
    return 1;
}

/* ---------------------------------------------------------------- responses */

static const char *reason(int code)
{
    switch (code) {
    case 101: return "Switching Protocols"; case 200: return "OK"; case 204: return "No Content";
    case 400: return "Bad Request"; case 401: return "Unauthorized"; case 403: return "Forbidden";
    case 404: return "Not Found"; case 405: return "Method Not Allowed"; case 409: return "Conflict";
    case 413: return "Payload Too Large"; case 415: return "Unsupported Media Type";
    case 429: return "Too Many Requests"; case 431: return "Request Header Fields Too Large";
    case 501: return "Not Implemented"; default: return "Internal Server Error";
    }
}

static void respond(sb_t *o, int code, const char *ctype, const char *body, size_t blen,
                    const char *extra, const http_config_t *cfg)
{
    sb_printf(o, "HTTP/1.1 %d %s\r\n", code, reason(code));
    sb_printf(o, "Content-Type: %s\r\nContent-Length: %zu\r\nConnection: close\r\n", ctype, blen);
    sb_puts(o, "Cache-Control: no-store\r\n"
               "X-Content-Type-Options: nosniff\r\n"
               "X-Frame-Options: DENY\r\n"
               "Referrer-Policy: no-referrer\r\n"
               "Cross-Origin-Opener-Policy: same-origin\r\n"
               "Cross-Origin-Resource-Policy: same-origin\r\n"
               "Permissions-Policy: camera=(), microphone=(), geolocation=()\r\n"
               "Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; "
               "connect-src 'self' ws: wss:; img-src 'self' data:; base-uri 'none'; form-action 'self'; "
               "frame-ancestors 'none'\r\n");
    if (cfg && cfg->secure_cookie) sb_puts(o, "Strict-Transport-Security: max-age=31536000\r\n");
    if (extra) sb_puts(o, extra);
    sb_puts(o, "\r\n");
    if (blen) sb_append(o, body, blen);
}

static void respond_json_error(sb_t *o, int code, const char *msg, const http_config_t *cfg)
{
    sb_t b; sb_init(&b);
    sb_puts(&b, "{\"error\":"); sb_json_str(&b, msg); sb_putc(&b, '}');
    respond(o, code, "application/json", b.data ? b.data : "", b.len, NULL, cfg);
    sb_free(&b);
}

void http_error_response(sb_t *out, int status)
{
    int code = status == -2 ? 431 : status == -3 ? 413 : status == -4 ? 501 : 400;
    respond(out, code, "text/plain; charset=utf-8", reason(code), strlen(reason(code)), NULL, NULL);
}

/* ------------------------------------------------------------------ helpers */

static int origin_ok(const http_req_t *rq)
{
    if (!rq->origin[0]) return 1;                 /* non-browser client; cookies still required */
    const char *o = rq->origin;
    if (!strncmp(o, "http://", 7)) o += 7;
    else if (!strncmp(o, "https://", 8)) o += 8;
    else return 0;                                /* includes "null" */
    return rq->host[0] && strcasecmp(o, rq->host) == 0;
}

static int cookie_get(const char *cookies, const char *name, char *out, size_t cap)
{
    size_t nl = strlen(name);
    const char *p = cookies;
    while (*p) {
        while (*p == ' ' || *p == ';') p++;
        if (!strncmp(p, name, nl) && p[nl] == '=') {
            p += nl + 1;
            size_t n = strcspn(p, ";");
            if (n >= cap) return -1;
            memcpy(out, p, n); out[n] = '\0';
            return 0;
        }
        p += strcspn(p, ";");
    }
    return -1;
}

static int is_json(const http_req_t *rq)
{
    return strncasecmp(rq->ctype, "application/json", 16) == 0;
}

static void session_cookie(char *out, size_t cap, const char *token, const http_config_t *cfg)
{
    snprintf(out, cap, "Set-Cookie: session=%s; Path=/; HttpOnly; SameSite=Strict; Max-Age=%d%s\r\n",
             token, token[0] ? (int)(SESSION_TTL_MS / 1000) : 0, cfg->secure_cookie ? "; Secure" : "");
}

static void ok_user(http_result_t *res, const http_config_t *cfg, const char *user, const char *token)
{
    char ck[256];
    session_cookie(ck, sizeof ck, token, cfg);
    sb_t b; sb_init(&b);
    sb_puts(&b, "{\"ok\":true,\"user\":"); sb_json_str(&b, user); sb_putc(&b, '}');
    respond(&res->resp, 200, "application/json", b.data, b.len, ck, cfg);
    sb_free(&b);
}

/* ---------------------------------------------------------------------- API */

static void api_register(const http_req_t *rq, const char *ip, const http_config_t *cfg, http_result_t *res)
{
    char name[64], pw[PASSWORD_MAX + 8];
    json_field_t f[2] = { { "username", name, sizeof name, 0 }, { "password", pw, sizeof pw, 0 } };

    if (rl_blocked(&g_register_ip, ip, 10, 3600)) { respond_json_error(&res->resp, 429, "Too many registrations from this address", cfg); return; }
    rl_hit(&g_register_ip, ip, 3600);

    if (json_parse_fields(rq->body, rq->body_len, f, 2) != JSON_OK || !f[0].found || !f[1].found) {
        respond_json_error(&res->resp, 400, "Invalid request", cfg); goto out;
    }
    if (!valid_username(name)) {
        respond_json_error(&res->resp, 400, "Username must be 3-24 characters: letters, digits, _ or -", cfg); goto out;
    }
    const char *problem = auth_password_problem(name, pw);
    if (problem) { respond_json_error(&res->resp, 400, problem, cfg); goto out; }

    int r = auth_register(name, pw);
    if (r == AUTH_EXISTS) { respond_json_error(&res->resp, 409, "Username already taken", cfg); goto out; }
    if (r == AUTH_FULL)   { respond_json_error(&res->resp, 429, "Server is full", cfg); goto out; }
    if (r != AUTH_OK)     { respond_json_error(&res->resp, 500, "Registration failed", cfg); goto out; }

    const char *canon = auth_canonical(name);
    char token[TOKEN_HEX_LEN + 1];
    if (!canon || auth_session_create(canon, token) < 0) { respond_json_error(&res->resp, 500, "Session error", cfg); goto out; }
    ok_user(res, cfg, canon, token);
    strncpy(res->new_user, canon, USERNAME_MAX);
out:
    secure_zero(pw, sizeof pw);
}

static void api_login(const http_req_t *rq, const char *ip, const http_config_t *cfg, http_result_t *res)
{
    char name[64], pw[PASSWORD_MAX + 8], canon[USERNAME_MAX + 1], lname[64];
    json_field_t f[2] = { { "username", name, sizeof name, 0 }, { "password", pw, sizeof pw, 0 } };

    if (rl_blocked(&g_login_ip, ip, 20, 600)) { respond_json_error(&res->resp, 429, "Too many failed attempts. Try again later.", cfg); return; }
    if (json_parse_fields(rq->body, rq->body_len, f, 2) != JSON_OK || !f[0].found || !f[1].found) {
        respond_json_error(&res->resp, 400, "Invalid request", cfg); goto out;
    }
    snprintf(lname, sizeof lname, "%s", name);
    str_lower(lname);
    if (rl_blocked(&g_login_user, lname, 5, 300)) { respond_json_error(&res->resp, 429, "Too many failed attempts. Try again later.", cfg); goto out; }

    if (!auth_verify(name, pw, canon)) {
        rl_hit(&g_login_ip, ip, 600);
        rl_hit(&g_login_user, lname, 300);
        respond_json_error(&res->resp, 401, "Invalid username or password", cfg);
        goto out;
    }
    rl_reset(&g_login_user, lname);
    char token[TOKEN_HEX_LEN + 1];
    if (auth_session_create(canon, token) < 0) { respond_json_error(&res->resp, 500, "Session error", cfg); goto out; }
    ok_user(res, cfg, canon, token);
out:
    secure_zero(pw, sizeof pw);
}

static void api_logout(const http_req_t *rq, const http_config_t *cfg, http_result_t *res)
{
    char token[TOKEN_HEX_LEN + 8];
    if (cookie_get(rq->cookie, "session", token, sizeof token) == 0) {
        uint8_t h[SESSION_HASH_LEN];
        if (auth_session_lookup(token, h)) { memcpy(res->kick_hash, h, sizeof h); res->kick = 1; }
        auth_session_destroy(token);
    }
    char ck[256];
    session_cookie(ck, sizeof ck, "", cfg);
    respond(&res->resp, 200, "application/json", "{\"ok\":true}", 11, ck, cfg);
}


/* The logged-in user for this request, or NULL. Optionally returns the session hash. */
static const char *request_user(const http_req_t *rq, uint8_t h[SESSION_HASH_LEN])
{
    char token[TOKEN_HEX_LEN + 8];
    if (cookie_get(rq->cookie, "session", token, sizeof token) != 0) return NULL;
    return auth_session_lookup(token, h);
}

static void api_password(const http_req_t *rq, const char *ip, const http_config_t *cfg, http_result_t *res)
{
    char oldp[PASSWORD_MAX + 8], newp[PASSWORD_MAX + 8], lname[64];
    json_field_t f[2] = { { "old", oldp, sizeof oldp, 0 }, { "new", newp, sizeof newp, 0 } };
    uint8_t h[SESSION_HASH_LEN];
    const char *user = request_user(rq, h);
    if (!user) { respond_json_error(&res->resp, 401, "Not logged in", cfg); return; }

    /* Guessing the current password through this endpoint is throttled like logging in. */
    snprintf(lname, sizeof lname, "%s", user);
    str_lower(lname);
    if (rl_blocked(&g_login_ip, ip, 20, 600) || rl_blocked(&g_login_user, lname, 5, 300)) {
        respond_json_error(&res->resp, 429, "Too many failed attempts. Try again later.", cfg); return;
    }
    if (json_parse_fields(rq->body, rq->body_len, f, 2) != JSON_OK || !f[0].found || !f[1].found) {
        respond_json_error(&res->resp, 400, "Invalid request", cfg); goto out;
    }
    int r = auth_change_password(user, oldp, newp);
    if (r == AUTH_BAD_CREDS) {
        rl_hit(&g_login_ip, ip, 600);
        rl_hit(&g_login_user, lname, 300);
        respond_json_error(&res->resp, 401, "Current password is incorrect", cfg); goto out;
    }
    if (r == AUTH_WEAK_PW) {
        const char *why = strcmp(oldp, newp) == 0 ? "New password must differ from the current one"
                                                  : auth_password_problem(user, newp);
        respond_json_error(&res->resp, 400, why ? why : "Password rejected", cfg); goto out;
    }
    if (r != AUTH_OK) { respond_json_error(&res->resp, 500, "Could not change password", cfg); goto out; }
    rl_reset(&g_login_user, lname);
    auth_session_destroy_user(user, h);          /* every other device is logged out; this one stays */
    respond(&res->resp, 200, "application/json", "{\"ok\":true}", 11, NULL, cfg);
out:
    secure_zero(oldp, sizeof oldp);
    secure_zero(newp, sizeof newp);
}

static void api_logout_all(const http_req_t *rq, const http_config_t *cfg, http_result_t *res)
{
    uint8_t h[SESSION_HASH_LEN];
    const char *user = request_user(rq, h);
    if (!user) { respond_json_error(&res->resp, 401, "Not logged in", cfg); return; }
    auth_session_destroy_user(user, NULL);
    memcpy(res->kick_hash, h, sizeof h); res->kick = 1;      /* this tab's socket closes now; others at the next session check */
    char ck[256];
    session_cookie(ck, sizeof ck, "", cfg);
    respond(&res->resp, 200, "application/json", "{\"ok\":true}", 11, ck, cfg);
}

static void api_me(const http_req_t *rq, const http_config_t *cfg, http_result_t *res)
{
    char token[TOKEN_HEX_LEN + 8];
    const char *user = NULL;
    if (cookie_get(rq->cookie, "session", token, sizeof token) == 0) user = auth_session_lookup(token, NULL);
    if (!user) { respond_json_error(&res->resp, 401, "Not logged in", cfg); return; }
    sb_t b; sb_init(&b);
    sb_puts(&b, "{\"user\":"); sb_json_str(&b, user); sb_putc(&b, '}');
    respond(&res->resp, 200, "application/json", b.data, b.len, NULL, cfg);
    sb_free(&b);
}

/* ---------------------------------------------------------------- WebSocket */

static int has_token(const char *list, const char *tok)
{
    size_t tl = strlen(tok);
    const char *p = list;
    while (*p) {
        while (*p == ' ' || *p == ',') p++;
        size_t n = strcspn(p, ", ");
        if (n == tl && strncasecmp(p, tok, tl) == 0) return 1;
        p += n;
    }
    return 0;
}

static void ws_upgrade(const http_req_t *rq, const http_config_t *cfg, http_result_t *res)
{
    if (strcmp(rq->method, "GET") != 0) { respond_json_error(&res->resp, 405, "Method not allowed", cfg); return; }
    if (!has_token(rq->connection, "upgrade") || strcasecmp(rq->upgrade, "websocket") != 0 ||
        strcmp(rq->ws_version, "13") != 0 || strlen(rq->ws_key) != 24) {
        respond_json_error(&res->resp, 400, "Bad WebSocket handshake", cfg); return;
    }
    if (!origin_ok(rq)) { respond_json_error(&res->resp, 403, "Origin not allowed", cfg); return; }

    char token[TOKEN_HEX_LEN + 8];
    const char *user = NULL;
    uint8_t h[SESSION_HASH_LEN];
    if (cookie_get(rq->cookie, "session", token, sizeof token) == 0) user = auth_session_lookup(token, h);
    if (!user) { respond_json_error(&res->resp, 401, "Login required", cfg); return; }

    char accept[29];
    ws_accept_key(rq->ws_key, accept);
    sb_printf(&res->resp, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                          "Connection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept);
    res->upgrade = 1;
    strncpy(res->user, user, USERNAME_MAX);
    memcpy(res->sess, h, sizeof h);
}

/* ------------------------------------------------------------------- static */

static void serve_file(const http_config_t *cfg, const char *name, const char *ctype, http_result_t *res)
{
    char path[512];
    snprintf(path, sizeof path, "%s/%s", cfg->webroot, name);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_size > (1 << 20)) {
        if (fd >= 0) close(fd);
        respond_json_error(&res->resp, 404, "Not found", cfg);
        return;
    }
    char *buf = malloc((size_t)st.st_size + 1);
    ssize_t n = buf ? read(fd, buf, (size_t)st.st_size) : -1;
    close(fd);
    if (n < 0) { free(buf); respond_json_error(&res->resp, 500, "Read error", cfg); return; }
    respond(&res->resp, 200, ctype, buf, (size_t)n, NULL, cfg);
    free(buf);
}

/* ------------------------------------------------------------------- router */

void http_route(const http_req_t *rq, const char *ip, const http_config_t *cfg, http_result_t *res)
{
    const char *path = rq->path;
    int is_get = strcmp(rq->method, "GET") == 0, is_post = strcmp(rq->method, "POST") == 0;

    if (strcmp(path, "/ws") == 0) { ws_upgrade(rq, cfg, res); return; }

    if (strncmp(path, "/api/", 5) == 0) {
        if (strcmp(path, "/api/me") == 0) {
            if (!is_get) { respond_json_error(&res->resp, 405, "Method not allowed", cfg); return; }
            api_me(rq, cfg, res); return;
        }
        int known = !strcmp(path, "/api/login") || !strcmp(path, "/api/register") || !strcmp(path, "/api/logout") ||
                    !strcmp(path, "/api/password") || !strcmp(path, "/api/logout-all");
        if (!known) { respond_json_error(&res->resp, 404, "Not found", cfg); return; }
        if (!is_post) { respond_json_error(&res->resp, 405, "Method not allowed", cfg); return; }
        /* CSRF defence in depth: same-origin check + JSON content type (not sendable by plain cross-site forms)
           on top of the SameSite=Strict cookie. */
        if (!origin_ok(rq)) { respond_json_error(&res->resp, 403, "Origin not allowed", cfg); return; }
        if (!is_json(rq))   { respond_json_error(&res->resp, 415, "Content-Type must be application/json", cfg); return; }
        if (!strcmp(path, "/api/login"))    api_login(rq, ip, cfg, res);
        else if (!strcmp(path, "/api/register")) api_register(rq, ip, cfg, res);
        else if (!strcmp(path, "/api/password")) api_password(rq, ip, cfg, res);
        else if (!strcmp(path, "/api/logout-all")) api_logout_all(rq, cfg, res);
        else api_logout(rq, cfg, res);
        return;
    }

    if (!is_get) { respond_json_error(&res->resp, 405, "Method not allowed", cfg); return; }

    /* Static files are an explicit allow-list: no filesystem path ever derives from the URL. */
    if (!strcmp(path, "/") || !strcmp(path, "/index.html")) serve_file(cfg, "index.html", "text/html; charset=utf-8", res);
    else if (!strcmp(path, "/app.js"))    serve_file(cfg, "app.js", "application/javascript; charset=utf-8", res);
    else if (!strcmp(path, "/style.css")) serve_file(cfg, "style.css", "text/css; charset=utf-8", res);
    else if (!strcmp(path, "/favicon.ico")) respond(&res->resp, 204, "text/plain", "", 0, NULL, cfg);
    else respond_json_error(&res->resp, 404, "Not found", cfg);
}
