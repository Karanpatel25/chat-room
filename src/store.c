#define _POSIX_C_SOURCE 200809L
#include "store.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#define STORE_MAX 20000
#define STORE_DROP 2000

typedef struct {
    uint64_t id;
    int64_t  ts;
    char     from[USERNAME_MAX + 1];
    char     to[USERNAME_MAX + 1];
    char    *text;
    uint64_t reply;      /* id of the quoted message, 0 = none */
    int      deleted;
} smsg_t;

static smsg_t   *g_msgs;
static size_t    g_n, g_cap;
static uint64_t  g_last_id;
static int       g_fd = -1;
static char      g_logpath[512], g_rpath[512];

/* Messages deleted for everyone (kept sorted by id; also survives in-memory eviction of old messages). */
typedef struct { uint64_t id; char from[USERNAME_MAX + 1]; char to[USERNAME_MAX + 1]; } del_t;
static del_t    *g_del;
static size_t    g_ndel, g_delcap;

/* Receipt table. Key (from,to):
     DM        (a, b)   del/rd = watermarks for messages a -> b
     group     ("", u)  rd     = newest group message user u has read
     last seen (u, "")  del    = last-seen timestamp (reused field, see S lines) */
typedef struct {
    char     from[USERNAME_MAX + 1];
    char     to[USERNAME_MAX + 1];
    uint64_t del, rd;
} rc_t;

static rc_t  *g_rc;
static size_t g_rcn, g_rccap;
static int    g_rfd = -1;

/* ------------------------------------------------------------ messages */

static int push(int64_t ts, const char *from, const char *to, const char *text, uint64_t reply, uint64_t *id_out)
{
    if (g_n >= STORE_MAX) {                  /* in-memory cap: forget the oldest batch */
        for (size_t i = 0; i < STORE_DROP; i++) free(g_msgs[i].text);
        memmove(g_msgs, g_msgs + STORE_DROP, (g_n - STORE_DROP) * sizeof *g_msgs);
        g_n -= STORE_DROP;
    }
    if (g_n == g_cap) {
        size_t nc = g_cap ? g_cap * 2 : 256;
        smsg_t *p = realloc(g_msgs, nc * sizeof *p);
        if (!p) return -1;
        g_msgs = p; g_cap = nc;
    }
    smsg_t *m = &g_msgs[g_n];
    m->text = strdup(text);
    if (!m->text) return -1;
    m->id = ++g_last_id;
    m->ts = ts;
    m->reply = reply;
    m->deleted = 0;
    snprintf(m->from, sizeof m->from, "%s", from);
    snprintf(m->to, sizeof m->to, "%s", to);
    g_n++;
    if (id_out) *id_out = m->id;
    return 0;
}


/* ------------------------------------------------------------- log helpers */

typedef struct { int64_t ts; const char *from, *to, *text; uint64_t reply; } logline_t;

/* One messages.log line (newline already stripped; modified in place):
   ts \t from \t to \t text [\t reply_id].  Returns 1 if it is a valid message line. */
static int parse_log_line(char *line, logline_t *o)
{
    char *t1 = strchr(line, '\t'); if (!t1) return 0; *t1++ = '\0';
    char *t2 = strchr(t1, '\t');   if (!t2) return 0; *t2++ = '\0';
    char *t3 = strchr(t2, '\t');   if (!t3) return 0; *t3++ = '\0';
    char *t4 = strchr(t3, '\t');                       /* message text never contains tabs */
    o->reply = 0;
    if (t4) {
        *t4++ = '\0';
        if (parse_u64(t4, &o->reply) < 0 || o->reply == 0) return 0;
    }
    if (!valid_username(t1) || (t2[0] && !valid_username(t2))) return 0;
    size_t tl = strlen(t3);
    if (tl == 0 || tl > MSG_MAX_BYTES || !utf8_valid(t3, tl)) return 0;
    o->ts = (int64_t)strtoll(line, NULL, 10);
    o->from = t1; o->to = t2; o->text = t3;
    return 1;
}

static smsg_t *find_id(uint64_t id)
{
    size_t lo = 0, hi = g_n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (g_msgs[mid].id == id) return &g_msgs[mid];
        if (g_msgs[mid].id < id) lo = mid + 1; else hi = mid;
    }
    return NULL;
}

static int del_cmp(const void *a, const void *b)
{
    uint64_t x = ((const del_t *)a)->id, y = ((const del_t *)b)->id;
    return x < y ? -1 : x > y;
}

static del_t *del_find(uint64_t id)
{
    del_t key; key.id = id;
    return g_ndel ? bsearch(&key, g_del, g_ndel, sizeof *g_del, del_cmp) : NULL;
}

/* Returns 1 if newly recorded. */
static int del_add(uint64_t id, const char *from, const char *to)
{
    if (del_find(id)) return 0;
    if (g_ndel == g_delcap) {
        size_t nc = g_delcap ? g_delcap * 2 : 16;
        del_t *p = realloc(g_del, nc * sizeof *p);
        if (!p) return 0;
        g_del = p; g_delcap = nc;
    }
    del_t *d = &g_del[g_ndel++];
    d->id = id;
    snprintf(d->from, sizeof d->from, "%s", from);
    snprintf(d->to, sizeof d->to, "%s", to);
    qsort(g_del, g_ndel, sizeof *g_del, del_cmp);
    return 1;
}

static void mark_deleted(smsg_t *m) { m->deleted = 1; m->text[0] = '\0'; }

/* Rewrite messages.log, replacing the text of deleted messages with a placeholder. Every line stays in
   place (ids are line positions), so receipts and replies keep pointing at the right messages. */
static void scrub_log(void)
{
    if (!g_ndel) return;
    char tmp[sizeof g_logpath + 8];
    snprintf(tmp, sizeof tmp, "%s.tmp", g_logpath);
    FILE *in = fopen(g_logpath, "r");
    if (!in) return;
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    FILE *out = fd >= 0 ? fdopen(fd, "w") : NULL;
    if (!out) { if (fd >= 0) close(fd); fclose(in); return; }

    uint64_t id = 0;
    char *line = NULL; size_t cap = 0; ssize_t len;
    int ok = 1;
    while ((len = getline(&line, &cap, in)) > 0) {
        char *copy = strdup(line);
        int wrote = 0;
        if (copy) {
            copy[strcspn(copy, "\n")] = '\0';
            logline_t ll;
            if (parse_log_line(copy, &ll)) {
                id++;
                if (del_find(id)) {
                    fprintf(out, "%lld\t%s\t%s\t(deleted)\n", (long long)ll.ts, ll.from, ll.to);
                    wrote = 1;
                }
            }
            free(copy);
        } else ok = 0;
        if (!wrote && fwrite(line, 1, (size_t)len, out) != (size_t)len) ok = 0;
    }
    free(line);
    fclose(in);
    if (fflush(out) != 0) ok = 0;
    fsync(fileno(out));
    if (fclose(out) != 0) ok = 0;
    if (ok) rename(tmp, g_logpath); else unlink(tmp);
}

/* ------------------------------------------------------------- receipts */

static rc_t *rc_find(const char *from, const char *to, int create)
{
    for (size_t i = 0; i < g_rcn; i++)
        if (!strcmp(g_rc[i].from, from) && !strcmp(g_rc[i].to, to)) return &g_rc[i];
    if (!create) return NULL;
    if (g_rcn == g_rccap) {
        size_t nc = g_rccap ? g_rccap * 2 : 64;
        rc_t *p = realloc(g_rc, nc * sizeof *p);
        if (!p) return NULL;
        g_rc = p; g_rccap = nc;
    }
    rc_t *r = &g_rc[g_rcn++];
    memset(r, 0, sizeof *r);
    snprintf(r->from, sizeof r->from, "%s", from);
    snprintf(r->to, sizeof r->to, "%s", to);
    return r;
}

static void rlog(char kind, const char *a, const char *b, uint64_t v)
{
    if (g_rfd < 0) return;
    sb_t l; sb_init(&l);
    sb_printf(&l, "%c\t%s\t%s\t%llu\n", kind, a, b, (unsigned long long)v);
    if (!l.oom) { ssize_t w = write(g_rfd, l.data, l.len); (void)w; }
    sb_free(&l);
}

static void load_receipts(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return;
    char *line = NULL; size_t cap = 0; ssize_t len;
    while ((len = getline(&line, &cap, f)) > 0) {
        line[strcspn(line, "\n")] = '\0';
        /* K \t from \t to \t value */
        char kind = line[0];
        if ((kind != 'D' && kind != 'R' && kind != 'S' && kind != 'X') || line[1] != '\t') continue;
        char *a = line + 2;
        char *b = strchr(a, '\t'); if (!b) continue; *b++ = '\0';
        char *v = strchr(b, '\t'); if (!v) continue; *v++ = '\0';
        uint64_t val;
        if (parse_u64(v, &val) < 0) continue;
        if (kind == 'X') {                                   /* message deleted for everyone */
            if (!valid_username(a) || (b[0] && !valid_username(b)) || val == 0) continue;
            del_add(val, a, b);
            smsg_t *m = find_id(val);
            if (m && !strcmp(m->from, a)) mark_deleted(m);
            continue;
        }
        if (kind == 'S') {
            if (!valid_username(a) || b[0]) continue;
            rc_t *r = rc_find(a, "", 1);
            if (r) r->del = val;
            continue;
        }
        if ((a[0] && !valid_username(a)) || !valid_username(b)) continue;
        rc_t *r = rc_find(a, b, 1);
        if (!r) continue;
        if (kind == 'D') { if (val > r->del) r->del = val; }
        else { if (val > r->rd) r->rd = val; if (val > r->del) r->del = val; }
    }
    free(line);
    fclose(f);
}


/* Rewrite receipts.log with one line per live watermark (it otherwise grows with every receipt). */
static void compact_receipts(void)
{
    char tmp[sizeof g_rpath + 8];
    snprintf(tmp, sizeof tmp, "%s.tmp", g_rpath);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    FILE *out = fd >= 0 ? fdopen(fd, "w") : NULL;
    if (!out) { if (fd >= 0) close(fd); return; }
    for (size_t i = 0; i < g_rcn; i++) {
        const rc_t *r = &g_rc[i];
        if (!r->to[0]) {                                              /* last-seen entry */
            if (r->del) fprintf(out, "S\t%s\t\t%llu\n", r->from, (unsigned long long)r->del);
            continue;
        }
        if (r->rd) fprintf(out, "R\t%s\t%s\t%llu\n", r->from, r->to, (unsigned long long)r->rd);
        if (r->del > r->rd && r->from[0]) fprintf(out, "D\t%s\t%s\t%llu\n", r->from, r->to, (unsigned long long)r->del);
    }
    for (size_t i = 0; i < g_ndel; i++)
        fprintf(out, "X\t%s\t%s\t%llu\n", g_del[i].from, g_del[i].to, (unsigned long long)g_del[i].id);
    int ok = fflush(out) == 0;
    fsync(fileno(out));
    if (fclose(out) != 0) ok = 0;
    if (ok) rename(tmp, g_rpath); else unlink(tmp);
}

int store_init(const char *datadir)
{
    snprintf(g_logpath, sizeof g_logpath, "%s/messages.log", datadir);
    snprintf(g_rpath, sizeof g_rpath, "%s/receipts.log", datadir);

    FILE *f = fopen(g_logpath, "r");
    if (f) {
        char *line = NULL; size_t cap = 0; ssize_t len;
        while ((len = getline(&line, &cap, f)) > 0) {
            line[strcspn(line, "\n")] = '\0';
            logline_t ll;
            if (!parse_log_line(line, &ll)) continue;
            push(ll.ts, ll.from, ll.to, ll.text, ll.reply, NULL);
        }
        free(line);
        fclose(f);
    }
    load_receipts(g_rpath);          /* applies deletions to the loaded messages */
    scrub_log();                     /* make sure deleted texts are gone from disk */
    compact_receipts();

    g_fd = open(g_logpath, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (g_fd < 0) { perror("open messages.log"); return -1; }
    fchmod(g_fd, 0600);
    g_rfd = open(g_rpath, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (g_rfd < 0) { perror("open receipts.log"); return -1; }
    fchmod(g_rfd, 0600);
    return 0;
}

void store_shutdown(void)
{
    for (size_t i = 0; i < g_n; i++) free(g_msgs[i].text);
    free(g_msgs);
    g_msgs = NULL; g_n = g_cap = 0; g_last_id = 0;
    free(g_rc);
    g_rc = NULL; g_rcn = g_rccap = 0;
    free(g_del);
    g_del = NULL; g_ndel = g_delcap = 0;
    if (g_fd >= 0) close(g_fd);
    if (g_rfd >= 0) close(g_rfd);
    g_fd = g_rfd = -1;
}

int store_add(const char *from, const char *to, const char *text, int64_t ts_ms, uint64_t reply, uint64_t *id_out)
{
    /* The text has already been validated to contain no control characters (so no tabs/newlines). */
    if (push(ts_ms, from, to, text, reply, id_out) < 0) return -1;
    if (g_fd >= 0) {
        sb_t line; sb_init(&line);
        sb_printf(&line, "%lld\t%s\t%s\t%s", (long long)ts_ms, from, to, text);
        if (reply) sb_printf(&line, "\t%llu", (unsigned long long)reply);
        sb_putc(&line, '\n');
        if (!line.oom) { ssize_t w = write(g_fd, line.data, line.len); (void)w; }
        sb_free(&line);
    }
    return 0;
}

uint64_t store_last_id(const char *from, const char *to)
{
    for (size_t i = g_n; i > 0; i--) {
        const smsg_t *m = &g_msgs[i - 1];
        if (!from[0]) { if (!m->to[0]) return m->id; }
        else if (!strcmp(m->from, from) && !strcmp(m->to, to)) return m->id;
    }
    return 0;
}

/* ---------------------------------------------------------- receipt API */

void store_receipts(const char *from, const char *to, uint64_t *delivered, uint64_t *read)
{
    const rc_t *r = rc_find(from, to, 0);
    if (delivered) *delivered = r ? r->del : 0;
    if (read) *read = r ? r->rd : 0;
}

int store_mark_delivered(const char *from, const char *to, uint64_t upto)
{
    rc_t *r = rc_find(from, to, 1);
    if (!r || upto <= r->del) return 0;
    r->del = upto;
    rlog('D', from, to, upto);
    return 1;
}

int store_mark_read(const char *from, const char *to, uint64_t upto)
{
    rc_t *r = rc_find(from, to, 1);
    if (!r || upto <= r->rd) return 0;
    r->rd = upto;
    if (upto > r->del) r->del = upto;
    rlog('R', from, to, upto);
    return 1;
}

int64_t store_last_seen(const char *user)
{
    const rc_t *r = rc_find(user, "", 0);
    return r ? (int64_t)r->del : 0;
}

void store_set_last_seen(const char *user, int64_t ts_ms)
{
    rc_t *r = rc_find(user, "", 1);
    if (!r || ts_ms <= 0) return;
    r->del = (uint64_t)ts_ms;
    rlog('S', user, "", (uint64_t)ts_ms);
}

/* -------------------------------------------------------------- queries */

static int in_conversation(const smsg_t *m, const char *me, const char *with)
{
    if (with[0] == '\0') return m->to[0] == '\0';
    return (strcmp(m->from, me) == 0 && strcmp(m->to, with) == 0) ||
           (strcmp(m->from, with) == 0 && strcmp(m->to, me) == 0);
}

int store_reply_ok(const char *me, const char *with, uint64_t reply)
{
    const smsg_t *m = find_id(reply);
    return m && !m->deleted && in_conversation(m, me, with);
}

void store_reply_json(sb_t *out, uint64_t id)
{
    const smsg_t *m = find_id(id);
    sb_printf(out, "{\"id\":\"%llu\",\"from\":", (unsigned long long)id);
    sb_json_str(out, m ? m->from : "");
    sb_puts(out, ",\"text\":");
    if (m && !m->deleted) {
        char buf[81];
        size_t tl = utf8_trunc_len(m->text, strlen(m->text), 80);
        memcpy(buf, m->text, tl); buf[tl] = '\0';
        sb_json_str(out, buf);
    } else sb_json_str(out, "");
    sb_printf(out, ",\"deleted\":%s}", (m && m->deleted) || del_find(id) ? "true" : "false");
}

int store_delete(const char *user, uint64_t id, char to_out[USERNAME_MAX + 1])
{
    smsg_t *m = find_id(id);
    if (!m || m->deleted) return -1;
    if (strcmp(m->from, user) != 0) return -2;
    snprintf(to_out, USERNAME_MAX + 1, "%s", m->to);
    mark_deleted(m);
    if (del_add(id, m->from, m->to)) rlog('X', m->from, m->to, id);
    if (g_fd >= 0) {                                   /* scrub the text from disk, then reopen for appending */
        close(g_fd);
        scrub_log();
        g_fd = open(g_logpath, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    }
    return 0;
}

void store_history_json(sb_t *out, const char *me, const char *with, int max, uint64_t before, int *more)
{
    size_t idx[HISTORY_LIMIT + 1];
    int found = 0;
    if (max > HISTORY_LIMIT) max = HISTORY_LIMIT;
    if (max < 1) max = 1;
    for (size_t i = g_n; i > 0 && found < max + 1; i--) {      /* one extra row tells us if more exist */
        const smsg_t *m = &g_msgs[i - 1];
        if (before && m->id >= before) continue;
        if (in_conversation(m, me, with)) idx[found++] = i - 1;
    }
    if (more) *more = found > max;
    if (found > max) found = max;

    uint64_t del = 0, rd = 0;
    if (with[0]) store_receipts(me, with, &del, &rd);

    sb_putc(out, '[');
    for (int k = found - 1; k >= 0; k--) {
        const smsg_t *m = &g_msgs[idx[k]];
        if (k != found - 1) sb_putc(out, ',');
        sb_printf(out, "{\"id\":\"%llu\",\"from\":", (unsigned long long)m->id);
        sb_json_str(out, m->from);
        sb_puts(out, ",\"to\":");   sb_json_str(out, m->to);
        sb_puts(out, ",\"text\":"); sb_json_str(out, m->text);
        sb_printf(out, ",\"ts\":%lld", (long long)m->ts);
        if (m->deleted) sb_puts(out, ",\"deleted\":true");
        if (m->reply && !m->deleted) { sb_puts(out, ",\"reply\":"); store_reply_json(out, m->reply); }
        if (with[0] && !strcmp(m->from, me))
            sb_printf(out, ",\"status\":\"%s\"", m->id <= rd ? "read" : m->id <= del ? "delivered" : "sent");
        sb_putc(out, '}');
    }
    sb_putc(out, ']');
}

unsigned store_unread(const char *me, const char *with)
{
    uint64_t rd = 0;
    store_receipts(with, me, NULL, &rd);          /* DM: with -> me ; group: ("", me) */
    unsigned n = 0;
    for (size_t i = g_n; i > 0; i--) {
        const smsg_t *m = &g_msgs[i - 1];
        if (m->id <= rd) break;                   /* ids only grow along the array */
        if (!with[0]) { if (!m->to[0] && strcmp(m->from, me)) n++; }
        else if (!strcmp(m->from, with) && !strcmp(m->to, me)) n++;
    }
    return n;
}

static void set_preview(conv_summary_t *e, const smsg_t *m)
{
    e->last_deleted = m->deleted;
    size_t tl = utf8_trunc_len(m->text, strlen(m->text), PREVIEW_BYTES);
    memcpy(e->last_text, m->text, tl);
    e->last_text[tl] = '\0';
    snprintf(e->last_from, sizeof e->last_from, "%s", m->from);
    e->last_id = m->id;
    e->last_ts = m->ts;
}

size_t store_summaries(const char *me, conv_summary_t **out)
{
    *out = NULL;
    size_t n = 1, cap = 32;
    conv_summary_t *s = calloc(cap, sizeof *s);
    if (!s) return 0;
    store_receipts("", me, NULL, &s[0].rd);

    for (size_t i = 0; i < g_n; i++) {
        const smsg_t *m = &g_msgs[i];
        conv_summary_t *e = NULL;
        if (!m->to[0]) {
            e = &s[0];
            if (strcmp(m->from, me) && m->id > e->rd) e->unread++;
        } else {
            int mine = !strcmp(m->from, me);
            if (!mine && strcmp(m->to, me)) continue;               /* someone else's DM */
            const char *partner = mine ? m->to : m->from;
            for (size_t k = 1; k < n; k++) if (!strcmp(s[k].with, partner)) { e = &s[k]; break; }
            if (!e) {
                if (n == cap) {
                    cap *= 2;
                    conv_summary_t *p = realloc(s, cap * sizeof *s);
                    if (!p) { free(s); return 0; }
                    s = p;
                }
                e = &s[n++];
                memset(e, 0, sizeof *e);
                snprintf(e->with, sizeof e->with, "%s", partner);
                store_receipts(partner, me, &e->delivered, &e->rd);
            }
            if (!mine) {
                e->last_in_id = m->id;
                if (m->id > e->rd) e->unread++;
            }
        }
        set_preview(e, m);
    }
    for (size_t k = 1; k < n; k++) {
        if (s[k].last_from[0] && !strcmp(s[k].last_from, me)) {
            uint64_t del, rd;
            store_receipts(me, s[k].with, &del, &rd);
            snprintf(s[k].last_status, sizeof s[k].last_status, "%s",
                     s[k].last_id <= rd ? "read" : s[k].last_id <= del ? "delivered" : "sent");
        }
    }
    *out = s;
    return n;
}
