#include "chat.h"
#include "auth.h"
#include "json.h"
#include "store.h"
#include "util.h"
#include <stdlib.h>
#include <string.h>

static void send_sb(client_t *c, sb_t *b)
{
    if (!b->oom) srv_send_text(c, b->data, b->len);
    sb_free(b);
}

static void send_error(client_t *c, const char *msg)
{
    sb_t b; sb_init(&b);
    sb_puts(&b, "{\"type\":\"error\",\"message\":"); sb_json_str(&b, msg); sb_putc(&b, '}');
    send_sb(c, &b);
}

static void send_users(client_t *c)
{
    sb_t b; sb_init(&b);
    sb_puts(&b, "{\"type\":\"users\",\"users\":[");
    for (size_t i = 0; i < auth_user_count(); i++) {
        const char *n = auth_user_at(i);
        int online = srv_user_conn_count(n) > 0;
        if (i) sb_putc(&b, ',');
        sb_puts(&b, "{\"name\":"); sb_json_str(&b, n);
        sb_printf(&b, ",\"online\":%s,\"last_seen\":%lld}", online ? "true" : "false",
                  (long long)(online ? 0 : store_last_seen(n)));
    }
    sb_puts(&b, "]}");
    send_sb(c, &b);
}

/* before == 0: the newest page. Otherwise the page of messages older than `before`. */
static void send_history(client_t *c, const char *me, const char *with, uint64_t before)
{
    sb_t msgs; sb_init(&msgs);
    int more = 0;
    store_history_json(&msgs, me, with, HISTORY_LIMIT, before, &more);

    sb_t b; sb_init(&b);
    sb_puts(&b, "{\"type\":\"history\",\"with\":"); sb_json_str(&b, with);
    if (before) sb_printf(&b, ",\"before\":\"%llu\"", (unsigned long long)before);
    else        sb_puts(&b, ",\"before\":\"\"");
    sb_printf(&b, ",\"more\":%s,\"messages\":", more ? "true" : "false");
    if (msgs.oom) b.oom = 1; else sb_append(&b, msgs.data, msgs.len);
    sb_putc(&b, '}');
    sb_free(&msgs);
    send_sb(c, &b);
}

static void send_convs(client_t *c, const conv_summary_t *s, size_t n)
{
    sb_t b; sb_init(&b);
    sb_puts(&b, "{\"type\":\"convs\",\"convs\":[");
    for (size_t i = 0; i < n; i++) {
        if (i) sb_putc(&b, ',');
        sb_puts(&b, "{\"with\":");       sb_json_str(&b, s[i].with);
        sb_printf(&b, ",\"last_id\":\"%llu\"", (unsigned long long)s[i].last_id);
        sb_puts(&b, ",\"last_from\":");  sb_json_str(&b, s[i].last_from);
        sb_puts(&b, ",\"last_text\":");  sb_json_str(&b, s[i].last_text);
        sb_puts(&b, ",\"last_status\":"); sb_json_str(&b, s[i].last_status);
        sb_printf(&b, ",\"last_ts\":%lld,\"unread\":%u,\"last_deleted\":%s}", (long long)s[i].last_ts, s[i].unread,
                  s[i].last_deleted ? "true" : "false");
    }
    sb_puts(&b, "]}");
    send_sb(c, &b);
}

/* Tell `to_user` (the original sender) that their DMs to `with` up to `upto` were delivered / read. */
static void send_receipt(const char *to_user, const char *with, const char *status, uint64_t upto)
{
    sb_t b; sb_init(&b);
    sb_puts(&b, "{\"type\":\"receipt\",\"with\":"); sb_json_str(&b, with);
    sb_printf(&b, ",\"status\":\"%s\",\"upto\":\"%llu\"}", status, (unsigned long long)upto);
    if (!b.oom) srv_send_user(to_user, b.data, b.len);
    sb_free(&b);
}

/* Keep a user's other tabs/devices in sync after they read a conversation. */
static void send_unread(const char *user, const char *with)
{
    sb_t b; sb_init(&b);
    sb_puts(&b, "{\"type\":\"unread\",\"with\":"); sb_json_str(&b, with);
    sb_printf(&b, ",\"count\":%u}", store_unread(user, with));
    if (!b.oom) srv_send_user(user, b.data, b.len);
    sb_free(&b);
}

static void presence(const char *user, int online, int64_t last_seen)
{
    sb_t b; sb_init(&b);
    sb_puts(&b, "{\"type\":\"presence\",\"name\":"); sb_json_str(&b, user);
    sb_printf(&b, ",\"online\":%s,\"last_seen\":%lld}", online ? "true" : "false", (long long)last_seen);
    if (!b.oom) srv_broadcast(b.data, b.len, NULL);
    sb_free(&b);
}

void chat_on_connect(client_t *c, const char *user)
{
    sb_t b; sb_init(&b);
    sb_puts(&b, "{\"type\":\"hello\",\"user\":"); sb_json_str(&b, user); sb_putc(&b, '}');
    send_sb(c, &b);
    send_users(c);

    conv_summary_t *s = NULL;
    size_t n = store_summaries(user, &s);
    if (s) {
        send_convs(c, s, n);
        /* Everything addressed to this user is now delivered: advance watermarks, tell the senders. */
        for (size_t i = 1; i < n; i++)
            if (s[i].last_in_id > s[i].delivered &&
                store_mark_delivered(s[i].with, user, s[i].last_in_id))
                send_receipt(s[i].with, user, "delivered", s[i].last_in_id);
        free(s);
    }
    send_history(c, user, "", 0);
    if (srv_user_conn_count(user) == 1) presence(user, 1, 0);
}

void chat_on_disconnect(const char *user)
{
    if (srv_user_conn_count(user) == 0) {
        int64_t now = wall_ms();
        store_set_last_seen(user, now);
        presence(user, 0, now);
    }
}

void chat_on_register(const char *user) { presence(user, 0, 0); }

void chat_on_text(client_t *c, const char *user, const char *text, size_t len)
{
    char type[16], to[64], with[64], body[MSG_MAX_BYTES + 1], upto[24], before[24], reply[24], mid[24];
    json_field_t f[8] = {
        { "type", type, sizeof type, 0 }, { "to", to, sizeof to, 0 },
        { "with", with, sizeof with, 0 }, { "text", body, sizeof body, 0 },
        { "upto", upto, sizeof upto, 0 }, { "before", before, sizeof before, 0 },
        { "reply", reply, sizeof reply, 0 }, { "id", mid, sizeof mid, 0 },
    };
    int r = json_parse_fields(text, len, f, 8);
    if (r == JSON_TOO_LONG) { send_error(c, "Message too long (max 1000 bytes)"); return; }
    if (r != JSON_OK || !f[0].found) { send_error(c, "Malformed message"); return; }

    /* Identity always comes from the authenticated session, never from the payload. */
    if (!strcmp(type, "msg")) {
        if (!f[3].found) { send_error(c, "Missing text"); return; }
        size_t bl = strlen(body);
        if (has_control_chars(body, bl)) { send_error(c, "Message contains control characters"); return; }
        char *t = str_trim(body);
        if (!*t) return;                                   /* blank: ignore */

        const char *target = "";
        if (f[1].found && to[0]) {
            target = auth_canonical(to);
            if (!target) { send_error(c, "No such user"); return; }
            if (!strcmp(target, user)) { send_error(c, "You can't message yourself"); return; }
        }
        uint64_t rid = 0;                                   /* optional: quote another message */
        if (f[6].found && reply[0]) {
            if (parse_u64(reply, &rid) < 0 || !store_reply_ok(user, target, rid)) {
                send_error(c, "Can't reply to that message"); return;
            }
        }
        int64_t ts = wall_ms();
        uint64_t id = 0;
        if (store_add(user, target, t, ts, rid, &id) < 0) { send_error(c, "Could not store message"); return; }

        sb_t b; sb_init(&b);
        sb_printf(&b, "{\"type\":\"msg\",\"id\":\"%llu\",\"from\":", (unsigned long long)id);
        sb_json_str(&b, user);
        sb_puts(&b, ",\"to\":"); sb_json_str(&b, target);
        sb_puts(&b, ",\"text\":"); sb_json_str(&b, t);
        sb_printf(&b, ",\"ts\":%lld", (long long)ts);
        if (rid) { sb_puts(&b, ",\"reply\":"); store_reply_json(&b, rid); }
        sb_putc(&b, '}');
        if (!b.oom) {
            if (!target[0]) srv_broadcast(b.data, b.len, NULL);
            else { srv_send_user(target, b.data, b.len); srv_send_user(user, b.data, b.len); }
        }
        sb_free(&b);
        /* Recipient has a live connection: it is delivered right away. */
        if (target[0] && srv_user_conn_count(target) > 0 && store_mark_delivered(user, target, id))
            send_receipt(user, target, "delivered", id);
    } else if (!strcmp(type, "history")) {
        const char *w = "";
        uint64_t bid = 0;
        if (f[2].found && with[0]) {
            w = auth_canonical(with);
            if (!w || !strcmp(w, user)) { send_error(c, "No such user"); return; }
        }
        if (f[5].found && before[0] && parse_u64(before, &bid) < 0) { send_error(c, "Bad id"); return; }
        send_history(c, user, w, bid);
    } else if (!strcmp(type, "delete")) {
        /* {"type":"delete","id":"<id>"}: delete one of my own messages for everyone */
        uint64_t did;
        if (!f[7].found || parse_u64(mid, &did) < 0) { send_error(c, "Bad id"); return; }
        char dto[USERNAME_MAX + 1];
        int dr = store_delete(user, did, dto);
        if (dr == -1) { send_error(c, "No such message"); return; }
        if (dr == -2) { send_error(c, "You can only delete your own messages"); return; }
        sb_t b; sb_init(&b);
        sb_printf(&b, "{\"type\":\"deleted\",\"id\":\"%llu\",\"from\":", (unsigned long long)did);
        sb_json_str(&b, user);
        sb_puts(&b, ",\"to\":"); sb_json_str(&b, dto); sb_putc(&b, '}');
        if (!b.oom) {
            if (!dto[0]) srv_broadcast(b.data, b.len, NULL);
            else { srv_send_user(dto, b.data, b.len); srv_send_user(user, b.data, b.len); }
        }
        sb_free(&b);
    } else if (!strcmp(type, "read")) {
        /* {"type":"read","with":"bob"|"","upto":"<id>"}: I have read everything `with` sent me up to id. */
        if (!srv_light_ok(c)) return;                      /* over the (generous) receipt budget: drop */
        uint64_t uid;
        if (!f[4].found || parse_u64(upto, &uid) < 0) { send_error(c, "Bad id"); return; }
        const char *w = "";
        if (f[2].found && with[0]) {
            w = auth_canonical(with);
            if (!w || !strcmp(w, user)) { send_error(c, "No such user"); return; }
        }
        /* Clamp to what actually exists, so a client can't pre-mark future messages as read. */
        uint64_t last = store_last_id(w, user);
        uint64_t eff = uid < last ? uid : last;
        if (eff == 0 || !store_mark_read(w, user, eff)) return;
        if (w[0]) send_receipt(w, user, "read", eff);      /* no read ticks for the group room */
        send_unread(user, w);
    } else if (!strcmp(type, "typing")) {
        sb_t b; sb_init(&b);
        const char *target = "";
        if (f[1].found && to[0]) {
            target = auth_canonical(to);
            if (!target || !strcmp(target, user)) { sb_free(&b); return; }
        }
        sb_puts(&b, "{\"type\":\"typing\",\"from\":"); sb_json_str(&b, user);
        sb_puts(&b, ",\"to\":"); sb_json_str(&b, target); sb_putc(&b, '}');
        if (!b.oom) {
            if (!target[0]) srv_broadcast(b.data, b.len, user);
            else srv_send_user(target, b.data, b.len);
        }
        sb_free(&b);
    } else if (!strcmp(type, "users")) {
        send_users(c);
    } else {
        send_error(c, "Unknown message type");
    }
}
