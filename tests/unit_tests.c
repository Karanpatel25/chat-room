#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "sha256.h"
#include "sha1.h"
#include "base64.h"
#include "ws.h"
#include "json.h"
#include "util.h"
#include "ratelimit.h"
#include "store.h"
#include "auth.h"
#include <unistd.h>

static int fails, total;
#define CHECK(c) do { total++; if (!(c)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } } while (0)

static void hexs(const uint8_t *b, size_t n, char *o) { hex_encode(b, n, o); }

static void test_sha(void)
{
    uint8_t d[32]; char h[65];
    sha256("abc", 3, d); hexs(d, 32, h);
    CHECK(!strcmp(h, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    sha256("", 0, d); hexs(d, 32, h);
    CHECK(!strcmp(h, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    const char *two = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    sha256(two, strlen(two), d); hexs(d, 32, h);
    CHECK(!strcmp(h, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));

    uint8_t s1[20]; char h1[41];
    sha1((const uint8_t *)"abc", 3, s1); hexs(s1, 20, h1);
    CHECK(!strcmp(h1, "a9993e364706816aba3e25717850c26c9cd0d89d"));

    /* HMAC RFC 4231 test case 2 */
    hmac_sha256((const uint8_t *)"Jefe", 4, (const uint8_t *)"what do ya want for nothing?", 28, d); hexs(d, 32, h);
    CHECK(!strcmp(h, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));

    /* PBKDF2-HMAC-SHA256 vectors */
    pbkdf2_sha256((const uint8_t *)"password", 8, (const uint8_t *)"salt", 4, 1, d, 32); hexs(d, 32, h);
    CHECK(!strcmp(h, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"));
    pbkdf2_sha256((const uint8_t *)"password", 8, (const uint8_t *)"salt", 4, 4096, d, 32); hexs(d, 32, h);
    CHECK(!strcmp(h, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"));
}

static void test_ws_key(void)
{
    char out[29];
    ws_accept_key("dGhlIHNhbXBsZSBub25jZQ==", out);
    CHECK(!strcmp(out, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));   /* RFC 6455 section 1.3 */
}

static void test_ws_parse(void)
{
    ws_frame_t f; int code;
    /* masked "Hello" from RFC 6455 section 5.7 */
    uint8_t hello[] = { 0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58 };
    CHECK(ws_parse(hello, sizeof hello, 8192, &f, &code) == 1);
    ws_unmask(hello + f.header_len, f.payload_len, f.mask);
    CHECK(f.payload_len == 5 && memcmp(hello + f.header_len, "Hello", 5) == 0);
    CHECK(ws_parse(hello, 5, 8192, &f, &code) == 0);                 /* truncated */
    uint8_t unmasked[] = { 0x81, 0x01, 'a' };
    CHECK(ws_parse(unmasked, sizeof unmasked, 8192, &f, &code) == -1);   /* must be masked */
    uint8_t rsv[] = { 0xC1, 0x81, 0, 0, 0, 0, 'a' };
    CHECK(ws_parse(rsv, sizeof rsv, 8192, &f, &code) == -1);
    uint8_t big[] = { 0x81, 0xFE, 0xFF, 0xFF, 0, 0, 0, 0 };            /* 65535 > limit */
    CHECK(ws_parse(big, sizeof big, 8192, &f, &code) == -1 && code == 1009);
    uint8_t ping_frag[] = { 0x09, 0x80, 0, 0, 0, 0 };                    /* control frame without FIN */
    CHECK(ws_parse(ping_frag, sizeof ping_frag, 8192, &f, &code) == -1);
    uint8_t hdr[10];
    CHECK(ws_frame_header(WS_TEXT, 5, hdr) == 2 && hdr[0] == 0x81 && hdr[1] == 5);
    CHECK(ws_frame_header(WS_TEXT, 300, hdr) == 4 && hdr[1] == 126);
    CHECK(ws_frame_header(WS_TEXT, 70000, hdr) == 10 && hdr[1] == 127);
}

static void test_json(void)
{
    char type[16], text[32], name[8];
    json_field_t f[3] = { {"type", type, sizeof type, 0}, {"text", text, sizeof text, 0}, {"name", name, sizeof name, 0} };
    const char *ok = "{\"type\":\"msg\",\"x\":{\"type\":\"evil\",\"a\":[1,2,{\"b\":null}]},\"text\":\"h\\u00e9llo \\\"q\\\"\\n\"}";
    CHECK(json_parse_fields(ok, strlen(ok), f, 3) == JSON_OK);
    CHECK(f[0].found && !strcmp(type, "msg"));                         /* nested "type" must be ignored */
    CHECK(f[1].found && !strcmp(text, "h\xc3\xa9llo \"q\"\n"));
    CHECK(!f[2].found);

    const char *dup = "{\"type\":\"a\",\"type\":\"b\"}";
    CHECK(json_parse_fields(dup, strlen(dup), f, 3) == JSON_MALFORMED);
    const char *trailing = "{\"type\":\"a\"} x";
    CHECK(json_parse_fields(trailing, strlen(trailing), f, 3) == JSON_MALFORMED);
    const char *trunc = "{\"type\":\"a";
    CHECK(json_parse_fields(trunc, strlen(trunc), f, 3) == JSON_MALFORMED);
    const char *nul = "{\"type\":\"a\\u0000b\"}";
    CHECK(json_parse_fields(nul, strlen(nul), f, 3) == JSON_MALFORMED);
    const char *lone = "{\"type\":\"\\ud800\"}";
    CHECK(json_parse_fields(lone, strlen(lone), f, 3) == JSON_MALFORMED);
    const char *emoji = "{\"type\":\"\\ud83d\\ude00\"}";
    CHECK(json_parse_fields(emoji, strlen(emoji), f, 3) == JSON_OK && !strcmp(type, "\xf0\x9f\x98\x80"));
    const char *longv = "{\"name\":\"abcdefghijkl\"}";
    CHECK(json_parse_fields(longv, strlen(longv), f, 3) == JSON_TOO_LONG);
    const char *notobj = "[1,2]";
    CHECK(json_parse_fields(notobj, strlen(notobj), f, 3) == JSON_MALFORMED);
    char deep[200]; memset(deep, '[', 100); deep[100] = 0;
    char doc[300]; snprintf(doc, sizeof doc, "{\"a\":%s}", deep);
    CHECK(json_parse_fields(doc, strlen(doc), f, 3) == JSON_MALFORMED); /* depth bomb */
}

static void test_util(void)
{
    CHECK(utf8_valid("h\xc3\xa9llo", 6));
    CHECK(!utf8_valid("\xc0\xaf", 2));          /* overlong */
    CHECK(!utf8_valid("\xed\xa0\x80", 3));      /* surrogate */
    CHECK(!utf8_valid("\xf4\x90\x80\x80", 4));  /* > U+10FFFF */
    CHECK(!utf8_valid("\xe2\x82", 2));          /* truncated */
    CHECK(valid_username("alice_01") && valid_username("A-b"));
    CHECK(!valid_username("ab") && !valid_username("has space") && !valid_username("a:b") && !valid_username("<script>"));
    CHECK(has_control_chars("a\tb", 3) && !has_control_chars("ab", 2));

    sb_t b; sb_init(&b);
    sb_json_str(&b, "a\"b\\c\n\x01");
    CHECK(!strcmp(b.data, "\"a\\\"b\\\\c\\n\\u0001\""));
    sb_free(&b);

    uint8_t raw[4] = { 0xde, 0xad, 0xbe, 0xef }, back[4]; char hx[9];
    hex_encode(raw, 4, hx);
    CHECK(!strcmp(hx, "deadbeef") && hex_decode(hx, back, 4) == 0 && !memcmp(raw, back, 4));
    CHECK(hex_decode("zz", back, 1) == -1);
}

static void test_ratelimit(void)
{
    static rl_t rl;
    rl_init(&rl);
    for (int i = 0; i < 3; i++) { CHECK(!rl_blocked(&rl, "k", 3, 60)); rl_hit(&rl, "k", 60); }
    CHECK(rl_blocked(&rl, "k", 3, 60));
    CHECK(!rl_blocked(&rl, "other", 3, 60));
    rl_reset(&rl, "k");
    CHECK(!rl_blocked(&rl, "k", 3, 60));
    for (int i = 0; i < RL_SLOTS * 3; i++) { char k[32]; snprintf(k, sizeof k, "flood%d", i); rl_hit(&rl, k, 60); }
    CHECK(1); /* no overflow / crash when flooded with unique keys */
}


static void test_ids_and_trunc(void)
{
    uint64_t v = 7;
    CHECK(parse_u64("0", &v) == 0 && v == 0);
    CHECK(parse_u64("123456789012345678", &v) == 0 && v == 123456789012345678ULL);
    CHECK(parse_u64("", &v) == -1 && parse_u64("12a", &v) == -1 && parse_u64("-1", &v) == -1);
    CHECK(parse_u64("1234567890123456789", &v) == -1);                 /* 19 digits: could overflow */
    CHECK(utf8_trunc_len("hello", 5, 10) == 5 && utf8_trunc_len("hello", 5, 3) == 3);
    CHECK(utf8_trunc_len("h\xc3\xa9llo", 6, 2) == 1);                  /* would split the 2-byte char */
    CHECK(utf8_trunc_len("\xf0\x9f\x98\x80x", 5, 3) == 0);             /* would split a 4-byte emoji */
}

static void test_json_receipt_fields(void)
{
    char type[16], with[64], upto[24];
    json_field_t f[3] = { {"type", type, sizeof type, 0}, {"with", with, sizeof with, 0}, {"upto", upto, sizeof upto, 0} };
    const char *ok = "{\"type\":\"read\",\"with\":\"bob\",\"upto\":\"42\"}";
    CHECK(json_parse_fields(ok, strlen(ok), f, 3) == JSON_OK && f[2].found && !strcmp(upto, "42"));
    const char *num = "{\"type\":\"read\",\"with\":\"bob\",\"upto\":42}";   /* number, not a string: ignored */
    CHECK(json_parse_fields(num, strlen(num), f, 3) == JSON_OK && !f[2].found);
    const char *dup = "{\"upto\":\"1\",\"upto\":\"2\"}";
    CHECK(json_parse_fields(dup, strlen(dup), f, 3) == JSON_MALFORMED);
    const char *big = "{\"upto\":\"1234567890123456789012345\"}";           /* > buffer */
    CHECK(json_parse_fields(big, strlen(big), f, 3) == JSON_TOO_LONG);
}

static int has(const sb_t *b, const char *needle) { return b->data && strstr(b->data, needle) != NULL; }

static void test_store(void)
{
    char dir[] = "/tmp/chat_unit_XXXXXX";
    if (!mkdtemp(dir)) { CHECK(0); return; }
    char p1[300], p2[300];
    snprintf(p1, sizeof p1, "%s/messages.log", dir);
    snprintf(p2, sizeof p2, "%s/receipts.log", dir);

    /* legacy 4-field log (as written by the old server) must still load; ids follow log order */
    FILE *f = fopen(p1, "w");
    fputs("1000\talice\t\told group\n1001\talice\tbob\told dm\nbad line\n1002\tbob\talice\told reply\n", f);
    fclose(f);
    CHECK(store_init(dir) == 0);
    CHECK(store_last_id("", "") == 1 && store_last_id("alice", "bob") == 2 && store_last_id("bob", "alice") == 3);

    uint64_t id = 0;
    CHECK(store_add("alice", "bob", "new dm", 2000, 0, &id) == 0 && id == 4);
    CHECK(store_add("carol", "", "hello group", 2001, 0, &id) == 0 && id == 5);

    /* history: oldest first, own DMs carry status, others' don't, group has no status */
    sb_t b; sb_init(&b); int more = -1;
    store_history_json(&b, "alice", "bob", 50, 0, &more);
    CHECK(more == 0 && has(&b, "\"old dm\"") && has(&b, "\"new dm\"") && has(&b, "\"old reply\""));
    CHECK(has(&b, "\"status\":\"sent\"") && !has(&b, "hello group"));
    CHECK(strstr(b.data, "old dm") < strstr(b.data, "old reply") && strstr(b.data, "old reply") < strstr(b.data, "new dm"));
    sb_free(&b);

    /* receipts: watermarks only move forward; read implies delivered; persisted */
    CHECK(store_mark_delivered("alice", "bob", 2) == 1 && store_mark_delivered("alice", "bob", 2) == 0);
    CHECK(store_mark_delivered("alice", "bob", 1) == 0);
    uint64_t d, r;
    store_receipts("alice", "bob", &d, &r);
    CHECK(d == 2 && r == 0);
    CHECK(store_mark_read("alice", "bob", 4) == 1 && store_mark_read("alice", "bob", 3) == 0);
    store_receipts("alice", "bob", &d, &r);
    CHECK(d == 4 && r == 4);
    sb_init(&b); store_history_json(&b, "alice", "bob", 50, 0, &more);
    CHECK(has(&b, "\"status\":\"read\"") && !has(&b, "\"status\":\"sent\""));
    sb_free(&b);

    /* unread counts + chat list */
    CHECK(store_unread("bob", "alice") == 0);                          /* bob read up to 4 via the watermark */
    CHECK(store_unread("alice", "bob") == 1);                          /* "old reply" never read by alice */
    CHECK(store_unread("alice", "") == 1 && store_unread("carol", "") == 1);   /* group: own msgs never count */
    CHECK(store_mark_read("", "alice", 1) == 1 && store_unread("alice", "") == 1);
    conv_summary_t *s = NULL;
    size_t n = store_summaries("alice", &s);
    CHECK(n == 2 && s && s[0].with[0] == '\0' && !strcmp(s[0].last_text, "hello group") && s[0].unread == 1);
    CHECK(!strcmp(s[1].with, "bob") && !strcmp(s[1].last_text, "new dm") && s[1].unread == 1);
    CHECK(!strcmp(s[1].last_status, "read") && s[1].last_in_id == 3 && s[1].last_id == 4);
    free(s);
    n = store_summaries("dave", &s);                                   /* a user with no conversations */
    CHECK(n == 1 && s && s[0].last_id == 5 && s[0].unread == 2);
    free(s);

    /* last seen */
    CHECK(store_last_seen("bob") == 0);
    store_set_last_seen("bob", 123456789);
    CHECK(store_last_seen("bob") == 123456789);

    /* pagination: 60 more group messages */
    for (int i = 0; i < 60; i++) { char t[32]; snprintf(t, sizeof t, "g%d", i); store_add("alice", "", t, 3000 + i, 0, &id); }
    sb_init(&b); store_history_json(&b, "alice", "", 50, 0, &more);
    CHECK(more == 1 && has(&b, "\"g59\"") && !has(&b, "\"g9\"") && !has(&b, "\"hello group\""));
    sb_free(&b);
    sb_init(&b); store_history_json(&b, "alice", "", 50, id - 9, &more);         /* page older than g50 */
    CHECK(more == 1 && has(&b, "\"g49\"") && !has(&b, "\"g50\""));
    sb_free(&b);
    sb_init(&b); store_history_json(&b, "alice", "", 50, 2, &more);              /* before id 2: only the first group msg */
    CHECK(more == 0 && has(&b, "old group") && !has(&b, "hello group"));
    sb_free(&b);

    /* everything survives a restart */
    store_shutdown();
    CHECK(store_init(dir) == 0);
    store_receipts("alice", "bob", &d, &r);
    CHECK(d == 4 && r == 4 && store_last_seen("bob") == 123456789);
    CHECK(store_last_id("carol", "") == 5 && store_unread("alice", "bob") == 1);
    CHECK(store_add("bob", "alice", "after restart", 9000, 0, &id) == 0 && id == 66);   /* ids continue */
    store_shutdown();
    unlink(p1); unlink(p2); rmdir(dir);
}

static char *slurp(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    char *buf = calloc(1, 1 << 16);
    size_t n = buf ? fread(buf, 1, (1 << 16) - 1, f) : 0;
    if (buf) buf[n] = '\0';
    fclose(f);
    return buf;
}
static int count_lines(const char *s) { int n = 0; for (; s && *s; s++) if (*s == '\n') n++; return n; }

static void test_store_reply_delete(void)
{
    char dir[] = "/tmp/chat_unit2_XXXXXX";
    if (!mkdtemp(dir)) { CHECK(0); return; }
    char p1[300], p2[300];
    snprintf(p1, sizeof p1, "%s/messages.log", dir);
    snprintf(p2, sizeof p2, "%s/receipts.log", dir);
    CHECK(store_init(dir) == 0);

    uint64_t id1, id2, id3, id4;
    CHECK(store_add("alice", "bob", "secret plan", 100, 0, &id1) == 0 && id1 == 1);
    CHECK(store_add("bob", "alice", "ok", 101, id1, &id2) == 0 && id2 == 2);
    CHECK(store_add("carol", "", "group msg", 102, 0, &id3) == 0);

    CHECK(store_reply_ok("bob", "alice", id1) && store_reply_ok("alice", "bob", id1));
    CHECK(!store_reply_ok("carol", "alice", id1));            /* not part of that DM */
    CHECK(!store_reply_ok("bob", "", id1));                   /* DM message can't be quoted in the group */
    CHECK(!store_reply_ok("bob", "alice", 99));

    sb_t b; sb_init(&b); int more;
    store_history_json(&b, "bob", "alice", 50, 0, &more);
    CHECK(has(&b, "\"reply\":{\"id\":\"1\",\"from\":\"alice\",\"text\":\"secret plan\",\"deleted\":false}"));
    sb_free(&b);

    char to[USERNAME_MAX + 1];
    CHECK(store_delete("bob", id1, to) == -2);                /* not the sender */
    CHECK(store_delete("alice", 99, to) == -1);
    CHECK(store_delete("alice", id1, to) == 0 && !strcmp(to, "bob"));
    CHECK(store_delete("alice", id1, to) == -1);              /* already gone */
    CHECK(!store_reply_ok("bob", "alice", id1));              /* can't reply to a deleted message */

    sb_init(&b);
    store_history_json(&b, "bob", "alice", 50, 0, &more);
    CHECK(has(&b, "\"deleted\":true") && !has(&b, "secret plan"));
    sb_free(&b);
    char *log = slurp(p1);
    CHECK(log && !strstr(log, "secret plan") && strstr(log, "(deleted)") && count_lines(log) == 3);   /* line stays: ids don't shift */
    free(log);

    /* deletion + replies survive a restart; ids are unchanged */
    store_shutdown();
    CHECK(store_init(dir) == 0);
    CHECK(store_last_id("alice", "bob") == 1 && store_last_id("bob", "alice") == 2 && !store_reply_ok("bob", "alice", 1));
    sb_init(&b); store_history_json(&b, "bob", "alice", 50, 0, &more);
    CHECK(has(&b, "\"deleted\":true") && !has(&b, "secret plan") && has(&b, "\"text\":\"ok\""));
    sb_free(&b);

    /* a deleted last message shows up as such in the chat list */
    CHECK(store_add("alice", "bob", "oops", 200, 0, &id4) == 0 && id4 == 4);
    CHECK(store_delete("alice", id4, to) == 0);
    conv_summary_t *s = NULL;
    size_t n = store_summaries("alice", &s);
    CHECK(n == 2 && s[1].last_deleted == 1 && s[1].last_text[0] == '\0' && s[1].last_id == 4);
    free(s);

    /* receipts.log compaction: hundreds of watermark moves collapse to a few lines on restart */
    for (uint64_t i = 1; i <= 300; i++) store_mark_read("bob", "alice", i);
    store_set_last_seen("bob", 555);
    char *r = slurp(p2);
    int before = count_lines(r); free(r);
    store_shutdown();
    CHECK(store_init(dir) == 0);
    r = slurp(p2);
    int after = count_lines(r); free(r);
    CHECK(before > 300 && after <= 6);
    uint64_t d, rd;
    store_receipts("bob", "alice", &d, &rd);
    CHECK(rd == 300 && d == 300 && store_last_seen("bob") == 555);
    CHECK(store_delete("alice", id4, to) == -1);              /* the X records survived compaction */

    store_shutdown();
    unlink(p1); unlink(p2); rmdir(dir);
}

static void test_auth_password(void)
{
    char dir[] = "/tmp/chat_unit3_XXXXXX";
    if (!mkdtemp(dir)) { CHECK(0); return; }
    char p[300], canon[USERNAME_MAX + 1];
    CHECK(auth_init(dir) == 0);
    CHECK(auth_register("zed", "correct-horse-1") == AUTH_OK);
    CHECK(auth_register("amy", "another-pass-77") == AUTH_OK);
    CHECK(auth_change_password("zed", "wrong-pass-123", "brand-new-pw-9") == AUTH_BAD_CREDS);
    CHECK(auth_change_password("zed", "correct-horse-1", "short") == AUTH_WEAK_PW);
    CHECK(auth_change_password("zed", "correct-horse-1", "correct-horse-1") == AUTH_WEAK_PW);
    CHECK(auth_change_password("zed", "correct-horse-1", "zed") == AUTH_WEAK_PW);
    CHECK(auth_verify("zed", "correct-horse-1", canon) == 1);           /* failed attempts changed nothing */
    CHECK(auth_change_password("zed", "correct-horse-1", "brand-new-pw-9") == AUTH_OK);
    CHECK(auth_verify("zed", "correct-horse-1", canon) == 0);
    CHECK(auth_verify("zed", "brand-new-pw-9", canon) == 1 && !strcmp(canon, "zed"));
    CHECK(auth_verify("amy", "another-pass-77", canon) == 1);           /* other users untouched */
    CHECK(auth_register("bob2", "pass-for-bob-22") == AUTH_OK);         /* appending still works after the rewrite */

    auth_shutdown();
    CHECK(auth_init(dir) == 0);                                         /* persisted */
    CHECK(auth_verify("zed", "brand-new-pw-9", canon) == 1 && auth_verify("zed", "correct-horse-1", canon) == 0);
    CHECK(auth_verify("amy", "another-pass-77", canon) == 1 && auth_verify("bob2", "pass-for-bob-22", canon) == 1);

    char t1[TOKEN_HEX_LEN + 1], t2[TOKEN_HEX_LEN + 1], t3[TOKEN_HEX_LEN + 1];
    uint8_t h1[SESSION_HASH_LEN];
    CHECK(auth_session_create("zed", t1) == 0 && auth_session_create("zed", t2) == 0 && auth_session_create("amy", t3) == 0);
    CHECK(auth_session_lookup(t1, h1) != NULL);
    CHECK(auth_session_destroy_user("zed", h1) == 1);                   /* keeps t1, drops t2 only */
    CHECK(auth_session_lookup(t1, NULL) && !auth_session_lookup(t2, NULL) && auth_session_lookup(t3, NULL));
    CHECK(auth_session_destroy_user("zed", NULL) == 1 && !auth_session_lookup(t1, NULL) && auth_session_lookup(t3, NULL));

    auth_shutdown();
    snprintf(p, sizeof p, "%s/users.db", dir); unlink(p);
    snprintf(p, sizeof p, "%s/users.db.tmp", dir); unlink(p);
    rmdir(dir);
}

int main(void)
{
    test_sha(); test_ws_key(); test_ws_parse(); test_json(); test_util(); test_ratelimit();
    test_ids_and_trunc(); test_json_receipt_fields(); test_store(); test_store_reply_delete(); test_auth_password();
    printf("%d/%d checks passed\n", total - fails, total);
    return fails ? 1 : 0;
}
