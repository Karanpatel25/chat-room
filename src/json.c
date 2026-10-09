#include "json.h"
#include <string.h>
#include <stdint.h>

#define MAX_DEPTH 8

typedef struct { const char *p, *end; } cur_t;

static void skip_ws(cur_t *c)
{
    while (c->p < c->end && (*c->p == ' ' || *c->p == '\t' || *c->p == '\n' || *c->p == '\r')) c->p++;
}

static int hex4(const char *p, uint32_t *out)
{
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) {
        char ch = p[i];
        v <<= 4;
        if (ch >= '0' && ch <= '9') v |= (uint32_t)(ch - '0');
        else if (ch >= 'a' && ch <= 'f') v |= (uint32_t)(ch - 'a' + 10);
        else if (ch >= 'A' && ch <= 'F') v |= (uint32_t)(ch - 'A' + 10);
        else return -1;
    }
    *out = v;
    return 0;
}

static size_t put_utf8(uint32_t cp, char *o)
{
    if (cp < 0x80)    { o[0] = (char)cp; return 1; }
    if (cp < 0x800)   { o[0] = (char)(0xC0 | cp >> 6); o[1] = (char)(0x80 | (cp & 0x3F)); return 2; }
    if (cp < 0x10000) { o[0] = (char)(0xE0 | cp >> 12); o[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
                        o[2] = (char)(0x80 | (cp & 0x3F)); return 3; }
    o[0] = (char)(0xF0 | cp >> 18); o[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
    o[2] = (char)(0x80 | ((cp >> 6) & 0x3F)); o[3] = (char)(0x80 | (cp & 0x3F));
    return 4;
}

/* Parse a string at c->p (which must be at the opening quote).
   If out != NULL decode into it (cap bytes incl. NUL).
   Returns JSON_OK, JSON_MALFORMED or JSON_TOO_LONG. */
static int parse_string(cur_t *c, char *out, size_t cap)
{
    if (c->p >= c->end || *c->p != '"') return JSON_MALFORMED;
    c->p++;
    size_t o = 0;
    int too_long = 0;
    while (c->p < c->end) {
        unsigned char ch = (unsigned char)*c->p++;
        if (ch == '"') {
            if (out) {
                if (too_long) return JSON_TOO_LONG;
                out[o] = '\0';
            }
            return JSON_OK;
        }
        if (ch < 0x20) return JSON_MALFORMED;           /* raw control chars are illegal */
        char tmp[4]; size_t tl = 0;
        if (ch == '\\') {
            if (c->p >= c->end) return JSON_MALFORMED;
            char e = *c->p++;
            switch (e) {
            case '"': tmp[0] = '"';  tl = 1; break;
            case '\\': tmp[0] = '\\'; tl = 1; break;
            case '/': tmp[0] = '/';  tl = 1; break;
            case 'b': tmp[0] = '\b'; tl = 1; break;
            case 'f': tmp[0] = '\f'; tl = 1; break;
            case 'n': tmp[0] = '\n'; tl = 1; break;
            case 'r': tmp[0] = '\r'; tl = 1; break;
            case 't': tmp[0] = '\t'; tl = 1; break;
            case 'u': {
                uint32_t cp;
                if (c->end - c->p < 4 || hex4(c->p, &cp) < 0) return JSON_MALFORMED;
                c->p += 4;
                if (cp >= 0xD800 && cp <= 0xDBFF) {              /* high surrogate */
                    uint32_t lo;
                    if (c->end - c->p < 6 || c->p[0] != '\\' || c->p[1] != 'u' || hex4(c->p + 2, &lo) < 0
                        || lo < 0xDC00 || lo > 0xDFFF) return JSON_MALFORMED;
                    c->p += 6;
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                    return JSON_MALFORMED;                       /* lone low surrogate */
                }
                if (cp == 0) return JSON_MALFORMED;              /* no embedded NULs */
                tl = put_utf8(cp, tmp);
                break;
            }
            default: return JSON_MALFORMED;
            }
        } else {
            tmp[0] = (char)ch; tl = 1;
        }
        if (out) {
            if (o + tl >= cap) too_long = 1;
            else { memcpy(out + o, tmp, tl); o += tl; }
        }
    }
    return JSON_MALFORMED; /* unterminated */
}

static int skip_value(cur_t *c, int depth);

static int skip_container(cur_t *c, int depth, char close, int is_obj)
{
    if (depth > MAX_DEPTH) return JSON_MALFORMED;
    c->p++; /* opening bracket */
    skip_ws(c);
    if (c->p < c->end && *c->p == close) { c->p++; return JSON_OK; }
    for (;;) {
        skip_ws(c);
        if (is_obj) {
            if (parse_string(c, NULL, 0) != JSON_OK) return JSON_MALFORMED;
            skip_ws(c);
            if (c->p >= c->end || *c->p != ':') return JSON_MALFORMED;
            c->p++;
            skip_ws(c);
        }
        if (skip_value(c, depth + 1) != JSON_OK) return JSON_MALFORMED;
        skip_ws(c);
        if (c->p >= c->end) return JSON_MALFORMED;
        if (*c->p == ',') { c->p++; continue; }
        if (*c->p == close) { c->p++; return JSON_OK; }
        return JSON_MALFORMED;
    }
}

static int skip_value(cur_t *c, int depth)
{
    if (c->p >= c->end) return JSON_MALFORMED;
    char ch = *c->p;
    if (ch == '"') return parse_string(c, NULL, 0) == JSON_OK ? JSON_OK : JSON_MALFORMED;
    if (ch == '{') return skip_container(c, depth, '}', 1);
    if (ch == '[') return skip_container(c, depth, ']', 0);
    if (c->end - c->p >= 4 && strncmp(c->p, "true", 4) == 0)  { c->p += 4; return JSON_OK; }
    if (c->end - c->p >= 5 && strncmp(c->p, "false", 5) == 0) { c->p += 5; return JSON_OK; }
    if (c->end - c->p >= 4 && strncmp(c->p, "null", 4) == 0)  { c->p += 4; return JSON_OK; }
    /* number */
    const char *s = c->p;
    if (*c->p == '-') c->p++;
    if (c->p >= c->end || *c->p < '0' || *c->p > '9') return JSON_MALFORMED;
    while (c->p < c->end && ((*c->p >= '0' && *c->p <= '9') || *c->p == '.' || *c->p == 'e' ||
                             *c->p == 'E' || *c->p == '+' || *c->p == '-')) c->p++;
    return c->p > s ? JSON_OK : JSON_MALFORMED;
}

int json_parse_fields(const char *s, size_t n, json_field_t *fields, size_t nfields)
{
    cur_t c = { s, s + n };
    char keybuf[64];
    for (size_t i = 0; i < nfields; i++) fields[i].found = 0;

    skip_ws(&c);
    if (c.p >= c.end || *c.p != '{') return JSON_MALFORMED;
    c.p++;
    skip_ws(&c);
    if (c.p < c.end && *c.p == '}') { c.p++; goto done; }

    for (;;) {
        skip_ws(&c);
        int r = parse_string(&c, keybuf, sizeof keybuf);
        if (r == JSON_TOO_LONG) {                 /* key too long to be one we want: re-parse as skip */
            return JSON_MALFORMED;
        }
        if (r != JSON_OK) return JSON_MALFORMED;
        skip_ws(&c);
        if (c.p >= c.end || *c.p != ':') return JSON_MALFORMED;
        c.p++;
        skip_ws(&c);

        json_field_t *f = NULL;
        for (size_t i = 0; i < nfields; i++)
            if (strcmp(fields[i].key, keybuf) == 0) { f = &fields[i]; break; }

        if (f && c.p < c.end && *c.p == '"') {
            if (f->found) return JSON_MALFORMED;  /* duplicate key: ambiguous, reject */
            r = parse_string(&c, f->out, f->cap);
            if (r != JSON_OK) return r;
            f->found = 1;
        } else {
            if (f && f->found) return JSON_MALFORMED;
            if (skip_value(&c, 1) != JSON_OK) return JSON_MALFORMED;
        }
        skip_ws(&c);
        if (c.p >= c.end) return JSON_MALFORMED;
        if (*c.p == ',') { c.p++; continue; }
        if (*c.p == '}') { c.p++; break; }
        return JSON_MALFORMED;
    }
done:
    skip_ws(&c);
    return c.p == c.end ? JSON_OK : JSON_MALFORMED;   /* no trailing garbage */
}
