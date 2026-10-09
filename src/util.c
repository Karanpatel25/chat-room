#define _POSIX_C_SOURCE 200809L
#include "util.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>

void sb_init(sb_t *b) { b->data = NULL; b->len = b->cap = 0; b->oom = 0; }
void sb_free(sb_t *b) { free(b->data); sb_init(b); }
void sb_reset(sb_t *b) { b->len = 0; if (b->data) b->data[0] = '\0'; b->oom = 0; }

static int sb_reserve(sb_t *b, size_t extra)
{
    if (b->oom) return -1;
    size_t need = b->len + extra + 1;
    if (need < b->len) { b->oom = 1; return -1; }
    if (need > b->cap) {
        size_t nc = b->cap ? b->cap : 256;
        while (nc < need) nc *= 2;
        char *p = realloc(b->data, nc);
        if (!p) { b->oom = 1; return -1; }
        b->data = p;
        b->cap = nc;
    }
    return 0;
}

void sb_append(sb_t *b, const void *s, size_t n)
{
    if (sb_reserve(b, n) < 0) return;
    if (n) memcpy(b->data + b->len, s, n);
    b->len += n;
    b->data[b->len] = '\0';
}

void sb_puts(sb_t *b, const char *s) { sb_append(b, s, strlen(s)); }
void sb_putc(sb_t *b, char c) { sb_append(b, &c, 1); }

void sb_printf(sb_t *b, const char *fmt, ...)
{
    va_list ap, ap2;
    va_start(ap, fmt);
    va_copy(ap2, ap);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n > 0 && sb_reserve(b, (size_t)n) == 0) {
        vsnprintf(b->data + b->len, (size_t)n + 1, fmt, ap2);
        b->len += (size_t)n;
    }
    va_end(ap2);
}

void sb_json_str(sb_t *b, const char *s)
{
    static const char hexd[] = "0123456789abcdef";
    sb_putc(b, '"');
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        unsigned char c = *p;
        switch (c) {
        case '"':  sb_puts(b, "\\\""); break;
        case '\\': sb_puts(b, "\\\\"); break;
        case '\n': sb_puts(b, "\\n");  break;
        case '\r': sb_puts(b, "\\r");  break;
        case '\t': sb_puts(b, "\\t");  break;
        default:
            if (c < 0x20 || c == 0x7f) {
                char esc[7] = { '\\', 'u', '0', '0', hexd[c >> 4], hexd[c & 15], 0 };
                sb_puts(b, esc);
            } else {
                sb_putc(b, (char)c);
            }
        }
    }
    sb_putc(b, '"');
}

int rand_bytes(uint8_t *buf, size_t n)
{
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, buf + got, n - got);
        if (r <= 0) { close(fd); return -1; }
        got += (size_t)r;
    }
    close(fd);
    return 0;
}

void hex_encode(const uint8_t *in, size_t n, char *out)
{
    static const char hexd[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i]     = hexd[in[i] >> 4];
        out[2 * i + 1] = hexd[in[i] & 15];
    }
    out[2 * n] = '\0';
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int hex_decode(const char *hex, uint8_t *out, size_t n)
{
    if (strlen(hex) != 2 * n) return -1;
    for (size_t i = 0; i < n; i++) {
        int hi = hexval(hex[2 * i]), lo = hexval(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)(hi << 4 | lo);
    }
    return 0;
}

int ct_equal(const void *a, const void *b, size_t n)
{
    const volatile uint8_t *x = a, *y = b;
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) diff |= (uint8_t)(x[i] ^ y[i]);
    return diff == 0;
}

void secure_zero(void *p, size_t n)
{
    volatile uint8_t *v = p;
    while (n--) *v++ = 0;
}

int utf8_valid(const char *s, size_t n)
{
    const unsigned char *p = (const unsigned char *)s, *end = p + n;
    while (p < end) {
        unsigned char c = *p;
        if (c < 0x80) { p++; continue; }
        size_t extra;
        uint32_t cp;
        if (c >= 0xC2 && c <= 0xDF)      { extra = 1; cp = c & 0x1F; }
        else if (c >= 0xE0 && c <= 0xEF) { extra = 2; cp = c & 0x0F; }
        else if (c >= 0xF0 && c <= 0xF4) { extra = 3; cp = c & 0x07; }
        else return 0;
        if ((size_t)(end - p) <= extra) return 0;
        for (size_t i = 1; i <= extra; i++) {
            if ((p[i] & 0xC0) != 0x80) return 0;
            cp = (cp << 6) | (p[i] & 0x3F);
        }
        if (extra == 2 && (cp < 0x800 || (cp >= 0xD800 && cp <= 0xDFFF))) return 0;
        if (extra == 3 && (cp < 0x10000 || cp > 0x10FFFF)) return 0;
        p += extra + 1;
    }
    return 1;
}

int has_control_chars(const char *s, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x20 || c == 0x7f) return 1;
    }
    return 0;
}

int valid_username(const char *s)
{
    size_t n = strlen(s);
    if (n < USERNAME_MIN || n > USERNAME_MAX) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!(isalnum(c) || c == '_' || c == '-')) return 0;
        if (c >= 0x80) return 0;
    }
    return 1;
}

int64_t mono_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

int64_t wall_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

char *str_trim(char *s)
{
    while (*s == ' ' || *s == '\t') s++;
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t')) s[--n] = '\0';
    return s;
}

void str_lower(char *s)
{
    for (; *s; s++) *s = (char)tolower((unsigned char)*s);
}

int parse_u64(const char *s, uint64_t *out)
{
    size_t n = strlen(s);
    if (n == 0 || n > 18) return -1;
    uint64_t v = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') return -1;
        v = v * 10 + (uint64_t)(s[i] - '0');
    }
    *out = v;
    return 0;
}

size_t utf8_trunc_len(const char *s, size_t n, size_t max)
{
    if (n <= max) return n;
    size_t k = max;
    while (k > 0 && ((unsigned char)s[k] & 0xC0) == 0x80) k--;   /* don't cut inside a multi-byte char */
    return k;
}
