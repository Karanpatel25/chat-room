#ifndef UTIL_H
#define UTIL_H

#include <stddef.h>
#include <stdint.h>

/* ---- growable string/byte buffer ---- */
typedef struct {
    char  *data;
    size_t len;
    size_t cap;
    int    oom;
} sb_t;

void sb_init(sb_t *b);
void sb_free(sb_t *b);
void sb_reset(sb_t *b);
void sb_append(sb_t *b, const void *s, size_t n);
void sb_puts(sb_t *b, const char *s);
void sb_putc(sb_t *b, char c);
void sb_printf(sb_t *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
/* Append s as a quoted, escaped JSON string. */
void sb_json_str(sb_t *b, const char *s);

/* ---- randomness / encoding / comparison ---- */
int  rand_bytes(uint8_t *buf, size_t n);                  /* 0 on success (/dev/urandom) */
void hex_encode(const uint8_t *in, size_t n, char *out);  /* out: 2n+1 bytes */
int  hex_decode(const char *hex, uint8_t *out, size_t n); /* 0 ok; hex must be exactly 2n chars */
int  ct_equal(const void *a, const void *b, size_t n);    /* constant time, 1 if equal */
void secure_zero(void *p, size_t n);

/* ---- validation ---- */
int  utf8_valid(const char *s, size_t n);
int  has_control_chars(const char *s, size_t n);          /* bytes <0x20 or 0x7f */
int  parse_u64(const char *s, uint64_t *out);             /* strict decimal, 1-18 digits; 0 ok, -1 bad */
size_t utf8_trunc_len(const char *s, size_t n, size_t max); /* longest prefix <= max bytes ending on a char boundary */
#define USERNAME_MIN 3
#define USERNAME_MAX 24
int  valid_username(const char *s);                       /* [A-Za-z0-9_-]{3,24} */

/* ---- time ---- */
int64_t mono_ms(void);   /* monotonic, for timers */
int64_t wall_ms(void);   /* unix epoch ms, for timestamps */

/* ---- misc ---- */
char *str_trim(char *s);                                  /* in place; returns pointer into s */
void  str_lower(char *s);

#endif
