#ifndef SHA256_H
#define SHA256_H
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t h[8];
    uint8_t  buf[64];
    uint64_t total;
    size_t   blen;
} sha256_ctx;

void sha256_init(sha256_ctx *c);
void sha256_update(sha256_ctx *c, const void *data, size_t len);
void sha256_final(sha256_ctx *c, uint8_t out[32]);
void sha256(const void *data, size_t len, uint8_t out[32]);
void hmac_sha256(const uint8_t *key, size_t klen, const uint8_t *msg, size_t mlen, uint8_t out[32]);
/* PBKDF2-HMAC-SHA256 (RFC 8018) */
void pbkdf2_sha256(const uint8_t *pw, size_t pwlen, const uint8_t *salt, size_t saltlen,
                   uint32_t iters, uint8_t *out, size_t outlen);
#endif
