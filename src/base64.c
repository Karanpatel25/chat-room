#include "base64.h"

static const char T[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

size_t base64_encode(const uint8_t *src, size_t len, char *dest)
{
    size_t o = 0, i = 0;
    for (; i + 3 <= len; i += 3) {
        uint32_t v = (uint32_t)src[i] << 16 | (uint32_t)src[i+1] << 8 | src[i+2];
        dest[o++] = T[v >> 18]; dest[o++] = T[(v >> 12) & 63];
        dest[o++] = T[(v >> 6) & 63]; dest[o++] = T[v & 63];
    }
    if (len - i == 1) {
        uint32_t v = (uint32_t)src[i] << 16;
        dest[o++] = T[v >> 18]; dest[o++] = T[(v >> 12) & 63];
        dest[o++] = '='; dest[o++] = '=';
    } else if (len - i == 2) {
        uint32_t v = (uint32_t)src[i] << 16 | (uint32_t)src[i+1] << 8;
        dest[o++] = T[v >> 18]; dest[o++] = T[(v >> 12) & 63];
        dest[o++] = T[(v >> 6) & 63]; dest[o++] = '=';
    }
    dest[o] = '\0';
    return o;
}
