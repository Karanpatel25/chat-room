#include "ws.h"
#include "sha1.h"
#include "base64.h"
#include <stdio.h>
#include <string.h>

void ws_accept_key(const char *client_key, char out[29])
{
    char combined[128];
    uint8_t digest[20];
    snprintf(combined, sizeof combined, "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", client_key);
    sha1((const uint8_t *)combined, strlen(combined), digest);
    base64_encode(digest, 20, out);
}

size_t ws_frame_header(int opcode, size_t n, uint8_t hdr[10])
{
    hdr[0] = (uint8_t)(0x80 | (opcode & 0x0f));
    if (n < 126) { hdr[1] = (uint8_t)n; return 2; }
    if (n < 65536) { hdr[1] = 126; hdr[2] = (uint8_t)(n >> 8); hdr[3] = (uint8_t)n; return 4; }
    hdr[1] = 127;
    for (int i = 0; i < 8; i++) hdr[2 + i] = (uint8_t)((uint64_t)n >> (8 * (7 - i)));
    return 10;
}

int ws_parse(const uint8_t *buf, size_t len, size_t max_payload, ws_frame_t *f, int *close_code)
{
    if (len < 2) return 0;
    int rsv = buf[0] & 0x70;
    f->fin = (buf[0] & 0x80) != 0;
    f->opcode = buf[0] & 0x0f;
    int masked = (buf[1] & 0x80) != 0;
    uint64_t plen = buf[1] & 0x7f;
    size_t hl = 2;

    *close_code = 1002;
    if (rsv) return -1;
    if (!(f->opcode == WS_CONT || f->opcode == WS_TEXT || f->opcode == WS_BINARY ||
          f->opcode == WS_CLOSE || f->opcode == WS_PING || f->opcode == WS_PONG)) return -1;
    if (!masked) return -1;                      /* RFC 6455: clients MUST mask */

    if (plen == 126) {
        if (len < 4) return 0;
        plen = (uint64_t)buf[2] << 8 | buf[3];
        if (plen < 126) return -1;               /* non-minimal encoding */
        hl = 4;
    } else if (plen == 127) {
        if (len < 10) return 0;
        plen = 0;
        for (int i = 0; i < 8; i++) plen = (plen << 8) | buf[2 + i];
        if (plen >> 63) return -1;
        if (plen < 65536) return -1;
        hl = 10;
    }
    if (f->opcode >= 0x8 && (plen > 125 || !f->fin)) return -1;   /* control frame rules */
    if (plen > max_payload) { *close_code = 1009; return -1; }

    hl += 4;
    if (len < hl) return 0;
    memcpy(f->mask, buf + hl - 4, 4);
    f->header_len = hl;
    f->payload_len = (size_t)plen;
    if (len < hl + (size_t)plen) return 0;
    return 1;
}

void ws_unmask(uint8_t *p, size_t n, const uint8_t mask[4])
{
    for (size_t i = 0; i < n; i++) p[i] ^= mask[i & 3];
}
