#ifndef WS_H
#define WS_H
#include <stddef.h>
#include <stdint.h>

#define WS_CONT   0x0
#define WS_TEXT   0x1
#define WS_BINARY 0x2
#define WS_CLOSE  0x8
#define WS_PING   0x9
#define WS_PONG   0xA

typedef struct {
    int    fin;
    int    opcode;
    size_t header_len;
    size_t payload_len;
    uint8_t mask[4];
} ws_frame_t;

/* out must hold 29 bytes. */
void   ws_accept_key(const char *client_key, char out[29]);
/* Writes a server (unmasked) frame header; returns its length (2..10). */
size_t ws_frame_header(int opcode, size_t payload_len, uint8_t hdr[10]);
/* Parse one client frame from buf.
   1  = complete frame available (total size = header_len + payload_len)
   0  = need more data
   -1 = protocol violation; *close_code is the close status to send. */
int    ws_parse(const uint8_t *buf, size_t len, size_t max_payload, ws_frame_t *f, int *close_code);
void   ws_unmask(uint8_t *payload, size_t n, const uint8_t mask[4]);
#endif
