#ifndef BASE64_H
#define BASE64_H
#include <stddef.h>
#include <stdint.h>
/* dest must hold 4*((len+2)/3)+1 bytes. Returns chars written (NUL-terminated). */
size_t base64_encode(const uint8_t *src, size_t len, char *dest);
#endif
