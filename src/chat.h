#ifndef CHAT_H
#define CHAT_H
#include <stddef.h>
#include "server.h"

void chat_on_connect(client_t *c, const char *user);
void chat_on_disconnect(const char *user);          /* called after the connection was removed */
void chat_on_register(const char *user);            /* a new account exists */
/* Handle one complete, UTF-8-valid, NUL-terminated text frame from an authenticated client. */
void chat_on_text(client_t *c, const char *user, const char *text, size_t len);
#endif
