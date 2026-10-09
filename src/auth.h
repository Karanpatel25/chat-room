#ifndef AUTH_H
#define AUTH_H
#include <stddef.h>
#include <stdint.h>
#include "util.h"

#define MAX_USERS 1000
#define PBKDF2_ITERS 100000
#define SESSION_TTL_MS (24LL * 3600 * 1000)
#define PASSWORD_MIN 8
#define PASSWORD_MAX 128
#define SESSION_HASH_LEN 32
#define TOKEN_HEX_LEN 64

/* Load users from <datadir>/users.db (created if absent). 0 on success. */
int  auth_init(const char *datadir);
void auth_shutdown(void);

enum { AUTH_OK = 0, AUTH_BAD_NAME = -1, AUTH_WEAK_PW = -2, AUTH_EXISTS = -3, AUTH_FULL = -4, AUTH_INTERNAL = -5, AUTH_BAD_CREDS = -6 };
int  auth_register(const char *name, const char *password);
/* Change a password (verifies the old one; rewrites users.db atomically).
   AUTH_OK, AUTH_BAD_CREDS (old password wrong), AUTH_WEAK_PW (see auth_password_problem) or AUTH_INTERNAL. */
int  auth_change_password(const char *name, const char *old_pw, const char *new_pw);
/* Returns 1 if credentials are valid; canonical (stored-case) name copied to canon. */
int  auth_verify(const char *name, const char *password, char canon[USERNAME_MAX + 1]);

/* Case-insensitive lookup. Returns stored-case name or NULL. */
const char *auth_canonical(const char *name);
size_t      auth_user_count(void);
const char *auth_user_at(size_t i);

/* Sessions (in memory). Token is 64 hex chars; only its SHA-256 is kept server-side. */
int  auth_session_create(const char *user, char token_out[TOKEN_HEX_LEN + 1]);
/* Returns user name or NULL. If sess_hash != NULL receives the token hash. */
const char *auth_session_lookup(const char *token, uint8_t sess_hash[SESSION_HASH_LEN]);
int  auth_session_valid(const uint8_t sess_hash[SESSION_HASH_LEN]);
void auth_session_destroy(const char *token);
/* Destroy every session of a user, except the one whose hash is keep (may be NULL). Returns the count. */
int  auth_session_destroy_user(const char *user, const uint8_t keep[SESSION_HASH_LEN]);

/* Returns a weakness description or NULL if acceptable. */
const char *auth_password_problem(const char *name, const char *password);
#endif
