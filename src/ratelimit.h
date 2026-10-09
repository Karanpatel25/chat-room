#ifndef RATELIMIT_H
#define RATELIMIT_H
#include <stdint.h>

#define RL_SLOTS 512
#define RL_KEYLEN 64

/* Fixed-window counter keyed by string (IP, username...). Fixed size: oldest
   entries are evicted, so memory use can't be inflated by an attacker. */
typedef struct {
    struct { char key[RL_KEYLEN]; int count; int64_t start_ms; } e[RL_SLOTS];
} rl_t;

void rl_init(rl_t *rl);
int  rl_blocked(rl_t *rl, const char *key, int max, int window_sec);   /* 1 if over the limit */
void rl_hit(rl_t *rl, const char *key, int window_sec);                /* record one event */
void rl_reset(rl_t *rl, const char *key);                              /* forget key */
#endif
