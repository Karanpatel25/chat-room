#include "ratelimit.h"
#include "util.h"
#include <string.h>

void rl_init(rl_t *rl) { memset(rl, 0, sizeof *rl); }

static int find(rl_t *rl, const char *key)
{
    for (int i = 0; i < RL_SLOTS; i++)
        if (rl->e[i].key[0] && strncmp(rl->e[i].key, key, RL_KEYLEN - 1) == 0) return i;
    return -1;
}

int rl_blocked(rl_t *rl, const char *key, int max, int window_sec)
{
    int i = find(rl, key);
    if (i < 0) return 0;
    if (mono_ms() - rl->e[i].start_ms > (int64_t)window_sec * 1000) { rl->e[i].key[0] = '\0'; return 0; }
    return rl->e[i].count >= max;
}

void rl_hit(rl_t *rl, const char *key, int window_sec)
{
    int64_t now = mono_ms();
    int i = find(rl, key);
    if (i >= 0 && now - rl->e[i].start_ms > (int64_t)window_sec * 1000) { rl->e[i].key[0] = '\0'; i = -1; }
    if (i < 0) {
        int oldest = 0;
        for (int j = 0; j < RL_SLOTS; j++) {
            if (!rl->e[j].key[0]) { oldest = j; break; }
            if (rl->e[j].start_ms < rl->e[oldest].start_ms) oldest = j;
        }
        i = oldest;
        memset(&rl->e[i], 0, sizeof rl->e[i]);
        strncpy(rl->e[i].key, key, RL_KEYLEN - 1);
        rl->e[i].start_ms = now;
    }
    rl->e[i].count++;
}

void rl_reset(rl_t *rl, const char *key)
{
    int i = find(rl, key);
    if (i >= 0) rl->e[i].key[0] = '\0';
}
