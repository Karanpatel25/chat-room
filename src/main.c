#define _POSIX_C_SOURCE 200809L
#include "server.h"
#include "auth.h"
#include "store.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/stat.h>
#include <errno.h>

static void on_signal(int sig) { (void)sig; server_stop(); }

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [options]\n"
        "  -p PORT        listen port (default 8080)\n"
        "  -b ADDR        bind IPv4 address (default 127.0.0.1; use 0.0.0.0 to expose on the network)\n"
        "  -d DIR         data directory (default ./data)\n"
        "  -w DIR         web root (default ./public)\n"
        "  --secure       mark cookies Secure + send HSTS (use when served over HTTPS via a proxy)\n"
        "  --trust-proxy  take client IP from X-Forwarded-For (only behind a reverse proxy you control)\n", prog);
}

int main(int argc, char **argv)
{
    server_config_t cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.port = 8080;
    snprintf(cfg.bind_addr, sizeof cfg.bind_addr, "127.0.0.1");
    snprintf(cfg.datadir, sizeof cfg.datadir, "./data");
    snprintf(cfg.webroot, sizeof cfg.webroot, "./public");

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-p") && i + 1 < argc) {
            char *end; long p = strtol(argv[++i], &end, 10);
            if (*end || p < 1 || p > 65535) { fprintf(stderr, "Invalid port\n"); return 2; }
            cfg.port = (int)p;
        } else if (!strcmp(argv[i], "-b") && i + 1 < argc) snprintf(cfg.bind_addr, sizeof cfg.bind_addr, "%s", argv[++i]);
        else if (!strcmp(argv[i], "-d") && i + 1 < argc) snprintf(cfg.datadir, sizeof cfg.datadir, "%s", argv[++i]);
        else if (!strcmp(argv[i], "-w") && i + 1 < argc) snprintf(cfg.webroot, sizeof cfg.webroot, "%s", argv[++i]);
        else if (!strcmp(argv[i], "--secure")) cfg.secure_cookie = 1;
        else if (!strcmp(argv[i], "--trust-proxy")) cfg.trust_proxy = 1;
        else { usage(argv[0]); return 2; }
    }

    if (mkdir(cfg.datadir, 0700) < 0 && errno != EEXIST) { perror("mkdir data dir"); return 1; }
    if (auth_init(cfg.datadir) < 0 || store_init(cfg.datadir) < 0) return 1;
    if (server_init(&cfg) < 0) return 1;

    signal(SIGPIPE, SIG_IGN);
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    printf("Chat server listening on http://%s:%d/\n", cfg.bind_addr, cfg.port);
    if (strcmp(cfg.bind_addr, "127.0.0.1") != 0 && !cfg.secure_cookie)
        printf("WARNING: exposed beyond localhost without TLS. Passwords and messages travel in clear text;\n"
               "         put a TLS reverse proxy (nginx/caddy) in front and pass --secure.\n");
    fflush(stdout);

    server_run();

    printf("\nShutting down...\n");
    server_cleanup();
    store_shutdown();
    auth_shutdown();
    return 0;
}
