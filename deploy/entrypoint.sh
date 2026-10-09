#!/bin/sh
# Container entrypoint (Render, Fly, plain Docker, ...).
#  - listens on $PORT (Render sets it; defaults to 8080 elsewhere), on all interfaces
#  - stores data in $DATA_DIR; a mounted persistent disk is usually root-owned, so fix ownership first
#  - then drops root and runs the server as the unprivileged "chat" user
set -e
DATA="${DATA_DIR:-/app/data}"
mkdir -p "$DATA"
chown chat:chat "$DATA" 2>/dev/null || true
chmod 700 "$DATA" 2>/dev/null || true
exec setpriv --reuid=chat --regid=chat --clear-groups \
    /app/chat_server -p "${PORT:-8080}" -b 0.0.0.0 -d "$DATA" -w /app/public --secure --trust-proxy
