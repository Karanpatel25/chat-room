# Secure Multi-User Chat (C + WebSocket)

A real-time chat server written in C11 with no external dependencies, plus a browser frontend.
One program serves the web page, the JSON API and the WebSocket endpoint.

**Features**

- Accounts: sign up / log in / log out (passwords hashed with PBKDF2-HMAC-SHA256, per-user salt)
- **Group chat** (`# General`) and **personal (1-to-1) chat** with any registered user, online or offline
- Message history for the group and for each private conversation (persisted across restarts)
- Online/offline presence with "last seen", typing indicators, multi-tab / multi-device per account
- **WhatsApp-style chat list**: conversations sorted by latest activity with last-message preview, time and
  unread badge; unread counts are kept on the server, so they survive reloads and sync across tabs/devices
- **Message ticks in private chats**: ✓ sent, ✓✓ delivered (recipient online or has since connected),
  blue ✓✓ read (recipient had the chat open). Receipt state is persisted
- Unread-messages divider, date separators, and "Load older messages" pagination
- **Reply to a message** (quoted in the bubble, click the quote to jump to it) and **delete for everyone**
  (tombstone for both sides; the text is scrubbed from `messages.log` too)
- Messages typed while disconnected are queued, shown dimmed, and sent automatically on reconnect
- Unread count in the tab title, optional desktop notifications, emoji picker
- Settings: change password (logs every other device out) and log out of all devices
- Responsive dark UI

## Build and run

```bash
make                 # release build  -> ./chat_server
./chat_server        # http://127.0.0.1:8080
```

Open the URL in two browsers (or one normal + one private window), sign up as two different users,
and click the other user in the sidebar to start a private chat.

```
Options:
  -p PORT        listen port (default 8080)
  -b ADDR        bind address (default 127.0.0.1 - localhost only)
  -d DIR         data directory (default ./data)
  -w DIR         web root (default ./public)
  --secure       Secure cookies + HSTS (use when served over HTTPS via a proxy)
  --trust-proxy  take client IP from X-Forwarded-For (only behind a proxy you control)
```

Other targets: `make debug` (AddressSanitizer + UBSan), `make test` (unit + end-to-end tests,
needs `python3`), `make clean`.

## Security model

| Area | What is done |
|---|---|
| Passwords | PBKDF2-HMAC-SHA256, 100,000 iterations, 16-byte random salt per user, constant-time compare. Iteration count is stored per user so it can be raised later. Min 8 / max 128 chars, common-password blocklist. Unknown usernames burn the same CPU time, so response timing doesn't reveal which accounts exist. |
| Sessions | 256-bit random token from `/dev/urandom` in an `HttpOnly; SameSite=Strict` cookie (`Secure` with `--secure`). Only the SHA-256 of the token is kept server-side. 24h expiry. New token on every login (no fixation). Logout destroys the session **and closes its live WebSockets**; expiry is also enforced on open sockets. |
| Identity | The sender of every message is taken from the authenticated session, never from the message body. |
| Brute force | Login: 5 failures/5 min per account, 20 failures/10 min per IP -> HTTP 429. Registration: 10/hour per IP. Per-connection token-bucket message rate limit; persistent flooders are disconnected. |
| CSRF / CSWSH | WebSocket and POST endpoints verify the `Origin` header matches `Host`; JSON-only content type; SameSite=Strict cookie. |
| Injection / XSS | Strict JSON parser (rejects duplicate keys, trailing data, NULs, bad surrogates, depth bombs); all output JSON-escaped; frontend only uses `textContent` (never `innerHTML`); CSP `default-src 'none'; script-src 'self'`; control characters and invalid UTF-8 rejected. |
| HTTP hardening | Static files are an explicit allow-list (URL never becomes a file path -> no traversal); rejects `Transfer-Encoding`, duplicate `Content-Length`, bare CR/LF, oversized headers/bodies; `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `no-store`. |
| WebSocket | RFC 6455: client frames must be masked, RSV bits and opcodes validated, 8 KB max message, fragmentation reassembly, ping/pong keepalive, idle/half-open connection cleanup. |
| Resource limits | 512 connections, 20 per IP, 8 per user, 1 MB write-buffer cap (slow consumers dropped), 10 s timeout for incomplete HTTP requests. |
| Files | Data dir `0700`, `users.db` / `messages.log` / `receipts.log` `0600`. Binds to `127.0.0.1` by default. |

### Things you must still do for real deployments

1. **Use TLS.** The C server speaks plain HTTP. Put nginx/Caddy in front, terminate HTTPS there,
   proxy `/` including WebSocket upgrades, and start with `--secure --trust-proxy`.
   Without TLS, passwords and messages are readable on the network. The server prints a warning
   when bound beyond localhost without `--secure`.
2. Messages are stored **unencrypted** on the server (`data/messages.log`). This is server-side
   chat, not end-to-end encryption - the server operator can read private messages.
3. Sessions are in memory, so everyone is logged out when the server restarts.
4. Hashing runs on the single event-loop thread (~50 ms per login). The per-IP/per-account
   throttles bound abuse; for a large public service, move hashing to worker threads.
5. No password reset / e-mail verification (there is no e-mail). Back up `data/users.db`.
6. `messages.log` grows forever; the server keeps the newest 20,000 messages in memory.

## Protocol

`POST /api/register`, `POST /api/login` with `{"username","password"}` set the session cookie.
`POST /api/logout`, `GET /api/me`. Then `GET /ws` (WebSocket, cookie required).

Message ids are decimal strings, assigned by the server in log order (1, 2, 3...). Ids are strings
because the JSON reader only extracts string fields.

Client -> server (JSON text frames)

```
{"type":"msg","to":"","text":"hi all"}            group message  (to = "" or omitted)
{"type":"msg","to":"bob","text":"hi bob"}         private message
{"type":"history","with":""|"bob"}                newest 50 messages of a conversation
{"type":"history","with":"bob","before":"120"}    the 50 messages older than id 120
{"type":"read","with":"bob"|"","upto":"130"}      I have read everything bob sent me up to id 130
{"type":"msg","to":"bob","text":"...","reply":"120"}   quote message 120 (must be in the same conversation, not deleted)
{"type":"delete","id":"120"}                    delete one of my own messages for everyone
{"type":"typing","to":""|"bob"}
{"type":"users"}
```

Server -> client

```
hello     {"user"}
users     {"users":[{"name","online","last_seen"}]}
presence  {"name","online","last_seen"}
convs     {"convs":[{"with","last_id","last_from","last_text","last_status","last_ts","unread","last_deleted"}]}   chat list, sent on connect; entry 0 = group
msg       {"id","from","to","text","ts","reply"?:{"id","from","text","deleted"}}
deleted   {"id","from","to"}                      message `id` was deleted for everyone
history   {"with","before","more","messages":[{"id","from","to","text","ts","status"?,"reply"?,"deleted"?}]}   status only on your own DMs; deleted messages have text ""
receipt   {"with","status":"delivered"|"read","upto"}   your DMs to `with` with id <= upto reached that state
unread    {"with","count"}                               authoritative unread count (e.g. after reading in another tab)
typing    {"from","to"}
error     {"message"}
```

**How receipts work.** Per direction (`alice -> bob`) the server stores two watermarks, *delivered* and
*read*: "every DM from alice to bob with id <= W". A message's tick is derived from them, so persistence is a
tiny append-only `data/receipts.log` (`D`/`R` watermark lines, `S` last-seen lines). `read` is clamped to the
newest message that actually exists, so a client can't pre-mark future messages as read, and it can only affect
conversations it is part of. `read` frames are charged to a separate, larger rate-limit bucket so they don't
use up the budget for real messages. The group room has unread counts but no per-message ticks.

`messages.log` keeps its original format (`ts<TAB>from<TAB>to<TAB>text`, plus an optional 5th `reply_id` field);
ids are assigned in file order on load, so logs written by older versions still work. Because ids are line
positions, the file is never trimmed. Deleting a message rewrites its line to `(deleted)` in place instead
(atomically, via a temp file), so ids and receipts stay valid and the old text is really gone from disk.
`receipts.log` is compacted to one line per watermark every time the server starts.

HTTP API (JSON POST, same-origin): `/api/register`, `/api/login`, `/api/logout`, `/api/password`
(`{"old","new"}`, throttled like logins), `/api/logout-all`; `GET /api/me`.

## Deployment

- `Dockerfile` + `deploy/entrypoint.sh`: multi-stage build. The entrypoint listens on `$PORT` (default 8080) on all
  interfaces, stores data in `$DATA_DIR` (default `/app/data`), fixes ownership of a mounted disk, then runs the
  server as an unprivileged user.
- `render.yaml`: Render Blueprint (see below).
- `deploy/chat.service`: hardened systemd unit (binds to localhost, SIGTERM flushes the logs).
- `deploy/Caddyfile`: automatic-HTTPS reverse proxy. Run the server with `--secure --trust-proxy` behind it.
- `deploy/backup.sh DATADIR BACKUPDIR`: timestamped tarballs, keeps the newest 48 (run it from cron).
- `.github/workflows/ci.yml`: build + tests, then the ASan/UBSan build, then the frontend test.

## Layout

```
Makefile  README.md
src/   main.c server.c(poll loop, sockets, WS framing glue) chat.c(group/DM logic)
       http.c(parser, router, auth API) ws.c json.c auth.c(users, sessions) store.c(messages)
       ratelimit.c util.c sha1.c sha256.c base64.c
public/ index.html app.js style.css
tests/  unit_tests.c (RFC vectors for SHA/HMAC/PBKDF2/WebSocket, JSON, framing, message store + receipts)
        e2e_test.py  (126 end-to-end checks incl. auth, DMs, receipts, replies, deletes, passwords, abuse cases)
        frontend_smoke.js  (jsdom test of public/app.js: `npm i jsdom && make test-frontend`)
data/   created at runtime: users.db, messages.log, receipts.log
```


### Deploying on Render

1. Push this repo to GitHub.
2. Render dashboard -> **New -> Blueprint** -> select the repo (it reads `render.yaml`), or create a **Web
   Service** with runtime **Docker** and add a **Persistent Disk** mounted at `/var/data` plus the environment
   variable `DATA_DIR=/var/data`.
3. Open `https://<service>.onrender.com`. Render terminates TLS and the server is already started with
   `--secure --trust-proxy`, so cookies are `Secure` and rate limits see the real client IP.

Things to know:
- **Persistence needs a paid instance + disk.** On the free plan the filesystem is wiped on every deploy and
  restart, so accounts and messages disappear, and the service sleeps after about 15 minutes without traffic
  (every WebSocket drops; clients reconnect automatically). Fine for a demo, not for real use.
- **One instance only.** Users, sessions, rate limits and presence live in this process's memory and the data
  files live on one disk, so don't scale to several instances. A disk-backed service also redeploys with a
  brief downtime instead of zero-downtime.
- Sessions are in memory: every deploy/restart logs everyone out and they must sign in again.
- Back up the disk (`deploy/backup.sh`, or Render disk snapshots).
