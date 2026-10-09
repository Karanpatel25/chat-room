#!/usr/bin/env python3
"""End-to-end tests: starts ./chat_server on a temp dir/port and drives it over HTTP + raw WebSockets.
Standard library only."""
import base64, json, os, shutil, socket, struct, subprocess, sys, tempfile, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORT = int(os.environ.get("TEST_PORT", "18080"))
passed = failed = 0

def check(name, cond):
    global passed, failed
    if cond: passed += 1
    else: failed += 1; print("FAIL:", name)

import http.client as hc

def http(method, path, body=None, headers=None, raw_body=None):
    c = hc.HTTPConnection("127.0.0.1", PORT, timeout=10)
    h = dict(headers or {})
    data = raw_body
    if body is not None:
        data = json.dumps(body); h.setdefault("Content-Type", "application/json")
    c.request(method, path, body=data, headers=h)
    r = c.getresponse(); b = r.read()
    out = (r.status, dict((k.lower(), v) for k, v in r.getheaders()), b)
    c.close(); return out

def jb(b):
    try: return json.loads(b)
    except Exception: return {}

def cookie_of(hdrs):
    sc = hdrs.get("set-cookie", "")
    return sc.split(";")[0] if sc.startswith("session=") else None

class WS:
    def __init__(self, cookie, origin=f"http://127.0.0.1:{PORT}", expect=101):
        self.s = socket.create_connection(("127.0.0.1", PORT), timeout=5)
        key = base64.b64encode(os.urandom(16)).decode()
        req = (f"GET /ws HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
               f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n")
        if origin: req += f"Origin: {origin}\r\n"
        if cookie: req += f"Cookie: {cookie}\r\n"
        self.s.sendall((req + "\r\n").encode())
        self.buf = b""
        while b"\r\n\r\n" not in self.buf:
            d = self.s.recv(4096)
            if not d: break
            self.buf += d
        head, _, self.buf = self.buf.partition(b"\r\n\r\n")
        self.status = int(head.split()[1])
        self.head = head.decode(errors="replace")
    def send_raw_frame(self, op, payload, fin=True, mask=True):
        b0 = (0x80 if fin else 0) | op
        n = len(payload); hdr = bytes([b0])
        mk = (0x80 if mask else 0)
        if n < 126: hdr += bytes([mk | n])
        elif n < 65536: hdr += bytes([mk | 126]) + struct.pack(">H", n)
        else: hdr += bytes([mk | 127]) + struct.pack(">Q", n)
        if mask:
            m = os.urandom(4); payload = bytes(c ^ m[i % 4] for i, c in enumerate(payload)); hdr += m
        self.s.sendall(hdr + payload)
    def send(self, obj): self.send_raw_frame(1, json.dumps(obj).encode())
    def _need(self, n):
        while len(self.buf) < n:
            d = self.s.recv(65536)
            if not d: raise EOFError
            self.buf += d
    def recv_frame(self):
        self._need(2)
        op = self.buf[0] & 0x0f; n = self.buf[1] & 0x7f; off = 2
        if n == 126: self._need(4); n = struct.unpack(">H", self.buf[2:4])[0]; off = 4
        elif n == 127: self._need(10); n = struct.unpack(">Q", self.buf[2:10])[0]; off = 10
        self._need(off + n)
        p = self.buf[off:off + n]; self.buf = self.buf[off + n:]
        return op, p
    def recv(self, timeout=3):
        self.s.settimeout(timeout)
        while True:
            op, p = self.recv_frame()
            if op == 1: return json.loads(p)
            if op == 8: return {"type": "__close__", "code": struct.unpack(">H", p[:2])[0] if len(p) >= 2 else 0}
            if op == 9: self.send_raw_frame(10, p)
    def recv_until(self, typ, timeout=3, pred=None):
        end = time.time() + timeout
        while time.time() < end:
            try: m = self.recv(timeout=max(0.1, end - time.time()))
            except (socket.timeout, EOFError): return None
            if m.get("type") == typ and (pred is None or pred(m)): return m
        return None
    def close(self):
        try: self.s.close()
        except Exception: pass

def register(name, pw="correct-horse-1"):
    st, h, b = http("POST", "/api/register", {"username": name, "password": pw})
    return st, cookie_of(h), jb(b)

def main():
    tmp = tempfile.mkdtemp(prefix="chat_e2e_")
    exe = os.path.join(ROOT, "chat_server")
    srv = subprocess.Popen([exe, "-p", str(PORT), "-d", tmp, "-w", os.path.join(ROOT, "public")],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        for _ in range(50):
            try: socket.create_connection(("127.0.0.1", PORT), timeout=0.2).close(); break
            except OSError: time.sleep(0.1)

        # ---- static + headers
        st, h, b = http("GET", "/")
        check("index served", st == 200 and b"<title>Chat</title>" in b)
        check("security headers", "content-security-policy" in h and h.get("x-content-type-options") == "nosniff" and h.get("x-frame-options") == "DENY")
        check("path traversal blocked", http("GET", "/../src/main.c")[0] == 404 and http("GET", "/%2e%2e/src/main.c")[0] == 404)
        check("data files not served", http("GET", "/users.db")[0] == 404)
        check("unknown method rejected", http("DELETE", "/")[0] == 405)

        # ---- registration / login
        check("me requires login", http("GET", "/api/me")[0] == 401)
        st, alice_ck, d = register("alice")
        check("register ok", st == 200 and alice_ck and d.get("user") == "alice")
        st, h, _ = http("POST", "/api/register", {"username": "alice2", "password": "correct-horse-1"})
        sc = h.get("set-cookie", "")
        check("cookie flags", "HttpOnly" in sc and "SameSite=Strict" in sc)
        check("duplicate name (case-insens.) rejected", http("POST", "/api/register", {"username": "ALICE", "password": "correct-horse-1"})[0] == 409)
        check("weak password rejected", http("POST", "/api/register", {"username": "weakling", "password": "short"})[0] == 400)
        check("common password rejected", http("POST", "/api/register", {"username": "weakling", "password": "password"})[0] == 400)
        check("bad username rejected", http("POST", "/api/register", {"username": "<img src=x>", "password": "correct-horse-1"})[0] == 400)
        check("json content-type required", http("POST", "/api/login", raw_body='{"username":"alice","password":"x"}', headers={"Content-Type": "text/plain"})[0] == 415)
        check("cross-origin POST blocked", http("POST", "/api/login", {"username": "alice", "password": "x"}, headers={"Origin": "http://evil.example"})[0] == 403)
        check("malformed json rejected", http("POST", "/api/login", raw_body="{nope", headers={"Content-Type": "application/json"})[0] == 400)
        st, h, b = http("GET", "/api/me", headers={"Cookie": alice_ck})
        check("me with cookie", st == 200 and jb(b).get("user") == "alice")
        check("forged cookie rejected", http("GET", "/api/me", headers={"Cookie": "session=" + "0" * 64})[0] == 401)

        st, h, b = http("POST", "/api/login", {"username": "AlIcE", "password": "correct-horse-1"})
        check("login case-insensitive, canonical name", st == 200 and jb(b).get("user") == "alice")
        new_ck = cookie_of(h)
        check("new session token each login", new_ck and new_ck != alice_ck)
        st1, _, b1 = http("POST", "/api/login", {"username": "alice", "password": "wrong-password"})
        st2, _, b2 = http("POST", "/api/login", {"username": "nobody", "password": "wrong-password"})
        check("same error for bad pw / unknown user", st1 == 401 and st2 == 401 and b1 == b2)

        # ---- login brute-force throttle (per username: 5 failures)
        codes = [http("POST", "/api/login", {"username": "alice", "password": "bad%d" % i})[0] for i in range(7)]
        check("account lockout after repeated failures", 429 in codes)
        st, _, _ = http("POST", "/api/login", {"username": "alice", "password": "correct-horse-1"})
        check("locked even for right password during lockout", st == 429)

        # ---- websocket auth
        w = WS(None);   check("ws without cookie -> 401", w.status == 401); w.close()
        w = WS("session=" + "a" * 64); check("ws bad cookie -> 401", w.status == 401); w.close()
        w = WS(alice_ck, origin="http://evil.example"); check("ws foreign origin -> 403", w.status == 403); w.close()

        st, bob_ck, _ = register("bob")
        st, carol_ck, _ = register("carol")
        a = WS(alice_ck); check("ws alice upgrade", a.status == 101)
        hello = a.recv_until("hello"); check("hello identifies user", hello and hello["user"] == "alice")
        users = a.recv_until("users")
        check("user list includes all accounts", users and {u["name"] for u in users["users"]} >= {"alice", "bob", "carol"})
        check("group history sent on connect", a.recv_until("history", pred=lambda m: m["with"] == "") is not None)

        b = WS(bob_ck); check("ws bob upgrade", b.status == 101)
        check("alice sees bob come online", a.recv_until("presence", pred=lambda m: m["name"] == "bob" and m["online"]) is not None)
        c = WS(carol_ck); c.recv_until("hello")
        a.recv_until("presence", pred=lambda m: m["name"] == "carol")

        # ---- group chat
        a.send({"type": "msg", "to": "", "text": "hello everyone"})
        for who, sock in (("alice", a), ("bob", b), ("carol", c)):
            m = sock.recv_until("msg", pred=lambda m: m["text"] == "hello everyone")
            check(f"group msg delivered to {who}", m and m["from"] == "alice" and m["to"] == "")

        # ---- spoofing: client-supplied sender is ignored
        a.send({"type": "msg", "to": "", "text": "spoof", "from": "bob", "name": "bob", "username": "bob"})
        m = c.recv_until("msg", pred=lambda m: m["text"] == "spoof")
        check("sender cannot be spoofed", m and m["from"] == "alice")

        # ---- private chat
        a.send({"type": "msg", "to": "bob", "text": "psst bob"})
        m = b.recv_until("msg", pred=lambda m: m["text"] == "psst bob")
        check("DM delivered to recipient", m and m["from"] == "alice" and m["to"] == "bob")
        check("DM echoed to sender", a.recv_until("msg", pred=lambda m: m["text"] == "psst bob") is not None)
        check("DM NOT delivered to third party", c.recv_until("msg", timeout=1, pred=lambda m: m["text"] == "psst bob") is None)
        b.send({"type": "msg", "to": "ALICE", "text": "hi alice"})
        check("DM reply (case-insens. target)", a.recv_until("msg", pred=lambda m: m["text"] == "hi alice") is not None)
        c.send({"type": "history", "with": "alice"})
        h = c.recv_until("history", pred=lambda m: m["with"] == "alice")
        check("third party history has no DMs between others", h and all(x["text"] not in ("psst bob", "hi alice") for x in h["messages"]))
        a.send({"type": "history", "with": "bob"})
        h = a.recv_until("history", pred=lambda m: m["with"] == "bob")
        check("DM history returned", h and [x["text"] for x in h["messages"]] == ["psst bob", "hi alice"])
        a.send({"type": "history", "with": ""})
        h = a.recv_until("history", pred=lambda m: m["with"] == "")
        check("group history excludes DMs", h and all(x["to"] == "" for x in h["messages"]))
        a.send({"type": "msg", "to": "ghost", "text": "x"})
        check("DM to unknown user -> error", a.recv_until("error") is not None)
        a.send({"type": "msg", "to": "alice", "text": "x"})
        check("DM to self -> error", a.recv_until("error") is not None)

        # ---- typing
        b.send({"type": "typing", "to": "alice"})
        check("typing delivered to target", a.recv_until("typing", pred=lambda m: m["from"] == "bob") is not None)
        check("typing in DM not leaked to third party", c.recv_until("typing", timeout=1) is None)

        # ---- message ids, delivery receipts, read receipts, unread counts
        time.sleep(1.2)   # let the per-connection token buckets refill
        a.send({"type": "msg", "to": "bob", "text": "r1"})
        m_b = b.recv_until("msg", pred=lambda m: m["text"] == "r1")
        m_a = a.recv_until("msg", pred=lambda m: m["text"] == "r1")
        check("messages carry string ids (same for both parties)",
              m_b and m_a and isinstance(m_b.get("id"), str) and m_b["id"].isdigit() and m_b["id"] == m_a["id"])
        r1 = m_b["id"] if m_b else "0"
        rc = a.recv_until("receipt", pred=lambda m: m["status"] == "delivered" and m["with"] == "bob" and int(m["upto"]) >= int(r1))
        check("sender gets 'delivered' receipt when recipient is online", rc is not None)
        check("receipts are not leaked to a third party", c.recv_until("receipt", timeout=1) is None)

        b.send({"type": "read", "with": "alice", "upto": r1})
        rc = a.recv_until("receipt", pred=lambda m: m["status"] == "read" and m["with"] == "bob" and int(m["upto"]) >= int(r1))
        check("sender gets 'read' receipt", rc is not None)
        un = b.recv_until("unread", pred=lambda m: m["with"] == "alice")
        check("reader's tabs get an unread count update", un and un["count"] == 0)

        c.send({"type": "read", "with": "alice", "upto": "999999999"})
        check("read from someone with no DMs forges nothing",
              a.recv_until("receipt", timeout=1, pred=lambda m: m["status"] == "read" and m["with"] == "carol") is None)
        b.send({"type": "read", "with": "alice", "upto": "999999999"})     # far beyond the newest message
        time.sleep(0.3)
        a.send({"type": "msg", "to": "bob", "text": "r2"})
        a.recv_until("msg", pred=lambda m: m["text"] == "r2")
        a.send({"type": "history", "with": "bob"})
        h = a.recv_until("history", pred=lambda m: m["with"] == "bob" and any(x["text"] == "r2" for x in m["messages"]))
        st_by_text = {x["text"]: x.get("status") for x in h["messages"] if x["from"] == "alice"} if h else {}
        check("read-upto beyond newest is clamped (later message not pre-read)",
              st_by_text.get("r1") == "read" and st_by_text.get("r2") == "delivered")
        check("only own DMs carry a status",
              h and all(("status" in x) == (x["from"] == "alice") for x in h["messages"]))

        a.send({"type": "history", "with": "bob", "before": r1})
        h = a.recv_until("history", pred=lambda m: m.get("before") == r1)
        check("history pagination: only older messages, 'more' flag",
              h and len(h["messages"]) >= 2 and all(int(x["id"]) < int(r1) for x in h["messages"]) and h["more"] is False)
        hi_id = next((x["id"] for x in (h["messages"] if h else []) if x["text"] == "hi alice"), "0")
        a.send({"type": "history", "with": "bob", "before": "abc"})
        check("bad pagination id -> error", a.recv_until("error") is not None)
        a.send({"type": "read", "with": "bob", "upto": "nope"})
        check("bad read id -> error", a.recv_until("error") is not None)
        a.send({"type": "read", "with": "ghost", "upto": "1"})
        check("read for unknown user -> error", a.recv_until("error") is not None)

        a.send({"type": "read", "with": "bob", "upto": hi_id})
        check("bob sees alice read his message",
              b.recv_until("receipt", pred=lambda m: m["status"] == "read" and m["with"] == "alice" and int(m["upto"]) >= int(hi_id)) is not None)

        # offline recipient: stays 'sent' until they connect, then becomes 'delivered'
        c.close(); time.sleep(0.6)
        pr = a.recv_until("presence", pred=lambda m: m["name"] == "carol" and not m["online"])
        check("offline presence carries last_seen", pr and pr.get("last_seen", 0) > 0)
        a.send({"type": "msg", "to": "carol", "text": "while you were out"})
        off = a.recv_until("msg", pred=lambda m: m["text"] == "while you were out")
        a.send({"type": "history", "with": "carol"})
        h = a.recv_until("history", pred=lambda m: m["with"] == "carol")
        check("message to offline user is 'sent', not delivered",
              h and h["messages"] and h["messages"][-1].get("status") == "sent")
        c = WS(carol_ck)
        users2 = c.recv_until("users")                      # frame order: hello, users, convs, history
        cv = c.recv_until("convs")
        ent = next((e for e in (cv["convs"] if cv else []) if e["with"] == "alice"), None)
        check("convs frame: unread count + last message preview",
              ent and ent["unread"] == 1 and ent["last_text"] == "while you were out" and ent["last_from"] == "alice")
        check("convs frame always lists the group room first", cv and cv["convs"][0]["with"] == "")
        check("offline message becomes 'delivered' when recipient connects",
              off and a.recv_until("receipt", pred=lambda m: m["with"] == "carol" and m["status"] == "delivered" and int(m["upto"]) >= int(off["id"])) is not None)
        check("users frame carries last_seen", users2 and all("last_seen" in u for u in users2["users"]))
        c.send({"type": "read", "with": "alice", "upto": off["id"]})
        un = c.recv_until("unread", pred=lambda m: m["with"] == "alice")
        check("unread cleared after read", un and un["count"] == 0)
        check("alice sees carol read it",
              a.recv_until("receipt", pred=lambda m: m["with"] == "carol" and m["status"] == "read") is not None)

        # read-receipt flood: separate light bucket, no 'too fast' errors for a normal burst
        for i in range(12): c.send({"type": "read", "with": "alice", "upto": off["id"]})
        check("burst of read frames doesn't trip the message rate limit",
              c.recv_until("error", timeout=1, pred=lambda m: "too fast" in m.get("message", "")) is None)

        # ---- replies + delete for everyone
        time.sleep(1.2)
        a.send({"type": "msg", "to": "bob", "text": "the plan is X"})
        pm = a.recv_until("msg", pred=lambda m: m["text"] == "the plan is X")
        b.recv_until("msg", pred=lambda m: m["text"] == "the plan is X")
        P = pm["id"] if pm else "0"
        b.send({"type": "msg", "to": "alice", "text": "sounds good", "reply": P})
        rm = a.recv_until("msg", pred=lambda m: m["text"] == "sounds good")
        check("reply carries a quote of the original",
              rm and rm.get("reply", {}).get("id") == P and rm["reply"]["text"] == "the plan is X" and rm["reply"]["from"] == "alice")
        c.send({"type": "msg", "to": "alice", "text": "sneaky", "reply": P})
        check("can't reply to a message from a conversation you're not in", c.recv_until("error") is not None)
        b.send({"type": "msg", "to": "", "text": "wrong room", "reply": P})
        check("can't quote a DM in the group room", b.recv_until("error") is not None)
        b.send({"type": "msg", "to": "alice", "text": "bad ref", "reply": "abc"})
        check("bad reply id rejected", b.recv_until("error") is not None)
        a.send({"type": "history", "with": "bob"})
        hh = a.recv_until("history", pred=lambda m: m["with"] == "bob" and any(x["text"] == "sounds good" for x in m["messages"]))
        check("history includes the reply quote",
              hh and any(x["text"] == "sounds good" and x.get("reply", {}).get("id") == P for x in hh["messages"]))

        b.send({"type": "delete", "id": P})
        check("can't delete someone else's message", b.recv_until("error", pred=lambda m: "own" in m["message"]) is not None)
        a.send({"type": "delete", "id": "999999"})
        check("deleting an unknown message -> error", a.recv_until("error") is not None)
        a.send({"type": "delete", "id": P})
        da = a.recv_until("deleted", pred=lambda m: m["id"] == P)
        db_ = b.recv_until("deleted", pred=lambda m: m["id"] == P)
        check("both parties get a 'deleted' frame", da and db_ and da["from"] == "alice" and da["to"] == "bob")
        check("third party doesn't see DM deletions", c.recv_until("deleted", timeout=1) is None)
        a.send({"type": "history", "with": "bob"})
        hh = a.recv_until("history", pred=lambda m: m["with"] == "bob" and any(x["id"] == P for x in m["messages"]))
        gone = next((x for x in hh["messages"] if x["id"] == P), None) if hh else None
        check("history shows the tombstone without text", gone and gone.get("deleted") is True and gone["text"] == "")
        check("quote of a deleted message is blanked",
              hh and all(x["reply"]["deleted"] is True and x["reply"]["text"] == "" for x in hh["messages"] if x["text"] == "sounds good"))
        check("deleted text is scrubbed from messages.log",
              "the plan is X" not in open(os.path.join(tmp, "messages.log")).read())
        b.send({"type": "msg", "to": "alice", "text": "re: deleted", "reply": P})
        check("can't reply to a deleted message", b.recv_until("error") is not None)
        a.send({"type": "delete", "id": P})
        check("deleting twice -> error", a.recv_until("error") is not None)

        # ---- change password / log out everywhere
        st, ck1, _ = register("dave", "dave-old-pass-1")
        st, h, _ = http("POST", "/api/login", {"username": "dave", "password": "dave-old-pass-1"}); ck2 = cookie_of(h)
        d1 = WS(ck1); d1.recv_until("history")      # drain the connect-time frames (hello, users, convs, history)
        d2 = WS(ck2); d2.recv_until("history")
        H1 = {"Cookie": ck1}
        check("password change needs a session", http("POST", "/api/password", {"old": "x", "new": "y"})[0] == 401)
        check("wrong current password -> 401", http("POST", "/api/password", {"old": "nope-nope-1", "new": "dave-new-pass-2"}, H1)[0] == 401)
        check("weak new password -> 400", http("POST", "/api/password", {"old": "dave-old-pass-1", "new": "short"}, H1)[0] == 400)
        check("same password -> 400", http("POST", "/api/password", {"old": "dave-old-pass-1", "new": "dave-old-pass-1"}, H1)[0] == 400)
        check("password change ok", http("POST", "/api/password", {"old": "dave-old-pass-1", "new": "dave-new-pass-2"}, H1)[0] == 200)
        check("old password no longer works", http("POST", "/api/login", {"username": "dave", "password": "dave-old-pass-1"})[0] == 401)
        st, h, _ = http("POST", "/api/login", {"username": "dave", "password": "dave-new-pass-2"}); ck3 = cookie_of(h)
        check("new password works", st == 200 and ck3)
        check("current session survives, other sessions are revoked",
              http("GET", "/api/me", headers=H1)[0] == 200 and http("GET", "/api/me", headers={"Cookie": ck2})[0] == 401)
        time.sleep(6)   # the server re-checks live sockets every 5s
        check("revoked session's socket is closed", d2.recv_until("__close__", timeout=4) is not None)
        d1.send({"type": "users"})
        check("current session's socket stays open", d1.recv_until("users", timeout=2) is not None)
        check("logout-all needs a session", http("POST", "/api/logout-all", {})[0] == 401)
        st, h, _ = http("POST", "/api/logout-all", {}, {"Cookie": ck3})
        check("logout-all ok + clears cookie", st == 200 and "max-age=0" in h.get("set-cookie", "").lower())
        check("every session is gone",
              http("GET", "/api/me", headers=H1)[0] == 401 and http("GET", "/api/me", headers={"Cookie": ck3})[0] == 401)
        time.sleep(6)
        check("socket of a logged-out-everywhere session is closed", d1.recv_until("__close__", timeout=4) is not None)
        st, h, _ = http("POST", "/api/login", {"username": "dave", "password": "dave-new-pass-2"}); ck4 = cookie_of(h)
        codes = [http("POST", "/api/password", {"old": "wrong-guess-%d" % i, "new": "dave-newer-pass-3"}, {"Cookie": ck4})[0] for i in range(7)]
        check("guessing the current password is throttled", codes[:5] == [401] * 5 and 429 in codes[5:])
        d1.close(); d2.close()

        # ---- XSS-ish payloads are returned as data, JSON-escaped
        payload = '<img src=x onerror=alert(1)>"\\'
        a.send({"type": "msg", "to": "", "text": payload})
        m = b.recv_until("msg", pred=lambda m: "onerror" in m["text"])
        check("payload round-trips as plain data", m and m["text"] == payload)

        # ---- validation
        a.send({"type": "msg", "to": "", "text": "x" * 1001})
        check("oversized message rejected", a.recv_until("error") is not None)
        a.send({"type": "msg", "to": "", "text": "tab\there"})
        check("control chars rejected", a.recv_until("error") is not None)
        a.s.sendall(b"")  # keep alive
        a.send_raw_frame(1, b'{"type":"msg","type":"users"}')
        check("duplicate JSON keys rejected", a.recv_until("error") is not None)
        a.send_raw_frame(1, b"\xff\xfe")
        m = a.recv_until("__close__", timeout=3)
        check("invalid UTF-8 closes connection (1007)", m and m["code"] == 1007)
        a.close()

        # ---- protocol-level abuse
        x = WS(bob_ck); x.recv_until("hello")
        x.send_raw_frame(1, b'{"type":"users"}', mask=False)
        m = x.recv_until("__close__", timeout=3); check("unmasked client frame -> close 1002", m and m["code"] == 1002); x.close()
        x = WS(bob_ck); x.recv_until("hello")
        x.s.sendall(b"\x81\xff" + struct.pack(">Q", 1 << 40) + b"\0\0\0\0")
        m = x.recv_until("__close__", timeout=3); check("huge frame length -> close 1009", m and m["code"] == 1009); x.close()
        x = WS(bob_ck); x.recv_until("hello")
        x.send_raw_frame(2, b"\x00\x01")
        m = x.recv_until("__close__", timeout=3); check("binary frame -> close 1003", m and m["code"] == 1003); x.close()
        x = WS(bob_ck); x.recv_until("hello")
        x.send_raw_frame(1, b'{"type":"msg","to":"","text":"frag', fin=False)
        x.send_raw_frame(0, b'mented"}', fin=True)
        check("fragmented message reassembled", b.recv_until("msg", pred=lambda m: m["text"] == "fragmented") is not None)
        x.send_raw_frame(9, b"hi")
        ok = False
        for _ in range(5):
            op, p = x.recv_frame()
            if op == 10 and p == b"hi": ok = True; break
        check("ping answered with pong", ok); x.close()

        # ---- rate limiting
        x = WS(carol_ck); x.recv_until("hello")
        for i in range(40): x.send({"type": "typing", "to": ""})
        got_rl = False; end = time.time() + 3
        while time.time() < end:
            try: m = x.recv(timeout=1)
            except Exception: break
            if m.get("type") == "error" and "too fast" in m.get("message", ""): got_rl = True; break
        check("message flood is rate limited", got_rl); x.close()

        # ---- malformed HTTP
        s = socket.create_connection(("127.0.0.1", PORT)); s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n")
        check("Transfer-Encoding refused", b" 501 " in s.recv(200)); s.close()
        s = socket.create_connection(("127.0.0.1", PORT)); s.sendall(b"POST /api/login HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n")
        check("duplicate Content-Length refused", b" 400 " in s.recv(200)); s.close()
        s = socket.create_connection(("127.0.0.1", PORT)); s.sendall(b"GET / HTTP/1.1\r\nX: " + b"a" * 9000 + b"\r\n\r\n")
        check("oversized headers refused", b" 431 " in s.recv(200)); s.close()
        s = socket.create_connection(("127.0.0.1", PORT)); s.sendall(b"POST /api/login HTTP/1.1\r\nHost: x\r\nContent-Length: 999999\r\n\r\n")
        check("oversized body refused", b" 413 " in s.recv(200)); s.close()

        # ---- logout kills live sockets and the session
        y = WS(bob_ck); y.recv_until("hello")
        st, h, _ = http("POST", "/api/logout", {}, headers={"Cookie": bob_ck})
        check("logout ok + cookie cleared", st == 200 and "Max-Age=0" in h.get("set-cookie", ""))
        m = y.recv_until("__close__", timeout=3); check("logout closes live websocket", m is not None); y.close()
        check("session invalid after logout", http("GET", "/api/me", headers={"Cookie": bob_ck})[0] == 401)
        b.close(); c.close()

        # ---- persistence
        srv.terminate(); srv.wait(timeout=5)
        check("clean shutdown exit code 0", srv.returncode == 0)
        db = open(os.path.join(tmp, "users.db")).read()
        check("passwords not stored in clear", "correct-horse-1" not in db and db.count("\n") >= 3)
        check("data files private (0600)", oct(os.stat(os.path.join(tmp, "users.db")).st_mode & 0o777) == "0o600")
        srv = subprocess.Popen([exe, "-p", str(PORT), "-d", tmp, "-w", os.path.join(ROOT, "public")], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for _ in range(50):
            try: socket.create_connection(("127.0.0.1", PORT), timeout=0.2).close(); break
            except OSError: time.sleep(0.1)
        st, h, _ = http("POST", "/api/login", {"username": "carol", "password": "correct-horse-1"})
        check("accounts survive restart", st == 200)
        rl_lines = [l.split("\t")[:3] for l in open(os.path.join(tmp, "receipts.log")).read().splitlines() if l]
        check("receipts.log is compacted on start (one line per watermark)", len(rl_lines) == len({tuple(x) for x in rl_lines}))
        d2 = WS(cookie_of(h)); d2.recv_until("hello")
        cv2 = d2.recv_until("convs")
        ent2 = next((e for e in (cv2["convs"] if cv2 else []) if e["with"] == "alice"), None)
        check("read state + chat list survive restart",
              ent2 and ent2["unread"] == 0 and ent2["last_text"] == "while you were out")
        d2.send({"type": "history", "with": "alice"}); hh = d2.recv_until("history", pred=lambda m: m["with"] == "alice")
        d2.send({"type": "history", "with": ""}); gh = d2.recv_until("history", pred=lambda m: m["with"] == "")
        check("group history survives restart", gh and any(x["text"] == "hello everyone" for x in gh["messages"]))
        d2.close()
        st, h, _ = http("POST", "/api/login", {"username": "bob", "password": "correct-horse-1"})
        d3 = WS(cookie_of(h)); d3.recv_until("hello")
        d3.send({"type": "history", "with": "alice"}); bh = d3.recv_until("history", pred=lambda m: m["with"] == "alice")
        check("read receipts (status) survive restart",
              bh and any(x["text"] == "hi alice" and x.get("status") == "read" for x in bh["messages"]))
        check("message ids survive restart (same ids as before)",
              bh and all(x["id"].isdigit() for x in bh["messages"]) and
              [int(x["id"]) for x in bh["messages"]] == sorted(int(x["id"]) for x in bh["messages"]))
        check("deleted message stays deleted after restart",
              bh and any(x["id"] == P and x.get("deleted") and x["text"] == "" for x in bh["messages"]))
        d3.close()
        st, h, _ = http("POST", "/api/login", {"username": "dave", "password": "dave-new-pass-2"})
        check("changed password survives restart", st == 200)
    finally:
        if srv.poll() is None: srv.terminate(); 
        try: srv.wait(timeout=5)
        except Exception: srv.kill()
        shutil.rmtree(tmp, ignore_errors=True)
    print(f"e2e: {passed} passed, {failed} failed")
    return 1 if failed else 0

if __name__ == "__main__":
    sys.exit(main())
