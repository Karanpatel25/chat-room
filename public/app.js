'use strict';
/* All user-controlled text is inserted with textContent / createTextNode, never innerHTML. */
(() => {
  const $ = (id) => document.getElementById(id);
  const authScreen = $('auth-screen'), chatScreen = $('chat-screen');
  const GROUP = '';                       // conversation key of the group room
  const RANK = { sent: 0, delivered: 1, read: 2 };

  const state = {
    me: null, ws: null, users: new Map(), convs: new Map(), current: GROUP,
    reconnectAttempts: 0, reconnectTimer: null, intentionalClose: false,
    typingTimers: new Map(), lastTypingSent: 0, authMode: 'login', filter: '',
    pending: [],            // messages typed while disconnected: { to, text, reply }
    replyTo: null,          // { id, from, text } being quoted by the composer
  };
  const BASE_TITLE = document.title;
  const EMOJI = ['\u{1F600}','\u{1F602}','\u{1F60A}','\u{1F60D}','\u{1F970}','\u{1F60E}','\u{1F914}','\u{1F62E}','\u{1F622}','\u{1F62D}','\u{1F621}','\u{1F44D}','\u{1F44E}','\u{1F44F}','\u{1F64F}','\u{1F4AA}','\u{2764}\u{FE0F}','\u{1F525}','\u{1F389}','\u{2728}','\u{1F440}','\u{1F4AF}','\u{2705}','\u{1F44B}'];

  /* ---------------- helpers ---------------- */
  function toast(msg) {
    const t = $('toast');
    t.textContent = msg; t.hidden = false;
    clearTimeout(toast.timer);
    toast.timer = setTimeout(() => { t.hidden = true; }, 4000);
  }
  function conv(key) {
    if (!state.convs.has(key)) {
      state.convs.set(key, { msgs: [], loaded: false, unread: 0, last: null, more: false,
                             loadingOlder: false, readSent: 0, openUnread: null, dividerId: null });
    }
    return state.convs.get(key);
  }
  const hhmm = (d) => d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  const sameDay = (a, b) => a.toDateString() === b.toDateString();
  function fmtTime(ts) {
    const d = new Date(ts);
    return sameDay(d, new Date()) ? hhmm(d) : d.toLocaleDateString([], { month: 'short', day: 'numeric' }) + ' ' + hhmm(d);
  }
  function fmtListTime(ts) {                       // chat list: time today, "Yesterday", else date
    if (!ts) return '';
    const d = new Date(ts), now = new Date(), y = new Date(now.getTime() - 86400000);
    if (sameDay(d, now)) return hhmm(d);
    if (sameDay(d, y)) return 'Yesterday';
    return d.toLocaleDateString([], { month: 'short', day: 'numeric' });
  }
  function fmtDay(ts) {
    const d = new Date(ts), now = new Date(), y = new Date(now.getTime() - 86400000);
    if (sameDay(d, now)) return 'Today';
    if (sameDay(d, y)) return 'Yesterday';
    return d.toLocaleDateString([], { weekday: 'long', month: 'long', day: 'numeric' });
  }
  function fmtLastSeen(ts) {
    if (!ts) return 'offline';
    const d = new Date(ts), now = new Date(), y = new Date(now.getTime() - 86400000);
    if (sameDay(d, now)) return `last seen today at ${hhmm(d)}`;
    if (sameDay(d, y)) return `last seen yesterday at ${hhmm(d)}`;
    return `last seen ${d.toLocaleDateString([], { month: 'short', day: 'numeric' })} at ${hhmm(d)}`;
  }
  async function api(path, body) {
    const res = await fetch(path, {
      method: body === undefined ? 'GET' : 'POST',
      headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: 'same-origin',
    });
    let data = {};
    try { data = await res.json(); } catch (_) { /* non-JSON error */ }
    return { ok: res.ok, status: res.status, data };
  }
  function send(obj) {
    if (state.ws && state.ws.readyState === WebSocket.OPEN) { state.ws.send(JSON.stringify(obj)); return true; }
    return false;
  }
  function tickEl(status) {
    const t = document.createElement('span');
    t.className = 'tick ' + status;
    t.textContent = status === 'sent' ? '\u2713' : '\u2713\u2713';
    t.title = status;
    return t;
  }
  // Raise a message/preview status (never lower it).
  function bump(obj, level) {
    if (RANK[level] > RANK[obj.status || 'sent']) { obj.status = level; return true; }
    return false;
  }
  function setLast(c, m) {
    if (c.last && Number(m.id) < Number(c.last.id)) return;
    c.last = { id: m.id, from: m.from, text: m.text, ts: m.ts, status: m.status || '', deleted: !!m.deleted };
  }

  /* ---------------- auth UI ---------------- */
  function showAuth() {
    state.intentionalClose = true;
    if (state.ws) state.ws.close();
    clearTimeout(state.reconnectTimer);
    chatScreen.hidden = true; authScreen.hidden = false;
    $('auth-password').value = '';
    $('auth-username').focus();
  }
  function setAuthMode(mode) {
    state.authMode = mode;
    const reg = mode === 'register';
    $('tab-login').classList.toggle('active', !reg);
    $('tab-register').classList.toggle('active', reg);
    $('auth-submit').textContent = reg ? 'Create account' : 'Log in';
    $('auth-password').autocomplete = reg ? 'new-password' : 'current-password';
    $('auth-hint').hidden = !reg;
    $('auth-error').hidden = true;
  }
  $('tab-login').addEventListener('click', () => setAuthMode('login'));
  $('tab-register').addEventListener('click', () => setAuthMode('register'));
  $('auth-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const btn = $('auth-submit'), err = $('auth-error');
    btn.disabled = true; err.hidden = true;
    try {
      const r = await api(state.authMode === 'register' ? '/api/register' : '/api/login',
        { username: $('auth-username').value.trim(), password: $('auth-password').value });
      if (r.ok) { $('auth-password').value = ''; startChat(r.data.user); }
      else { err.textContent = r.data.error || 'Something went wrong'; err.hidden = false; }
    } catch (_) {
      err.textContent = 'Cannot reach the server'; err.hidden = false;
    } finally { btn.disabled = false; }
  });
  $('logout-btn').addEventListener('click', async () => {
    state.intentionalClose = true;
    try { await api('/api/logout', {}); } catch (_) { /* ignore */ }
    state.users.clear(); state.convs.clear(); state.pending = []; state.me = null; state.current = GROUP;
    document.title = BASE_TITLE;
    showAuth();
  });

  /* ---------------- websocket ---------------- */
  function startChat(user) {
    state.me = user;
    state.users.clear(); state.convs.clear(); state.current = GROUP;
    $('me-name').textContent = user;
    authScreen.hidden = true; chatScreen.hidden = false;
    renderAll();
    connect();
  }
  function connect() {
    state.intentionalClose = false;
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${proto}//${location.host}/ws`);   // same host/port as the page
    state.ws = ws;
    setStatus('Connecting…', false);

    ws.onopen = () => { state.reconnectAttempts = 0; setStatus('Connected', true); flushPending(); };
    ws.onmessage = (ev) => {
      if (typeof ev.data !== 'string') return;
      let m; try { m = JSON.parse(ev.data); } catch (_) { return; }
      handle(m);
    };
    ws.onclose = async () => {
      if (state.ws !== ws || state.intentionalClose) return;
      setStatus('Disconnected — reconnecting…', false);
      // If the session is gone (expired / logged out elsewhere) go back to the login screen.
      try { const r = await api('/api/me'); if (r.status === 401) { toast('Session ended. Please log in again.'); showAuth(); return; } } catch (_) {}
      const delay = Math.min(1000 * 2 ** Math.min(state.reconnectAttempts++, 5), 30000);
      state.reconnectTimer = setTimeout(connect, delay);
    };
  }
  function setStatus(text, online) {
    $('status').textContent = text;
    $('me-dot').classList.toggle('on', online);
  }

  function handle(m) {
    switch (m.type) {
      case 'hello': state.me = m.user; $('me-name').textContent = m.user; break;
      case 'users':
        state.users = new Map(m.users.map((u) => [u.name, { online: !!u.online, lastSeen: u.last_seen || 0 }]));
        renderSidebar(); renderHeader();
        if (state.current !== GROUP) requestHistory(state.current);
        break;
      case 'presence': {
        const prev = state.users.get(m.name) || {};
        state.users.set(m.name, { online: !!m.online, lastSeen: m.online ? prev.lastSeen || 0 : (m.last_seen || prev.lastSeen || 0) });
        renderSidebar(); renderHeader();
        break;
      }
      case 'convs':
        for (const e of m.convs) {
          const c = conv(e.with);
          c.unread = e.unread;
          c.last = e.last_id === '0' ? null : { id: e.last_id, from: e.last_from, text: e.last_text, ts: e.last_ts, status: e.last_status, deleted: !!e.last_deleted };
        }
        renderSidebar();
        break;
      case 'history': {
        const c = conv(m.with);
        if (m.before) {                                     // an older page: prepend
          const have = new Set(c.msgs.map((x) => x.id));
          c.msgs = m.messages.filter((x) => !have.has(x.id)).concat(c.msgs);
          c.more = !!m.more; c.loadingOlder = false;
          if (m.with === state.current) renderMessages('prepend');
          break;
        }
        c.msgs = m.messages; c.loaded = true; c.more = !!m.more;
        if (c.msgs.length) setLast(c, c.msgs[c.msgs.length - 1]);
        if (m.with === state.current) {
          const n = c.openUnread !== null ? c.openUnread : c.unread;   // unread count when the chat was opened
          c.openUnread = 0;
          const incoming = c.msgs.filter((x) => x.from !== state.me);
          c.dividerId = n > 0 && incoming.length ? incoming[Math.max(0, incoming.length - n)].id : null;
          renderMessages(c.dividerId ? 'divider' : 'bottom');
          markRead();
        }
        renderSidebar();
        break;
      }
      case 'msg': {
        const key = m.to === GROUP ? GROUP : (m.from === state.me ? m.to : m.from);
        const c = conv(key);
        if (key !== GROUP && !state.users.has(key)) state.users.set(key, { online: true, lastSeen: 0 });
        if (m.from === state.me && key !== GROUP) m.status = 'sent';
        if (!c.msgs.some((x) => x.id === m.id)) c.msgs.push(m);
        if (c.msgs.length > 500) c.msgs.splice(0, c.msgs.length - 500);
        setLast(c, m);
        if (key === state.current) {
          const box = $('messages');
          const near = box.scrollHeight - box.scrollTop - box.clientHeight < 80 || m.from === state.me;
          renderMessages(near ? 'bottom' : 'same');
          clearTyping(m.from);
          if (m.from !== state.me) markRead();
        } else if (m.from !== state.me) c.unread++;
        if (m.from !== state.me) notify(key, m);
        renderSidebar();
        break;
      }
      case 'deleted': {                                      // someone deleted a message for everyone
        const key = m.to === GROUP ? GROUP : (m.from === state.me ? m.to : m.from);
        const c = conv(key);
        for (const x of c.msgs) {
          if (x.id === m.id) { x.deleted = true; x.text = ''; delete x.reply; }
          if (x.reply && x.reply.id === m.id) x.reply.deleted = true;
        }
        if (c.last && c.last.id === m.id) { c.last.deleted = true; c.last.text = ''; }
        if (state.replyTo && state.replyTo.id === m.id) setReply(null);
        if (key === state.current) renderMessages('same');
        renderSidebar();
        break;
      }
      case 'receipt': {                                     // my DMs to m.with were delivered / read
        const c = conv(m.with), up = Number(m.upto), lvl = m.status === 'read' ? 'read' : 'delivered';
        let changed = false;
        for (const x of c.msgs) if (x.from === state.me && Number(x.id) <= up && bump(x, lvl)) changed = true;
        if (c.last && c.last.from === state.me && Number(c.last.id) <= up && bump(c.last, lvl)) changed = true;
        if (changed) { if (m.with === state.current) renderMessages('same'); renderSidebar(); }
        break;
      }
      case 'unread':                                        // authoritative count (e.g. read in another tab)
        conv(m.with).unread = m.count;
        renderSidebar();
        break;
      case 'typing': {
        const key = m.to === GROUP ? GROUP : m.from;
        if (key !== state.current) break;
        showTyping(m.from);
        break;
      }
      case 'error': toast(m.message || 'Error'); break;
    }
  }

  /* ---------------- conversations ---------------- */
  function requestHistory(key) { send({ type: 'history', with: key }); }
  function loadOlder() {
    const c = conv(state.current);
    if (!c.more || c.loadingOlder || !c.msgs.length) return;
    c.loadingOlder = true;
    if (!send({ type: 'history', with: state.current, before: c.msgs[0].id })) c.loadingOlder = false;
  }
  // Tell the server (and so the sender) I've read the open conversation, if I'm actually looking at it.
  function markRead() {
    if (!state.me || document.visibilityState !== 'visible') return;
    const key = state.current, c = conv(key);
    let upto = 0;
    for (let i = c.msgs.length - 1; i >= 0; i--) if (c.msgs[i].from !== state.me) { upto = Number(c.msgs[i].id); break; }
    if (upto > c.readSent && send({ type: 'read', with: key, upto: String(upto) })) c.readSent = upto;
    if (c.unread) { c.unread = 0; renderSidebar(); }
  }
  function openConv(key) {
    state.current = key;
    const c = conv(key);
    c.openUnread = c.unread; c.unread = 0; c.dividerId = null;
    setReply(null);
    requestHistory(key);
    $('typing').textContent = '';
    renderAll();
    $('sidebar').classList.remove('open');
    $('msg-input').focus();
  }

  /* ---------------- rendering ---------------- */
  function convRow(key, label, online, c) {
    const li = document.createElement('li');
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'conv' + (key === state.current ? ' active' : '');

    const av = document.createElement('span');
    av.className = 'avatar' + (key === GROUP ? ' group' : '');
    av.textContent = key === GROUP ? '#' : label.charAt(0).toUpperCase();
    if (online !== null) { const d = document.createElement('span'); d.className = 'dot' + (online ? ' on' : ''); av.appendChild(d); }
    b.appendChild(av);

    const meta = document.createElement('span'); meta.className = 'meta';
    const row1 = document.createElement('span'); row1.className = 'row1';
    const n = document.createElement('span'); n.className = 'name'; n.textContent = label; row1.appendChild(n);
    const last = c ? c.last : null;
    if (last) { const t = document.createElement('span'); t.className = 'ltime'; t.textContent = fmtListTime(last.ts); row1.appendChild(t); }
    meta.appendChild(row1);

    const row2 = document.createElement('span'); row2.className = 'row2';
    const pv = document.createElement('span'); pv.className = 'preview';
    if (last) {
      if (last.from === state.me) {
        if (key !== GROUP) pv.appendChild(tickEl(last.status || 'sent'));
        pv.appendChild(document.createTextNode(' '));
      } else if (key === GROUP) pv.appendChild(document.createTextNode(last.from + ': '));
      pv.appendChild(document.createTextNode(last.deleted ? '\u{1F6AB} This message was deleted' : last.text));
    } else pv.textContent = key === GROUP ? 'No messages yet' : 'Tap to chat';
    row2.appendChild(pv);
    if (c && c.unread > 0) { const u = document.createElement('span'); u.className = 'badge'; u.textContent = String(c.unread); row2.appendChild(u); }
    meta.appendChild(row2);
    b.appendChild(meta);

    b.addEventListener('click', () => openConv(key));
    li.appendChild(b);
    return li;
  }
  function renderSidebar() {
    const q = state.filter.toLowerCase();
    const label = (key) => (key === GROUP ? '# General' : key);

    // Chats: the group room plus every person I have messages with, newest activity first.
    const keys = [GROUP];
    for (const [key, c] of state.convs) if (key !== GROUP && c.last) keys.push(key);
    const rows = keys.filter((k) => label(k).toLowerCase().includes(q))
      .sort((a, b) => ((conv(b).last ? conv(b).last.ts : 0) - (conv(a).last ? conv(a).last.ts : 0)));
    const chats = $('chat-list'); chats.textContent = '';
    for (const k of rows) {
      const u = state.users.get(k);
      chats.appendChild(convRow(k, label(k), k === GROUP ? null : !!(u && u.online), conv(k)));
    }
    if (!rows.length) { const li = document.createElement('li'); li.className = 'empty'; li.textContent = 'No matches'; chats.appendChild(li); }
    updateTitle();

    // New chat: people I haven't talked to yet.
    const list = $('user-list'); list.textContent = '';
    const people = [...state.users.entries()]
      .filter(([n]) => n !== state.me && !(state.convs.get(n) && state.convs.get(n).last) && n.toLowerCase().includes(q))
      .sort((a, b) => (b[1].online - a[1].online) || a[0].localeCompare(b[0], undefined, { sensitivity: 'base' }));
    $('people-head').hidden = !people.length && !q;
    if (!people.length) {
      const li = document.createElement('li'); li.className = 'empty';
      li.textContent = q ? 'No matches' : (state.users.size > 1 ? 'You have chatted with everyone' : 'No other users yet');
      list.appendChild(li);
    }
    for (const [name, u] of people) list.appendChild(convRow(name, name, u.online, state.convs.get(name) || null));
  }
  function renderHeader() {
    if (state.current === GROUP) {
      $('conv-title').textContent = '# General';
      const online = [...state.users.values()].filter((u) => u.online).length;
      $('conv-sub').textContent = `Group chat · ${online} online`;
    } else {
      $('conv-title').textContent = state.current;
      const u = state.users.get(state.current);
      $('conv-sub').textContent = u && u.online ? 'online' : fmtLastSeen(u ? u.lastSeen : 0);
    }
    $('msg-input').placeholder = state.current === GROUP ? 'Message everyone' : `Message ${state.current}`;
  }
  /* mode: 'bottom' (scroll to newest), 'same' (leave scroll alone), 'prepend' (older page added on top),
           'divider' (scroll to the "unread messages" line) */
  function renderMessages(mode = 'bottom') {
    const box = $('messages');
    const prevH = box.scrollHeight, prevTop = box.scrollTop;
    box.textContent = '';
    const c = conv(state.current);

    if (c.more) {
      const btn = document.createElement('button');
      btn.type = 'button'; btn.className = 'older'; btn.textContent = 'Load older messages';
      btn.addEventListener('click', loadOlder);
      box.appendChild(btn);
    }
    if (!c.msgs.length) {
      const d = document.createElement('div'); d.className = 'sys';
      d.textContent = state.current === GROUP ? 'No messages yet. Say hello!' : `This is the start of your private chat with ${state.current}.`;
      box.appendChild(d);
    }
    let lastDay = null, divider = null;
    for (const m of c.msgs) {
      const day = new Date(m.ts).toDateString();
      if (day !== lastDay) {
        lastDay = day;
        const s = document.createElement('div'); s.className = 'daysep'; s.textContent = fmtDay(m.ts); box.appendChild(s);
      }
      if (c.dividerId && m.id === c.dividerId) {
        divider = document.createElement('div'); divider.className = 'unread-divider'; divider.textContent = 'Unread messages';
        box.appendChild(divider);
      }
      const mine = m.from === state.me;
      const el = document.createElement('div');
      el.className = 'msg' + (mine ? ' mine' : '') + (m.deleted ? ' deleted' : '');
      el.dataset.id = m.id;
      if (!mine && state.current === GROUP) {
        const w = document.createElement('span'); w.className = 'who'; w.textContent = m.from; el.appendChild(w);
      }
      if (m.reply && !m.deleted) el.appendChild(quoteEl(m.reply));
      el.appendChild(document.createTextNode(m.deleted ? '\u{1F6AB} This message was deleted' : m.text));
      const t = document.createElement('span'); t.className = 'time';
      t.appendChild(document.createTextNode(fmtTime(m.ts)));
      if (mine && !m.deleted && state.current !== GROUP) { t.appendChild(document.createTextNode(' ')); t.appendChild(tickEl(m.status || 'sent')); }
      el.appendChild(t);
      if (!m.deleted) el.appendChild(actionsEl(m, mine));
      box.appendChild(el);
    }
    for (const p of state.pending) {                       // typed while offline: shown dimmed until sent
      if (p.to !== state.current) continue;
      const el = document.createElement('div'); el.className = 'msg mine pending';
      el.appendChild(document.createTextNode(p.text));
      const t = document.createElement('span'); t.className = 'time'; t.textContent = '\u{1F552} waiting to send'; el.appendChild(t);
      box.appendChild(el);
    }
    if (mode === 'prepend') box.scrollTop = prevTop + (box.scrollHeight - prevH);
    else if (mode === 'same') box.scrollTop = prevTop;
    else if (mode === 'divider' && divider) box.scrollTop = Math.max(0, divider.offsetTop - 60);
    else box.scrollTop = box.scrollHeight;
  }

  function quoteEl(r) {
    const q = document.createElement('span'); q.className = 'quote';
    const w = document.createElement('span'); w.className = 'qwho'; w.textContent = r.from || 'Message';
    const t = document.createElement('span'); t.className = 'qtext';
    t.textContent = r.deleted ? '\u{1F6AB} Message deleted' : (r.text || 'Original message');
    q.appendChild(w); q.appendChild(t);
    q.addEventListener('click', () => {
      const target = [...$('messages').children].find((e) => e.dataset && e.dataset.id === r.id);
      if (target) { target.scrollIntoView({ block: 'center' }); target.classList.add('flash'); setTimeout(() => target.classList.remove('flash'), 1200); }
    });
    return q;
  }
  function actionsEl(m, mine) {
    const a = document.createElement('span'); a.className = 'actions';
    const rb = document.createElement('button'); rb.type = 'button'; rb.textContent = '\u21A9'; rb.title = 'Reply'; rb.setAttribute('aria-label', 'Reply');
    rb.addEventListener('click', () => setReply({ id: m.id, from: m.from, text: m.text.slice(0, 80) }));
    a.appendChild(rb);
    if (mine) {
      const db = document.createElement('button'); db.type = 'button'; db.textContent = '\u{1F5D1}'; db.title = 'Delete for everyone'; db.setAttribute('aria-label', 'Delete for everyone');
      db.addEventListener('click', () => { if (confirm('Delete this message for everyone?')) send({ type: 'delete', id: m.id }); });
      a.appendChild(db);
    }
    return a;
  }
  function setReply(r) {
    state.replyTo = r;
    $('reply-bar').hidden = !r;
    if (r) { $('reply-who').textContent = r.from === state.me ? 'You' : r.from; $('reply-text').textContent = r.text; $('msg-input').focus(); }
  }
  function updateTitle() {
    let n = 0;
    for (const c of state.convs.values()) n += c.unread || 0;
    document.title = n > 0 ? `(${n}) ${BASE_TITLE}` : BASE_TITLE;
  }
  function notify(key, m) {
    if (!('Notification' in window) || Notification.permission !== 'granted') return;
    if (document.visibilityState === 'visible' && key === state.current) return;
    try {
      const n = new Notification(key === GROUP ? `# General \u2013 ${m.from}` : m.from, { body: m.deleted ? '' : m.text.slice(0, 120), tag: 'chat-' + key });
      n.onclick = () => { window.focus(); openConv(key); n.close(); };
    } catch (_) { /* some browsers only allow notifications from a service worker */ }
  }
  function flushPending() {
    while (state.pending.length) {
      const p = state.pending[0];
      const o = { type: 'msg', to: p.to, text: p.text };
      if (p.reply) o.reply = p.reply;
      if (!send(o)) return;
      state.pending.shift();
    }
    if (state.me) renderMessages('same');
  }
  function buildEmoji() {
    const pop = $('emoji-pop');
    for (const e of EMOJI) {
      const b = document.createElement('button'); b.type = 'button'; b.textContent = e; b.setAttribute('aria-label', 'Insert ' + e);
      b.addEventListener('click', () => {
        const i = $('msg-input');
        const a = i.selectionStart == null ? i.value.length : i.selectionStart, z = i.selectionEnd == null ? a : i.selectionEnd;
        if (i.value.length - (z - a) + e.length > i.maxLength) return;
        i.value = i.value.slice(0, a) + e + i.value.slice(z);
        i.focus(); i.selectionStart = i.selectionEnd = a + e.length;
      });
      pop.appendChild(b);
    }
  }
  function toggleEmoji(show) {
    const pop = $('emoji-pop');
    pop.hidden = show === undefined ? !pop.hidden : !show;
    $('emoji-btn').setAttribute('aria-expanded', String(!pop.hidden));
  }
  function showSettings(show) {
    $('settings').hidden = !show;
    if (show) { $('pw-msg').hidden = true; $('pw-old').focus(); }
    else { $('pw-old').value = ''; $('pw-new').value = ''; }
  }

  function renderAll() { renderSidebar(); renderHeader(); renderMessages(); }

  /* ---------------- typing indicator ---------------- */
  function showTyping(from) {
    clearTimeout(state.typingTimers.get(from));
    state.typingTimers.set(from, setTimeout(() => clearTyping(from), 3000));
    updateTyping();
  }
  function clearTyping(from) { clearTimeout(state.typingTimers.get(from)); state.typingTimers.delete(from); updateTyping(); }
  function updateTyping() {
    const names = [...state.typingTimers.keys()];
    $('typing').textContent = !names.length ? '' : names.length === 1 ? `${names[0]} is typing…` : 'Several people are typing…';
  }

  /* ---------------- composer ---------------- */
  $('msg-form').addEventListener('submit', (e) => {
    e.preventDefault();
    const input = $('msg-input');
    const text = input.value.trim();
    if (!text) return;
    if ('Notification' in window && Notification.permission === 'default') Notification.requestPermission().catch(() => {});
    const o = { type: 'msg', to: state.current, text };
    if (state.replyTo) o.reply = state.replyTo.id;
    flushPending();                                       // retry anything queued earlier first (keeps order)
    if (state.pending.length === 0 && send(o)) { input.value = ''; setReply(null); toggleEmoji(false); return; }
    if (state.pending.length >= 50) { toast('Too many unsent messages'); return; }
    state.pending.push({ to: state.current, text, reply: state.replyTo ? state.replyTo.id : null });   // sent automatically on reconnect
    input.value = ''; setReply(null); toggleEmoji(false);
    renderMessages('bottom');
    toast('Not connected \u2013 your message will be sent when you are back online.');
  });
  $('reply-cancel').addEventListener('click', () => setReply(null));
  $('emoji-btn').addEventListener('click', () => toggleEmoji());
  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    if (!$('settings').hidden) showSettings(false);
    else if (!$('emoji-pop').hidden) toggleEmoji(false);
    else if (state.replyTo) setReply(null);
  });
  $('settings-btn').addEventListener('click', () => showSettings(true));
  $('settings-close').addEventListener('click', () => showSettings(false));
  $('settings').addEventListener('click', (e) => { if (e.target === $('settings')) showSettings(false); });
  $('pw-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const msg = $('pw-msg'); msg.hidden = false; msg.classList.remove('error');
    try {
      const r = await api('/api/password', { old: $('pw-old').value, new: $('pw-new').value });
      if (r.ok) { msg.textContent = 'Password changed. Other devices were logged out.'; $('pw-old').value = ''; $('pw-new').value = ''; }
      else { msg.textContent = r.data.error || 'Could not change password'; msg.classList.add('error'); }
    } catch (_) { msg.textContent = 'Cannot reach the server'; msg.classList.add('error'); }
  });
  $('logout-all-btn').addEventListener('click', async () => {
    state.intentionalClose = true;
    try { await api('/api/logout-all', {}); } catch (_) { /* ignore */ }
    showSettings(false);
    state.users.clear(); state.convs.clear(); state.pending = []; state.me = null; state.current = GROUP;
    document.title = BASE_TITLE;
    showAuth();
  });
  $('msg-input').addEventListener('input', () => {
    const now = Date.now();
    if (now - state.lastTypingSent > 2000) { state.lastTypingSent = now; send({ type: 'typing', to: state.current }); }
  });
  $('user-filter').addEventListener('input', (e) => { state.filter = e.target.value; renderSidebar(); });
  $('menu-btn').addEventListener('click', () => $('sidebar').classList.toggle('open'));
  $('messages').addEventListener('scroll', () => { if ($('messages').scrollTop < 60) loadOlder(); });
  buildEmoji();
  document.addEventListener('visibilitychange', markRead);
  window.addEventListener('focus', markRead);

  /* ---------------- boot ---------------- */
  (async () => {
    try {
      const r = await api('/api/me');
      if (r.ok) { startChat(r.data.user); return; }
    } catch (_) { /* fall through to login */ }
    authScreen.hidden = false;
    $('auth-username').focus();
  })();
})();
