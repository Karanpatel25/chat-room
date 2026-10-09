// Frontend smoke test: runs public/app.js in jsdom against a fake WebSocket. Needs: npm i jsdom
const { JSDOM } = require('jsdom');
const fs = require('fs');
const root = require('path').join(__dirname, '..', 'public') + '/';
const html = fs.readFileSync(root + 'index.html', 'utf8').replace('<script src="/app.js"></script>', '');
const dom = new JSDOM(html, { runScripts: 'outside-only', pretendToBeVisual: true, url: 'http://localhost/' });
const w = dom.window;
const sent = [];
let sock;
w.WebSocket = class { constructor() { sock = this; this.readyState = 1; setTimeout(() => this.onopen && this.onopen(), 0); }
  send(s) { sent.push(JSON.parse(s)); } close() {} };
w.WebSocket.OPEN = 1;
w.fetch = async () => ({ ok: true, status: 200, json: async () => ({ user: 'alice' }) });
w.eval(fs.readFileSync(root + 'app.js', 'utf8'));
const push = (o) => sock.onmessage({ data: JSON.stringify(o) });
const $ = (id) => w.document.getElementById(id);
let fails = 0; const ok = (n, c) => { if (!c) { fails++; console.log('FAIL', n); } else console.log('ok  ', n); };
const T = Date.now();

(async () => {
  await new Promise((r) => setTimeout(r, 20));           // boot: /api/me -> startChat -> connect
  push({ type: 'hello', user: 'alice' });
  push({ type: 'users', users: [{ name: 'alice', online: true, last_seen: 0 }, { name: 'bob', online: false, last_seen: T - 3600e3 }, { name: 'carol', online: true, last_seen: 0 }] });
  push({ type: 'convs', convs: [
    { with: '', last_id: '0', last_from: '', last_text: '', last_status: '', last_ts: 0, unread: 0 },
    { with: 'bob', last_id: '7', last_from: 'bob', last_text: 'lunch?', last_status: '', last_ts: T - 60e3, unread: 2 } ] });
  push({ type: 'history', with: '', before: '', more: false, messages: [] });

  ok('chat list shows group + bob, carol under "New chat"',
     $('chat-list').children.length === 2 && $('user-list').textContent.includes('carol') && !$('user-list').textContent.includes('bob'));
  ok('bob row shows preview + unread badge 2', $('chat-list').textContent.includes('lunch?') && $('chat-list').querySelector('.badge').textContent === '2');
  ok('bob (most recent) sorted above empty group', $('chat-list').children[0].textContent.includes('bob'));

  // open bob: history with 3 messages, 2 unread -> divider before the first unread
  $('chat-list').children[0].querySelector('button').click();
  ok('openConv requests history', sent.some((m) => m.type === 'history' && m.with === 'bob'));
  ok('header shows last seen', $('conv-sub').textContent.startsWith('last seen'));
  push({ type: 'history', with: 'bob', before: '', more: true, messages: [
    { id: '5', from: 'alice', to: 'bob', text: 'hey', ts: T - 300e3, status: 'delivered' },
    { id: '6', from: 'bob', to: 'alice', text: 'hi', ts: T - 120e3 },
    { id: '7', from: 'bob', to: 'alice', text: 'lunch?', ts: T - 60e3 } ] });
  ok('unread divider placed before 2nd incoming-from-end (id 6)',
     $('messages').textContent.indexOf('Unread messages') < $('messages').textContent.indexOf('hi') &&
     $('messages').textContent.indexOf('Unread messages') > $('messages').textContent.indexOf('hey'));
  ok('own message shows double grey tick', $('messages').querySelector('.tick.delivered') !== null);
  ok('"Load older messages" button shown when more=true', $('messages').querySelector('button.older') !== null);
  ok('sent read receipt for newest incoming (7)', sent.some((m) => m.type === 'read' && m.with === 'bob' && m.upto === '7'));
  ok('unread badge cleared locally', !$('chat-list').querySelector('.badge'));

  // send + receipts: sent -> delivered -> read
  push({ type: 'msg', id: '8', from: 'alice', to: 'bob', text: 'yes!', ts: T });
  ok('new own msg shows single tick', $('messages').querySelector('.tick.sent') !== null);
  push({ type: 'receipt', with: 'bob', status: 'delivered', upto: '8' });
  ok('delivered receipt -> no sent ticks left', $('messages').querySelector('.tick.sent') === null);
  push({ type: 'receipt', with: 'bob', status: 'read', upto: '8' });
  ok('read receipt covers earlier msgs too -> 2 blue ticks', $('messages').querySelectorAll('.tick.read').length === 2);
  ok('chat-list preview tick upgraded too', $('chat-list').querySelector('.preview .tick.read') !== null);

  // pagination prepend, dedupe
  const oldTop = $('messages').querySelector('button.older');
  oldTop.click();
  ok('"older" requests before=<first id>', sent.some((m) => m.type === 'history' && m.before === '5'));
  push({ type: 'history', with: 'bob', before: '5', more: false, messages: [{ id: '3', from: 'bob', to: 'alice', text: 'ancient', ts: T - 86400e3 * 2 }] });
  ok('older page prepended, button gone, day separator added',
     $('messages').textContent.indexOf('ancient') < $('messages').textContent.indexOf('hey') && !$('messages').querySelector('button.older') && $('messages').querySelectorAll('.daysep').length >= 2);

  // incoming message in a background chat bumps unread + reorders; unread frame syncs from another tab
  push({ type: 'msg', id: '9', from: 'carol', to: 'alice', text: 'ping', ts: T + 1000 });
  ok('background msg adds carol to chat list with badge 1', $('chat-list').textContent.includes('ping') && $('chat-list').querySelector('.badge').textContent === '1');
  ok('carol no longer in "New chat"', !$('user-list').textContent.includes('carol'));
  push({ type: 'unread', with: 'carol', count: 0 });
  ok('unread frame clears badge', !$('chat-list').querySelector('.badge'));

  // XSS: message text only via textContent
  push({ type: 'msg', id: '10', from: 'bob', to: 'alice', text: '<img src=x onerror=alert(1)>', ts: T + 2000 });
  ok('HTML in message stays text', $('messages').querySelector('img') === null && $('messages').textContent.includes('<img src=x'));

  // ---- new features
  push({ type: 'msg', id: '11', from: 'carol', to: 'alice', text: 'hello again', ts: T + 3000 });
  ok('title badge counts unread', w.document.title.startsWith('(1)'));
  push({ type: 'unread', with: 'carol', count: 0 });
  ok('title badge clears', !w.document.title.startsWith('('));

  // reply: click reply on bob's message -> bar shown, outgoing msg carries reply id
  const bubble = [...$('messages').children].find((e) => e.dataset && e.dataset.id === '6');
  bubble.querySelector('.actions button').click();
  ok('reply bar shown', !$('reply-bar').hidden && $('reply-text').textContent === 'hi');
  $('msg-input').value = 'answer';
  $('msg-form').dispatchEvent(new w.Event('submit', { cancelable: true }));
  ok('outgoing msg includes reply id', sent.some((m) => m.type === 'msg' && m.text === 'answer' && m.reply === '6'));
  ok('reply bar cleared after send', $('reply-bar').hidden);
  push({ type: 'msg', id: '12', from: 'alice', to: 'bob', text: 'answer', ts: T + 4000, reply: { id: '6', from: 'bob', text: 'hi', deleted: false } });
  ok('quote rendered inside bubble', $('messages').querySelector('.quote .qtext').textContent === 'hi' && $('messages').querySelector('.quote .qwho').textContent === 'bob');

  // delete: own message has delete action; frame removes text everywhere
  const mine = [...$('messages').children].find((e) => e.dataset && e.dataset.id === '12');
  ok('own message has delete button, others do not', mine.querySelectorAll('.actions button').length === 2 && bubble.querySelectorAll('.actions button').length === 1);
  w.confirm = () => true;
  mine.querySelectorAll('.actions button')[1].click();
  ok('delete frame sent', sent.some((m) => m.type === 'delete' && m.id === '12'));
  push({ type: 'deleted', id: '12', from: 'alice', to: 'bob' });
  const after = [...$('messages').children].find((e) => e.dataset && e.dataset.id === '12');
  ok('deleted bubble shows tombstone, no text, no actions', after.textContent.includes('This message was deleted') && !after.textContent.includes('answer') && !after.querySelector('.actions'));
  ok('chat-list preview shows deleted', $('chat-list').textContent.includes('This message was deleted'));

  // offline queue: disconnect, type, reconnect -> flushed in order
  sock.readyState = 3;
  $('msg-input').value = 'queued one';
  $('msg-form').dispatchEvent(new w.Event('submit', { cancelable: true }));
  ok('offline message shown dimmed as pending', $('messages').querySelector('.msg.pending') !== null && $('msg-input').value === '');
  const n0 = sent.length;
  sock.readyState = 1; sock.onopen();
  ok('pending message sent on reconnect', sent.slice(n0).some((m) => m.type === 'msg' && m.text === 'queued one' && m.to === 'bob'));
  ok('pending bubble gone after flush', $('messages').querySelector('.msg.pending') === null);

  // emoji picker + settings
  ok('emoji picker populated', $('emoji-pop').children.length >= 16);
  $('emoji-btn').click();
  ok('emoji picker opens', !$('emoji-pop').hidden);
  $('msg-input').value = 'x';
  $('emoji-pop').children[0].click();
  ok('emoji inserted into input', $('msg-input').value.length > 1 && $('msg-input').value.startsWith('x'));
  $('settings-btn').click();
  ok('settings dialog opens', !$('settings').hidden);
  w.document.dispatchEvent(new w.KeyboardEvent('keydown', { key: 'Escape' }));
  ok('Escape closes settings', $('settings').hidden);
  console.log(fails ? `\n${fails} FAILED` : '\nfrontend smoke: all passed');
  process.exit(fails ? 1 : 0);
})();
