'use strict';
/* ============================================================
 * E2E checks for the three reported issues (runs in TEST_MODE):
 *   A) site -> TG text mirroring + reply linkage (meta.rt)
 *   B) site -> TG media mirroring (image/video/file via /api/mirror/media)
 *   C) delete notice content (bot shows WHICH message was deleted)
 *   D) TG -> site reply linkage (mirrored site message as reply target)
 * Run: node --test test/bridge.test.js
 * ============================================================ */
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { spawn } = require('node:child_process');
const http = require('node:http');
const path = require('node:path');
const os = require('node:os');
const fs = require('node:fs');

const ROOT = path.join(__dirname, '..');
const PORT = 18933;
const PW = 'BridgeTest#12345';
let child = null;
let bootLogs = [];
let dataDir = null;
let TOK = null;

function request(method, p, { headers = {}, body = null } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port: PORT, path: p, method, headers }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({
        status: res.statusCode,
        headers: res.headers,
        body: Buffer.concat(chunks),
        text: Buffer.concat(chunks).toString('utf8'),
      }));
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}
const json = (r) => JSON.parse(r.text || '{}');
const authed = (h = {}) => Object.assign({ Authorization: 'Bearer ' + TOK, 'Content-Type': 'application/json' }, h);

async function waitForHealth(timeoutMs = 10000) {
  const t0 = Date.now();
  for (;;) {
    try { const r = await request('GET', '/api/health'); if (r.status === 200) return r; } catch {}
    if (Date.now() - t0 > timeoutMs) throw new Error('server not healthy\n' + bootLogs.join('\n'));
    await new Promise((r) => setTimeout(r, 200));
  }
}

before(async () => {
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'panda-bridge-'));
  child = spawn(process.execPath, [path.join(ROOT, 'server.js')], {
    env: Object.assign({}, process.env, {
      PORT: String(PORT),
      KEY_SALT: 'bridge-test-salt-0123456789',
      PASSWORD: PW,
      VAULT_SECRET: 'bridge-test-vault-secret',
      VAULT_TEST_MODE: '1',
      TELEGRAM_ADMIN_ID: '555000111',
      RAILWAY_VOLUME_MOUNT_PATH: dataDir,
    }),
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout.on('data', (d) => bootLogs.push(String(d)));
  child.stderr.on('data', (d) => bootLogs.push(String(d)));
  await waitForHealth();
  const r = await request('POST', '/api/login', {
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ pw: PW, name: 'bridge' }),
  });
  assert.strictEqual(r.status, 200, 'login failed: ' + r.text);
  TOK = json(r).tok;
  assert.ok(TOK);
});

after(() => {
  if (child) { try { child.kill(); } catch {} }
  if (dataDir) { try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch {} }
});

const tgout = async () => json(await request('POST', '/__test/tgout', { headers: { 'Content-Type': 'application/json' }, body: '{}' })).out;
const flush = async () => request('POST', '/__test/flush', { headers: { 'Content-Type': 'application/json' }, body: '{}' });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function sendText(text, rt) {
  const meta = { k: 'text', from: 'tagbridge1234', un: 'bridge' };
  if (rt) meta.rt = rt;
  const r = await request('POST', '/api/send', {
    headers: authed(),
    body: JSON.stringify({ iv: 'AAAAAAAAAAAAAAAAAAAAAA==', c: Buffer.from(text).toString('base64'), meta }),
  });
  assert.strictEqual(r.status, 200, 'send: ' + r.text);
  const j = json(r);
  // mirror to TG like the client does
  await request('POST', '/api/mirror/text', {
    headers: authed(),
    body: JSON.stringify({ mid: j.id, text }),
  });
  return j.id;
}

test('A: site text mirrors to TG', async () => {
  const id = await sendText('پیام اول برای تلگرام');
  await flush();
  await sleep(300);
  const out = await tgout();
  const sends = out.filter(x => x.method === 'sendMessage' && String(x.payload.text || '').includes('پیام اول'));
  assert.ok(sends.length, 'text mirrored, out=' + JSON.stringify(out.slice(-5)));
});

test('A2: reply on site carries reply_to_message_id to TG', async () => {
  const idA = await sendText('متن هدف ریپلای');
  await flush(); await sleep(200);
  const idB = await sendText('این یک ریپلای است', idA);
  await flush(); await sleep(200);
  const out = await tgout();
  const rep = out.filter(x => x.method === 'sendMessage' && String(x.payload.text || '').includes('این یک ریپلای است')).pop();
  assert.ok(rep, 'reply mirrored');
  assert.ok(rep.payload.reply_to_message_id !== undefined,
    'reply_to_message_id must ride along — got ' + JSON.stringify(rep.payload));
});

test('B: image media mirrors to TG via sendPhoto', async () => {
  // tiny fake "jpeg"
  const bytes = Buffer.from([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01]);
  const env = JSON.stringify({ iv: 'AAAAAAAAAAAAAAAAAAAAAA==', c: Buffer.from(bytes).toString('base64'), miv: 'AAAAAAAAAAAAAAAAAAAAAA==', mc: Buffer.from('image/jpeg').toString('base64') });
  const up = await request('PUT', '/api/blob', { headers: authed({ 'Content-Type': 'application/octet-stream' }), body: env });
  assert.strictEqual(up.status, 200, 'blob upload: ' + up.text);
  const bid = json(up).bid;

  const meta = { k: 'image', from: 'tagbridge1234', un: 'bridge', blob: bid, name: 'photo.jpg', mime: 'image/jpeg', size: bytes.length };
  const nEnc = { iv: 'AAAAAAAAAAAAAAAAAAAAAA==', c: Buffer.from('عکس تستی').toString('base64') };
  const r = await request('POST', '/api/send', { headers: authed(), body: JSON.stringify({ iv: nEnc.iv, c: nEnc.c, meta }) });
  assert.strictEqual(r.status, 200, 'send media: ' + r.text);
  const mid = json(r).id;

  const mm = await request('POST', '/api/mirror/media', {
    headers: authed({
      'Content-Type': 'application/octet-stream',
      'x-vault-mid': mid, 'x-vault-kind': 'image', 'x-vault-mime': 'image%2Fjpeg',
      'x-vault-name': 'photo.jpg', 'x-vault-cap': encodeURIComponent('کپشن عکس'),
    }),
    body: bytes,
  });
  assert.strictEqual(mm.status, 200, 'mirror/media: ' + mm.text);
  assert.ok(!json(mm).skipped, 'must not be rate-skipped: ' + mm.text);
  await sleep(300);
  const out = await tgout();
  const photos = out.filter(x => x.method === 'sendPhoto');
  assert.ok(photos.length, 'sendPhoto must appear, out tail=' + JSON.stringify(out.slice(-4)));
});

test('B2: video media mirrors to TG via sendVideo', async () => {
  const bytes = Buffer.from([0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70, 0x6D, 0x70, 0x34]);
  const env = JSON.stringify({ iv: 'AAAAAAAAAAAAAAAAAAAAAA==', c: bytes.toString('base64'), miv: 'AAAAAAAAAAAAAAAAAAAAAA==', mc: Buffer.from('video/mp4').toString('base64') });
  const up = await request('PUT', '/api/blob', { headers: authed({ 'Content-Type': 'application/octet-stream' }), body: env });
  assert.strictEqual(up.status, 200);
  const bid = json(up).bid;
  const meta = { k: 'video', from: 'tagbridge1234', un: 'bridge', blob: bid, name: 'clip.mp4', mime: 'video/mp4', size: bytes.length };
  const nEnc = { iv: 'AAAAAAAAAAAAAAAAAAAAAA==', c: Buffer.from('ویدیو تستی').toString('base64') };
  const r = await request('POST', '/api/send', { headers: authed(), body: JSON.stringify({ iv: nEnc.iv, c: nEnc.c, meta }) });
  assert.strictEqual(r.status, 200);
  const mid = json(r).id;
  const mm = await request('POST', '/api/mirror/media', {
    headers: authed({
      'Content-Type': 'application/octet-stream',
      'x-vault-mid': mid, 'x-vault-kind': 'video', 'x-vault-mime': 'video%2Fmp4',
      'x-vault-name': 'clip.mp4', 'x-vault-cap': '',
    }),
    body: bytes,
  });
  assert.strictEqual(mm.status, 200, 'mirror/media video: ' + mm.text);
  await sleep(300);
  const out = await tgout();
  assert.ok(out.filter(x => x.method === 'sendVideo').length, 'sendVideo must appear');
});

test('C: delete notice names the deleted message', async () => {
  const id = await sendText('این پیام قرار است حذف شود');
  await flush(); await sleep(200);
  const del = await request('POST', '/api/delete', {
    headers: authed(),
    body: JSON.stringify({ ids: [id], prev: ['این پیام قرار است حذف شود'] }),
  });
  assert.strictEqual(del.status, 200, 'delete: ' + del.text);
  await sleep(300);
  const out = await tgout();
  const notes = out.filter(x => x.method === 'sendMessage' && String(x.payload.text || '').includes('حذف'));
  assert.ok(notes.length, 'delete notice sent');
  const lastNote = notes[notes.length - 1].payload.text;
  assert.ok(lastNote.includes('این پیام قرار است حذف شود'),
    'notice must show the deleted message content — got: ' + lastNote);
  // mirrored TG copy must be deleted as well
  const dels = json(await request('POST', '/__test/tgdel', { headers: { 'Content-Type': 'application/json' }, body: '{}' })).deletes;
  assert.ok(dels.length, 'TG mirror deleteMessage captured');
});

test('D: TG admin replying to a MIRRORED SITE message links on the site', async () => {
  // site message A mirrors to TG mid 999
  const idA = await sendText('پیام سایت که در تلگرام mirror شد');
  await flush(); await sleep(200);
  await request('POST', '/__test/mirror', { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ mid: idA, tgm: 999 }) });
  // admin replies in TG to mid 999
  const br = await request('POST', '/__test/bridge', {
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ tgm: 556, text: 'ریپلای ادمین از تلگرام', rly: 999 }),
  });
  assert.strictEqual(br.status, 200, 'bridge: ' + br.text);
  const sid = json(br).id;
  const h = await request('GET', '/api/history', { headers: authed() });
  const hj = json(h);
  const m = hj.messages.find(x => x.id === sid);
  assert.ok(m, 'bridged message in history');
  assert.ok(m.meta && m.meta.rt === idA,
    'reply must be LINKED to site message ' + idA + ' — meta=' + JSON.stringify(m.meta));
});
