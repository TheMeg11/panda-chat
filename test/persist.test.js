'use strict';
/* ============================================================
 * v33 persistence tests — blobs must SURVIVE a server restart
 * (the root cause of «رسانه در دسترس نیست» after redeploys) and
 * delete notices must fall back to the mirror-plaintext cache
 * when the client sends no preview.
 * Run: node --test test/persist.test.js
 * ============================================================ */
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { spawn } = require('node:child_process');
const http = require('node:http');
const path = require('node:path');
const os = require('node:os');
const fs = require('node:fs');

const ROOT = path.join(__dirname, '..');
const PORT = 18935;
const PW = 'Persist#12345';
let child = null;
let bootLogs = [];
let dataDir = null;
let TOK = null;

function request(method, p, { headers = {}, body = null } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port: PORT, path: p, method, headers }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, text: Buffer.concat(chunks).toString('utf8'), buf: Buffer.concat(chunks) }));
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}
const json = (r) => JSON.parse(r.text || '{}');
const authed = (h = {}) => Object.assign({ Authorization: 'Bearer ' + TOK, 'Content-Type': 'application/json' }, h);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function startServer() {
  child = spawn(process.execPath, [path.join(ROOT, 'server.js')], {
    env: Object.assign({}, process.env, {
      PORT: String(PORT),
      KEY_SALT: 'persist-salt-0123456789',
      PASSWORD: PW,
      VAULT_SECRET: 'persist-vault-secret',
      VAULT_TEST_MODE: '1',
      TELEGRAM_ADMIN_ID: '555000111',
      RAILWAY_VOLUME_MOUNT_PATH: dataDir,
    }),
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout.on('data', (d) => bootLogs.push(String(d)));
  child.stderr.on('data', (d) => bootLogs.push(String(d)));
  const t0 = Date.now();
  for (;;) {
    try { const r = await request('GET', '/api/health'); if (r.status === 200) return; } catch {}
    if (Date.now() - t0 > 12000) throw new Error('boot timeout\n' + bootLogs.join('\n'));
    await new Promise((r) => setTimeout(r, 200));
  }
}
function stopServer() {
  return new Promise((resolve) => {
    if (!child) return resolve();
    child.once('exit', () => resolve());
    try { child.kill(); } catch { resolve(); }
    setTimeout(resolve, 3000);
  });
}

before(async () => {
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'panda-persist-'));
  await startServer();
  const r = await request('POST', '/api/login', {
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ pw: PW, name: 'persist' }),
  });
  TOK = json(r).tok;
  assert.ok(TOK, 'login');
});

after(async () => { await stopServer(); try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch {} });

test('v33: blob survives a full server restart (disk-backed)', async () => {
  const bytes = Buffer.from('MEDIA-BYTES-' + 'x'.repeat(1000));
  const env = JSON.stringify({
    iv: 'AAAAAAAAAAAAAAAAAAAAAA==',
    c: Buffer.from(bytes).toString('base64'),
    miv: 'AAAAAAAAAAAAAAAAAAAAAA==',
    mc: Buffer.from('application/octet-stream').toString('base64'),
  });
  const up = await request('PUT', '/api/blob', { headers: authed({ 'Content-Type': 'application/octet-stream' }), body: env });
  assert.strictEqual(up.status, 200, 'upload: ' + up.text);
  const bid = json(up).bid;
  assert.ok(bid);
  // a blob file must exist on the volume
  const files = fs.readdirSync(path.join(dataDir, 'blobs')).filter(f => f.endsWith('.json'));
  assert.ok(files.some(f => f.startsWith(bid)), 'envelope persisted under blobs/');
  // restart the whole process
  await stopServer();
  bootLogs = [];
  await startServer();
  // old session tokens die, but the blob must still be there after login
  const re = await request('POST', '/api/login', {
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ pw: PW, name: 'persist' }),
  });
  TOK = json(re).tok;
  assert.ok(TOK);
  const get = await request('GET', '/api/blob/' + bid, { headers: authed() });
  assert.strictEqual(get.status, 200, 'blob GET after restart: ' + get.text);
  const env2 = json(get);
  assert.strictEqual(env2.c, Buffer.from(bytes).toString('base64'), 'envelope bytes identical');
});

test('v33: delete notice falls back to the mirror-plaintext cache', async () => {
  // send + mirror a text (no prev will be sent on delete)
  const meta = { k: 'text', from: 'tagpersist1234', un: 'persist' };
  const text = 'این پیام بدون prev حذف می‌شود';
  const r = await request('POST', '/api/send', {
    headers: authed(),
    body: JSON.stringify({ iv: 'AAAAAAAAAAAAAAAAAAAAAA==', c: Buffer.from(text).toString('base64'), meta }),
  });
  const mid = json(r).id;
  await request('POST', '/api/mirror/text', { headers: authed(), body: JSON.stringify({ mid, text }) });
  await request('POST', '/__test/flush', { headers: { 'Content-Type': 'application/json' }, body: '{}' });
  await sleep(300);
  const del = await request('POST', '/api/delete', {
    headers: authed(),
    body: JSON.stringify({ ids: [mid] }),   // NO prev — cache fallback must kick in
  });
  assert.strictEqual(del.status, 200);
  await sleep(250);
  const out = json(await request('POST', '/__test/tgout', { headers: { 'Content-Type': 'application/json' }, body: '{}' })).out;
  const notes = out.filter(x => x.method === 'sendMessage' && String(x.payload.text || '').includes('حذف'));
  assert.ok(notes.length, 'notice sent');
  const lastNote = notes[notes.length - 1].payload.text;
  assert.ok(lastNote.includes(text), 'cache fallback names the deleted message — got: ' + lastNote);
});

test('v33: wipe clears blob disk too', async () => {
  const before0 = fs.readdirSync(path.join(dataDir, 'blobs')).filter(f => f.endsWith('.json'));
  const r = await request('DELETE', '/api/history', { headers: authed() });
  assert.strictEqual(r.status, 200);
  const after0 = fs.readdirSync(path.join(dataDir, 'blobs')).filter(f => f.endsWith('.json'));
  assert.strictEqual(after0.length, 0, 'blob files wiped with history (' + before0.length + ' existed)');
});
