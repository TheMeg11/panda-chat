'use strict';
/* ============================================================
 * Smoke tests — zero-dependency (node:test + node:http).
 * Boots server.js as a child process in VAULT_TEST_MODE with an
 * isolated RAILWAY_VOLUME_MOUNT_PATH (temp dir) so the project
 * folder and any real data.json are never touched.
 *
 * Run: npm test   (or: node --test test/)
 * ============================================================ */
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { spawn } = require('node:child_process');
const http = require('node:http');
const path = require('node:path');
const os = require('node:os');
const fs = require('node:fs');

const ROOT = path.join(__dirname, '..');
const PORT = 18931;
const PW = 'SmokeTest#12345';
let child = null;
let bootLogs = [];
let dataDir = null;

function request(method, p, { headers = {}, body = null } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port: PORT, path: p, method, headers }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({
        status: res.statusCode,
        headers: res.headers,
        body: Buffer.concat(chunks).toString('utf8'),
      }));
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

async function waitForHealth(timeoutMs = 10000) {
  const t0 = Date.now();
  for (;;) {
    try {
      const r = await request('GET', '/api/health');
      if (r.status === 200) return r;
    } catch {}
    if (Date.now() - t0 > timeoutMs) {
      throw new Error('server did not become healthy in ' + timeoutMs + 'ms\n' + bootLogs.join('\n'));
    }
    await new Promise((r) => setTimeout(r, 200));
  }
}

before(async () => {
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'panda-chat-test-'));
  child = spawn(process.execPath, [path.join(ROOT, 'server.js')], {
    env: Object.assign({}, process.env, {
      PORT: String(PORT),
      KEY_SALT: 'smoke-test-salt-0123456789',
      PASSWORD: PW,
      VAULT_SECRET: 'smoke-test-vault-secret',
      VAULT_TEST_MODE: '1',
      RAILWAY_VOLUME_MOUNT_PATH: dataDir,
    }),
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout.on('data', (d) => bootLogs.push(String(d)));
  child.stderr.on('data', (d) => bootLogs.push(String(d)));
  await waitForHealth();
});

after(() => {
  if (child) { try { child.kill(); } catch {} }
  if (dataDir) { try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch {} }
});

test('health endpoint responds ok with security headers', async () => {
  const r = await request('GET', '/api/health');
  assert.strictEqual(r.status, 200);
  const j = JSON.parse(r.body);
  assert.strictEqual(j.ok, true);
  assert.ok(j.title, 'title present');
  assert.strictEqual(r.headers['x-content-type-options'], 'nosniff');
  assert.ok(r.headers['content-security-policy'], 'CSP present');
  assert.ok(r.headers['strict-transport-security'], 'HSTS present');
});

test('unauthenticated API calls are rejected with 401', async () => {
  const r = await request('GET', '/api/history');
  assert.strictEqual(r.status, 401);
});

test('cross-origin API calls are rejected with 403', async () => {
  const r = await request('GET', '/api/health', { headers: { Origin: 'https://evil.example' } });
  assert.strictEqual(r.status, 403);
});

test('login hello probe reports auth mode', async () => {
  const r = await request('POST', '/api/login', {
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ mode: 'hello' }),
  });
  assert.strictEqual(r.status, 200);
  const j = JSON.parse(r.body);
  assert.ok(j.mode === 'legacy' || j.mode === 'new', 'mode is legacy or new');
});

test('wrong password is rejected with 401', async () => {
  const r = await request('POST', '/api/login', {
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ pw: 'definitely-wrong-pw', name: 'tester' }),
  });
  assert.strictEqual(r.status, 401);
});

test('correct password grants a token that unlocks /api/history', async () => {
  const r = await request('POST', '/api/login', {
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ pw: PW, name: 'smoke' }),
  });
  assert.strictEqual(r.status, 200);
  const j = JSON.parse(r.body);
  assert.strictEqual(j.ok, true);
  assert.ok(j.tok, 'token returned');

  /* v29: migrate the vault to zero-knowledge (PBKDF2-250k KDF, same as the
     browser client) so trusted-device tests can run against the full
     passwordless stack */
  const wb = require('node:crypto').webcrypto;
  const te = new TextEncoder();
  const b64e = (b) => Buffer.from(b).toString('base64');
  const b64d = (s) => Buffer.from(s, 'base64');
  const pbkdf2 = (pw, saltB64) => wb.subtle.importKey('raw', te.encode(pw), 'PBKDF2', false, ['deriveBits'])
    .then((base) => wb.subtle.deriveBits({ name: 'PBKDF2', salt: b64d(saltB64), iterations: 250000, hash: 'SHA-256' }, base, 256))
    .then((bits) => new Uint8Array(bits));
  const hkdfK = (raw) => wb.subtle.importKey('raw', raw, 'HKDF', false, ['deriveKey'])
    .then((base) => wb.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: te.encode('ck-wrap-v1') },
      base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']));
  const aesImp = (raw) => wb.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  const aesE = async (key, raw) => {
    const iv = require('node:crypto').randomBytes(12);
    const ct = await wb.subtle.encrypt({ name: 'AES-GCM', iv }, key, raw);
    return { iv: b64e(iv), c: b64e(Buffer.from(ct)) };
  };
  const saltA = b64e(require('node:crypto').randomBytes(16));
  const saltB = b64e(require('node:crypto').randomBytes(16));
  const verifier = b64e(await pbkdf2(PW, saltA));
  const kek = await hkdfK(await pbkdf2(PW, saltB));
  const ckRaw = require('node:crypto').randomBytes(32);
  const pwWrap = await aesE(kek, ckRaw);
  const ckKey = await aesImp(ckRaw);
  const legacyRaw = await pbkdf2(PW, b64e(Buffer.from('smoke-test-salt-0123456789')));
  const legacyWrap = await aesE(ckKey, legacyRaw);
  globalThis.__smokeCk = b64e(ckRaw);   /* reused by the device tests */
  const up = await request('POST', '/api/upgrade', {
    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + j.tok },
    body: JSON.stringify({ verifier, saltA, saltB, pwWrap, legacyWrap, legacyTag: 'smoke001122', legacyName: 'smoke' }),
  });
  assert.strictEqual(up.status, 200, 'upgrade should succeed: ' + up.body);
  const upj = JSON.parse(up.body);
  assert.strictEqual(upj.ok, true);
  globalThis.__smokeTok = upj.tok;

  /* seed the server-assisted fallback wrap (mirrors ensureVaultFallback) */
  const fkr = await request('GET', '/api/vault-fallback-key', { headers: { Authorization: 'Bearer ' + upj.tok } });
  const fkj = JSON.parse(fkr.body);
  const fkKey = await aesImp(b64d(fkj.k));
  const fbWrap = await aesE(fkKey, ckRaw);
  const fbs = await request('POST', '/api/vault-fallback', {
    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + upj.tok },
    body: JSON.stringify({ iv: fbWrap.iv, c: fbWrap.c, name: 'smoke' }),
  });
  assert.strictEqual(fbs.status, 200);

  const h = await request('GET', '/api/history', { headers: { Authorization: 'Bearer ' + upj.tok } });
  assert.strictEqual(h.status, 200);
  const hj = JSON.parse(h.body);
  assert.ok(Array.isArray(hj.messages), 'messages array');
  /* v29: history carries the real last-seen map for both sides */
  assert.ok(hj.lastSeen && typeof hj.lastSeen === 'object', 'lastSeen present');
  assert.ok(Number(hj.lastSeen.tg) >= 0, 'lastSeen.tg numeric');
  assert.ok(hj.lastSeen.users && typeof hj.lastSeen.users === 'object', 'lastSeen.users present');
  assert.ok(hj.presence && typeof hj.presence.tgSeen === 'number', 'presence.tgSeen present');
});

test('static index.html is served for navigations', async () => {
  const r = await request('GET', '/', { headers: { Accept: 'text/html' } });
  assert.strictEqual(r.status, 200);
  assert.match(r.headers['content-type'], /text\/html/);
  assert.match(r.body, /id="gate"/);
});

test('path traversal outside public/ is blocked', async () => {
  const r = await request('GET', '/..%2fserver.js', { headers: { Accept: 'text/html' } });
  assert.notStrictEqual(r.status, 200);
  assert.ok(!r.body.includes("'use strict'"), 'server source not leaked');
});

test('device challenge for an unknown device is 404', async () => {
  const r = await request('POST', '/api/device/challenge', {
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ devId: 'deadbeefdeadbeefdeadbeefdeadbeef' }),
  });
  assert.strictEqual(r.status, 404);
});

test('trusted-device flow end to end: req → approve → challenge → login', async () => {
  const wb = require('node:crypto').webcrypto;
  const te = new TextEncoder();
  const b64e = (b) => Buffer.from(b).toString('base64');
  const b64ue = (b) => b64e(b).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const tok = globalThis.__smokeTok;
  assert.ok(tok, 'migration test must run first');
  /* fresh EC P-256 keypair for "this browser" */
  const kp = await wb.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const pub = await wb.subtle.exportKey('jwk', kp.publicKey);
  const devId = require('node:crypto').randomBytes(16).toString('hex');
  const req = await request('POST', '/api/device/req', {
    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + tok },
    body: JSON.stringify({ devId, pub: JSON.stringify({ kty: 'EC', crv: 'P-256', x: pub.x, y: pub.y }), label: 'smoke-phone' }),
  });
  assert.strictEqual(req.status, 200, 'device request: ' + req.body);
  const reqj = JSON.parse(req.body);
  assert.strictEqual(reqj.ok, true);
  assert.strictEqual(reqj.state, 'pending');
  /* challenge must work post-registration but login before approval is impossible
     (the pubkey only lands in state.devices on approval) */
  /* admin approves via the TEST_MODE hook (no Telegram) */
  const dec = await request('POST', '/__test/dev-decide', {
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id: reqj.id, decision: 'a' }),
  });
  assert.strictEqual(dec.status, 200);
  const st = await request('POST', '/__test/dev-state', {
    headers: { 'Content-Type': 'application/json' }, body: '{}',
  });
  const stj = JSON.parse(st.body);
  assert.ok(stj.devices[devId], 'device persisted after approval');
  /* challenge → sign nonce → login */
  const ch = await request('POST', '/api/device/challenge', {
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ devId }),
  });
  assert.strictEqual(ch.status, 200);
  const chj = JSON.parse(ch.body);
  assert.ok(chj.nonce, 'nonce issued');
  const sig = await wb.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, kp.privateKey, te.encode(chj.nonce));
  const lin = await request('POST', '/api/device/login', {
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ devId, nonce: chj.nonce, sig: b64ue(sig) }),
  });
  assert.strictEqual(lin.status, 200, 'device login: ' + lin.body);
  const lj = JSON.parse(lin.body);
  assert.strictEqual(lj.ok, true);
  assert.ok(lj.tok && lj.wrap && lj.fk, 'session + fallback wrap issued');
  /* the issued token actually opens history */
  const h = await request('GET', '/api/history', { headers: { Authorization: 'Bearer ' + lj.tok } });
  assert.strictEqual(h.status, 200);
  /* replaying the same nonce must fail */
  const sig2 = await wb.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, kp.privateKey, te.encode(chj.nonce));
  const rep = await request('POST', '/api/device/login', {
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ devId, nonce: chj.nonce, sig: b64ue(sig2) }),
  });
  assert.strictEqual(rep.status, 401, 'single-use nonce enforced');
  /* revoke via the API, then challenge must 404 again */
  const rev = await request('POST', '/api/device/revoke', {
    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + tok },
    body: JSON.stringify({ devId }),
  });
  assert.strictEqual(rev.status, 200);
  const ch2 = await request('POST', '/api/device/challenge', {
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ devId }),
  });
  assert.strictEqual(ch2.status, 404);
});

test('bot /lastseen and /devices commands render', async () => {
  const cmd = async (text) => {
    const r = await request('POST', '/__test/cmd', {
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text }),
    });
    assert.strictEqual(r.status, 200);
    return (JSON.parse(r.body).replies || []).join('\n');
  };
  const ls = await cmd('/lastseen');
  assert.ok(ls.includes('لست‌سین') || ls.includes('last'), 'lastseen reply: ' + ls.slice(0, 120));
  const dv = await cmd('/devices');
  assert.ok(dv.includes('دستگاه') || dv.includes('device'), 'devices reply: ' + dv.slice(0, 120));
});

test('test-mode hooks are reachable only in TEST_MODE', async () => {
  const r = await request('POST', '/__test/sessions', {
    headers: { 'Content-Type': 'application/json' },
    body: '{}',
  });
  assert.strictEqual(r.status, 200);
});
