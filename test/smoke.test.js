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
  const h = await request('GET', '/api/history', { headers: { Authorization: 'Bearer ' + j.tok } });
  assert.strictEqual(h.status, 200);
  const hj = JSON.parse(h.body);
  assert.ok(Array.isArray(hj.messages), 'messages array');
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

test('test-mode hooks are reachable only in TEST_MODE', async () => {
  const r = await request('POST', '/__test/sessions', {
    headers: { 'Content-Type': 'application/json' },
    body: '{}',
  });
  assert.strictEqual(r.status, 200);
});
