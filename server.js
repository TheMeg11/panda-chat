'use strict';
/* ============================================================
 * vault-chat v18 — E2EE web chat bridged with a Telegram bot
 * Zero-dependency Node.js server (http + crypto only).
 *
 * Security model (v18 FULL ZERO-KNOWLEDGE):
 *   - The chat key (CK) is generated INSIDE the browser and never
 *     sent to the server. The server stores only opaque WRAPS:
 *       · pwWrap    = AES-GCM(KEK, CK)      KEK = HKDF(PBKDF2(pw, saltB))
 *       · claimWrap = AES-GCM(HKDF(code), CK)  for passwordless login
 *       · legacyWrap= AES-GCM(CK, K_legacy) for pre-v18 history
 *   - Login sends only a PBKDF2 verifier; the server keeps
 *     scrypt(verifier). The plaintext password is DELETED from state.
 *   - data.json stays AES-256-GCM encrypted at rest (VAULT_SECRET).
 *   - Telegram side is inherently plaintext (bot cannot know CK).
 *     Messages coming FROM telegram are clearly tagged in the UI.
 *
 * Identity (v18 multi-user, shared password):
 *   - Every site session has a display name + a random per-session
 *     tag; messages carry {from: tag, name}. Bubbles are right/left
 *     by tag — like a Telegram group. Profiles are per display name.
 *
 * Bridge model:
 *   - Webhook (secret header) with long-polling fallback.
 *   - Site -> TG : plaintext mirror goes through an ANTI-SPAM
 *     aggregator (merge bursts, per-minute cap + digest).
 *   - TG -> site : bot downloads up to 20MB file, caches bytes in RAM
 *     and broadcasts metadata; site fetches via /api/tgfile/:fid.
 * ============================================================ */

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

/* ------------------------- config ------------------------- */
const PORT = Number(process.env.PORT || 8080);
const PUB = path.join(__dirname, 'public');

const KEY_SALT = String(process.env.KEY_SALT || '');
let PASSWORD = String(process.env.PASSWORD || '');
let PASSWORD_HASH = String(process.env.PASSWORD_HASH || '');

const TG_TOKEN = String(process.env.TELEGRAM_BOT_TOKEN || '');
const RAILWAY_API_TOKEN = String(process.env.RAILWAY_API_TOKEN || '');
const R_PID = String(process.env.RAILWAY_PROJECT_ID || '');
const R_EID = String(process.env.RAILWAY_ENVIRONMENT_ID || '');
const R_SID = String(process.env.RAILWAY_SERVICE_ID || '');

const MAX_JSON_BODY = 512 * 1024;         // json endpoints
const MAX_TEXT_CIPHER = 64 * 1024;        // ciphertext ceiling for text bodies
const MAX_RAW_BLOB = 62 * 1024 * 1024;    // encrypted blob upload (~55MB real data)
const MAX_MIRROR_MEDIA = 52 * 1024 * 1024;// plaintext passthrough to TG
const BLOB_BUDGET = 170 * 1024 * 1024;    // RAM budget e2ee blobs
const TGBUF_BUDGET = 120 * 1024 * 1024;   // RAM budget telegram files
const MAX_MESSAGES = 1500;
const HISTORY_WINDOW = 400;

/* access-request (forgot password) config — v18 hardened */
const REQ_TTL = 15 * 60 * 1000;          // admin has 15 minutes to decide
const CLAIM_TTL = 10 * 60 * 1000;        // after approval, claim window
const REQ_SWEEP_MS = 20 * 1000;
const REQ_MIN_GAP_MS = 20 * 1000;        // min gap between requests per IP
const REQ_MAX_PER_HOUR = 3;              // per IP
const REQ_MAX_OPEN = 2;                  // global open requests
const DENY_BLOCK_MS = 24 * 3600 * 1000;  // v19: after an admin denial this IP cannot re-request for 24h
/* v20: anti-attack — more than 3 access-requests in 15 min from one IP bans
   the IP outright for 24h (every API answer 403) until /unban_user frees it */
const REQ_WIN_MS = 15 * 60 * 1000;
const REQ_WIN_MAX = 3;
const IPBLOCK_MS = 24 * 3600 * 1000;
/* v20: session lifecycle notify — grace period before an SSE drop counts as
   "session closed" (page refresh reconnects within the window) */
const SESS_CLOSE_GRACE_MS = Math.max(1000, Number(process.env.SESS_CLOSE_GRACE_MS) || 90 * 1000);
const TEST_MODE = process.env.VAULT_TEST_MODE === '1';

/* v24: passwordless re-entry — after a user logs out (or their token dies),
   the SAME IP may re-enter without a password for 300 minutes. The chat key
   still travels only as the server-assisted fallback wrap (admin-approved
   v20.1 mechanism), so this adds no new key exposure. */
const REENTRY_TTL = 300 * 60 * 1000;
/* v24: global GIF repositories (Tenor). Tenor's official API is discontinued
   and Giphy needs a paid key — but tenor.com search/home pages are
   server-rendered with direct media.tenor.com URLs, so we scrape those
   (10-min cache, small UA-lookalike requests, generous timeouts). */
const GIF_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36';
const GIF_FETCH_CAP = 15 * 1024 * 1024;
const GIF_HOST_OK = /^https:\/\/media\d?\.tenor\.com\/[A-Za-z0-9_-]+\/[A-Za-z0-9_.%-]+\.(gif|mp4)(\?.*)?$/;
/* v18 anti-spam mirror aggregator */
const MIRROR_MERGE_MS = 1500;            // burst window for text merging
const MIRROR_MERGE_MAX = 3600;           // merged message char ceiling
const MIRROR_RATE_CAP = 20;              // tg sends per minute before digesting
const MIRROR_DIGEST_MIN_MS = 60 * 1000;  // min gap between digests

/* SSE stream tickets (v18: token never appears in URLs) */
const STREAM_TICKET_TTL = 30 * 1000;

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.ico': 'image/x-icon',
  '.webmanifest': 'application/manifest+json; charset=utf-8',
  '.woff2': 'font/woff2',
  '.woff': 'font/woff',
  '.txt': 'text/plain; charset=utf-8',
};

/* ------------------------- tiny utils ------------------------- */
const b64u = (buf) => Buffer.from(buf).toString('base64url');
function hmac(secret, data) {
  return crypto.createHmac('sha256', secret).update(String(data)).digest();
}
function safeEq(a, b) {
  const A = Buffer.from(String(a)), B = Buffer.from(String(b));
  return A.length === B.length && crypto.timingSafeEqual(A, B);
}
function rid() { return Date.now().toString(36) + Math.random().toString(36).slice(2, 8); }

function log(...a) { console.log(new Date().toISOString().slice(11, 19), '[vault]', ...a); }

/* ------------------------- persistent overlay (data.json) ------------------------- */
/* When a Railway volume is attached, RAILWAY_VOLUME_MOUNT_PATH points at it
   (e.g. /data). data.json + stickers then live on the persistent volume and
   survive redeploys; statfs on it reports the REAL volume size, not the host. */
const DATA_DIR = process.env.RAILWAY_VOLUME_MOUNT_PATH || __dirname;
const ON_VOLUME = DATA_DIR !== __dirname;
const DATA_FILE = path.join(DATA_DIR, 'data.json');

function migrateToVolume() {
  if (!ON_VOLUME) return;
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    if (!fs.existsSync(DATA_FILE) && fs.existsSync(path.join(__dirname, 'data.json'))) {
      fs.copyFileSync(path.join(__dirname, 'data.json'), DATA_FILE);
      log('migrated data.json ->', DATA_DIR);
    }
    const src = path.join(__dirname, 'stickers'), dst = path.join(DATA_DIR, 'stickers');
    if (!fs.existsSync(path.join(dst, 'index.json')) && fs.existsSync(path.join(src, 'index.json'))) {
      fs.mkdirSync(dst, { recursive: true });
      fs.copyFileSync(path.join(src, 'index.json'), path.join(dst, 'index.json'));
      for (const f of fs.readdirSync(src)) {
        if (f === 'index.json' || f === 'index.json.tmp') continue;
        try { fs.copyFileSync(path.join(src, f), path.join(dst, f)); } catch {}
      }
      log('migrated stickers ->', dst);
    }
  } catch (e) { log('volume migrate fail:', e.message); }
}
migrateToVolume();

const state = {
  /* VAULT_SECRET keeps session tokens stable across redeploys (ephemeral container
     would regenerate data.json and kill every 6h session on each deploy) */
  secret: process.env.VAULT_SECRET || crypto.randomBytes(32).toString('base64'),
  adminId: process.env.TELEGRAM_ADMIN_ID || null,
  adminName: null,
  /* v17 legacy: kept ONLY until the first v18 login migrates to zero-knowledge;
     afterwards password.p is wiped and auth carries wraps instead */
  password: { p: '', h: '' },
  /* v18 zero-knowledge auth:
     { mode:'new', cred (scrypt of login verifier), saltA, saltB,
       pwWrap {iv,c}, legacyWrap {iv,c}|null, legacyTag|null, legacyName|null,
       createdAt } — every field except the scrypt cred is opaque to the server */
  auth: null,
  /* v18 per-display-name profiles: nameLower -> {name, photo, updated} */
  profiles: {},
  legacySender: null,               // {tag, name} of pre-v18 site messages
  sitePersona: { name: '', photo: '' },
  tgPersona: { name: 'تلگرام', photo: '' },
  tgOffset: 0,
  webhookSecret: 'vh' + crypto.randomBytes(16).toString('hex'),
  revokeAt: 0,                       // sessions issued before this ts are dead (/revoke, /pass)
  siteTitle: 'Panda Chat',           // v15: brand/title — changeable live via /title
  sidSeq: 1000,                      // v15: numeric session ids for /revoke<sid>
  lastBackupAt: 0,                   // v19: encrypted auto-backup timestamp
  backupOn: true,                    // v30: auto-backup toggle (/backup on|off)
  /* v20.1: CK wrapped under a server-derived fallback key — lets a freshly
     approved passwordless user enter with NOTHING but the admin's TG tap,
     even when no site tab is open. Tradeoff (explicitly requested): the
     server CAN assist key delivery; the TG approval remains the gate. */
  vaultFallback: null,
  /* v27: fingerprint (WebAuthn platform) login — admin-approved, one credential.
     { name, nameLower, uh (userHandle b64url), credId (b64url), jwk (ES256
     pubkey JSON), counter, created, regAt, ua }. The CK still never leaves
     the browser: fingerprint login re-uses the v20.1 fallback wrap. */
  finger: null,
  /* v29: real last-seen — {tg: ts of last admin activity, users: {nameLower: ts}} */
  lastSeen: { tg: 0, users: {} },
  /* v29: trusted devices — devId(hex) -> {id, label, name, jwk, ip, ua,
     createdAt, approvedAt, lastUsedAt, revoked}. Only the PUBLIC half of an
     EC P-256 pair lives here; login proves key possession over a server nonce
     and the private half stays wrapped inside the local pattern/PIN lock. */
  devices: {},
};
function authMode() { return state.auth && state.auth.mode === 'new' ? 'new' : 'legacy'; }

/* --- v14 at-rest encryption: data.json is AES-256-GCM encrypted on disk.
   The storage key is derived (HKDF-SHA256, dedicated salt/info) from
   VAULT_SECRET — the same persistent env that keeps tokens stable — so a
   stolen data.json file alone reveals nothing (password, admin id, personas).
   Legacy plaintext files load transparently and are re-encrypted on the next
   save; if decryption ever fails (env lost/changed), the file is kept as
   .unreadable-<ts> backup and the server boots fresh instead of crashing. --- */
let STORE_KEY = null;
let encOnDisk = false;             // true once the on-disk data.json is our encrypted envelope
function deriveStoreKey() {
  const material = process.env.VAULT_SECRET || state.secret;
  try {
    STORE_KEY = Buffer.from(crypto.hkdfSync('sha256',
      Buffer.from(String(material), 'utf8'), 'vault-at-rest-salt-v1', 'vault-data-json-v1', 32));
  } catch (e) {
    STORE_KEY = crypto.createHash('sha256').update(String(material)).digest();
  }
  if (!process.env.VAULT_SECRET) log('WARN: VAULT_SECRET unset — at-rest key is per-boot; set VAULT_SECRET for persistence');
}
function encStore(plain) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', STORE_KEY, iv);
  const ct = Buffer.concat([c.update(String(plain), 'utf8'), c.final()]);
  return JSON.stringify({ vault_enc: 1, alg: 'aes-256-gcm', iv: iv.toString('base64'), tag: c.getAuthTag().toString('base64'), ct: ct.toString('base64') });
}
function decStore(raw) {
  const env = JSON.parse(raw);
  if (!env || env.vault_enc !== 1 || env.alg !== 'aes-256-gcm' || !env.iv || !env.tag || !env.ct) throw new Error('bad envelope');
  const d = crypto.createDecipheriv('aes-256-gcm', STORE_KEY, Buffer.from(env.iv, 'base64'));
  d.setAuthTag(Buffer.from(env.tag, 'base64'));
  return Buffer.concat([d.update(Buffer.from(env.ct, 'base64')), d.final()]).toString('utf8');
}
deriveStoreKey();

/* v20.1: fallback KEK — derived from the same persistent material as the
   at-rest store key. The client wraps CK under it and uploads the wrap, so a
   claim can complete even with no other site session open. */
function fbKekB64() {
  const material = process.env.VAULT_SECRET || state.secret;
  try {
    return Buffer.from(crypto.hkdfSync('sha256', Buffer.from(String(material), 'utf8'), 'vault-fb-salt-v1', 'ck-vault-fb-v1', 32)).toString('base64');
  } catch {
    return crypto.createHash('sha256').update('fb:' + String(material)).digest().toString('base64');
  }
}

/* v29: shared sanitizer for device labels / UAs — no control chars, no <> */
const devLabel = (s) => String(s || '').replace(/\p{Cc}/gu, ' ').replace(/[<>]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 60);
function loadData() {
  let raw = null;
  try { raw = fs.readFileSync(DATA_FILE, 'utf8'); } catch { return; /* first boot */ }
  let j;
  if (raw.trimStart().startsWith('{"vault_enc"')) {
    try {
      j = JSON.parse(decStore(raw));
      encOnDisk = true;
      log('data.json decrypted (AES-256-GCM at-rest) OK');
    } catch (e) {
      const bak = DATA_FILE + '.unreadable-' + Date.now();
      try { fs.renameSync(DATA_FILE, bak); log('data.json UNREADABLE (' + e.message + ') — kept as ' + path.basename(bak)); }
      catch (e2) { log('data.json UNREADABLE (' + e.message + ') and backup failed: ' + e2.message); }
      log('starting with fresh state — restore by setting the same VAULT_SECRET');
      return;
    }
  } else {
    try { j = JSON.parse(raw); } catch { return; }
    encOnDisk = false;
    log('data.json loaded (legacy plaintext — will be encrypted on next save)');
  }
  if (j && typeof j === 'object') {
    if (typeof j.secret === 'string' && j.secret.length > 20) state.secret = j.secret;
    if (j.adminId) state.adminId = String(j.adminId);
    if (j.tgOffset) state.tgOffset = Number(j.tgOffset) || 0;
    if (j.password && j.password.p) { state.password = j.password; PASSWORD = j.password.p; PASSWORD_HASH = j.password.h || ''; }
    if (j.auth && j.auth.mode === 'new') state.auth = j.auth;   // v18 zero-knowledge credential
    if (j.profiles && typeof j.profiles === 'object') state.profiles = j.profiles;
    if (j.legacySender) state.legacySender = j.legacySender;
    if (j.sitePersona) state.sitePersona = Object.assign(state.sitePersona, j.sitePersona);
    if (j.tgPersona) state.tgPersona = Object.assign(state.tgPersona, j.tgPersona);
    if (Number.isFinite(j.revokeAt)) state.revokeAt = j.revokeAt;
    if (typeof j.siteTitle === 'string' && sanitizeTitle(j.siteTitle)) state.siteTitle = sanitizeTitle(j.siteTitle);
    if (Number.isFinite(j.sidSeq) && j.sidSeq > state.sidSeq) state.sidSeq = Math.floor(j.sidSeq);
    if (Number.isFinite(j.lastBackupAt)) state.lastBackupAt = j.lastBackupAt;   // v19
    if (typeof j.backupOn === 'boolean') state.backupOn = j.backupOn;           // v30
    if (j.vaultFallback && j.vaultFallback.iv && j.vaultFallback.c) state.vaultFallback = { iv: String(j.vaultFallback.iv).slice(0, 64), c: String(j.vaultFallback.c).slice(0, 512) };   // v20.1
    if (j.finger && typeof j.finger === 'object' && j.finger.credId && j.finger.jwk) state.finger = {   // v27
      name: sanitizeName(j.finger.name), nameLower: String(j.finger.nameLower || '').toLowerCase().slice(0, 40),
      uh: String(j.finger.uh || '').replace(/[^A-Za-z0-9_-]/g, '').slice(0, 64),
      credId: String(j.finger.credId).replace(/[^A-Za-z0-9_-]/g, '').slice(0, 128),
      jwk: String(j.finger.jwk).slice(0, 512), counter: Number(j.finger.counter) || 0,
      created: Number(j.finger.created) || 0, regAt: Number(j.finger.regAt) || 0,
      ua: String(j.finger.ua || '').replace(/[\u0000-\u001f<>]/g, ' ').slice(0, 60) };
    /* v29: last-seen map (bounded) */
    if (j.lastSeen && typeof j.lastSeen === 'object') {
      state.lastSeen = { tg: Number(j.lastSeen.tg) || 0, users: {} };
      const lu = j.lastSeen.users;
      if (lu && typeof lu === 'object') {
        for (const [k, v] of Object.entries(lu).slice(-80)) {
          const ts = Number(v);
          if (ts > 0) state.lastSeen.users[String(k).toLowerCase().slice(0, 40)] = ts;
        }
      }
    }
    /* v29: trusted devices (public JWKs only — re-validate every field) */
    if (j.devices && typeof j.devices === 'object') {
      for (const [id, d] of Object.entries(j.devices)) {
        const did = String(id).toLowerCase().slice(0, 64);
        if (!/^[a-z0-9]{16,64}$/.test(did) || !d || typeof d !== 'object') continue;
        let jwk = null;
        try { jwk = JSON.parse(String(d.jwk || '')); } catch {}
        if (!jwk || jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !jwk.x || !jwk.y) continue;
        state.devices[did] = {
          id: did,
          label: devLabel(d.label),
          name: sanitizeName(d.name),
          jwk: JSON.stringify({ kty: 'EC', crv: 'P-256', x: String(jwk.x).slice(0, 64), y: String(jwk.y).slice(0, 64) }),
          ip: String(d.ip || '').slice(0, 60),
          ua: devLabel(d.ua),
          createdAt: Number(d.createdAt) || 0,
          approvedAt: Number(d.approvedAt) || 0,
          lastUsedAt: Number(d.lastUsedAt) || 0,
          revoked: !!d.revoked,
        };
      }
    }
    if (Array.isArray(j.sessions)) loadSessions(j.sessions);
  }
}
let saveTmr = null;
/* v29: the actual write lives in flushSave() so shutdown paths (SIGTERM /
   SIGINT / fatal error) can force a synchronous flush — no state is ever
   lost in the 400ms debounce window. */
function flushSave() {
  clearTimeout(saveTmr); saveTmr = null;
  try {
    const plain = JSON.stringify({
      secret: state.secret, adminId: state.adminId, tgOffset: state.tgOffset,
      password: state.password, auth: state.auth, profiles: state.profiles,
      legacySender: state.legacySender,
      sitePersona: state.sitePersona, tgPersona: state.tgPersona,
      revokeAt: state.revokeAt, siteTitle: state.siteTitle, sidSeq: state.sidSeq,
      lastBackupAt: state.lastBackupAt, backupOn: state.backupOn !== false, vaultFallback: state.vaultFallback,
      finger: state.finger,
      lastSeen: state.lastSeen, devices: state.devices,   // v29
      sessions: sessionsForDisk(),
    });
    const tmp = DATA_FILE + '.tmp';
    fs.writeFileSync(tmp, encStore(plain));
    fs.renameSync(tmp, DATA_FILE);
    encOnDisk = true;
  } catch (e) { log('saveData fail', e.message); }
}
function saveData() {
  clearTimeout(saveTmr);
  saveTmr = setTimeout(flushSave, 400);
}

/* ---------------- v19 encrypted auto-backup ----------------
   data.json is ALREADY an AES-256-GCM envelope (key = HKDF(VAULT_SECRET))
   that holds every durable secret: zero-knowledge credential + wraps,
   profiles, personas, sessions, the token HMAC secret. Daily (and once
   after each boot) the exact file is sent as a Telegram DOCUMENT to the
   admin PV — so even a lost Railway volume is recoverable. The document
   is useless to anyone without VAULT_SECRET. Message history is
   deliberately NOT part of it (messages live in RAM + the TG mirror). */
const BACKUP_MS = 24 * 3600 * 1000;
let backupBusy = false;
async function runBackup(reason) {
  if ((!TG_TOKEN && !TEST_MODE) || !state.adminId) return { ok: false, why: 'no-bridge' };
  if (backupBusy) return { ok: false, why: 'busy' };
  backupBusy = true;
  try {
    if (!fs.existsSync(DATA_FILE)) return { ok: false, why: 'no-file' };
    const buf = fs.readFileSync(DATA_FILE);
    const stamp = new Date().toISOString().slice(0, 16).replace('T', ' ') + ' UTC';
    const fname = 'vault-backup-' + new Date().toISOString().slice(0, 10) + '.json';
    const cap = '🗄 بکاپ ' + reason + ' — ' + faNum(stamp.replace(/\d/g, d => faNumStr[+d])) + '\n'
      + '📦 حجم: ' + fmtSize(buf.length) + '\n'
      + '🔐 این فایل با VAULT_SECRET رمزشده است — بدون سرور اصلی قابل‌خواندن نیست.\n'
      + '♻️ بازیابی: همین فایل را با نام data.json روی volume بگذار و همان VAULT_SECRET را نگه دار.';
    if (TEST_MODE) {
      lastTgOut.push({ method: 'sendDocument', payload: '(form)', cap, size: buf.length, fname });
      state.lastBackupAt = Date.now();
      return { ok: true, size: buf.length, fname, test: true };
    }
    const form = new FormData();
    form.append('chat_id', String(state.adminId));
    form.append('caption', cap);
    form.append('document', new Blob([buf]), fname);
    await tgEnqueue(() => tgCall('sendDocument', form, true));
    state.lastBackupAt = Date.now();
    saveData();
    log('backup (' + reason + ') sent — ' + fmtSize(buf.length));
    return { ok: true, size: buf.length, fname };
  } catch (e) {
    log('backup fail:', e.message);
    return { ok: false, why: e.message };
  } finally { backupBusy = false; }
}
if (!TEST_MODE) {
  setTimeout(() => { if (state.backupOn) runBackup('بوت').catch(() => {}); }, 30000);   // after boot settles (v30: gated)
  setInterval(() => { if (state.backupOn) runBackup('روزانه').catch(() => {}); }, BACKUP_MS);   // v30: gated
}

/* ------------------------- session tokens ------------------------- */
const TOKEN_TTL = 12 * 3600 * 1000;
function makeToken() {
  const exp = Date.now() + TOKEN_TTL;
  return exp + '.' + b64u(hmac(state.secret, 't' + exp));
}
function verifyToken(tok) {
  if (!tok) return false;
  const i = tok.indexOf('.');
  if (i < 1) return false;
  const exp = Number(tok.slice(0, i));
  if (!exp || Date.now() > exp) return false;
  /* server-side revocation: any token ISSUED before revokeAt is dead.
     (issue time = exp - TTL). This is what makes /revoke and /pass real. */
  if (state.revokeAt && (exp - TOKEN_TTL) <= state.revokeAt) return false;
  /* v15: single-session revocation — /revoke<sid> kills exactly one token */
  const rec = sessions.get(String(tok || ''));
  if (rec && rec.revoked) return false;
  try { return safeEq(b64u(hmac(state.secret, 't' + exp)), tok.slice(i + 1)); }
  catch { return false; }
}
function revokeAllSessions() {
  /* -1ms: a token created in the SAME millisecond right after this call
     (upgrade/password endpoints) must count as issued AFTER the revoke */
  state.revokeAt = Date.now() - 1;
  saveData();
  broadcastSafe({ type: 'revoked' });
  log('all sessions revoked (issued <=', new Date(state.revokeAt).toISOString(), ')');
}

/* ------------- v15 per-session registry (login cards + /revoke<sid>) -------------
   Tokens stay stateless HMACs; the registry only ADDS an identity + a kill
   switch per token. Old tokens (pre-v15) keep working and simply have no sid. */
const SESSIONS_KEEP = 60;
const sessions = new Map();     // tok -> {sid, tok, t, exp, kind, name, code, ip, dev, revoked}
const sidIndex = new Map();     // sid -> tok
function sessionsForDisk() {
  return [...sessions.values()]
    .sort((a, b) => a.t - b.t).slice(-SESSIONS_KEEP)
    .map(r => ({ sid: r.sid, tok: r.tok, t: r.t, exp: r.exp, kind: r.kind, name: r.name, code: r.code, ip: r.ip, dev: r.dev, revoked: !!r.revoked }));
}
function loadSessions(arr) {
  const now = Date.now();
  for (const r of arr) {
    if (!r || typeof r.tok !== 'string' || !r.sid || !(r.exp > now - 24 * 3600 * 1000)) continue;
    const rec = { sid: String(r.sid), tok: r.tok, t: Number(r.t) || now, exp: Number(r.exp) || now,
                  kind: ['claim', 'reentry', 'finger', 'device'].includes(r.kind) ? r.kind : 'pw', name: String(r.name || ''), code: String(r.code || ''),
                  ip: String(r.ip || ''), dev: String(r.dev || ''), revoked: !!r.revoked };
    sessions.set(rec.tok, rec); sidIndex.set(rec.sid, rec.tok);
    const n = parseInt(rec.sid, 10); if (Number.isFinite(n) && n >= state.sidSeq) state.sidSeq = n + 1;
  }
}
function registerSession(tok, kind, info) {
  const i = String(tok || '').indexOf('.');
  if (i < 1) return null;
  const exp = Number(tok.slice(0, i));
  if (!exp) return null;
  let sid = String(++state.sidSeq);
  while (sidIndex.has(sid)) sid = String(++state.sidSeq);  // paranoia after manual edits
  const rec = { sid, tok: String(tok), t: Date.now(), exp, kind: ['claim', 'reentry', 'finger', 'device'].includes(kind) ? kind : 'pw',
                name: sanitizeName(info && info.name), code: sanitizeCode(info && info.code),
                ip: String((info && info.ip) || ''), dev: String((info && info.dev) || '').slice(0, 60), revoked: false };
  sessions.set(rec.tok, rec); sidIndex.set(rec.sid, rec.tok);
  // trim oldest untracked beyond keep-list
  if (sessions.size > SESSIONS_KEEP) {
    const old = [...sessions.values()].sort((a, b) => a.t - b.t);
    while (sessions.size > SESSIONS_KEEP) {
      const v = old.shift();
      sessions.delete(v.tok); sidIndex.delete(v.sid);
    }
  }
  saveData();
  return rec;
}
function revokeSession(sid) {
  const tok = sidIndex.get(String(sid));
  if (!tok) return null;
  const rec = sessions.get(tok);
  if (rec.revoked) return { rec, already: true };
  rec.revoked = true;
  saveData();
  /* kick that exact live connection, if any — the client clears its stored
     session and reloads to the gate; other tabs/clients stay untouched */
  for (const c of sseClients) {
    if (c.sessSid === rec.sid) {
      sseWrite(c, { type: 'revoked', single: true, sid: rec.sid });
      try { c.end(); } catch {}
      sseClients.delete(c);
    }
  }
  log('session #' + rec.sid, 'revoked (' + rec.kind + (rec.name ? ' · ' + rec.name : '') + ')');
  return { rec, already: false };
}

/* ------------------------- login rate limit (v18: progressive + global) ------------------------- */
const loginFails = new Map();   // ip -> {fails:[ts], lockUntil}
const apiHits = new Map();      // ip -> {n, t0}
let globalLockUntil = 0;        // distributed brute-force guard
let globalFailWindow = Date.now();
let globalFailCount = 0;
const LOGIN_LOCK_TIERS = [[5, 15 * 60 * 1000], [10, 3600 * 1000], [20, 6 * 3600 * 1000]];
setInterval(() => {
  const now = Date.now();
  for (const [ip, o] of loginFails) {
    o.fails = o.fails.filter(ts => now - ts < 15 * 60 * 1000);
    if (!o.fails.length && o.lockUntil < now) loginFails.delete(ip);
  }
  for (const [ip, o] of apiHits) if (now - o.t0 > 60000) apiHits.delete(ip);
  if (now - globalFailWindow > 15 * 60 * 1000) { globalFailCount = 0; globalFailWindow = now; }
}, 60000);
function loginGate(ip) { 
  const now = Date.now();
  if (globalLockUntil > now) return { ok: false };
  const o = loginFails.get(ip);
  if (o && o.lockUntil > now) return { ok: false };
  return { ok: true };
}
function recordLoginFail(ip) {
  const now = Date.now();
  const o = loginFails.get(ip) || { fails: [], lockUntil: 0 };
  o.fails.push(now);
  for (const [n, dur] of LOGIN_LOCK_TIERS) {
    if (o.fails.length >= n) o.lockUntil = Math.max(o.lockUntil, now + dur);
  }
  loginFails.set(ip, o);
  globalFailCount++;
  if (globalFailCount >= 120) { globalLockUntil = now + 5 * 60 * 1000; globalFailCount = 0; log('GLOBAL login lock 5min (distributed brute-force guard)'); }
  return o.fails.length;
}
function loginClear(ip) { loginFails.delete(ip); }
function clientIp(req) {
  const xf = req.headers['x-forwarded-for'];
  return (xf ? String(xf).split(',')[0].trim() : '') || req.socket.remoteAddress || '?';
}
function tooManyApi(req) {
  const ip = clientIp(req), now = Date.now();
  let o = apiHits.get(ip);
  if (!o) { o = { n: 0, t0: now }; apiHits.set(ip, o); }
  if (now - o.t0 > 60000) { o.n = 0; o.t0 = now; }
  return (++o.n > 240);
}

/* --- v18 security headers — injected into EVERY writeHead (single point) --- */
const CSP = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
  "img-src 'self' data: blob:; media-src 'self' blob:; font-src 'self'; connect-src 'self' blob:; " +
  "worker-src 'self'; manifest-src 'self'; object-src 'none'; base-uri 'none'; " +
  "form-action 'self'; frame-ancestors 'none'";
const SEC_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Permissions-Policy': 'camera=(), microphone=(self), geolocation=(), payment=(), interest-cohort=()',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Content-Security-Policy': CSP,
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
};
const _writeHead = http.ServerResponse.prototype.writeHead;
http.ServerResponse.prototype.writeHead = function (code, ...args) {
  let headers = null;
  if (args.length && args[0] && typeof args[0] === 'object' && !Array.isArray(args[0])) headers = args[0];
  else if (args.length > 1 && args[1] && typeof args[1] === 'object') headers = args[1];
  else { headers = {}; args.splice(args.length ? 1 : 0, 0, headers); }
  for (const [k, v] of Object.entries(SEC_HEADERS)) if (headers[k] === undefined) headers[k] = v;
  return _writeHead.apply(this, [code, ...args]);
};

/* --- v18 CORS: same-origin only — any cross-origin /api request is rejected ---
   v30 fix: the browser's Origin is also compared against the Host the request
   actually reached (proxy-aware via x-forwarded-host), so login works on ANY
   domain — *.up.railway.app, custom domains, render.com, … — with zero config.
   Genuine cross-origin requests (Origin host ≠ Host header and not allow-listed)
   are still hard-rejected with 403. */
function corsAllowed(req) {
  const o = String(req.headers.origin || '');
  if (!o) return true;                       // same-origin fetch/SSE usually has no Origin on GET
  let oh = '';
  try { oh = new URL(o).host.toLowerCase().replace(/:443$/, ''); } catch { return false; }
  if (!oh) return false;
  const host = String(req.headers['x-forwarded-host'] || req.headers.host || '')
    .split(',')[0].trim().toLowerCase().replace(/:443$/, '');
  if (host && oh === host) return true;      // true same-origin — works on any domain
  const dom = String(process.env.RAILWAY_PUBLIC_DOMAIN || '').trim().toLowerCase()
    .replace(/^https?:\/\//, '').replace(/\/+$/, '');
  const ok = new Set(['https://vault.texastudio.ir']);
  if (dom) ok.add('https://' + dom);
  if (TEST_MODE && /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(o)) ok.add(o);
  return ok.has(o.toLowerCase());
}

/* --- v18 SSE stream tickets: the session token never appears in any URL --- */
const streamTickets = new Map();   // ticket -> {tok, exp}
function makeStreamTicket(tok) {
  const t = crypto.randomBytes(24).toString('base64url');
  streamTickets.set(t, { tok, exp: Date.now() + STREAM_TICKET_TTL });
  if (streamTickets.size > 400) {
    const now = Date.now();
    for (const [k, v] of streamTickets) if (v.exp < now) streamTickets.delete(k);
  }
  return t;
}
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of streamTickets) if (v.exp < now) streamTickets.delete(k);
}, 15000);

/* ------------------------- password core ------------------------- */
function scryptHash(pw) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(String(pw), salt, 64, { N: 16384, r: 8, p: 1, maxmem: 128 * 1024 * 1024 });
  return `scrypt$16384$8$1$${salt.toString('base64')}$${hash.toString('base64')}`;
}
function scryptVerify(pw, stored) {
  const m = /^scrypt\$(\d+)\$(\d+)\$(\d+)\$([A-Za-z0-9+/=]+)\$([A-Za-z0-9+/=]+)$/.exec(stored || '');
  if (!m) return false;
  try {
    const N = +m[1], r = +m[2], p = +m[3];
    const salt = Buffer.from(m[4], 'base64');
    const want = Buffer.from(m[5], 'base64');
    const got = crypto.scryptSync(String(pw), salt, want.length, { N, r, p, maxmem: 512 * 1024 * 1024 });
    return crypto.timingSafeEqual(got, want);
  } catch { return false; }
}
function passwordOk(pw) {
  if (PASSWORD_HASH && scryptVerify(pw, PASSWORD_HASH)) return true;
  if (PASSWORD && safeEq(pw, PASSWORD)) { // plaintext fallback env
    if (!PASSWORD_HASH || !scryptVerify(pw, PASSWORD_HASH)) {
      // transparent upgrade to canonical hash format
      PASSWORD_HASH = scryptHash(pw);
      state.password = { p: PASSWORD, h: PASSWORD_HASH };
      saveData();
      persistRailway({ PASSWORD, PASSWORD_HASH }).catch(() => {});
    }
    return true;
  }
  return false;
}

/* v18 — ZERO-KNOWLEDGE core.
   The server NEVER derives or stores the chat key. It only verifies a
   client-computed PBKDF2 verifier (then scrypt-hashes it for storage) and
   serves opaque wraps. The old vaultSecretsFor() (which derived the vault
   key from the password server-side) was removed in v18 — that was the
   critical finding of the authorized pentest. */
const VAULT_WORDS = ['Luna','Sable','Orbit','Nova','Echo','Iris','Comet','Delta','Aurora','Zephyr','Mango','Kiwi','Pixel','Quartz','Tango','Umbra'];

/* create the new-mode credential from a client verifier (client-generated
   salts travel with the upgrade — they are public KDF parameters) */
function newAuthFrom(verifier, saltA, saltB, pwWrap, legacyWrap, legacyTag, legacyName) {
  return {
    mode: 'new',
    cred: scryptHash(String(verifier)),          // scrypt(verifier) — never the verifier itself
    saltA: String(saltA || '').replace(/[^A-Za-z0-9+/=]/g, '').slice(0, 64) || crypto.randomBytes(16).toString('base64'),
    saltB: String(saltB || '').replace(/[^A-Za-z0-9+/=]/g, '').slice(0, 64) || crypto.randomBytes(16).toString('base64'),
    pwWrap: { iv: String(pwWrap.iv || '').slice(0, 64), c: String(pwWrap.c || '').slice(0, 512) },
    legacyWrap: legacyWrap ? { iv: String(legacyWrap.iv || '').slice(0, 64), c: String(legacyWrap.c || '').slice(0, 512) } : null,
    legacyTag: legacyTag ? String(legacyTag).slice(0, 24) : null,
    legacyName: legacyName ? sanitizeName(legacyName) : null,
    createdAt: Date.now(),
  };
}
function verifyAuth(verifier) {
  if (!state.auth || state.auth.mode !== 'new') return false;
  return scryptVerify(String(verifier || ''), state.auth.cred);
}
/* v21 — rotate the zero-knowledge LOGIN credential to a new password.
   THE ORIGINAL BUG: /pass only updated PASSWORD/PASSWORD_HASH, but in 'new'
   mode /api/login checks state.auth.cred (bound to the ORIGINAL password) —
   so the bot-side password change never took effect on the site. v20.2 fixed
   the rotation but FAILED HARD when no server key backup existed — locking the
   owner out of their own admin panel («کلید پشتیبان سرور موجود نیست»). THE
   OWNER DIRECTIVE (v21): the Telegram bot is the site's ADMIN PANEL and must
   have FULL authority — /pass must NEVER fail.
   Recovery ladder for the chat key (CK):
     1. vaultFallback  = AES-GCM(fbKek, CK)        (armed at every login)
     2. legacyWrap     + original env PASSWORD     (pre-migration rescue)
     3. NO KEY RECOVERABLE → mint a FRESH CK server-side and hard-wipe all
        stored ciphertext (it is undecryptable without the old CK anyway).
        Owner explicitly accepted data loss in exchange for guaranteed access.
   The KDF chain is byte-identical to the browser (scripts/kdf_check.mjs):
     verifier = base64(PBKDF2-SHA256(pw, saltA, 250000, 32B))
     KEK      = HKDF-SHA256(PBKDF2(pw, saltB), salt=0^32, info='ck-wrap-v1')
     pwWrap   = base64(AES-GCM ct || tag)
   Returns { ok:true, rekeyed } (truthy) or false in legacy mode. */
function rotateCredentialTo(pw) {
  if (!state.auth || state.auth.mode !== 'new') return false;
  /* --- recover the CK (WebCrypto ciphertext = ct || tag(16B)) --- */
  let ck = null, rekeyed = false;
  if (state.vaultFallback && state.vaultFallback.iv && state.vaultFallback.c) {
    try {
      const fk = Buffer.from(fbKekB64(), 'base64');
      const full = Buffer.from(state.vaultFallback.c, 'base64');
      const d = crypto.createDecipheriv('aes-256-gcm', fk, Buffer.from(state.vaultFallback.iv, 'base64'));
      d.setAuthTag(full.subarray(full.length - 16));
      const k = Buffer.concat([d.update(full.subarray(0, full.length - 16)), d.final()]);
      if (k.length === 32) ck = k;
    } catch { /* fall through to the next ladder step */ }
  }
  if (!ck) ck = recoverCKViaLegacy(String(process.env.PASSWORD || ''));
  if (!ck) { ck = crypto.randomBytes(32); rekeyed = true; }   // admin authority: /pass can not fail
  /* fresh public KDF parameters + wraps, all server-side */
  const saltA = crypto.randomBytes(16).toString('base64');
  const saltB = crypto.randomBytes(16).toString('base64');
  const verifier = crypto.pbkdf2Sync(String(pw), Buffer.from(saltA, 'base64'), 250000, 32, 'sha256').toString('base64');
  const vkB = crypto.pbkdf2Sync(String(pw), Buffer.from(saltB, 'base64'), 250000, 32, 'sha256');
  const kek = Buffer.from(crypto.hkdfSync('sha256', vkB, Buffer.alloc(32), Buffer.from('ck-wrap-v1', 'utf8'), 32));
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', kek, iv);
  const ct = Buffer.concat([c.update(ck), c.final()]);
  const fk2 = Buffer.from(fbKekB64(), 'base64');
  const fiv = crypto.randomBytes(12);
  const fc = crypto.createCipheriv('aes-256-gcm', fk2, fiv);
  const fct = Buffer.concat([fc.update(ck), fc.final()]);
  /* all crypto succeeded — only NOW mutate the credential */
  state.auth.cred = scryptHash(verifier);
  state.auth.saltA = saltA;
  state.auth.saltB = saltB;
  state.auth.pwWrap = { iv: iv.toString('base64'), c: Buffer.concat([ct, c.getAuthTag()]).toString('base64') };
  state.auth.createdAt = Date.now();
  state.vaultFallback = { iv: fiv.toString('base64'), c: Buffer.concat([fct, fc.getAuthTag()]).toString('base64') };
  if (rekeyed) hardWipeOnRekey();
  saveData();
  return { ok: true, rekeyed };
}

/* v21: a freshly-minted CK makes every stored ciphertext (messages, blobs,
   claim wraps) permanently undecryptable — wipe them so the vault stays
   consistent instead of showing garbage bubbles. Owner accepted data loss. */
function hardWipeOnRekey() {
  claimCode = null;
  try { blobs.clear(); } catch {}
  wipeSite();               // clears messages + TG mirror maps + broadcasts + deletes TG copies
  saveData();
  log('v21 rekey: chat key re-minted — all stored ciphertext wiped');
}

/* v20.2 emergency rescue: recover the CK from the stored legacyWrap using the
   ORIGINAL password (kept in env PASSWORD since setup). legacyWrap =
   AES-GCM(CK, PBKDF2(originalPw, KEY_SALT)) — uploaded at migration time.
   Returns the 32-byte CK or null. This is what un-orphans a vault whose
   fallback wrap is missing and whose admin forgot the original password. */
function recoverCKViaLegacy(pw) {
  try {
    if (!pw || !state.auth || !state.auth.legacyWrap || !state.auth.legacyWrap.iv || !state.auth.legacyWrap.c || !process.env.KEY_SALT) return null;
    const legacyRaw = crypto.pbkdf2Sync(String(pw), Buffer.from(String(process.env.KEY_SALT), 'base64'), 250000, 32, 'sha256');
    const full = Buffer.from(state.auth.legacyWrap.c, 'base64');
    const d = crypto.createDecipheriv('aes-256-gcm', legacyRaw, Buffer.from(state.auth.legacyWrap.iv, 'base64'));
    d.setAuthTag(full.subarray(full.length - 16));
    const ck = Buffer.concat([d.update(full.subarray(0, full.length - 16)), d.final()]);
    return ck.length === 32 ? ck : null;
  } catch { return null; }
}

/* v21 boot auto-heal: a /pass password recorded before v21 never made it into
   the login credential. If a recorded password exists, make the credential
   match it at boot (v21 rotation can not fail — fresh-CK fallback).
   Idempotent: skipped when the credential ALREADY verifies against the
   recorded password (no needless re-rotation, no repeated TG notices).
   Target precedence: state.password.p (explicit /pass by the admin — always
   wins) → VAULT_REKEY_PW (one-shot operator env, applies once). */
function credMatches(pw) {
  try {
    if (!state.auth || state.auth.mode !== 'new' || !state.auth.saltA) return false;
    const verifier = crypto.pbkdf2Sync(String(pw), Buffer.from(state.auth.saltA, 'base64'), 250000, 32, 'sha256').toString('base64');
    return scryptVerify(verifier, state.auth.cred);
  } catch { return false; }
}
function healStoredPassword() {
  if (authMode() !== 'new') return false;
  const rekeyEnv = String(process.env.VAULT_REKEY_PW || '').trim();
  const target = (state.password && state.password.p) || (rekeyEnv && rekeyEnv !== '-' ? rekeyEnv : '');
  if (!target) return false;
  if (credMatches(target)) return false;          // already in sync — nothing to do
  let healed = false, rekeyed = false;
  try {
    const r = rotateCredentialTo(target);
    if (r) { healed = true; rekeyed = !!(r && r.rekeyed); }
  } catch (e) {
    log('v21 heal rotate failed (unexpected):', e.message.slice(0, 80));
  }
  if (healed) {
    state.password = { p: target, h: scryptHash(target) };
    saveData();
    if (rekeyEnv && rekeyEnv !== '-') persistRailway({ VAULT_REKEY_PW: '-' }).catch(() => {});
    log('v21 heal: login credential rotated to the recorded password' + (rekeyed ? ' (CK re-minted, data wiped)' : ''));
  }
  return healed ? { healed: true, rekeyed } : false;
}

/* wipe the plaintext password — called once the client has uploaded the wraps */
function purgePlaintextPassword() {
  if (state.password && state.password.p) {
    state.password = { p: '', h: PASSWORD_HASH || state.password.h || '' };
    PASSWORD = '';
    log('zero-knowledge migration: plaintext password purged from state');
  }
  persistRailway({ PASSWORD: '' }).catch(() => {});
}
/* the CURRENT claim code (passwordless login). Plaintext code lives only in
   RAM for the claim window; data.json stores sha256(code) + the client-made
   claimWrap. Server cannot derive the CK from either at rest. */
let claimCode = null;             // {code, hash, exp, reqId, wrap:{iv,c}|null}
function genClaimCode() {
  const A = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
  const pick = () => Array.from(crypto.randomBytes(4), b => A[b % A.length]).join('');
  return pick() + '-' + pick() + '-' + pick();
}

/* persist variables back to Railway so /pass survives redeploys */
async function railGraphql(query, variables) {
  const res = await fetch('https://backboard.railway.app/graphql/v2', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + RAILWAY_API_TOKEN },
    body: JSON.stringify({ query, variables }),
  });
  const j = await res.json();
  if (j.errors) throw new Error(j.errors[0] && j.errors[0].message || 'railway error');
  return j.data;
}
const railCache = new Map(); // dedupe rapid identical writes
function persistRailway(varsObj) {
  /* real fix: never fall back to baked-in project/environment/service IDs —
     those belonged to a different Railway project entirely (leftover from
     the original developer's own deploy). Only sync if THIS deployment's
     own Railway-injected IDs are present. */
  if (!RAILWAY_API_TOKEN || !R_PID || !R_EID || !R_SID) return Promise.resolve(false);
  for (const [k, v] of Object.entries(varsObj)) {
    const key = k + ':' + v;
    if (railCache.get(k) === key) continue;
    railCache.set(k, key);
    /* v21 fix: Railway's GraphQL schema returns a bare Boolean! for
       variableUpsert — a { name } selection made every persist fail with
       «must not have a selection». */
    railGraphql(
      'mutation($input:VariableUpsertInput!){ variableUpsert(input:$input) }',
      { input: {
          projectId: R_PID, environmentId: R_EID, serviceId: R_SID,
          name: k, value: String(v), skipDeploys: true,
        } }
    ).catch((e) => { log('railway var sync failed:', e.message); });
  }
  return Promise.resolve(true);
}

/* ------------------------- messages / blobs store ------------------------- */
const stickers = loadStickerIndex();   // cloud stickers: [{id,kind,ts,size}]
function loadStickerIndex() {
  try {
    const v = JSON.parse(fs.readFileSync(path.join(DATA_DIR, 'stickers', 'index.json'), 'utf8'));
    return Array.isArray(v) ? v : [];
  } catch { return []; }
}
let stkTmr = null;
function saveStickers() {
  clearTimeout(stkTmr);
  stkTmr = setTimeout(() => {
    try {
      fs.mkdirSync(path.join(DATA_DIR, 'stickers'), { recursive: true });
      const tmp = path.join(DATA_DIR, 'stickers', 'index.json.tmp');
      fs.writeFileSync(tmp, JSON.stringify(stickers));
      fs.renameSync(tmp, path.join(DATA_DIR, 'stickers', 'index.json'));
    } catch (e) { log('saveStickers fail', e.message); }
  }, 300);
}
function stkFind(id) { return stickers.find(s => s.id === id); }

let seq = Date.now() % 100000;
function nextId() { seq = (seq + 1) % 1000000; return Date.now().toString(36) + '-' + seq.toString(36); }

const messages = [];            // newest last; each: {id, ts, iv?, c?, t?, meta:{}, reacts?}
const blobs = new Map();        // bid -> {env:{iv,c,miv,mc}, size, lastTouch}
let webhookActive = false;
const tgFiles = new Map();      // fid -> {buf, mime, name, size, lastTouch}
/* ------- v20: disk-backed L2 cache for TG files (stickers / gifs / ...) -------
   Repeat views and «ذخیره» actions are served from the server disk instead of
   re-downloading from Telegram: faster re-sends, no wasted user bandwidth,
   and the cache survives restarts. LRU-pruned past TGCACHE_MAX_BYTES. ------- */
const TGCACHE_DIR = path.join(DATA_DIR, 'tgcache');
const TGCACHE_MAX_BYTES = 300 * 1024 * 1024;
const tgDisk = new Map();       // fid -> {f, mime, size, ts}
let tgDiskBytes = 0;
function tgDiskLoad() {
  try {
    const j = JSON.parse(fs.readFileSync(path.join(TGCACHE_DIR, 'index.json'), 'utf8'));
    for (const [k, v] of Object.entries(j || {})) if (v && v.f) tgDisk.set(k, v);
  } catch {}
  tgDiskBytes = 0;
  for (const v of tgDisk.values()) tgDiskBytes += v.size || 0;
}
function tgDiskSave() {
  try {
    fs.mkdirSync(TGCACHE_DIR, { recursive: true });
    const o = {};
    for (const [k, v] of tgDisk) o[k] = v;
    fs.writeFileSync(path.join(TGCACHE_DIR, 'index.json.tmp'), JSON.stringify(o));
    fs.renameSync(path.join(TGCACHE_DIR, 'index.json.tmp'), path.join(TGCACHE_DIR, 'index.json'));
  } catch {}
}
function tgDiskPut(fid, buf, mime) {
  try {
    fs.mkdirSync(TGCACHE_DIR, { recursive: true });
    const f = crypto.createHash('sha1').update(String(fid)).digest('hex').slice(0, 24);
    fs.writeFileSync(path.join(TGCACHE_DIR, f), buf);
    const prev = tgDisk.get(fid);
    if (prev) tgDiskBytes -= prev.size || 0;
    tgDisk.set(fid, { f, mime, size: buf.length, ts: Date.now() });
    tgDiskBytes += buf.length;
    if (tgDiskBytes > TGCACHE_MAX_BYTES) {
      for (const [k2, v2] of [...tgDisk.entries()].sort((a, b) => a[1].ts - b[1].ts)) {
        if (tgDiskBytes <= TGCACHE_MAX_BYTES * 0.8) break;
        try { fs.unlinkSync(path.join(TGCACHE_DIR, v2.f)); } catch {}
        tgDiskBytes -= v2.size || 0;
        tgDisk.delete(k2);
      }
    }
    tgDiskSave();
  } catch {}
}
function tgDiskGet(fid) {
  const v = tgDisk.get(fid);
  if (!v) return null;
  try {
    const buf = fs.readFileSync(path.join(TGCACHE_DIR, v.f));
    v.ts = Date.now();
    return { buf, mime: v.mime, size: v.size };
  } catch { tgDisk.delete(fid); tgDiskSave(); return null; }
}
tgDiskLoad();
const tgMapRecv = new Map();    // telegram message_id -> site msg id
const sentTgMid = new Map();    // site msg id -> mirrored telegram message_id
const recvToTg = new Map();     // site msg id -> original telegram message_id (for replies to TG msgs)

let blobBytes = 0, tgbBytes = 0;
function touchLru(map) {
  let total = 0;
  for (const [k, v] of map) total += v.size || 0;
  return total;
}
function budgetEvict(map, label) {
  let budget = label === 'blob' ? BLOB_BUDGET : TGBUF_BUDGET;
  let total = touchLru(map);
  if (total <= budget) return;
  const items = [...map.entries()].sort((a, b) => a[1].lastTouch - b[1].lastTouch);
  for (const [k, v] of items) {
    if (total <= budget * 0.85) break;
    map.delete(k); total -= (v.size || 0);
    log('evicted', label, k.slice(0, 12));
  }
}

function pushMessage(m) {
  messages.push(m);
  while (messages.length > MAX_MESSAGES) {
    const old = messages.shift();
    broadcastSafe({ type: 'purge', ids: [old.id] });
    if (old.meta && old.meta.blob) blobs.delete(old.meta.blob);
  }
  return m;
}

/* ------------------------- access requests (forgot password) — v18 hardened ------------------------- */
const pendingReq = new Map();   // id -> {id,name,ip,status,ts,exp,msgId,consumed,claimExp}
const reqIpHits = new Map();    // ip -> {hour, n, last}
const statusHits = new Map();   // ip -> {n, t0} for status polling
const reqIpPending = new Map(); // v19: ip -> id — one live request per IP
const deny24 = new Map();       // v19: ip -> deniedAt — 24h lockout after admin denial
const reqWin = new Map();       // v20: ip -> {n, t0} — request flood window (15 min)
const ipBlock = new Map();      // v20: ip -> bannedAt — hard 24h API ban (attack)
const sessLive = new Map();     // v20: sid -> {conns, notified, closeTmr, name, dev, ip, openedAt}
function reqRateOk(ip) {
  const now = Date.now(), hour = Math.floor(now / 3600000);
  let o = reqIpHits.get(ip);
  if (!o || o.hour !== hour) { o = { hour, n: 0, last: 0 }; reqIpHits.set(ip, o); }
  if (now - o.last < REQ_MIN_GAP_MS) return { ok: false, wait: Math.max(1, Math.ceil((REQ_MIN_GAP_MS - (now - o.last)) / 1000)) };
  if (o.n >= REQ_MAX_PER_HOUR) return { ok: false, wait: Math.max(1, Math.ceil(((o.hour + 1) * 3600000 - now) / 60000)) };
  o.n++; o.last = now;
  return { ok: true, wait: 0 };
}
function statusRateOk(ip) {
  const now = Date.now();
  let o = statusHits.get(ip);
  if (!o || now - o.t0 > 60000) { o = { n: 0, t0: now }; statusHits.set(ip, o); }
  o.n++;
  return o.n <= 60;
}
function arqPublic(r) {
  /* v19: ready = the one-time code has been converted into a CK wrap by an
     online session (claim can succeed now); migrated = vault left legacy mode.
     v20: cc = the ephemeral claim code, handed ONLY to the browser holding the
     256-bit request id — with it the entry is fully automatic (no typing). The
     code alone is useless without the session-sealed wrap and vice-versa. */
  const ccLive = r.status === 'approved' && !r.consumed && claimCode && claimCode.reqId === r.id && claimCode.exp > Date.now();
  return { id: r.id, status: r.status, exp: r.exp,
    ready: !!(claimCode && claimCode.reqId === r.id && claimCode.wrap),
    migrated: authMode() === 'new',
    fb: authMode() === 'new' && !!state.vaultFallback,
    cc: ccLive ? claimCode.code : null };
}

/* recent logins ring (for the /sessions admin command) */
const loginLog = [];   // {t, ip, kind:'pw'|'claim', name, code}
function noteLogin(kind, ip, name, code) {
  loginLog.push({ t: Date.now(), ip: String(ip || '?'), kind, name: String(name || ''), code: String(code || '') });
  if (loginLog.length > 24) loginLog.shift();
}

/* --- اسم رمز (codename): an optional alias typed by the user in the access
       request form — shown ONLY to the admin in the Telegram card. No auto-
       generation: empty input means the card shows "-". --- */

function accessCardText(name, rec) {
  const mins = Math.round(REQ_TTL / 60000);
  const legacyNote = authMode() !== 'new'
    ? '\n\u26A0\uFE0F گاوصندوق هنوز به حالت صفر\u200cدانش ارتقا نیافته — بعد از تایید، ورود خودکار این کاربر پس از اولین ورود رمزی تو فعال می\u200cشود.'
    : '';
  return [
    '\u{1F513} درخواست ورود به چت بدون رمز عبور',
    '',
    '\u{1F464} نام درخواست\u200cدهنده: ' + name,
    '\u{1F3F7} اسم رمز: ' + (rec.code || '-'),
    '\u{1F4F1} دستگاه: ' + (rec.dev || 'نامشخص'),
    rec.xtra ? '\u2139\uFE0F ' + rec.xtra : null,
    '\u{1F310} IP: ' + (rec.ip || '?'),
    '\u23F3 زمان تصمیم\u200cگیری: ' + faMin(mins) + ' دقیقه',
    '',
    'با زدن \u2705 تایید، کاربر خودکار و بدون مرحله دوم وارد می\u200cشود.' + legacyNote,
  ].filter((x) => x !== null).join('\n');
}

async function sendAccessCard(name, rec) {
  const txt = accessCardText(name, rec);
  const res = await tgEnqueue(() => tgCall('sendMessage', {
    chat_id: state.adminId,
    text: txt,
    disable_web_page_preview: true,
    reply_markup: { inline_keyboard: [[
      { text: '\u2705 تایید ورود', callback_data: 'arq:' + rec.id + ':a' },
      { text: '\u274C رد', callback_data: 'arq:' + rec.id + ':d' },
    ]] },
  }));
  rec.msgId = res && res.message_id || null;
  rec.cardText = txt;
}
const faNumStr = ['۰','۱','۲','۳','۴','۵','۶','۷','۸','۹'];
function faMin(n) { return String(n).replace(/\d/g, d => faNumStr[+d]); }

/* ============================================================
   v27 — ورود با اثر انگشت (WebAuthn platform authenticator)
   ------------------------------------------------------------
   Flow (admin-gated, mirrors the v20 passwordless flow):
     1. logged-in user → POST /api/finger/req → TG card → admin tap
     2. approved       → state.finger = {name, uh, no credential yet}
     3. registration   → GET  /api/finger/reg-options
                          navigator.credentials.create() (fingerprint)
                        POST /api/finger/reg-verify (attestation checked)
     4. later logins   → POST /api/finger/auth-options
                          navigator.credentials.get() (fingerprint)
                        POST /api/finger/auth-verify → session
   Server keeps ONLY: credential id, ES256 public key (JWK), sign counter.
   The chat key never travels raw — fingerprint login hands out the same
   v20.1 server-assisted fallback wrap the owner approved for passwordless
   entry; without an armed fallback wrap the user is told to do one
   password login first. Zero-dependency: hand-rolled minimal CBOR.
   ============================================================ */
const fingerReqs = new Map();   // id -> request rec (RAM; decisions are live)
const fingerChal = new Map();   // challenge(b64url) -> {phase:'reg'|'auth', nameLower, exp}
setInterval(() => { const now = Date.now(); for (const [c, r] of fingerChal) if (r.exp < now) fingerChal.delete(c); }, 30000);

function reqHost(req) {
  return String(req.headers.host || '').split(',')[0].trim().split(':')[0];
}
/* minimal CBOR decode — enough for attestationObject + COSE keys
   (uint/negint/bytes/text/array/map/tags; definite lengths, as every
   mainstream authenticator emits) */
function cborItem(buf, p) {
  if (p >= buf.length) throw new Error('cbor-eof');
  const ib = buf[p++];
  const mt = ib >> 5, ai = ib & 31;
  let val = ai;
  if (ai === 24) val = buf[p++];
  else if (ai === 25) { val = buf.readUInt16BE(p); p += 2; }
  else if (ai === 26) { val = buf.readUInt32BE(p); p += 4; }
  else if (ai === 27) { val = buf.readUInt32BE(p) * 4294967296 + buf.readUInt32BE(p + 4); p += 8; }
  else if (ai >= 28) throw new Error('cbor-len');
  switch (mt) {
    case 0: return [val, p];
    case 1: return [-1 - val, p];
    case 2: case 3: {
      const s = buf.subarray(p, p + val); p += val;
      return [mt === 2 ? s : Buffer.from(s).toString('utf8'), p];
    }
    case 4: {
      const arr = [];
      for (let i = 0; i < val; i++) { const it = cborItem(buf, p); arr.push(it[0]); p = it[1]; }
      return [arr, p];
    }
    case 5: {
      const map = {};
      for (let i = 0; i < val; i++) {
        const k = cborItem(buf, p); p = k[1];
        const v = cborItem(buf, p); p = v[1];
        map[k[0]] = v[0];
      }
      return [map, p];
    }
    case 6: { const it = cborItem(buf, p); return [it[0], it[1]]; }
    default: return [null, p];   // simple values / floats we do not need
  }
}
function cborParse(buf) { const it = cborItem(buf, 0); return it[0]; }
/* authenticatorData: rpIdHash(32) flags(1) signCount(4) [attestedCredentialData] [exts]
   attestedCredentialData = AAGUID(16) credIdLen(u16) credId COSE-key  → len@53, id@55 */
function webauthnCred(ad) {
  const al = ad.readUInt16BE(53);
  const credId = ad.subarray(55, 55 + al);
  if (credId.length !== al) throw new Error('cred-eof');
  const it = cborItem(ad, 55 + al);
  return { credId, cose: it[0] };
}
function coseToJwk(c) {
  if (!c || c[1] !== 2 || c[3] !== -7 || c[-1] !== 1) throw new Error('alg-not-es256');
  const x = Buffer.from(c[-2]), y = Buffer.from(c[-3]);
  if (x.length !== 32 || y.length !== 32) throw new Error('bad-point');
  return { kty: 'EC', crv: 'P-256', x: x.toString('base64url'), y: y.toString('base64url') };
}
function es256Verify(jwk, data, sig) {
  try {
    const key = crypto.createPublicKey({ key: jwk, format: 'jwk' });
    return crypto.verify('sha256', data, key, sig);
  } catch { return false; }
}
function clientDataOf(b64url) {
  try { return JSON.parse(Buffer.from(String(b64url || ''), 'base64url').toString('utf8')); }
  catch { return null; }
}
function bufOf(b64url) {
  try { return Buffer.from(String(b64url || ''), 'base64url'); }
  catch { return null; }
}
/* origin must carry the SAME host this request arrived on (scheme-agnostic —
   works behind Railway's https edge AND on http://127.0.0.1 test runs) */
function originOk(cd, req) {
  try { return !!cd && new URL(cd.origin || '').host === String(req.headers.host || '').split(',')[0].trim(); }
  catch { return false; }
}

function fingerCardText(rec) {
  const mins = Math.round(REQ_TTL / 60000);
  return [
    '\u{1F590} درخواست فعال\u200cسازی ورود با اثر انگشت',
    '',
    '\u{1F464} نام کاربر: ' + rec.name,
    '\u{1F4F1} دستگاه: ' + (rec.dev || 'نامشخص'),
    '\u{1F310} IP: ' + (rec.ip || '?'),
    '\u23F3 زمان تصمیم\u200cگیری: ' + faMin(mins) + ' دقیقه',
    '',
    'با زدن \u2705، کاربر می\u200cتواند در تنظیمات سایت اثر انگشتش را ثبت کند و پس از آن بدون تایپ رمز وارد شود (فقط از همان دستگاه).',
  ].join('\n');
}
async function sendFingerCard(rec) {
  const txt = fingerCardText(rec);
  const res = await tgEnqueue(() => tgCall('sendMessage', {
    chat_id: state.adminId,
    text: txt,
    disable_web_page_preview: true,
    reply_markup: { inline_keyboard: [[
      { text: '\u2705 تایید اثر انگشت', callback_data: 'frq:' + rec.id + ':a' },
      { text: '\u274C رد', callback_data: 'frq:' + rec.id + ':d' },
    ]] },
  }));
  rec.msgId = res && res.message_id || null;
  rec.cardText = txt;
}
function resolveFingerRequest(id, decision) {
  const rec = fingerReqs.get(id);
  if (!rec) return { code: 'gone' };
  if (rec.status !== 'pending') return { code: 'done', rec };
  rec.status = decision === 'a' ? 'approved' : 'denied';
  /* same anti-spam ladder as the passwordless flow: denial → 24h request lock */
  if (rec.status === 'denied') deny24.set(rec.ip || '?', Date.now());
  if (rec.status === 'approved' && authMode() === 'new') {
    state.finger = {
      name: rec.name, nameLower: rec.nameLower,
      uh: crypto.randomBytes(16).toString('base64url'),
      credId: null, jwk: null, counter: 0,
      created: Date.now(), regAt: 0, ua: rec.dev || '',
    };
    saveData();
  }
  const label = rec.status === 'approved'
    ? '\u2705 تایید شد — کاربر حالا در تنظیمات سایت اثر انگشتش را ثبت می\u200cکند.'
    : '\u274C رد شد — تا ۲۴ ساعت امکان درخواست مجدد نیست.';
  if (rec.msgId && TG_TOKEN && state.adminId) {
    tgEnqueue(() => tgCall('editMessageText', {
      chat_id: state.adminId, message_id: rec.msgId,
      text: (rec.cardText || '') + '\n\n' + label,
      reply_markup: { inline_keyboard: [] },
    }).catch(() => {})).catch(() => {});
  }
  broadcastSafe({ type: 'finger', id: rec.id, status: rec.status });
  log('finger-request', id.slice(0, 8), rec.status);
  return { code: 'ok', rec };
}

/* ============================================================
   v29 — trusted device (ورود بدون رمز، فقط با قفل شخصی)
   Flow (admin-gated, mirrors the v27 finger flow):
     1. logged-in user → sets a local pattern/PIN lock, generates an
        EC P-256 keypair in the browser, POSTs /api/device/req
        {devId, pub JWK, label} → TG card → admin ✅/❌
     2. approved → state.devices[devId] = {pub, label, name, …} (persisted)
     3. gate login → POST /api/device/challenge {devId} → nonce
                           POST /api/device/login {devId, nonce, sig}
                       → session + v20.1 fallback wrap (same as reentry)
   Server keeps ONLY the public JWK. The private half never leaves the
   browser and is AES-GCM wrapped under the user's pattern/PIN, so a
   stranger with the phone cannot passwordless-enter without the lock.
   ============================================================ */
const devReqs = new Map();   // id -> pending registration rec (RAM)
const devChal = new Map();   // nonce -> {devId, exp} (single-use)
setInterval(() => { const now = Date.now(); for (const [n, r] of devChal) if (r.exp < now) devChal.delete(n); }, 30000);

/* WebCrypto ECDSA signs IEEE-P1363 (raw r||s, 64B); accept DER too. */
function devVerify(jwk, data, sig) {
  try {
    const key = crypto.createPublicKey({ key: jwk, format: 'jwk' });
    if (crypto.verify('sha256', data, { key, dsaEncoding: 'ieee-p1363' }, sig)) return true;
    return crypto.verify('sha256', data, key, sig);
  } catch { return false; }
}

function deviceCardText(rec) {
  const mins = Math.round(REQ_TTL / 60000);
  return [
    '\u{1F4F1} درخواست اعتماد به دستگاه (ورود بدون رمز)',
    '',
    '\u{1F464} نام کاربر: ' + rec.name,
    '\u{1F4F1} دستگاه: ' + (rec.label || 'نامشخص'),
    '\u{1F310} IP: ' + (rec.ip || '?'),
    '\u{1F517} شناسه: ' + rec.devId.slice(0, 8) + '…',
    '\u23F3 زمان تصمیم\u200cگیری: ' + faMin(mins) + ' دقیقه',
    '',
    'با زدن \u2705 این دستگاه می\u200cتواند بدون تایپ رمز سایت و فقط با «قفل شخصی» (الگو/کد) وارد شود.',
    'اگر شناسه را نمی\u200cشناسی، رد کن — با رد، تا ۲۴ ساعت درخواست مجدد ممکن نیست.',
  ].join('\n');
}
async function sendDeviceCard(rec) {
  const txt = deviceCardText(rec);
  const res = await tgEnqueue(() => tgCall('sendMessage', {
    chat_id: state.adminId,
    text: txt,
    disable_web_page_preview: true,
    reply_markup: { inline_keyboard: [[
      { text: '\u2705 تایید دستگاه', callback_data: 'drq:' + rec.id + ':a' },
      { text: '\u274C رد', callback_data: 'drq:' + rec.id + ':d' },
    ]] },
  }));
  rec.msgId = res && res.message_id || null;
  rec.cardText = txt;
}
function resolveDeviceRequest(id, decision) {
  const rec = devReqs.get(id);
  if (!rec) return { code: 'gone' };
  if (rec.status !== 'pending') return { code: 'done', rec };
  rec.status = decision === 'a' ? 'approved' : 'denied';
  if (rec.status === 'denied') deny24.set(rec.ip || '?', Date.now());
  if (rec.status === 'approved' && authMode() === 'new') {
    state.devices[rec.devId] = {
      id: rec.devId, label: rec.label, name: rec.name, nameLower: rec.nameLower,
      jwk: rec.pub, ip: rec.ip, ua: rec.ua,
      createdAt: Date.now(), approvedAt: Date.now(), lastUsedAt: 0, revoked: false,
    };
    saveData();
  }
  const label = rec.status === 'approved'
    ? '\u2705 تایید شد — این دستگاه از این پس با قفل شخصی وارد می\u200cشود.'
    : '\u274C رد شد — تا ۲۴ ساعت امکان درخواست مجدد نیست.';
  if (rec.msgId && TG_TOKEN && state.adminId) {
    tgEnqueue(() => tgCall('editMessageText', {
      chat_id: state.adminId, message_id: rec.msgId,
      text: (rec.cardText || '') + '\n\n' + label,
      reply_markup: { inline_keyboard: [] },
    }).catch(() => {})).catch(() => {});
  }
  broadcastSafe({ type: 'device', id: rec.id, devId: rec.devId, status: rec.status });
  log('device-request', id.slice(0, 8), rec.status);
  return { code: 'ok', rec };
}

/* v20: attack ban — informative card to the admin with the exact unban command
   (command + identifier shown stuck together so it is copy-paste ready) */
async function bannedNotify(name, dev, ip) {
  if (!state.adminId) return;
  await adminNotify('\u{1F6A8} این کاربر بن شد'
    + '\n\u{1F464} نام: ' + (name || '?')
    + '\n\u{1F4F1} دستگاه: ' + (dev || 'نامشخص')
    + '\n\u{1F310} آی\u200cپی: ' + ip
    + '\n\u{1F4CA} دلیل: بیش از ۳ درخواست پشت\u200cسرهم (۱۵ دقیقه)'
    + '\n\u{1F513} آزادسازی: `/unban_user_' + ip + '`').catch(() => {});
}

async function resolveRequest(id, decision) {
  const rec = pendingReq.get(id);
  if (!rec) return { code: 'gone' };
  if (rec.status !== 'pending') return { code: 'done', rec };
  rec.status = decision === 'a' ? 'approved' : 'denied';
  /* v19: request slot frees up on any decision; denial locks this IP out of
     new requests for 24h (anti-spam, admin requested) */
  if (reqIpPending.get(rec.ip) === rec.id) reqIpPending.delete(rec.ip);
  if (rec.status === 'denied') deny24.set(rec.ip || '?', Date.now());
  if (rec.status === 'approved') {
    rec.claimExp = Date.now() + CLAIM_TTL;
    /* v18: one-time claim code. The plaintext code lives ONLY in RAM for the
       claim window; a logged-in site client turns it into an opaque CK wrap
       (/api/claim-wrap). The server can never derive the chat key from the
       stored hash + wrap alone. */
    const code = genClaimCode();
    claimCode = {
      code, reqId: id,
      hash: crypto.createHash('sha256').update(code).digest('hex'),
      exp: rec.claimExp, wrap: null,
    };
  }
  const label = rec.status === 'approved'
    ? '✅ تایید شد — کاربر خودکار وارد می\u200cشود (بدون مرحله دوم).'
    : '❌ رد شد — تا ۲۴ ساعت امکان درخواست مجدد ندارد.';
  const used = Date.now() < rec.exp ? '' : '\n\n⏳ این درخواست منقضی شده بود و بی\u200cاثر است.';
  if (rec.msgId && TG_TOKEN && state.adminId) {
    const codeLine = rec.status === 'approved' && claimCode
      ? '\n\n🔑 کد فعال\u200cسازی امن (پشت\u200cپرده — کاربر نیازی به تایپ آن ندارد): ' + claimCode.code +
        (claimCode.wrap ? '\n✅ کلید فعال شد — ورود خودکار انجام شد/می\u200cشود.' : '\n⏳ فعال\u200cسازی کلید: به محض حضور یکی از نشست\u200cهای فعال سایت، خودکار انجام می\u200cشود.')
      : '';
    await tgEnqueue(() => tgCall('editMessageText', {
      chat_id: state.adminId, message_id: rec.msgId,
      text: (rec.cardText || '') + '\n\n' + label + used + codeLine,
      reply_markup: { inline_keyboard: [] },
    }).catch(() => {})).catch(() => {});
  }
  broadcastSafe({ type: 'access', id: rec.id, status: rec.status });
  if (rec.status === 'approved' && claimCode) {
    /* authed site clients receive the code ephemerally to compute the wrap;
       it is never persisted */
    broadcastSafe({ type: 'claim', id: rec.id, code: claimCode.code, exp: claimCode.exp });
  }
  log('access-request', id, rec.status);
  return { code: 'ok', rec };
}

async function handleCallbackQuery(cq) {
  try {
    const data = String(cq.data || '');
    /* v27: frq: prefix — fingerprint-enable requests; v29: drq: — trusted devices (same approve/deny flow) */
    const mm = /^(arq|frq|drq):([a-z0-9]+):([ad])$/.exec(data);
    const answer = (text, alert) => tgEnqueue(() => tgCall('answerCallbackQuery', {
      callback_query_id: cq.id, text: text || undefined, show_alert: !!alert,
    })).catch(() => {});
    if (!mm) { await answer('درخواست نامعتبر است.', true); return; }
    const [, rqKind, id, dec] = mm;
    const rec = (rqKind === 'frq' ? fingerReqs : rqKind === 'drq' ? devReqs : pendingReq).get(id);
    if (!rec) {
      await editDeadButtons(cq, 'این درخواست دیگر وجود ندارد.');
      await answer('این درخواست منقضی شده است. \u23F3', true);
      return;
    }
    if (Date.now() > rec.exp) {
      if (rec.status === 'pending') {
        if (rqKind === 'frq' || rqKind === 'drq') { rec.status = 'expired'; broadcastSafe({ type: rqKind === 'frq' ? 'finger' : 'device', id: rec.id, status: 'expired' }); if (rec.msgId && TG_TOKEN && state.adminId) tgEnqueue(() => tgCall('editMessageText', { chat_id: state.adminId, message_id: rec.msgId, text: (rec.cardText || '') + '\n\n\u23F3 زمان تصمیم\u200cگیری تمام شد — درخواست منقضی شد.', reply_markup: { inline_keyboard: [] } }).catch(() => {})).catch(() => {}); }
        else await expireRequest(rec);
      }
      await editDeadButtons(cq, '\u23F3 این درخواست منقضی شده بود.');
      await answer('زمان تصمیم\u200cگیری گذشته است.', true);
      return;
    }
    if (rec.status !== 'pending') {
      await editDeadButtons(cq, rec.status === 'approved' ? '\u2705 قبلاً تایید شده بود.' : '\u274C قبلاً رد شده بود.');
      await answer('برای این درخواست قبلاً تصمیم گرفته شده است.', true);
      return;
    }
    const allowed = !cq.message || !cq.from || !state.adminId || String(cq.from.id) === String(state.adminId);
    if (!allowed) { await answer('فقط ادمین مجاز است.', true); return; }
    if (rqKind === 'frq') resolveFingerRequest(id, dec);
    else if (rqKind === 'drq') resolveDeviceRequest(id, dec);
    else await resolveRequest(id, dec);
    await answer(dec === 'a' ? 'تایید شد \u2705' : 'رد شد \u274C');
  } catch (e) { log('callback err:', e.message); }
}

async function editDeadButtons(cq, note) {
  try {
    if (!cq.message) return;
    await tgEnqueue(() => tgCall('editMessageText', {
      chat_id: cq.message.chat.id, message_id: cq.message.message_id,
      text: (cq.message.text || '') + '\n\n' + note,
      reply_markup: { inline_keyboard: [] },
    }));
  } catch {}
}

async function expireRequest(rec) {
  if (rec.status !== 'pending') return;
  rec.status = 'expired';
  if (reqIpPending.get(rec.ip) === rec.id) reqIpPending.delete(rec.ip);   // v19
  if (rec.msgId && TG_TOKEN && state.adminId) {
    tgEnqueue(() => tgCall('editMessageText', {
      chat_id: state.adminId, message_id: rec.msgId,
      text: (rec.cardText || '') + '\n\n\u23F3 زمان تصمیم\u200cگیری تمام شد \u2014 درخواست منقضی شد.',
      reply_markup: { inline_keyboard: [] },
    }).catch(() => {})).catch(() => {});
  }
  broadcastSafe({ type: 'access', id: rec.id, status: 'expired' });
}
setInterval(() => {
  const now = Date.now();
  for (const rec of [...pendingReq.values()]) {
    if (rec.status === 'pending' && now > rec.exp) expireRequest(rec).catch(() => {});
    if (now > rec.ts + REQ_TTL + CLAIM_TTL + 3600000) {
      pendingReq.delete(rec.id);
      if (reqIpPending.get(rec.ip) === rec.id) reqIpPending.delete(rec.ip);   // v19
    }
  }
  for (const [ip, t] of [...deny24]) if (now - t > DENY_BLOCK_MS) deny24.delete(ip);   // v19
  for (const [ip, w] of [...reqWin]) if (now - w.t0 > REQ_WIN_MS) reqWin.delete(ip);   // v20
}, REQ_SWEEP_MS);

/* ------------------------- SSE hub ------------------------- */
const sseClients = new Set();
let adminActiveAt = 0;

function sseWrite(res, obj) {
  try { res.write('data: ' + JSON.stringify(obj) + '\n\n'); } catch {}
}
function broadcast(obj) {
  for (const res of sseClients) sseWrite(res, obj);
}
function broadcastSafe(obj) {
  process.nextTick(() => broadcast(obj));
}
function presenceCount() {
  const tgAlive = Date.now() - adminActiveAt < 90 * 1000;
  return { n: sseClients.size + (tgAlive ? 1 : 0), tg: tgAlive, adminLinked: !!state.adminId,
           tgSeen: state.lastSeen.tg || 0 };   // v29: real last-seen for the site
}
function presenceTick() { broadcast(Object.assign({ type: 'presence' }, presenceCount())); }

/* ------------------------- v29: real last-seen ------------------------- */
function faAgo(ts) {
  const t = Number(ts) || 0;
  if (!t) return 'نامعلوم';
  const d = Date.now() - t;
  if (d < 90 * 1000) return 'همین حالا';
  const m = Math.floor(d / 60000);
  if (m < 60) return faNum(m) + ' دقیقه پیش';
  const h = Math.floor(m / 60);
  if (h < 24) return faNum(h) + ' ساعت پیش';
  const days = Math.floor(h / 24);
  if (days === 1) return 'دیروز';
  if (days < 7) return faNum(days) + ' روز پیش';
  try { return new Date(t).toLocaleDateString('fa-IR'); }
  catch { return faNum(Math.max(1, Math.floor(days / 30))) + ' ماه پیش'; }
}
/* key: 'tg' for admin activity, or a site display-name for user activity.
   15s debounce so typing bursts don't hammer data.json. */
function touchLastSeen(key, nameHint) {
  const now = Date.now();
  if (key === 'tg') {
    if (now - (state.lastSeen.tg || 0) < 15000) return;
    state.lastSeen.tg = now;
  } else {
    const k = String(key || nameHint || '').toLowerCase().slice(0, 40);
    if (!k) return;
    if (now - (state.lastSeen.users[k] || 0) < 15000) return;
    state.lastSeen.users[k] = now;
    const keys = Object.keys(state.lastSeen.users);
    if (keys.length > 60) {                       // bound the map
      keys.sort((a, b) => state.lastSeen.users[a] - state.lastSeen.users[b]);
      for (const old of keys.slice(0, keys.length - 60)) delete state.lastSeen.users[old];
    }
  }
  saveData();
}

/* --------------- v20: session lifecycle notify (bot-only) ---------------
   open  = first live SSE connection of a session  -> «ورود به سایت» card
   close = last connection gone for a grace period -> «نشست بسته شد» card
   (page refresh reconnects inside the grace window — no notify spam) */
function uaShort(ua) {
  const s = String(ua || '');
  const m = /Android[^;]*;\s*([^;)]+?)(?:\s+Build\/|\))/i.exec(s);
  if (m) return ('Android ' + m[1].trim()).slice(0, 48);
  if (/iPhone/i.test(s)) return 'iPhone' + (/OS (\d+)/.exec(s) ? ' · iOS ' + RegExp.$1 : '');
  if (/iPad/i.test(s)) return 'iPad';
  if (/Windows/i.test(s)) return 'Windows';
  if (/Mac OS X/i.test(s)) return 'Mac';
  if (/Linux/i.test(s)) return 'Linux';
  return '';
}
function sessOpen(srec, devQ, ua) {
  if (!srec || !srec.sid) return;
  let S = sessLive.get(srec.sid);
  if (!S) {
    S = { conns: 0, notified: false, closeTmr: null,
      name: srec.name || 'کاربر', dev: '', ip: srec.ip || '?', openedAt: Date.now() };
    sessLive.set(srec.sid, S);
  }
  S.conns++;
  if (S.closeTmr) { clearTimeout(S.closeTmr); S.closeTmr = null; }
  if (devQ) S.dev = String(devQ).replace(/[\u0000-\u001f<>]/g, ' ').slice(0, 60);
  else if (!S.dev && ua) S.dev = uaShort(ua);
  if (S.conns === 1 && !S.notified) {
    S.notified = true;
    S.openedAt = Date.now();
    /* v24 dedup: the login/claim/reentry flow ALWAYS sends a detailed session
       card (with /revoke<sid>) seconds before this live-connection notify —
       that duplicate «ورود به سایت» is now suppressed; the close notify and
       sessions without a card (very old tokens) still notify normally. */
    if (!(srec && srec.notified)) {
      adminNotify('\u{1F7E2} ورود به سایت: ' + S.name
        + '\n\u{1F4F1} ' + (S.dev || 'دستگاه نامشخص')
        + '\n\u{1F310} ' + S.ip).catch(() => {});
    }
  }
}
function sessClose(sid, reason) {
  const S = sessLive.get(String(sid));
  if (!S || S.conns <= 0) return;
  S.conns--;
  if (S.conns <= 0 && S.notified) {
    S.closeTmr = setTimeout(() => {
      sessLive.delete(String(sid));
      const mins = Math.max(1, Math.round((Date.now() - S.openedAt) / 60000));
      adminNotify('\u{1F534} نشست بسته شد: ' + S.name
        + '\n\u{1F4F1} ' + (S.dev || 'دستگاه نامشخص')
        + '\n\u23F1 مدت: ' + faNum(mins) + ' دقیقه'
        + (reason ? '\n\u21A9\uFE0F دلیل: ' + reason : '')).catch(() => {});
    }, SESS_CLOSE_GRACE_MS);
  }
}

setInterval(() => {
  for (const res of sseClients) { try { res.write(':hb\n\n'); } catch {} }
  presenceTick();
  budgetEvict(blobs, 'blob');
  budgetEvict(tgFiles, 'tg');
}, 25000);

/* mark delivered for ui ticks when someone is listening or mirrored */
function deliveredFlag(mid) {
  const m = messages.find(x => x.id === mid);
  if (!m) return;
  if (!m.dl) { m.dl = true; broadcastSafe({ type: 'update', id: mid, patch: { dl: true } }); }
}

/* ------------------------- telegram client ------------------------- */
const TG = 'https://api.telegram.org/bot' + TG_TOKEN;

let tgQueue = Promise.resolve();   // serialize outbound sends (ordering)
function tgEnqueue(fn) {
  const run = tgQueue.then(fn, fn);
  tgQueue = run.catch(() => {});
  return run;
}

async function tgCall(method, payload, isForm) {
  if (TEST_MODE) {
    lastTgOut.push({ method, payload: isForm ? '(form)' : payload });
    if (lastTgOut.length > 300) lastTgOut.shift();
  }
  /* test env without a bot: capture the call, skip the network entirely */
  if (TEST_MODE && !TG_TOKEN) return { message_id: 1, ok: true };
  const res = await fetch(TG + '/' + method, isForm
    ? { method: 'POST', body: payload }
    : { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload || {}) });
  const j = await res.json().catch(() => ({ ok: false, description: 'bad json' }));
  if (!j.ok) throw new Error(method + ': ' + (j.description || 'failed'));
  return j.result;
}
const lastTgOut = [];           // TEST_MODE capture of every outgoing TG call

const KIND_META = {
  photo:  { k: 'image' },
  video:  { k: 'video' },
  video_note: { k: 'video', round: true },
  animation: { k: 'gif' },
  voice:  { k: 'voice' },
  audio:  { k: 'audio' },
  document: { k: 'file' },
  sticker: { k: 'sticker' },
};

let polling = false;
async function pollLoop() {
  if (!TG_TOKEN) { log('TELEGRAM_BOT_TOKEN missing — bridge disabled'); return; }
  while (true) {
    try {
      const result = await tgCall('getUpdates', {
        timeout: 25,
        offset: state.tgOffset || undefined,
        allowed_updates: ['message', 'callback_query'],
      });
      for (const u of result || []) {
        state.tgOffset = u.update_id + 1;
        saveData();
        if (u.message) handleMessage(u.message).catch(e => log('tg handle err:', e.message));
        if (u.callback_query) handleCallbackQuery(u.callback_query).catch(e => log('tg cb err:', e.message));
      }
      polling = true;
    } catch (e) {
      if (/webhook is active/.test(e.message)) { log('webhook active — polling paused'); await new Promise(r => setTimeout(r, 60000)); continue; }
      polling = false;
      log('poll error:', e.message);
      await new Promise(r => setTimeout(r, 4000));
    }
  }
}

/* ---------------- webhook mode (default; polling is fallback) ---------------- */
async function setupWebhook() {
  if (!TG_TOKEN) return;
  const dom = process.env.RAILWAY_PUBLIC_DOMAIN;
  if (!dom) { log('no public domain — falling back to polling'); return pollLoop(); }
  try {
    await tgCall('deleteWebhook', { drop_pending_updates: false });
    await tgCall('setWebhook', {
      url: `https://${dom}/api/tgwebhook`,
      secret_token: state.webhookSecret,
      allowed_updates: ['message', 'callback_query'],
      drop_pending_updates: false,
    });
    log('webhook set → https://' + dom + '/api/tgwebhook');
    webhookActive = true;
  } catch (e) {
    log('setWebhook failed (' + e.message.slice(0, 90) + ') — falling back to polling');
    pollLoop();
  }
}

async function tgDownload(fileId, capMB) {
  const f = await tgCall('getFile', { file_id: fileId });
  if ((f.file_size || 0) > capMB * 1024 * 1024) throw new Error('file too large');
  let rec = [...tgFiles.entries()].find(([, v]) => v.fid === fileId);
  if (rec) { rec[1].lastTouch = Date.now(); return { buf: rec[1].buf, mime: rec[1].mime, size: rec[1].size }; }
  /* v20: L2 disk cache — no re-download from TG after eviction or restart */
  const dk = tgDiskGet(fileId);
  if (dk) {
    tgFiles.set(rid(), { fid: fileId, buf: dk.buf, mime: dk.mime, size: dk.size, lastTouch: Date.now() });
    return { buf: dk.buf, mime: dk.mime, size: dk.size };
  }
  const res = await fetch(`https://api.telegram.org/file/bot${TG_TOKEN}/${f.file_path}`);
  if (!res.ok) throw new Error('download failed');
  const ab = Buffer.from(await res.arrayBuffer());
  const mime = ({
    jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', webp: 'image/webp',
    webm: 'video/webm', tgs: 'application/x-tgs', json: 'application/json',
    mp4: 'video/mp4', ogg: 'audio/ogg', opus: 'audio/ogg', m4a: 'audio/mp4',
    mp3: 'audio/mpeg', pdf: 'application/pdf',
  })[(f.file_path.split('.').pop() || '').toLowerCase()] || 'application/octet-stream';
  const buf = ab; // keep one copy only
  tgDiskPut(fileId, buf, mime);   // v20
  tgFiles.set(rid(), { fid: fileId, buf, mime, size: buf.length, lastTouch: Date.now() });
  tgbBytes += buf.length;
  budgetEvict(tgFiles, 'tg');
  return { buf, mime, size: buf.length };
}

async function tgSendRaw(form) { return tgCall('sendDocument', form, true); }

async function bridgeInText(text, msg) {
  adminActiveAt = Date.now();
  const sid = nextId();
  if (msg.message_id) { tgMapRecv.set(msg.message_id, sid); recvToTg.set(sid, msg.message_id); }
  const rly = msg.reply_to_message && msg.reply_to_message.message_id;
  const rxRaw = (msg.reply_to_message && (msg.reply_to_message.text || msg.reply_to_message.caption)) || '';
  pushMessage({
    id: sid, ts: Date.now(),
    c: null, iv: null,
    t: String(text).slice(0, 4096),
    meta: { k: 'text', tg: 1, from: 'tg',
            name: state.tgPersona.name || null,
            rt: rly ? (tgMapRecv.get(rly) || null) : null,
            rtTg: rly || undefined,
            rx: rly ? String(rxRaw).replace(/\s+/g, ' ').trim().slice(0, 120) : undefined },
    reacts: null,
  });
  broadcast({ type: 'msg', m: messages[messages.length - 1] });
  presenceTick();
}

async function bridgeInMedia(kind, fileRef, msg, extra) {
  adminActiveAt = Date.now();
  const metaK = KIND_META[kind] ? KIND_META[kind].k : 'file';
  const cap = kind === 'animation' ? 20 : 20;
  const dl = await tgDownload(fileRef, cap).catch((e) => { throw e; });
  const fid = [...tgFiles.entries()].find(([, v]) => v.buf === dl.buf)[0];
  const sid = nextId();
  if (msg.message_id) { tgMapRecv.set(msg.message_id, sid); recvToTg.set(sid, msg.message_id); }
  const rly = msg.reply_to_message && msg.reply_to_message.message_id;
  const rxRaw = (msg.reply_to_message && (msg.reply_to_message.text || msg.reply_to_message.caption)) || '';
  const m = {
    id: sid, ts: Date.now(), c: null, iv: null,
    t: msg.caption ? String(msg.caption).slice(0, 1024) : '',
    meta: {
      k: metaK, tg: 1, from: 'tg', fid,
      round: !!(extra && extra.round),
      anim: metaK === 'gif',
      name: (msg.document && msg.document.file_name) || (msg.audio && msg.audio.title) || (state.tgPersona.name || null),
      mime: dl.mime,
      dur: (kind === 'voice' && msg.voice && msg.voice.duration) ||
           (kind === 'audio' && msg.audio && msg.audio.duration) ||
           (msg.video && msg.video.duration) || (msg.video_note && msg.video_note.duration) || undefined,
      w: msg.photo ? undefined : (msg.video ? msg.video.width : undefined),
      rt: rly ? (tgMapRecv.get(rly) || null) : null,
      rtTg: rly || undefined,
      rx: rly ? String(rxRaw).replace(/\s+/g, ' ').trim().slice(0, 120) : undefined,
    },
    reacts: null,
  };
  pushMessage(m);
  broadcast({ type: 'msg', m });
  presenceTick();
}

/* ------------------------- disk monitor (Railway disk guard) ------------------------- */
const VERSION = 'v31';
const bootAt = Date.now();

/* ---------------- v24 passwordless re-entry (same IP, 300 min) ----------------
   Armed at every successful login and refreshed on every live stream connect.
   A fresh gate load calls GET /api/reentry: if this IP still has a live
   window, it receives a brand-new session + the fallback wrap — zero typing. */
const reentry = new Map();        // ip -> {exp, name}
function reentryArm(ip, name) {
  if (authMode() !== 'new' || !state.vaultFallback) return;
  reentry.set(String(ip || '?'), { exp: Date.now() + REENTRY_TTL, name: sanitizeName(name) });
}
setInterval(() => { const now = Date.now(); for (const [ip, r] of reentry) if (r.exp < now) reentry.delete(ip); }, 60000);

const lastBotReplies = [];      // TEST_MODE capture for tgReply/adminNotify
const lastTgDeletes = [];       // TEST_MODE capture for deleteMessage calls (v17)
function recordTgDelete(mid) { lastTgDeletes.push(mid); if (lastTgDeletes.length > 300) lastTgDeletes.shift(); }
const DISK_WARN_PCT = Math.max(50, Math.min(99, Number(process.env.DISK_WARN_PCT || 80)));
const DISK_CRIT_PCT = Math.max(DISK_WARN_PCT + 1, Math.min(99, Number(process.env.DISK_CRIT_PCT || 90)));
const DISK_CHECK_MS = 5 * 60 * 1000;        // every 5 minutes
const DISK_WARN_COOLDOWN = 6 * 3600 * 1000; // repeat warn at most every 6h
const DISK_CRIT_COOLDOWN = 30 * 60 * 1000;  // repeat crit at most every 30min
let diskAlertAt = 0;
let diskForcePct = 0;           // test-only override (0 = real statfs)

function faNum(n) { return String(n).replace(/\d/g, d => faNumStr[+d]); }
function fmtSize(bytes) {
  const b = Number(bytes) || 0;
  if (b >= 1073741824) return faNum((b / 1073741824).toFixed(1)) + ' گیگابایت';
  if (b >= 1048576) return faNum(Math.round(b / 1048576)) + ' مگابایت';
  if (b >= 1024) return faNum(Math.round(b / 1024)) + ' کیلوبایت';
  return faNum(b) + ' بایت';
}
function fmtDur(ms) {
  const s = Math.max(0, Math.floor(ms / 1000));
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
  if (h > 0) return faNum(h) + ' ساعت و ' + faNum(m) + ' دقیقه';
  if (m > 0) return faNum(m) + ' دقیقه';
  return faNum(s) + ' ثانیه';
}
function fmtClock(t) {
  const d = new Date(t);
  const p = (n) => String(n).padStart(2, '0');
  return faNum(p(d.getHours()) + ':' + p(d.getMinutes()));
}

function diskUsage() {
  if (diskForcePct > 0) {
    const total = 20 * 1024 * 1024 * 1024;
    const used = Math.round(total * diskForcePct / 100);
    return { total, used, free: total - used, pct: diskForcePct, forced: true };
  }
  if (typeof fs.statfsSync !== 'function') return null;
  try {
    const st = fs.statfsSync(DATA_DIR);   // the Railway volume when attached — not the 2.9TB host disk
    const total = Number(st.blocks) * Number(st.bsize);
    const free = Number(st.bavail) * Number(st.bsize);
    if (!(total > 0)) return null;
    const used = Math.max(0, total - free);
    return { total, used, free, pct: (used / total) * 100, forced: false };
  } catch { return null; }
}

function storageLine() {
  return ON_VOLUME
    ? '\u2022 محل ذخیره\u200cسازی: \u2705 حجم پایدار Railway (' + DATA_DIR + ') — با دیپلوی پاک نمی\u200cشود'
    : '\u2022 محل ذخیره\u200cسازی: \u26A0\uFE0F دیسک موقتی کانتینر (حجم پایدار وصل نیست)';
}

function stickersDirStats() {
  const dir = path.join(DATA_DIR, 'stickers');
  const known = new Set(stickers.map(s => s.id + '.json'));
  let files = 0, bytes = 0; const orphans = [];
  try {
    for (const f of fs.readdirSync(dir)) {
      if (f === 'index.json' || f === 'index.json.tmp') continue;
      let sz = 0;
      try { sz = fs.statSync(path.join(dir, f)).size; } catch { continue; }
      files++; bytes += sz;
      if (f.endsWith('.json') && !known.has(f)) orphans.push(f);
    }
  } catch { /* dir missing yet */ }
  return { files, bytes, orphans };
}

function cleanupOrphans() {
  const dir = path.join(DATA_DIR, 'stickers');
  const { orphans } = stickersDirStats();
  let freed = 0;
  for (const f of orphans) {
    try {
      freed += fs.statSync(path.join(dir, f)).size;
      fs.unlinkSync(path.join(dir, f));
    } catch {}
  }
  try { // stray tmp files from interrupted writes
    for (const f of fs.readdirSync(dir)) {
      if (!f.endsWith('.tmp')) continue;
      try {
        freed += fs.statSync(path.join(dir, f)).size;
        fs.unlinkSync(path.join(dir, f));
      } catch {}
    }
  } catch {}
  if (orphans.length) log('cleanup: removed', orphans.length, 'orphan files,', fmtSize(freed));
  return { removed: orphans.length, freed };
}

function pruneOldestStickers(n) {
  const cnt = Math.max(0, Math.min(Number(n) || 0, stickers.length));
  const victims = [...stickers].sort((a, b) => a.ts - b.ts).slice(0, cnt);
  let freed = 0;
  for (const s of victims) {
    const i = stickers.findIndex(x => x.id === s.id);
    if (i >= 0) stickers.splice(i, 1);
    try { freed += s.size || fs.statSync(path.join(DATA_DIR, 'stickers', s.id + '.json')).size; } catch {}
    try { fs.unlinkSync(path.join(DATA_DIR, 'stickers', s.id + '.json')); } catch {}
  }
  if (victims.length) saveStickers();
  if (victims.length) log('cleanup: pruned', victims.length, 'oldest stickers,', fmtSize(freed));
  return { removed: victims.length, freed };
}

async function adminNotify(text) {
  if (TEST_MODE && !TG_TOKEN) {
    lastBotReplies.push(String(text));
    if (lastBotReplies.length > 10) lastBotReplies.shift();
    return true;
  }
  if (!TG_TOKEN || !state.adminId) { log('admin-notify (no bridge):', String(text).split('\n')[0]); return false; }
  try {
    await tgEnqueue(() => tgCall('sendMessage', { chat_id: state.adminId, text, disable_web_page_preview: true }));
    return true;
  } catch (e) { log('adminNotify fail:', e.message); return false; }
}

function diskLine(d) {
  return '• مصرف: ' + faNum(Math.round(d.pct)) + '٪ (' + fmtSize(d.used) + ' از ' + fmtSize(d.total) + ') — آزاد: ' + fmtSize(d.free);
}

async function monitorTick(reason) {
  const d = diskUsage();
  if (!d) return { pct: -1, action: 'none' };
  const st = stickersDirStats();
  const now = Date.now();
  if (d.pct >= DISK_CRIT_PCT) {
    const oc = cleanupOrphans();
    let pruned = { removed: 0, freed: 0 };
    if (stickers.length) pruned = pruneOldestStickers(Math.max(1, Math.ceil(stickers.length * 0.3)));
    if (now - diskAlertAt >= DISK_CRIT_COOLDOWN) {
      diskAlertAt = now;
      await adminNotify([
        '\u{1F6A8} هشدار دیسک — فضای بحرانی (' + (reason === 'test' ? 'تست' : 'خودکار') + ')',
        diskLine(d),
        '',
        'پاکسازی خودکار انجام شد:',
        '\u2022 فایل زائد حذف\u200cشده: ' + faNum(oc.removed) + ' (' + fmtSize(oc.freed) + ')',
        '\u2022 استیکرهای قدیمی حذف\u200cشده: ' + faNum(pruned.removed) + ' (' + fmtSize(pruned.freed) + ')',
        'استیکرهای باقی\u200cمانده: ' + faNum(stickers.length),
        '',
        'اگر باز هم پر شد، حجم دیتای پیام\u200cها را با /clear کم کن.',
      ].join('\n'));
    }
    return { pct: d.pct, action: 'crit', oc, pruned };
  }
  if (d.pct >= DISK_WARN_PCT) {
    if (now - diskAlertAt >= DISK_WARN_COOLDOWN) {
      diskAlertAt = now;
      await adminNotify([
        '\u{26A0}\u{FE0F} مانیتور دیسک — فضای دیسک پر می\u200cشود',
        diskLine(d),
        '\u2022 استیکرهای ابری: ' + faNum(stickers.length) + ' عدد (' + fmtSize(st.bytes) + ')',
        '',
        'در ' + faNum(DISK_CRIT_PCT) + '\u066A قدیمی\u200cترین استیکرها خودکار پاک می\u200cشوند. با /disk پیگیری کن.',
      ].join('\n'));
    }
    return { pct: d.pct, action: 'warn' };
  }
  diskAlertAt = 0;
  return { pct: d.pct, action: 'ok' };
}
setInterval(() => monitorTick('timer').catch(e => log('disk monitor err:', e.message)), DISK_CHECK_MS);

/* ------------------------- bot commands ------------------------- */
const pendingPfp = new Set(); // admin armed for next photo

function helpText() {
  return [
    '🤖 ربات ' + state.siteTitle + ' فعال است (' + VERSION + ').',
    '',
    '📡 وضعیت و نگهداری:',
    '/status — وضعیت سرور، چت و دیسک',
    '/disk — جزئیات فضای دیسک',
    '/backup [on|off] — بکاپ فوری رمزشده؛ یا روشن/خاموش‌کردن بکاپ خودکار (روزانه + بعد از هر دیپلوی)',
    '/unban_user — آزادسازی آی‌پی بن‌شده؛ مثال: /unban_user_1.2.3.4 (بدون ورودی: فهرست بن‌ها)',
    '/cleanup — پاکسازی فایل‌های زائد',
    '/sessions — نشست‌های اخیر و درخواست‌های باز',
    '/revoke yes — باطل‌کردن همهٔ نشست‌های سایت',
    '/revoke<شناسه> — اخراج فوری فقط یک نشست؛ مثال: /revoke1004',
    '/who — با ریپلای روی پیام سایت: مشخصات همان فرستنده؛ بدون ریپلای: لیست کاربران',
    '/lastseen — لست‌سین واقعی: آخرین فعالیت کاربران سایت و طرف تلگرام',
    '/devices — دستگاه‌های مورد اعتماد (ورود بدون رمز با قفل شخصی)؛ لغو: /rdev<شناسه>',
    '',
    '⚙️ تنظیمات:',
    '/name نام — تغییر نام نمایشی شما در سایت',
    '/title عنوان — تغییر عنوان/برند سایت؛ مثال: /title Panda Chat',
    '/pfp — تنظیم عکس پروفایل (عکس را همراه یا بعد از دستور بفرست)',
    '/clear — پاک کردن همهٔ پیام‌های سایت',
    '/pass رمزجدید — تغییر رمز ورود سایت (همیشه کار می‌کند — حتی بدون کلید پشتیبان، از نسخه ۲۱)',
    '/password — نمایش رمز فعلی سایت (فقط در همین چت خصوصی ادمین)',
    '/unlock — پاک‌کردن همهٔ قفل‌های تلاش ورود (پس از رمز اشتباه زیاد)',
    '',
    '🔔 با هر ورود موفق (با رمز یا بدون رمز) کارت ورود با شناسهٔ نشست اینجا می‌آید',
    'و می‌توانی همان لحظه فقط همان نشست را با /revoke<شناسه> اخراج کنی.',
    '',
    '🔁 تا ۳۰۰ دقیقه بعد از خروج، ورود دوباره از همان آی‌پی بدون رمز انجام می‌شود',
    '(با کارت «بازگشت خودکار» اینجا).',
    '',
    '🔓 اگر کسی رمز را نداند، از صفحهٔ ورود گزینهٔ «ورود بدون رمز» را می‌زند؛',
    'درخواستش با نام، مدل دستگاه و IP به اینجا می‌آید (۳۰ دقیقه فرصت).',
    '',
    '💽 اگر دیسک به ' + faNum(DISK_WARN_PCT) + '٪ برسد هشدار می‌دهم و در ' + faNum(DISK_CRIT_PCT) + '٪ قدیمی‌ترین استیکرها خودکار پاک می‌شوند.',
    '',
    'هر متن، عکس، ویدیو، ویس، موسیقی، فایل یا استیکری بفرستی مستقیم به سایت می‌رود؛',
    'با ریپلای روی پیام‌ها هم سمت سایت نقل‌قول نمایش داده می‌شود.',
  ].join('\n');
}

const BOT_COMMANDS = [
  { command: 'status', description: 'وضعیت سرور و چت' },
  { command: 'disk', description: 'فضای دیسک' },
  { command: 'backup', description: 'بکاپ فوری؛ یا روشن/خاموش‌کردن خودکار (on/off)' },
  { command: 'unban_user', description: 'آزادسازی آی‌پی بن‌شده؛ مثال: /unban_user_1.2.3.4' },
  { command: 'cleanup', description: 'پاکسازی فایل‌های زائد' },
  { command: 'sessions', description: 'نشست‌های اخیر و درخواست‌های باز' },
  { command: 'revoke', description: 'باطل‌کردن نشست‌ها (همه یا یکی)' },
  { command: 'who', description: 'فرستندهٔ پیام (ریپلای) یا لیست کاربران' },
  { command: 'lastseen', description: 'لست‌سین واقعی کاربران سایت' },
  { command: 'devices', description: 'دستگاه‌های مورد اعتماد' },
  { command: 'rdev', description: 'لغو اعتماد یک دستگاه؛ مثال: /rdev<شناسه>' },
  { command: 'name', description: 'تغییر نام نمایشی' },
  { command: 'title', description: 'تغییر عنوان سایت' },
  { command: 'pfp', description: 'تنظیم عکس پروفایل' },
  { command: 'clear', description: 'پاک کردن پیام‌های سایت' },
  { command: 'password', description: 'نمایش رمز فعلی سایت (فقط ادمین)' },
  { command: 'pass', description: 'تغییر رمز ورود (همیشه کار می‌کند)' },
  { command: 'unlock', description: 'پاک‌کردن قفل‌های تلاش ورود' },
  { command: 'help', description: 'راهنما' },
];
function syncBotCommands() {
  if (!TG_TOKEN) return;
  tgCall('setMyCommands', { commands: BOT_COMMANDS })
    .then(() => log('bot command menu synced (' + BOT_COMMANDS.length + ')'))
    .catch((e) => log('setMyCommands fail:', e.message));
}

function personaChanged(side) {
  broadcastSafe({
    type: 'profile', side,
    name: state[side === 'tg' ? 'tgPersona' : 'sitePersona'].name || '',
    photo: state[side === 'tg' ? 'tgPersona' : 'sitePersona'].photo || '',
  });
}

async function tgReply(text) {
  if (TEST_MODE && !TG_TOKEN) {
    lastBotReplies.push(String(text));
    if (lastBotReplies.length > 10) lastBotReplies.shift();
    return { ok: true, message_id: 1 };
  }
  return tgEnqueue(() => tgCall('sendMessage', {
    chat_id: state.adminId, text,
    parse_mode: undefined,
    disable_web_page_preview: true,
  }));
}

/* v18 hardening: also strip angle brackets (defense-in-depth for the Telegram
   cards and any future HTML sink) while keeping Persian ZWNJ characters */
function sanitizeName(n) { return String(n || '').replace(/[\u0000-\u001f<>]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 30); }
/* اسم رمز sanitizer: like the name but also strips angle brackets (defense-in-depth,
   same policy as the device label) — the value is echoed into the admin Telegram card */
function sanitizeCode(n) { return String(n || '').replace(/[\u0000-\u001f<>]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 30); }
/* v15 site title sanitizer: for /title + data.json — no control chars, no <>, 1..40 */
function sanitizeTitle(t) { return String(t || '').replace(/[\u0000-\u001f<>]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 40); }

async function setPassword(pw) {
  const p = String(pw || '').trim();
  if (p.length < 4 || p.length > 64) throw new Error('رمز باید ۴ تا ۶۴ کاراکتر باشد');
  /* v21: in zero-knowledge mode the login credential is state.auth — rotate it
     FIRST. Since v21 the rotation can NOT fail: when no server key backup is
     recoverable it mints a fresh CK and wipes the undecryptable ciphertext
     (the bot is the admin panel — the owner must never be locked out). */
  const rotated = authMode() === 'new' ? rotateCredentialTo(p) : false;
  PASSWORD = p;
  PASSWORD_HASH = scryptHash(p);
  state.password = { p, h: PASSWORD_HASH };
  state.pwRotatedAt = Date.now();
  saveData();
  let persisted = false;
  try { persisted = await persistRailway({ PASSWORD: p, PASSWORD_HASH }); } catch {}
  return { persisted, rotated, rekeyed: !!(rotated && rotated.rekeyed) };
}

/* v20: lift an attack-ban early. Accepts both «/unban_user 1.2.3.4» and
   the stuck form shown in the ban card: «/unban_user_1.2.3.4» */
async function unbanHandle(arg) {
  if (!arg) {
    if (!ipBlock.size) { await tgReply('فهرست بن خالی است ✅ — هیچ آی\u200cپی\u200cای بن نیست.'); return; }
    const lines = [...ipBlock.entries()].map(([bip, ts]) => {
      const left = Math.max(0, IPBLOCK_MS - (Date.now() - ts));
      return '• ' + bip + ' — ' + faNum(Math.max(1, Math.ceil(left / 3600000))) + ' ساعت مانده — `/unban_user_' + bip + '`';
    });
    await tgReply('🚫 آی\u200cپی\u200cهای بن\u200cشده:\n' + lines.join('\n'));
    return;
  }
  if (ipBlock.has(arg)) {
    ipBlock.delete(arg);
    reqWin.delete(arg);
    await tgReply('✅ آی\u200cپی ' + arg + ' آزاد شد — دوباره می\u200cتواند درخواست بدهد.');
  } else {
    await tgReply('این آی\u200cپی در فهرست بن نیست (یا خودکار آزاد شده است).');
  }
}

async function handleCommand(msg, text) {
  const sp = text.indexOf(' ');
  const cmd = (sp < 0 ? text : text.slice(0, sp)).split('@')[0].toLowerCase();
  const arg = sp < 0 ? '' : text.slice(sp + 1).trim();
  /* v20: the stuck ban-release form — /unban_user_1.2.3.4 (no space) */
  const stuckUnban = /^\/unban_user[_\s](.+)$/.exec(cmd);
  if (stuckUnban) { await unbanHandle(stuckUnban[1].trim()); return; }
  /* v15: one-shot per-session revoke — /revoke1004 (no space) kills ONLY that session */
  const oneShot = /^\/revoke(\d{1,10})$/.exec(cmd);
  /* v29: one-shot device untrust — /rdev<id8> (no space); prefix must match exactly one device */
  const oneShotRdev = /^\/rdev([a-f0-9]{6,64})$/.exec(cmd);
  if (oneShotRdev) {
    const pfx = oneShotRdev[1];
    const hits = Object.values(state.devices).filter(d => d.id.startsWith(pfx));
    if (!hits.length) { await tgReply('❌ دستگاهی با شناسهٔ «' + pfx + '» پیدا نشد. فهرست با /devices'); return true; }
    if (hits.length > 1) { await tgReply('⚠️ چند دستگاه با این پیشوند مطابقت دارند — شناسه را کامل‌تر کن. /devices'); return true; }
    const d = hits[0];
    delete state.devices[d.id];
    saveData();
    broadcastSafe({ type: 'device', devId: d.id, status: 'revoked' });
    log('device revoked via bot:', d.id.slice(0, 8), (d.label || ''));
    await tgReply('⛔ اعتماد دستگاه «' + (d.label || 'نامشخص') + '» (' + d.id.slice(0, 8) + '…) لغو شد — دیگر بدون رمز وارد نمی‌شود.');
    return true;
  }
  if (oneShot) {
    const r = revokeSession(oneShot[1]);
    if (!r) { await tgReply('❌ نشست #' + faNum(oneShot[1]) + ' پیدا نشد. لیست را با /sessions ببین.'); return true; }
    if (r.already) { await tgReply('ℹ️ نشست #' + faNum(r.rec.sid) + ' قبلاً اخراج شده بود.'); return true; }
    const who = r.rec.kind === 'claim' ? ('بدون رمز («' + (r.rec.name || '؟') + '»' + (r.rec.code ? ' · 🏷 ' + r.rec.code : '') + ')') : r.rec.kind === 'finger' ? ('اثر انگشت («' + (r.rec.name || '؟') + '»)') : r.rec.kind === 'device' ? ('دستگاه اعتمادشده («' + (r.rec.name || '؟') + '»)') : 'با رمز';
    await tgReply('⛔ نشست #' + faNum(r.rec.sid) + ' (' + who + ') اخراج شد — فقط همین نشست باطل شد و بقیه دست‌نخورده‌اند.');
    return true;
  }
  switch (cmd) {
    case '/start':
    case '/help':
      await tgReply(helpText());
      return true;
    case '/who': {
      /* v18 — identify the site sender: reply to a mirrored site message
         with /who (or run bare /who to list known site users) */
      const rmid = msg.reply_to_message && msg.reply_to_message.message_id;
      if (!rmid) {
        const names = distinctSiteNames();
        const lines = ['👥 کاربران سایت (در ۲۰۰ پیام اخیر):'];
        if (!names.size) lines.push('  – هنوز کسی از سایت پیام نداده است');
        for (const n of names) {
          const prof = state.profiles[String(n).toLowerCase()];
          lines.push('  – ' + n + (prof && prof.updated ? ' · 🖼 پروفایل دارد' : ''));
        }
        lines.push('', 'ℹ️ روی یک پیامِ آینه‌شده از سایت ریپلای کن و /who بزن تا مشخصات همان فرستنده بیاید.');
        await tgReply(lines.join('\n'));
        return true;
      }
      const smid = sentTgMidRev.get(rmid);
      if (!smid) {
        await tgReply('ℹ️ این پیام از تلگرام است (فرستنده خود ادمین است) — روی پیام‌های آینه‌شده از سایت ریپلای کن.');
        return true;
      }
      const m = messages.find(x => x.id === smid);
      const sname = m && m.meta && (m.meta.un || m.meta.name);
      if (!sname) { await tgReply('ℹ️ فرستندهٔ این پیام نام نداشت (پیام قدیمی قبل از نسخه ۱۸).'); return true; }
      const prof = state.profiles[String(sname).toLowerCase()];
      if (prof && prof.photo) {
        const m64 = /^data:(image\/[a-z+]+);base64,(.+)$/i.exec(prof.photo);
        if (m64) {
          const buf = Buffer.from(m64[2], 'base64');
          const form = new FormData();
          form.append('chat_id', String(state.adminId));
          form.append('caption', '👤 فرستندهٔ این پیام در سایت: ' + sname);
          form.append('photo', new Blob([buf]), 'profile.jpg');
          await tgEnqueue(() => tgCall('sendPhoto', form, true));
          return true;
        }
      }
      await tgReply('👤 فرستندهٔ این پیام در سایت: ' + sname + '\n• این کاربر هنوز عکس پروفایلی ثبت نکرده است');
      return true;
    }
    case '/lastseen': {
      /* v29: real last-seen — tg side = admin activity, users = site activity */
      const lines = ['🕒 لست‌سین واقعی (بروزرسانی با هر پیام/فعالیت):'];
      const tgSeen = state.lastSeen.tg || 0;
      const tgAlive = Date.now() - adminActiveAt < 90000;
      lines.push('• تلگرام (شما): ' + (tgAlive ? 'همین حالا 🟢' : (tgSeen ? faAgo(tgSeen) : 'نامعلوم')));
      const entries = Object.entries(state.lastSeen.users).sort((a, b) => b[1] - a[1]).slice(0, 20);
      const liveNames = new Set();
      for (const S of sessLive.values()) if (S.conns > 0 && S.name) liveNames.add(String(S.name).toLowerCase());
      if (!entries.length) lines.push('• کاربران سایت: هنوز فعالیتی ثبت نشده');
      for (const [k, ts] of entries) {
        const prof = state.profiles[k];
        lines.push('• ' + ((prof && prof.name) || k) + ': ' + faAgo(ts) + (liveNames.has(k) ? ' 🟢 (آنلاین)' : ''));
      }
      await tgReply(lines.join('\n'));
      return true;
    }
    case '/devices': {
      const devs = Object.values(state.devices).sort((a, b) => (b.approvedAt || 0) - (a.approvedAt || 0));
      const pend = [...devReqs.values()].filter(r => r.status === 'pending');
      const lines = ['📱 دستگاه‌های مورد اعتماد (' + faNum(devs.length) + '):'];
      if (!devs.length) lines.push('  – هنوز دستگاهی ثبت نشده — از تنظیمات سایت «افزودن دستگاه» بزن.');
      for (const d of devs) {
        lines.push('  – ' + (d.label || 'نامشخص') + ' · ' + (d.name || '؟')
          + ' · تایید: ' + faAgo(d.approvedAt || d.createdAt)
          + ' · آخرین ورود: ' + (d.lastUsedAt ? faAgo(d.lastUsedAt) : 'هنوز نشده')
          + ' · ' + d.id.slice(0, 8));
        lines.push('    لغو: `/rdev' + d.id.slice(0, 8) + '`');
      }
      if (pend.length) {
        lines.push('', '⏳ در انتظار تایید (' + faNum(pend.length) + '):');
        for (const r of pend) lines.push('  – ' + (r.label || 'نامشخص') + ' · ' + (r.name || '؟') + ' · تا ' + faMin(Math.ceil((r.exp - Date.now()) / 60000)) + ' دقیقه دیگر');
      }
      await tgReply(lines.join('\n'));
      return true;
    }
    case '/name': {
      const n = sanitizeName(arg);
      if (!n) { await tgReply('❌ استفاده: /name نام‌نمایشی'); return true; }
      state.tgPersona.name = n;
      saveData(); personaChanged('tg');
      await tgReply('✅ نام شما در سایت «' + n + '» شد.');
      return true;
    }
    case '/pfp': {
      const ph = msg.photo;
      if (ph && ph.length) {
        const fileId = ph[Math.min(ph.length - 1, 2)].file_id; // medium-large is enough
        await applyTgPhoto(fileId);
        await tgReply('✅ عکس پروفایل آپدیت شد.');
        return true;
      }
      pendingPfp.add('x'); setTimeout(() => pendingPfp.delete('x'), 5 * 60 * 1000);
      await tgReply('حالا عکس پروفایل جدید را بفرست 📸 (تا ۵ دقیقه)');
      return true;
    }
    case '/clear': {
      wipeSite();
      await tgReply('🧹 همهٔ پیام‌ها پاک شدند — هم در سایت و هم در تلگرام (تا سقف ۴۸ ساعت تلگرام).');
      return true;
    }
    case '/pass': {
      if (!arg) { await tgReply('❌ استفاده: /pass رمز-جدید\nℹ️ دیدن رمز فعلی: /password'); return true; }
      try {
        const r = await setPassword(arg.split(/\s+/)[0]);
        revokeAllSessions();   /* really kill old tokens server-side, not just a client hint */
        /* v21: clear every login lockout so the owner can enter IMMEDIATELY
           with the new password (progressive 15min/1h/6h locks + global guard) */
        loginFails.clear(); globalLockUntil = 0; globalFailCount = 0;
        await tgReply('🔐 رمز تغییر کرد' + (r.persisted ? ' و برای همیشه ذخیره شد.' : ' (فعلاً تا ریستارت).')
          + '\n✅ ورود به سایت از این لحظه فقط با همین رمز ممکن است — نشست‌های قبلی باطل شدند.'
          + '\n🔓 قفل‌های ورود هم پاک شدند — همین حالا می‌توانی وارد شوی.'
          + (r.rekeyed
              ? '\n♻️ کلید پشتیبان پیدا نشد — کلید چت بازسازی شد و پیام‌های قبلی سایت پاک شدند (رمز قدیمی قابل بازیابی نبود).'
              : (r.rotated ? '\nℹ️ اعتبار ورود رمزنگاری صفر-دانش هم با رمز جدید همگام شد (کلید چت دست‌نخورده ماند).' : '')));
      } catch (e) {
        await tgReply('⛔ رمز عوض نشد: ' + e.message);
      }
      return true;
    }
    case '/unlock': {
      /* v21: admin panel authority — lift every login lockout at once
         (progressive per-IP locks from wrong tries + the global brute-force
         guard). Useful after a forgotten password, a shared-IP office, or
         a burst of failed tries by the owner's own device. */
      const n = loginFails.size;
      const wasGlobal = globalLockUntil > Date.now();
      loginFails.clear();
      globalLockUntil = 0; globalFailCount = 0;
      await tgReply('🔓 قفل‌های ورود پاک شد'
        + (n ? ' (' + faNum(n) + ' آی‌پی قفل‌شده آزاد شد)' : ' (قفلی وجود نداشت)')
        + (wasGlobal ? '\n🌍 قفل سراسری ضد حمله هم برداشته شد.' : '')
        + '\nℹ️ بن آی‌پی (اسپم درخواست ورود) جداست: /unban_user');
      return true;
    }
    case '/password': {
      /* v21: show the CURRENT site password to the admin — admin-gated by
         handleMessage (private chat + exact admin id). The response only ever
         travels to the same private chat the admin typed in. Since v21 the
         site-settings rotation ALSO records the new password (owner directive:
         the bot is the full admin panel), so the server knows it in every flow
         except a rotation done by a CACHED OLD client tab. */
      const cur = (state.password && state.password.p) || PASSWORD || '';
      if (cur) {
        await tgReply('🔑 رمز فعلی ورود سایت: ' + cur
          + '\n\n🔒 این پیام فقط برای تو در همین چت خصوصی ادمین نمایش داده می‌شود.');
      } else {
        await tgReply('🔒 سرور رمز فعلی را نمی‌داند (رمز از یک تب قدیمی بدون نسخهٔ جدید عوض شده است).'
          + '\nبرای گذاشتن رمز جدید: /pass رمز-جدید — همیشه بدون قید و شرط کار می‌کند.');
      }
      return true;
    }
    case '/status': {
      const pres = presenceCount();
      const mem = process.memoryUsage();
      const d = diskUsage();
      const lines = [
        '📊 وضعیت ' + state.siteTitle + ' ' + VERSION,
        '• آپ‌تایم: ' + fmtDur(Date.now() - bootAt),
        '• پل تلگرام: ' + (!TG_TOKEN ? 'خاموش' : (webhookActive ? 'وبهوک فعال ✅' : (polling ? 'پولینگ فعال ✅' : 'قطع ⚠️'))),
        '• حاضران در چت: ' + faNum(pres.n) + (pres.tg ? ' (شامل تلگرام)' : ''),
        '• پیام‌های ذخیره‌شده: ' + faNum(messages.length) + ' · حباب‌های رمزی در RAM: ' + faNum(blobs.size),
        '• حافظه سرور (RSS): ' + fmtSize(mem.rss),
        '• استیکرهای ابری: ' + faNum(stickers.length) + ' عدد',
      ];
      if (d) lines.push('• دیسک: ' + faNum(Math.round(d.pct)) + '٪ مصرف‌شده (' + fmtSize(d.used) + ' از ' + fmtSize(d.total) + ')' + (ON_VOLUME ? ' — حجم Railway' : ''));
      lines.push(storageLine());
      lines.push('• رمزنگاری حالت سکون: ' + (encOnDisk ? '\u2705 فعال (AES-256-GCM) — دیتابیس روی دیسک رمز است' : '\u23F3 در اولین ذخیره رمز می\u200cشود'));
      lines.push('• IPهای محدودشده (ورود ناموفق): ' + faNum(loginFails.size));
      const dep = String(process.env.RAILWAY_DEPLOYMENT_ID || '');
      if (dep) lines.push('• دیپلوی: ' + dep.slice(0, 12));
      await tgReply(lines.join('\n'));
      return true;
    }
    case '/disk': {
      const d = diskUsage();
      if (!d) { await tgReply('ℹ️ اطلاعات دیسک در این محیط در دسترس نیست.'); return true; }
      const st = stickersDirStats();
      await tgReply([
        '💽 وضعیت دیسک',
        diskLine(d),
        storageLine(),
        '• استیکرهای ابری: ' + faNum(stickers.length) + ' عدد در ' + faNum(st.files) + ' فایل (' + fmtSize(st.bytes) + ')',
        '• فایل‌های زائد: ' + faNum(st.orphans.length) + ' عدد',
        '• دیتابیس (data.json): ' + fmtSize((() => { try { return fs.statSync(DATA_FILE).size; } catch { return 0; } })()),
        '',
        'آستانهٔ هشدار: ' + faNum(DISK_WARN_PCT) + '٪ · آستانهٔ پاکسازی خودکار: ' + faNum(DISK_CRIT_PCT) + '٪',
      ].join('\n'));
      return true;
    }
    case '/cleanup': {
      const oc = cleanupOrphans();
      await tgReply(oc.removed
        ? '🧹 پاکسازی انجام شد:\n• ' + faNum(oc.removed) + ' فایل زائد حذف شد (' + fmtSize(oc.freed) + ' آزاد شد).'
        : '✅ فایل زائدی نبود — همه‌چیز تمیز است.');
      return true;
    }
    case '/backup': {
      /* v30: /backup on|off toggles the AUTOMATIC backup (boot + daily);
         a bare /backup still runs an immediate manual backup. */
      const a = String(arg || '').trim().toLowerCase();
      if (/^(on|روشن|فعال|enable)$/i.test(a)) {
        state.backupOn = true; saveData();
        await tgReply('🟢 بکاپ خودکار روشن شد — بعد از هر بوت و هر شب به همین چت می‌آید.');
        return true;
      }
      if (/^(off|خاموش|غیرفعال|disable)$/i.test(a)) {
        state.backupOn = false; saveData();
        await tgReply('⛔ بکاپ خودکار خاموش شد. بکاپ دستی: همین دستور را بدون پارامتر بزن.');
        return true;
      }
      await tgReply('⏳ در حال آماده‌سازی بکاپ رمزشده…\n(وضعیت خودکار: ' + (state.backupOn ? '🟢 روشن' : '🔴 خاموش') + ' — با /backup on یا /backup off عوضش کن)');
      const r = await runBackup('دستی');
      if (r.ok) await tgReply('✅ بکاپ رمزشده ارسال شد (' + fmtSize(r.size) + ') — همین فایل در بالا آمده است.\n♻️ بازیابی: فایل را با نام data.json روی volume بگذار + همان VAULT_SECRET.');
      else await tgReply('❌ بکاپ ناموفق: ' + (r.why === 'no-bridge' ? 'ربات متصل نیست' : r.why === 'no-file' ? 'فایل دیتابیس هنوز ساخته نشده' : r.why));
      return true;
    }
    case '/unban_user': {
      await unbanHandle(arg);
      return true;
    }
    case '/sessions': {
      const pendingArr = [...pendingReq.values()].filter(r => r.status === 'pending');
      const lines = [
        '👤 ' + state.siteTitle + ' — نشست‌ها:',
        '• اتصال‌های زنده: ' + faNum(sseClients.size),
        '• درخواست‌های باز (بدون رمز): ' + faNum(pendingArr.length),
      ];
      for (const r of pendingArr.slice(0, 5)) {
        lines.push('  – ' + r.name + ' · 🏷 ' + (r.code || '-') + ' · ' + (r.dev || 'دستگاه نامشخص') + ' · ' + fmtClock(r.ts));
      }
      const srecs = [...sessions.values()].sort((a, b) => b.t - a.t).slice(0, 10);
      lines.push('', '🔐 نشست‌های اخیر (جدیدترین اول):');
      if (!srecs.length) lines.push('  – هنوز نشستی ثبت نشده (نشست‌های قدیمی‌تر از نسخهٔ ۱۵ شناسه ندارند)');
      for (const s of srecs) {
        const who = s.kind === 'claim' ? 'بدون رمز («' + (s.name || '؟') + '»' + (s.code ? ' · 🏷 ' + s.code : '') + ')'
          : s.kind === 'reentry' ? 'بازگشت خودکار (آی‌پی)' + (s.name ? ' · ' + s.name : '')
          : s.kind === 'finger' ? 'اثر انگشت («' + (s.name || '؟') + '»)'
          : s.kind === 'device' ? 'دستگاه اعتمادشده («' + (s.name || '؟') + '»)'
          : 'با رمز' + (s.name ? ' · ' + s.name : '');
        lines.push('  – #' + s.sid + ' · ' + fmtClock(s.t) + ' · ' + who + ' · ' + (s.dev || 'دستگاه نامشخص') + ' · ' + (s.revoked ? '⛔ اخراج‌شده' : '✅ فعال'));
      }
      if (srecs.length) lines.push('', '⛔ اخراج فقط یک نشست: /revoke' + srecs[0].sid);
      lines.push('🕓 ورودی‌های قدیمی (۱۰ مورد آخر):');
      const recent = loginLog.slice(-10).reverse();
      if (!recent.length) lines.push('  – هنوز ورودی ثبت نشده');
      for (const L of recent) {
        lines.push('  – ' + fmtClock(L.t) + ' · ' + (L.kind === 'claim' ? 'بدون رمز («' + L.name + '»' + (L.code ? ' · 🏷 ' + L.code : '') + ')'
          : L.kind === 'finger' ? 'اثر انگشت («' + L.name + '»)'
          : L.kind === 'device' ? 'دستگاه اعتمادشده («' + L.name + '»)' : 'با رمز') + ' · IP ' + L.ip);
      }
      await tgReply(lines.join('\n'));
      return true;
    }
    case '/revoke': {
      const yes = /^(yes|بله|آره|اره)$/i.test(arg.trim());
      if (!yes) {
        await tgReply('⚠️ این کار همهٔ نشست‌های فعال سایت را باطل می‌کند و کاربر باید دوباره وارد شود.\nبرای تأیید بنویس: /revoke yes\n\nبرای اخراج فقط یک نشست، بدون فاصله بنویس: /revoke1004 (شناسه را از کارت ورود یا /sessions بگیر)');
        return true;
      }
      revokeAllSessions();   /* tokens issued before now are rejected server-side */
      await tgReply('🔐 همهٔ نشست‌ها باطل شد (سطح سرور). ورود بعدی فقط با رمز یا درخواست جدید ممکن است.');
      return true;
    }
    case '/title': {
      const t = sanitizeTitle(arg);
      if (!t) { await tgReply('❌ استفاده: /title عنوان-جدید\nمثال: /title Panda Chat'); return true; }
      state.siteTitle = t;
      saveData();
      broadcastSafe({ type: 'title', title: t });
      await tgReply('✅ عنوان سایت «' + t + '» شد — در صفحهٔ ورود، تب مرورگر و نام برنامه اعمال می‌شود.');
      return true;
    }
    default:
      await tgReply('دستور ناشناخته. /help را امتحان کن.');
      return true;
  }
}

async function applyTgPhoto(fileId) {
  const { buf, mime } = await tgDownload(fileId, 8);
  if (buf.length > 3 * 1024 * 1024) throw new Error('عکس خیلی بزرگ است');
  state.tgPhotoBuf = buf;
  state.tgPhotoMime = mime && mime.startsWith('image/') ? mime : 'image/jpeg';
  state.tgPersona.photo = '__tgphoto__';
  saveData();
  personaChanged('tg');
}

/* ---------------- v24 GIF repo scraping (Tenor server-rendered pages) ----------------
   Each SSR <picture> block carries: mp4 srcset (small, ideal for chat),
   a .gif <img> fallback and a human alt description. We parse those into
   {u: gifUrl, m: mp4Url, t: title}. Empty query = trending (homepage). */
const gifSearchCache = new Map();   // key -> {t, items}
const GIF_RES = /<picture><source type="video\/mp4" srcset="(https:\/\/media\d?\.tenor\.com\/[A-Za-z0-9_-]+\/[A-Za-z0-9_.%-]+\.mp4)[^"]*">[\s\S]{0,600}?<img src="(https:\/\/media\d?\.tenor\.com\/[A-Za-z0-9_-]+\/[A-Za-z0-9_.%-]+\.gif)"[^>]*?alt="([^"]*)"/g;
function gifScrape(html) {
  const items = [], seen = new Set();
  let m;
  GIF_RES.lastIndex = 0;
  while ((m = GIF_RES.exec(html)) && items.length < 60) {
    const key = m[1].split('/')[3];
    if (seen.has(key)) continue;
    seen.add(key);
    items.push({ u: m[2], m: m[1], t: String(m[3] || '').replace(/&amp;/g, '&').replace(/&quot;/g, '"').slice(0, 90) });
  }
  return items;
}
async function gifSearch(q, page) {
  const key = q + '|' + page;
  const c = gifSearchCache.get(key);
  if (c && Date.now() - c.t < 600000) return c.items;
  const p = q
    ? '/search/' + encodeURIComponent(q.toLowerCase().replace(/\s+/g, '-')).replace(/%2F/gi, '') + '-gifs' + (page > 1 ? '?page=' + page : '')
    : '/';
  const r = await fetch('https://tenor.com' + p, {
    headers: { 'User-Agent': GIF_UA, 'Accept': 'text/html,application/xhtml+xml', 'Accept-Language': 'en-US,en;q=0.9' },
    signal: AbortSignal.timeout(12000),
  });
  if (!r.ok) throw new Error('tenor ' + r.status);
  const items = gifScrape(await r.text());
  if (!items.length && q) throw new Error('tenor: no results');
  gifSearchCache.set(key, { t: Date.now(), items });
  if (gifSearchCache.size > 80) gifSearchCache.delete(gifSearchCache.keys().next().value);
  return items;
}

/* v17 — keep Telegram in sync with deletions made on the site.
   Telegram Bot API rule: a bot can delete a message in a private chat only
   within 48 hours of it being sent — older attempts fail with 400 and are
   ignored on purpose. */
function tgDeleteMirror(mid) {
  if (!state.adminId || !mid) return;
  if (TEST_MODE && !TG_TOKEN) { recordTgDelete(mid); return; }
  tgEnqueue(() => tgCall('deleteMessage', { chat_id: state.adminId, message_id: mid }).catch(() => {}));
}

/* v30 — explicit edit/delete notices to the admin bot chat.
   The mirrored TG copy is still edited/deleted in place (v17/v19 behavior);
   this ADDS a small human-visible notice so the admin KNOWS it happened.
   Rate-capped to avoid flooding on bulk wipes. */
let edNotifyWin = Date.now(), edNotifyCount = 0;
function editDeleteNotice(kind, name, count) {
  try {
    const now = Date.now();
    if (now - edNotifyWin > 60000) { edNotifyWin = now; edNotifyCount = 0; }
    if (++edNotifyCount > 15) return;                      /* anti-spam cap */
    if (!state.adminId) return;
    const who = String(name || '').replace(/[\u0000-\u001f<>]/g, ' ').trim().slice(0, 40) || 'کاربر';
    const n = Number(count) > 1 ? ' (' + faNum(Number(count)) + ' پیام)' : '';
    const txt = kind === 'edit'
      ? '✏️ ' + who + ' پیامی را ویرایش کرد'
      : '🗑 ' + who + ' پیامی را حذف کرد' + n;
    if (TEST_MODE && !TG_TOKEN) { lastTgOut.push({ method: 'sendMessage', payload: { chat_id: state.adminId, text: txt } }); return; }
    tgEnqueue(() => tgCall('sendMessage', { chat_id: state.adminId, text: txt }).catch(() => {}));
  } catch {}
}

/* record a finished mirror (site msg id -> TG message_id); if the site message
   was deleted while the mirror was still in flight, remove it from TG again */
const sentTgMidRev = new Map();    // v18: telegram message_id -> site msg id (for /who reply)
function mirrorSet(mid, tgMid) {
  if (!mid || !tgMid) return;
  if (messages.some(x => x.id === mid)) { sentTgMid.set(mid, tgMid); sentTgMidRev.set(tgMid, mid); }
  else tgDeleteMirror(tgMid);          /* deleted mid-flight — undo the mirror */
}

const TG_DELETE_GAP_MS = 35;    /* ≈20 msg/s — well under Telegram limits */
let wipeTgBusy = false;
function wipeTgSync(mids) {
  if (!state.adminId || wipeTgBusy || !mids.length) return;
  const list = mids.slice(-600);              /* older-than-48h ones just fail silently */
  wipeTgBusy = true;
  (async () => {
    try {
      for (const mid of list) {
        tgDeleteMirror(mid);
        await new Promise(r => setTimeout(r, TEST_MODE ? 2 : TG_DELETE_GAP_MS));
      }
    } catch {} finally { wipeTgBusy = false; }
  })();
}

function wipeSite() {
  /* v17: remember every mirrored TG message so the telegram chat is cleaned too */
  const tgMids = [];
  for (const m of messages) { const tgm = sentTgMid.get(m.id) || recvToTg.get(m.id); if (tgm) tgMids.push(tgm); }
  messages.length = 0;
  blobs.clear();
  tgMapRecv.clear();
  sentTgMid.clear();
  sentTgMidRev.clear();
  recvToTg.clear();
  broadcastSafe({ type: 'wipe' });
  if (tgMids.length) wipeTgSync(tgMids);
}

async function handleMessage(msg) {
  if (!msg.chat || msg.chat.type !== 'private') return;
  const uid = String(msg.from && msg.from.id || '');
  if (!state.adminId) {
    state.adminId = uid;
    state.adminName = [msg.from.first_name, msg.from.last_name].filter(Boolean).join(' ') || msg.from.username || '';
    saveData();
    log('telegram admin bound:', uid, state.adminName);
    await tgReply(helpText());
    presenceTick();
    return;
  }
  if (uid !== String(state.adminId)) {
    await tgEnqueue(() => tgCall('sendMessage', {
      chat_id: uid, text: '🔒 این گفتگوی خصوصی ادمین است.',
    })).catch(() => {});
    return;
  }
  touchLastSeen('tg');   /* v29: the admin acted — surface it as last-seen on the site */

  try {
    if (msg.text && msg.text.startsWith('/')) {
      await handleCommand(msg, msg.text.trim());
      return;
    }
    if (msg.photo) {
      if (pendingPfp.has('x')) {
        pendingPfp.delete('x');
        try {
          const fileId = msg.photo[Math.min(msg.photo.length - 1, 2)].file_id;
          await applyTgPhoto(fileId);
          await tgReply('✅ عکس پروفایل آپدیت شد.');
        } catch (e) { await tgReply('❌ ' + e.message); }
        return;
      }
      await bridgeInMedia('photo', msg.photo[msg.photo.length - 1].file_id, msg);
      return;
    }
    if (msg.sticker)   { await bridgeInMedia('sticker', msg.sticker.file_id, msg); return; }
    if (msg.animation) { await bridgeInMedia('animation', msg.animation.file_id, msg); return; }
    if (msg.video_note){ await bridgeInMedia('video_note', msg.video_note.file_id, msg, { round: true }); return; }
    if (msg.video)     { await bridgeInMedia('video', msg.video.file_id, msg); return; }
    if (msg.voice)     { await bridgeInMedia('voice', msg.voice.file_id, msg); return; }
    if (msg.audio)     { await bridgeInMedia('audio', msg.audio.file_id, msg); return; }
    if (msg.document)  {
      if ((msg.document.file_size || 0) > 20 * 1024 * 1024) {
        await tgReply('⚠️ فایل‌های بزرگ‌تر از ۲۰ مگابایت قابل انتقال نیستند.');
        return;
      }
      await bridgeInMedia('document', msg.document.file_id, msg);
      return;
    }
    if (typeof msg.text === 'string' && msg.text.length) {
      await bridgeInText(msg.text.slice(0, 4096), msg);
      return;
    }
    if (msg.location || msg.contact) {
      await tgReply('ℹ️ این نوع پیام پشتیبانی نمی‌شود.');
      return;
    }
  } catch (e) {
    log('handleMessage err:', e.message);
    try { await tgReply('⚠️ خطا در پردازش: ' + e.message.slice(0, 120)); } catch {}
  }
}

/* ------------------------- outbound mirror (site -> TG) ------------------------- */
function tgResolveReplyFor(meta) {
  // target was a site-originated msg that we already mirrored OR a TG msg received before
  if (meta && meta.rt) {
    if (sentTgMid.has(meta.rt)) return sentTgMid.get(meta.rt);
    if (recvToTg.has(meta.rt)) return recvToTg.get(meta.rt);
  }
  return undefined;
}

async function mirrorText(mid, text, meta, merged) {
  const replyTo = await tgResolveReplyFor(meta);
  const res = await tgEnqueue(() => tgCall('sendMessage', {
    chat_id: state.adminId,
    text: String(text).slice(0, 1024),
    reply_to_message_id: replyTo,
    allow_sending_without_reply: true,
  }));
  mirrorSet(mid, res.message_id);   /* v17: tracks deletion while in flight too */
  /* v19: a merged TG message holds several site texts — its edit would
     corrupt the others, so it is recorded as not-editable */
  if (merged && res.message_id) {
    tgMergedMids.add(res.message_id);
    if (tgMergedMids.size > 1000) tgMergedMids.clear();
  }
  return res;
}

async function mirrorMedia(kind, mimeName, mime, buf, mid, meta, cap) {
  let okMid = null;
  const replyTo = await tgResolveReplyFor(meta);
  /* v26: give mirrored files a real extension — TG then renders them right
     even on the document fallback (was: nameless «sticker-xxx» files) */
  const extForMime = (m) =>
    /gif/i.test(m) ? '.gif' : /mp4/i.test(m) ? '.mp4' : /webm/i.test(m) ? '.webm'
    : /webp/i.test(m) ? '.webp' : /png/i.test(m) ? '.png' : /jpe?g/i.test(m) ? '.jpg'
    : /ogg|opus/i.test(m) ? '.ogg' : /mpeg|mp3|mp4-audio/i.test(m) ? '.mp3'
    : /wav/i.test(m) ? '.wav' : /pdf/i.test(m) ? '.pdf' : '';
  const fname = String(mimeName || 'file').replace(/[\\/]/g, '-').slice(0, 60)
    + (/\.[a-z0-9]{2,5}$/i.test(String(mimeName || '')) ? '' : (extForMime(mime) || '.bin'));
  const fn = (f, extra) => {
    const form = new FormData();
    form.append('chat_id', String(state.adminId));
    if (replyTo) { form.append('reply_to_message_id', String(replyTo)); form.append('allow_sending_without_reply', 'true'); }
    /* v24: media caption rides along (never for stickers — TG has no sticker captions) */
    if (cap && kind !== 'sticker') form.append('caption', String(cap).slice(0, 1000));
    for (const [k, v] of Object.entries(extra || {})) form.append(k, String(v));
    form.append(f, new Blob([buf]), fname);
    return form;
  };
  const send = (method, form) => tgEnqueue(() => tgCall(method, form, true));

  try {
    switch (kind) {
      case 'image': {
        try { okMid = (await send('sendPhoto', fn('photo', {}))).message_id; }
        catch { okMid = (await send('sendDocument', fn('document', {}))).message_id; }
        break;
      }
      case 'video': {
        try { okMid = (await send('sendVideo', fn('video', { supports_streaming: 'true' }))).message_id; }
        catch { okMid = (await send('sendDocument', fn('document', {}))).message_id; }
        break;
      }
      case 'voice': {
        const ogg = /ogg|opus/i.test(mime || '');
        if (ogg) {
          try { okMid = (await send('sendVoice', fn('voice', {}))).message_id; break; } catch {}
        }
        try { okMid = (await send('sendAudio', fn('audio', { title: mimeName || 'ویس سایت' }))).message_id; }
        catch { okMid = (await send('sendDocument', fn('document', {}))).message_id; }
        break;
      }
      case 'audio': {
        try { okMid = (await send('sendAudio', fn('audio', { title: mimeName || 'آهنگ' }))).message_id; }
        catch { okMid = (await send('sendDocument', fn('document', {}))).message_id; }
        break;
      }
      case 'sticker': {
        /* v18: webp stickers go as real stickers in TG.
           v26: animated stickers (webm/mp4 from TG-origin re-shares) are NOT
           valid TG stickers — they went out as nameless documents before;
           now they ride sendAnimation and loop like real media */
        if (/^video\/(webm|mp4)/i.test(mime || '')) {
          try { okMid = (await send('sendAnimation', fn('animation', {}))).message_id; } catch {}
        }
        if (!okMid) {
          try { okMid = (await send('sendSticker', fn('sticker', {}))).message_id; }
          catch { okMid = (await send('sendDocument', fn('document', {}))).message_id; }
        }
        break;
      }
      case 'gif': {
        /* v26: tenor mp4 / .gif were falling through to `default` and leaving
           the bot as anonymous 115-KB files — they are animations now */
        try { okMid = (await send('sendAnimation', fn('animation', {}))).message_id; }
        catch { okMid = (await send('sendDocument', fn('document', {}))).message_id; }
        break;
      }
      default:
        okMid = (await send('sendDocument', fn('document', {}))).message_id;
    }
    mirrorSet(mid, okMid);          /* v17 */
  } catch (e) {
    throw e;
  }
}

/* ---------------- v18 anti-spam mirror aggregator (site -> TG) ----------------
   Rapid site texts are merged into ONE telegram message (1.5s burst window);
   past 20 TG sends/minute the rest collapses into a short digest line so a
   spammy site session can never flood the bot's private chat. */
const mirrorQ = [];                          // {mid, text, meta, ts}
const tgSendsMin = { n: 0, t0: Date.now() };
let digestPending = 0, lastDigestAt = 0;
const tgMergedMids = new Set();              // v19: TG mids of merged batches — edits skipped
const editSendsMin = { n: 0, t0: Date.now() };// v19: editMessageText rate cap
function tgRateTick() {
  const now = Date.now();
  if (now - tgSendsMin.t0 > 60000) { tgSendsMin.n = 0; tgSendsMin.t0 = now; }
  return (++tgSendsMin.n <= MIRROR_RATE_CAP);
}
function distinctSiteNames() {
  const names = new Set();
  for (let i = messages.length - 1, seen = 0; i >= 0 && seen < 200; i--, seen++) {
    const m = messages[i];
    if (m.meta && !m.meta.tg && (m.meta.un || m.meta.name)) names.add(m.meta.un || m.meta.name);
  }
  return names;
}
function mirrorEnqueueText(mid, text, meta) {
  mirrorQ.push({ mid, text: String(text || ''), meta: meta || {}, ts: Date.now() });
  if (mirrorQ.length > 60) mirrorQ.splice(0, mirrorQ.length - 60);
}
async function flushMirror(force) {
  if (!mirrorQ.length || !state.adminId) return;
  const now = Date.now();
  if (!force && now - mirrorQ[0].ts < MIRROR_MERGE_MS && mirrorQ.length < 8) return; // wait for burst
  const onlineSids = new Set();
  for (const c of sseClients) if (c.sessSid) onlineSids.add(c.sessSid);
  /* v20 naming rule: ONE site user online -> no name prefix (clean mirror);
     2+ online -> names shown. Fallback to recent-message names when no live
     SSE-tracked session exists (e.g. mirrors flushed right after boot). */
  const multi = onlineSids.size > 1 || (onlineSids.size === 0 && distinctSiteNames().size > 1);
  const batch = [];
  let len = 0;
  while (mirrorQ.length && batch.length < 12 && len < MIRROR_MERGE_MAX) {
    const it = mirrorQ.shift();
    batch.push(it);
    len += (multi && it.meta.name ? it.meta.name.length + 2 : 0) + it.text.length + 9;
  }
  if (!tgRateTick()) {
    digestPending += batch.length;
    maybeDigest();
    return;
  }
  const first = batch[0];
  let combined = '';
  for (const it of batch) {
    const sender = (multi && (it.meta.un || it.meta.name)) ? (it.meta.un || it.meta.name) + ': ' : '';
    const chunk = sender + it.text;
    combined = combined ? combined + '\n— — —\n' + chunk : chunk;
  }
  try {
    await mirrorText(first.mid, combined.slice(0, 3800), first.meta, batch.length > 1);
  } catch (e) { log('mirror merged fail:', e.message); }
}
function maybeDigest() {
  const now = Date.now();
  if (digestPending && now - lastDigestAt >= MIRROR_DIGEST_MIN_MS && state.adminId) {
    const n = digestPending; digestPending = 0; lastDigestAt = now;
    adminNotify('📥 ' + faNum(n) + ' پیام دیگر از سایت به‌دلیل حجم بالا در تلگرام نیامد — در خود سایت ببین.').catch(() => {});
  }
}
setInterval(() => { flushMirror(false).catch(e => log('mirror flush err:', e.message)); maybeDigest(); }, 400);

/* v18: profile card to the admin's Telegram when a site user updates it
   (Bot API has no "profile picture suggestion", so we send the photo card) */
async function notifyProfileToTg(prof) {
  if (!state.adminId) return;
  const caption = '👤 پروفایل «' + prof.name + '» در سایت آپدیت شد' + (prof.photo ? '' : ' (بدون عکس)');
  if (prof.photo) {
    const m64 = /^data:(image\/[a-z+]+);base64,(.+)$/i.exec(prof.photo);
    if (m64) {
      const buf = Buffer.from(m64[2], 'base64');
      const form = new FormData();
      form.append('chat_id', String(state.adminId));
      form.append('caption', caption);
      form.append('photo', new Blob([buf]), 'profile.jpg');
      await tgEnqueue(() => tgCall('sendPhoto', form, true)).catch(() => {});
      return;
    }
  }
  await adminNotify(caption);
}

/* ------------------------- body readers ------------------------- */
function readRaw(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = []; let n = 0;
    req.on('data', (c) => {
      n += c.length;
      if (n > limit) { reject(Object.assign(new Error('payload too large'), { code: 413 })); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}
async function readJson(req, limit) {
  const buf = await readRaw(req, limit || MAX_JSON_BODY);
  if (!buf.length) return {};
  try { return JSON.parse(buf.toString('utf8')); }
  catch { throw Object.assign(new Error('bad json'), { code: 400 }); }
}
function sendJson(res, code, obj, cacheMode) {
  const s = JSON.stringify(obj);
  const buf = Buffer.from(s);
  /* v25: cacheMode 'immutable' — content per id never changes (encrypted
     blobs / stickers / gif proxy), so slow networks can cache aggressively */
  const headers = {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': cacheMode === 'immutable' ? 'private, max-age=604800, immutable' : 'no-store',
  };
  if (buf.length > 900 && !res.headersSent && res.getHeader('Content-Encoding') !== 'gzip') {
    const ae = String(res.req && res.req.headers['accept-encoding'] || '');
    if (/\bgzip\b/.test(ae)) {
      try {
        const gz = zlib.gzipSync(buf, { level: 6 });
        if (gz.length < buf.length) {
          headers['Content-Encoding'] = 'gzip';
          headers.Vary = 'Accept-Encoding';
          res.writeHead(code, headers);
          return res.end(gz);
        }
      } catch {}
    }
  }
  headers['Content-Length'] = buf.length;
  res.writeHead(code, headers);
  res.end(buf);
}

/* ------------------------- static files ------------------------- */
const COMPRESSIBLE = new Set(['.html', '.js', '.css', '.json', '.svg', '.webmanifest', '.txt']);
const STATIC_CACHE = new Map();   // fp -> {mtimeMs,size,data,gz,etag}
function serveStatic(req, res, urlPath) {
  let p = decodeURIComponent(urlPath.split('?')[0]);
  if (p === '/' || p === '') p = '/index.html';
  const fp = path.join(PUB, path.normalize(p).replace(/^([./\\])+/, ''));
  if (!fp.startsWith(PUB)) { res.writeHead(403); res.end(); return; }

  fs.stat(fp, (err, st) => {
    const finishMiss = () => {
      /* v18: SPA fallback ONLY for genuine HTML navigations (GET, no file
         extension, Accept includes text/html) — everything else 404s */
      const accept = String(req.headers.accept || '');
      const isNav = req.method === 'GET' && !path.extname(p) && accept.includes('text/html');
      if (!isNav) {
        res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
        res.end('not found');
        return;
      }
      fs.readFile(path.join(PUB, 'index.html'), (e2, idx) => {
        if (e2) { res.writeHead(404); res.end('not found'); return; }
        res.writeHead(200, { 'Content-Type': MIME['.html'], 'Cache-Control': 'no-store' });
        res.end(idx);
      });
    };
    if (err || !st.isFile()) return finishMiss();

    const ext = path.extname(fp).toLowerCase();
    let c = STATIC_CACHE.get(fp);
    if (!c || c.mtimeMs !== st.mtimeMs || c.size !== st.size) {
      let data;
      try { data = fs.readFileSync(fp); } catch { return finishMiss(); }
      c = {
        mtimeMs: st.mtimeMs, size: st.size, data,
        gz: null,
        etag: 'W/"' + st.size.toString(36) + '-' + Math.floor(st.mtimeMs).toString(36) + '"',
      };
      STATIC_CACHE.set(fp, c);
      if (STATIC_CACHE.size > 220) { // crude cap
        const k0 = STATIC_CACHE.keys().next().value; STATIC_CACHE.delete(k0);
      }
    }
    // conditional request?
    const inm = req.headers['if-none-match'];
    if (inm && inm === c.etag) {
      res.writeHead(304, { ETag: c.etag, 'Cache-Control': isImmutableExt(ext) ? 'public, max-age=604800, immutable' : 'no-cache' });
      return res.end();
    }
    const isImmutable = isImmutableExt(ext);
    const headers = {
      'Content-Type': MIME[ext] || 'application/octet-stream',
      'Cache-Control': isImmutable ? 'public, max-age=604800, immutable' : 'no-cache',
      'X-Content-Type-Options': 'nosniff',
      ETag: c.etag,
    };
    if (/\.html$/.test(fp) || p === '/index.html' || p === '/sw.js') headers['Cache-Control'] = 'no-store';
    const ae = String(req.headers['accept-encoding'] || '');
    if (COMPRESSIBLE.has(ext) && /\bgzip\b/.test(ae)) {
      if (!c.gz) { try { c.gz = zlib.gzipSync(c.data, { level: 6 }); } catch {} }
      if (c.gz && c.gz.length < c.data.length) {
        headers['Content-Encoding'] = 'gzip'; headers.Vary = 'Accept-Encoding';
        headers['Content-Length'] = c.gz.length;
        res.writeHead(200, headers);
        return res.end(c.gz);
      }
    }
    headers['Content-Length'] = c.data.length;
    res.writeHead(200, headers);
    res.end(c.data);
  });
}
function isImmutableExt(ext) {
  return ext === '.woff2' || ext === '.woff' || ext === '.png' || ext === '.svg' || ext === '.ico';
}

/* history sanitizer for clients */
function publicMsg(m) {
  return {
    id: m.id, ts: m.ts,
    iv: m.iv || null, c: m.c || null, t: m.t || null,
    meta: m.meta || {}, reacts: m.reacts || null,
    dl: !!m.dl, ed: !!m.ed, pin: !!m.pin,
  };
}

/* ---------------- v15 login notification cards (only admin sees these) ---------------- */
function sessionCard(rec) {
  const lines = [
    '\u{1F7E2} ورود موفق به ' + state.siteTitle,
    '',
    '\u{1F511} روش: ' + (rec.kind === 'claim' ? 'بدون رمز (تایید ادمین)'
      : rec.kind === 'reentry' ? 'بازگشت خودکار (همان آی\u200cپی، تا ۳۰۰ دقیقه)'
      : rec.kind === 'finger' ? 'اثر انگشت (بدون تایپ رمز)'
      : rec.kind === 'device' ? 'دستگاه اعتمادشده (قفل شخصی)' : 'رمز عبور'),
  ];
  if (rec.name) lines.push('\u{1F464} نام: ' + rec.name);
  if (rec.kind === 'claim') lines.push('\u{1F3F7} اسم رمز: ' + (rec.code || '-'));
  lines.push(
    '\u{1F4F1} دستگاه: ' + (rec.dev || 'نامشخص'),
    '\u{1F310} IP: ' + (rec.ip || '?'),
    '\u{1F194} نشست: #' + rec.sid,
    '',
    '\u26D4 اخراج فوری فقط همین نشست:',
    '/revoke' + rec.sid,
  );
  return lines.join('\n');
}
const failNotifyAt = new Map();  // ip -> last notified ts (throttle failed-login alerts)
async function notifyFailedLogin(ip, count) {
  const now = Date.now();
  const last = failNotifyAt.get(ip) || 0;
  const urgent = count >= 50;
  if (!urgent && now - last < 5 * 60 * 1000) return;   // v18: at most one alert per 5 min per IP (anti-spam)
  if (urgent && now - last < 30 * 1000) return;
  failNotifyAt.set(ip, now);
  await adminNotify([
    urgent ? '🚨🚨 حملهٔ بروت-فورس جدی به ' + state.siteTitle : '⚠️ تلاش ناموفق برای ورود به ' + state.siteTitle,
    '🌐 IP: ' + ip,
    '🔢 تلاش‌های ناموفق اخیر: ' + faNum(count),
    '',
    urgent ? '⚠️ قفل تصاعدی فعال است. اگر خودت نبودی همین حالا: /pass رمزجدید و بعد /revoke yes' : 'اگر خودت نبودی: /pass رمزجدید و بعد /revoke yes',
  ].join('\n'));
}

/* ------------------------- router ------------------------- */
const server = http.createServer(async (req, res) => {
  const u = (req.url || '/').split('?')[0];
  const ip = clientIp(req);

  try {
    /* v20: attack-banned IP — every API call is a hard 403 (TG webhook exempt).
       The ban self-expires after 24h or is lifted early with /unban_user. */
    if (ipBlock.size && u.startsWith('/api/') && !u.startsWith('/api/tgwebhook') && ipBlock.has(ip)) {
      if (Date.now() - ipBlock.get(ip) < IPBLOCK_MS) {
        return sendJson(res, 403, { error: 'دسترسی این آی‌پی به‌دلیل درخواست‌های مشکوک موقتاً مسدود شده است' });
      }
      ipBlock.delete(ip);
    }

    /* v18: cross-origin API requests are rejected (same-origin only) */
    if (u.startsWith('/api/') && !corsAllowed(req)) {
      return sendJson(res, 403, { error: 'cross-origin not allowed' });
    }

    /* health (public — the gate reads the live title from here).
       v18: minimal info only — no bridge/admin/mode disclosure.
       v24.1: ?net=1 adds a one-shot outbound probe (fixed query, 10-min cache)
       so GIF-repo reachability can be verified from the deploy network. */
    if (u === '/api/health' && req.method === 'GET') {
      const out = { ok: true, title: state.siteTitle, version: VERSION, finger: !!(state.finger && state.finger.credId) };
      if (new URL(req.url, 'http://x').searchParams.get('net') === '1') {
        try {
          const items = await gifSearch('cat', 1);
          out.tenor = { ok: true, n: items.length };
        } catch (e) {
          out.tenor = { ok: false, err: String(e && e.message || e).slice(0, 60) };
        }
      }
      return sendJson(res, 200, out);
    }

    /* v15: dynamic webmanifest — /title changes the PWA name too (after reinstall/refresh) */
    if (u === '/manifest.webmanifest' && req.method === 'GET') {
      const t = state.siteTitle || 'Panda Chat';
      const man = {
        id: '/', name: t + ' \u2014 \u06AF\u0641\u062A\u200C\u0648\u06AF\u0648\u06CC \u0631\u0645\u0632\u0634\u062F\u0647', short_name: t,
        description: '\u06AF\u0641\u062A\u200C\u0648\u06AF\u0648\u06CC \u0631\u0645\u0632\u0634\u062F\u0647 \u0628\u0627 \u067E\u0644 \u062A\u0644\u06AF\u0631\u0627\u0645 \u2014 \u0631\u0645\u0632\u0646\u06AF\u0627\u0631\u06CC AES-256 \u0633\u0645\u062A \u0645\u0631\u0648\u0631\u06AF\u0631',
        lang: 'fa', dir: 'rtl', start_url: '/', scope: '/', display: 'standalone',
        display_override: ['standalone', 'minimal-ui'], orientation: 'portrait-primary',
        background_color: '#241a2e', theme_color: '#302340',
        categories: ['social', 'communication', 'security'],
        icons: [
          { src: '/icon-192.png?v=' + VERSION, sizes: '192x192', type: 'image/png', purpose: 'any' },
          { src: '/icon-512.png?v=' + VERSION, sizes: '512x512', type: 'image/png', purpose: 'any' },
          { src: '/icon-192.png?v=' + VERSION, sizes: '192x192', type: 'image/png', purpose: 'maskable' },
          { src: '/icon-512.png?v=' + VERSION, sizes: '512x512', type: 'image/png', purpose: 'maskable' },
        ],
      };
      res.writeHead(200, { 'Content-Type': MIME['.webmanifest'], 'Cache-Control': 'no-store' });
      return res.end(JSON.stringify(man));
    }

    /* telegram webhook receiver (public; verified via secret header)
       v18: rate-limited (120/min/IP) — guessing the random per-boot secret is
       hopeless, but now flooding the endpoint is throttled too. */
    if (u === '/api/tgwebhook' && req.method === 'POST') {
      /* v18: rate-limit FIRST — even 404s/floods can't loop freely */
      const now0 = Date.now();
      let wh = apiHits.get('wh:' + ip);
      if (!wh) { wh = { n: 0, t0: now0 }; apiHits.set('wh:' + ip, wh); }
      if (now0 - wh.t0 > 60000) { wh.n = 0; wh.t0 = now0; }
      wh.n++;
      if (wh.n > 120) return sendJson(res, 429, {});
      if (!TG_TOKEN) return sendJson(res, 404, {});
      const sec = req.headers['x-telegram-bot-api-secret-token'];
      if (!sec || !safeEq(sec, state.webhookSecret)) return sendJson(res, 401, { error: 'bad secret' });
      const upd = await readJson(req, 2 * 1024 * 1024);
      if (upd.message) handleMessage(upd.message).catch(e => log('tg handle err:', e.message));
      if (upd.callback_query) handleCallbackQuery(upd.callback_query).catch(e => log('tg cb err:', e.message));
      return sendJson(res, 200, { ok: true });
    }

    /* login — v18 dual mode:
       · {mode:'ver', verifier}  → zero-knowledge login (after migration)
       · {pw}                    → legacy login, allowed ONLY pre-migration;
         the v18 client uses its response to transparently POST /api/upgrade.
       Responses never contain key material; errors are uniform 401. */
    if (u === '/api/login' && req.method === 'POST') {
      const body = await readJson(req, 32 * 1024);
      /* v18: cheap public probe — which auth mode is active + the public KDF salt */
      if (body.mode === 'hello') {
        if (authMode() === 'new') return sendJson(res, 200, { ok: true, mode: 'new', saltA: state.auth.saltA, finger: !!(state.finger && state.finger.credId) });
        return sendJson(res, 200, { ok: true, mode: 'legacy', finger: !!(state.finger && state.finger.credId) });
      }
      if (!loginGate(ip).ok) {
        /* v20.2: tell the admin/user HOW LONG the lock lasts instead of a bare 429 */
        const o = loginFails.get(ip);
        const until = Math.max((o && o.lockUntil) || 0, globalLockUntil);
        const mins = Math.max(1, Math.ceil((until - Date.now()) / 60000));
        return sendJson(res, 429, { error: 'تلاش‌های ناموفق زیاد بود — حدود ' + faNum(Math.min(59, mins)) + ' دقیقه دیگر دوباره امتحان کنید' });
      }
      await new Promise(r => setTimeout(r, 120)); // constant-ish delay
      const mode = body.mode === 'ver' ? 'ver' : 'pw';
      let ok = false;
      if (mode === 'ver') {
        ok = verifyAuth(String(body.verifier || ''));
      } else {
        ok = authMode() === 'legacy' && passwordOk(String(body.pw || ''));
      }
      if (!ok) {
        const cnt = recordLoginFail(ip);
        log(`login FAIL (${mode}) from ${ip} (#${cnt})`);
        notifyFailedLogin(ip, cnt).catch(() => {});   // throttled brute-force alert
        return sendJson(res, 401, { error: 'unauthorized' });
      }
      loginClear(ip);
      log(`login OK (${mode}) from ${ip}`);
      noteLogin('pw', ip, sanitizeName(body.name));
      const tok = makeToken();
      const srec = registerSession(tok, 'pw', { name: body.name, ip, dev: body.dev });
      if (srec) { srec.notified = true; reentryArm(ip, body.name); adminNotify(sessionCard(srec)).catch(() => {}); }   /* v24: card + re-entry arm */
      if (mode === 'ver') {
        return sendJson(res, 200, {
          ok: true, tok, mode: 'new',
          saltA: state.auth.saltA, saltB: state.auth.saltB,
          pwWrap: state.auth.pwWrap,
          legacyWrap: state.auth.legacyWrap,
          legacyTag: state.auth.legacyTag, legacyName: state.auth.legacyName,
        });
      }
      /* legacy pw login: v17 clients keep working pre-migration;
         v18 clients see upgrade:true and immediately POST /api/upgrade */
      return sendJson(res, 200, { ok: true, tok, legacy: true, upgrade: authMode() === 'legacy', salt: KEY_SALT });
    }

    /* v18 zero-knowledge migration — one-time. The client (already logged in
       with the legacy password in THIS request chain) uploads its locally
       generated wraps + verifier; the server stores them as opaque blobs and
       PERMANENTLY deletes the plaintext password. All other sessions are
       revoked so every device re-enters through the verifier flow. */
    if (u === '/api/upgrade' && req.method === 'POST') {
      let auth = String(req.headers['authorization'] || '').replace(/^Bearer\s+/i, '');
      if (!verifyToken(auth)) return sendJson(res, 401, { error: 'unauthorized' });
      if (authMode() === 'new') return sendJson(res, 409, { error: 'already migrated' });
      const b = await readJson(req, 64 * 1024);
      if (!b || !b.pwWrap || !b.pwWrap.iv || !b.pwWrap.c || !b.verifier)
        return sendJson(res, 400, { error: 'bad payload' });
      state.auth = newAuthFrom(String(b.verifier), b.saltA, b.saltB, b.pwWrap, b.legacyWrap || null, b.legacyTag || null, b.legacyName || null);
      /* v20.1: the migrating client may include the server-assisted fallback
         wrap (CK under the fallback KEK) so approve-only entry works offline */
      if (b.vaultFallback && b.vaultFallback.iv && b.vaultFallback.c)
        state.vaultFallback = { iv: String(b.vaultFallback.iv).slice(0, 64), c: String(b.vaultFallback.c).slice(0, 512) };
      /* v21 CHANGE (owner directive — bot = full admin panel): KEEP the access
         password on record. The client just logged in with it, so the server
         already knew it; recording it keeps /password truthful and the boot
         heal consistent (it also keeps the legacyWrap rescue ladder usable,
         since recoverCKViaLegacy needs env PASSWORD). Trade-off accepted by
         the owner: the ACCESS password is admin-recoverable by design —
         message E2EE is untouched (CK still never leaves the browser). */
      const curPw = (state.password && state.password.p) || PASSWORD || '';
      if (curPw) {
        state.password = { p: curPw, h: PASSWORD_HASH || scryptHash(curPw) };
        persistRailway({ PASSWORD: curPw, PASSWORD_HASH: state.password.h }).catch(() => {});
        log('zero-knowledge migration completed; access password kept on record (v21 admin authority)');
      } else {
        purgePlaintextPassword();
        log('zero-knowledge migration completed; no plaintext was known — nothing recorded');
      }
      /* v24 FIX: revoke FIRST, then mint the replacement token — the old order
         (token before revoke) had a millisecond race where revokeAt could land
         on the new token's issue-ms and kill the very session it just issued
         (surfaced as random 401s right after the zero-knowledge migration). */
      revokeAllSessions();          // every old token dies here — new sessions need the verifier flow
      const tok2 = makeToken();
      const srec = registerSession(tok2, 'pw', { name: state.auth.legacyName, ip, dev: 'upgrade' });
      if (srec) { srec.notified = true; reentryArm(ip, state.auth.legacyName); adminNotify(sessionCard(srec)).catch(() => {}); }   /* v24 */
      return sendJson(res, 200, {
        ok: true, tok: tok2, mode: 'new',
        saltA: state.auth.saltA, saltB: state.auth.saltB,
        pwWrap: state.auth.pwWrap,
        legacyWrap: state.auth.legacyWrap,
        legacyTag: state.auth.legacyTag, legacyName: state.auth.legacyName,
      });
    }

    /* v18 password change (settings UI): client verifies old password locally
       by sending its old verifier; new verifier + new pwWrap replace the
       credential. The chat key (CK) itself never changes. */
    if (u === '/api/password' && req.method === 'POST') {
      const b = await readJson(req, 64 * 1024);
      if (!verifyAuth(String(b.oldVerifier || ''))) return sendJson(res, 403, { ok: false, error: 'رمز فعلی اشتباه است' });
      if (!b.newVerifier || !b.newPwWrap || !b.newPwWrap.iv || !b.newPwWrap.c)
        return sendJson(res, 400, { ok: false, error: 'bad payload' });
      state.auth.cred = scryptHash(String(b.newVerifier));
      state.auth.saltA = String(b.newSaltA || '').replace(/[^A-Za-z0-9+/=]/g, '').slice(0, 64) || crypto.randomBytes(16).toString('base64');
      state.auth.saltB = String(b.newSaltB || '').replace(/[^A-Za-z0-9+/=]/g, '').slice(0, 64) || crypto.randomBytes(16).toString('base64');
      state.auth.pwWrap = { iv: String(b.newPwWrap.iv).slice(0, 64), c: String(b.newPwWrap.c).slice(0, 512) };
      /* v21 CHANGE (owner directive — bot = full admin panel): the rotation now
         RECORDS the new plaintext so /password and the boot heal always stay
         truthful. Trade-off accepted by the owner: the server knows the ACCESS
         password (data.json is AES-256-GCM at rest; message E2EE is untouched —
         the CK still never leaves the browser except as opaque wraps). */
      const npw = String(b.newPw || '').slice(0, 64);
      if (npw) {
        PASSWORD = npw;
        PASSWORD_HASH = scryptHash(npw);
        state.password = { p: npw, h: PASSWORD_HASH };
        persistRailway({ PASSWORD: npw, PASSWORD_HASH }).catch(() => {});
      } else if ((state.password && state.password.p) || PASSWORD) {
        /* old cached client without newPw — keep the old behaviour (wipe the
           now-stale record) so /password never lies and heal never reverts */
        state.password = { p: '', h: state.password.h || '' };
        PASSWORD = '';
        persistRailway({ PASSWORD: '' }).catch(() => {});
        log('site-settings rotation: recorded plaintext password wiped (old client)');
      }
      saveData();
      revokeAllSessions();
      const tok3 = makeToken();
      const srec3 = registerSession(tok3, 'pw', { name: b.name, ip, dev: b.dev });
      if (srec3) srec3.notified = true;   /* v24: same device just rotated — no duplicate open notify */
      reentryArm(ip, b.name);
      return sendJson(res, 200, {
        ok: true, tok: tok3, mode: 'new',
        saltA: state.auth.saltA, saltB: state.auth.saltB,
        pwWrap: state.auth.pwWrap,
        legacyWrap: state.auth.legacyWrap,
        legacyTag: state.auth.legacyTag, legacyName: state.auth.legacyName,
      });
    }

    /* v18 SSE stream ticket (authenticated) — EventSource URLs then carry
       only this 30-second one-time ticket, never the session token */
    if (u === '/api/ticket' && req.method === 'POST') {
      let auth = String(req.headers['authorization'] || '').replace(/^Bearer\s+/i, '');
      if (!verifyToken(auth)) return sendJson(res, 401, { error: 'unauthorized' });
      return sendJson(res, 200, { ok: true, t: makeStreamTicket(auth), ttl: STREAM_TICKET_TTL });
    }

    /* v24: passwordless re-entry — the gate probes this on load. If this IP
       still has a live 300-min window (armed at the last login / refreshed
       while active), it gets a fresh session + the fallback wrap instantly. */
    if (u === '/api/reentry' && req.method === 'GET') {
      const r = reentry.get(ip);
      if (!r || r.exp < Date.now() || authMode() !== 'new' || !state.vaultFallback || ipBlock.has(ip))
        return sendJson(res, 404, { ok: false });
      if (!loginGate(ip).ok) return sendJson(res, 429, { ok: false, error: 'قفل ورود فعال است' });
      const tok = makeToken();
      loginClear(ip);
      log(`re-entry OK from ${ip}`);
      noteLogin('reentry', ip, r.name);
      const srec = registerSession(tok, 'reentry', { name: r.name, ip, dev: 're-entry' });
      if (srec) { srec.notified = true; reentryArm(ip, r.name); adminNotify(sessionCard(srec)).catch(() => {}); }
      return sendJson(res, 200, { ok: true, tok, wrap: state.vaultFallback, fk: fbKekB64(), name: r.name || '' });
    }

    /* ---- forgot-password: create access request (public, v18 hardened) ---- */
    if (u === '/api/access-request' && req.method === 'POST') {
      const body = await readJson(req, 4096).catch(() => ({}));
      const name = sanitizeName(body.name);
      if (!name || name.length < 2) return sendJson(res, 400, { error: 'نام معتبر وارد کنید' });
      /* short client-reported device fingerprint (model · os · browser) */
      const dev = String(body.dev || '').replace(/[\u0000-\u001f<>]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 60);
      /* v20: extra request context (local time · screen · language · timezone ·
         model via client-hints · visit count) — admin card only */
      const xtra = String(body.xtra || '').replace(/[\u0000-\u001f<>]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 140);
      /* v20: anti-attack — more than 3 requests in 15 min from one IP = ban.
         Counted FIRST so even spam after a denial eventually trips it. */
      const nowMs = Date.now();
      let win = reqWin.get(ip);
      if (!win || nowMs - win.t0 > REQ_WIN_MS) { win = { n: 0, t0: nowMs }; reqWin.set(ip, win); }
      win.n++;
      if (win.n > REQ_WIN_MAX) {
        ipBlock.set(ip, nowMs);
        reqWin.delete(ip);
        log('ip-ban (request flood):', ip);
        bannedNotify(name, dev, ip).catch(() => {});
        return sendJson(res, 403, { error: 'درخواست\u200cهای پشت\u200cسرهم زیاد بود — دسترسی این آی\u200cپی موقتاً مسدود شد' });
      }
      /* v19: a denied request locks this IP out of new requests for 24h
         (checked before the generic rate limiter so the message is precise) */
      const dn = deny24.get(ip);
      if (dn && Date.now() - dn < DENY_BLOCK_MS) {
        const hrs = Math.max(1, Math.ceil((dn + DENY_BLOCK_MS - Date.now()) / 3600000));
        return sendJson(res, 429, { error: 'درخواست قبلی‌ات رد شد — تا ' + faNum(hrs) + ' ساعت دیگر امکان درخواست جدید نیست' });
      }
      /* v19: one live request per IP (anti-spam) */
      const myPending = reqIpPending.get(ip);
      if (myPending && pendingReq.get(myPending) && pendingReq.get(myPending).status === 'pending') {
        return sendJson(res, 429, { error: 'درخواست قبلی‌ات هنوز در انتظار تصمیم ادمین است' });
      }
      const rl = reqRateOk(ip);
      if (!rl.ok) {
        return sendJson(res, 429, { error: 'تلاش‌ها زیاد بود — بعداً دوباره امتحان کنید' });
      }
      let livePending = 0;
      for (const r of pendingReq.values()) if (r.status === 'pending') livePending++;
      if (livePending >= REQ_MAX_OPEN) return sendJson(res, 429, { error: 'درخواست‌های باز زیاد است — کمی صبر کنید' });
      /* v19: pre-migration requests are now ALLOWED — the admin still gets the
         decision card (with a warning); the key activation simply waits until
         the vault is migrated (first password login) and a session uploads
         the wrap. The old behaviour rejected the request instantly with
         «اول یک بار با رمز وارد شوید» which felt like a dead end. */
      const id = crypto.randomBytes(16).toString('hex');   // 256-bit unguessable id
      const noBridge = !TG_TOKEN || !state.adminId;
      if (noBridge && !TEST_MODE) {
        return sendJson(res, 503, { error: 'ربات تلگرام هنوز متصل نیست — با ادمین تماس بگیرید' });
      }
      /* اسم رمز is typed by the user (optional) — sanitized for the admin card */
      const code = sanitizeCode(body.code);
      const rec = { id, name, dev, xtra, ip, code, status: 'pending', ts: Date.now(), exp: Date.now() + REQ_TTL, msgId: null, cardText: '', consumed: false };
      if (!noBridge) {
        try { await sendAccessCard(name, rec); }
        catch (e) {
          log('access card fail:', e.message);
          return sendJson(res, 502, { error: 'ارسال درخواست به ربات ناموفق بود — دوباره تلاش کنید' });
        }
      }
      pendingReq.set(id, rec);
      reqIpPending.set(ip, id);   // v19: one live request per IP
      log(`access-request ${id.slice(0, 8)}… by "${name}" from ${ip}${authMode() !== 'new' ? ' [pre-migration]' : ''}`);
      return sendJson(res, 200, arqPublic(rec));
    }

    /* ---- forgot-password: poll status (public, rate-limited) ---- */
    if (u.startsWith('/api/access-status/') && req.method === 'GET') {
      if (!statusRateOk(ip)) return sendJson(res, 429, { error: 'unauthorized' });
      const id = u.slice('/api/access-status/'.length).replace(/[^a-f0-9]/gi, '').slice(0, 64);
      const rec = pendingReq.get(id);
      if (!rec) return sendJson(res, 404, { status: 'gone' });
      return sendJson(res, 200, arqPublic(rec));
    }

    /* v18: a logged-in site session converts the ephemeral claim code into an
       opaque CK wrap (never sees the code in storage; never sends CK here) */
    if (u === '/api/claim-wrap' && req.method === 'POST') {
      let auth = String(req.headers['authorization'] || '').replace(/^Bearer\s+/i, '');
      if (!verifyToken(auth)) return sendJson(res, 401, { error: 'unauthorized' });
      const b = await readJson(req, 4096).catch(() => ({}));
      if (!claimCode || !b.wrap || !b.wrap.iv || !b.wrap.c) return sendJson(res, 404, { ok: false });
      const h = crypto.createHash('sha256').update(String(b.code || '')).digest('hex');
      if (h !== claimCode.hash) return sendJson(res, 403, { ok: false, error: 'کد نامعتبر' });
      const firstWrap = !claimCode.wrap;   // v19
      claimCode.wrap = { iv: String(b.wrap.iv).slice(0, 64), c: String(b.wrap.c).slice(0, 512) };
      if (firstWrap) {
        /* v19: the 10-minute claim window starts when the key is actually
           usable (e.g. pre-migration approvals that waited for migration) */
        claimCode.exp = Date.now() + CLAIM_TTL;
        const rec0 = pendingReq.get(claimCode.reqId);
        if (rec0 && rec0.status === 'approved') rec0.claimExp = claimCode.exp;
      }
      log('claim wrap stored for request', String(claimCode.reqId || '').slice(0, 8));
      return sendJson(res, 200, { ok: true });
    }

    /* v20.1: server-assisted fallback — a logged-in session fetches the
       fallback KEK, wraps its CK and uploads it (idempotent, done at login).
       This is what makes «approve tap alone ⇒ entry» work even when the
       admin approves from Telegram with no site tab open. */
    if (u === '/api/vault-fallback-key' && req.method === 'GET') {
      let auth = String(req.headers['authorization'] || '').replace(/^Bearer\s+/i, '');
      if (!verifyToken(auth)) return sendJson(res, 401, { error: 'unauthorized' });
      if (authMode() !== 'new') return sendJson(res, 409, { ok: false, error: 'legacy mode' });
      return sendJson(res, 200, { ok: true, k: fbKekB64() });
    }
    if (u === '/api/vault-fallback' && req.method === 'POST') {
      let auth = String(req.headers['authorization'] || '').replace(/^Bearer\s+/i, '');
      if (!verifyToken(auth)) return sendJson(res, 401, { error: 'unauthorized' });
      if (authMode() !== 'new') return sendJson(res, 409, { ok: false, error: 'legacy mode' });
      const b = await readJson(req, 4096).catch(() => ({}));
      if (!b || !b.iv || !b.c) return sendJson(res, 400, { ok: false, error: 'bad payload' });
      state.vaultFallback = { iv: String(b.iv).slice(0, 64), c: String(b.c).slice(0, 512) };
      saveData();
      /* v24: the client that armed the fallback also re-arms its 300-min
         re-entry window (carries its display name for the auto-entry card) */
      reentryArm(ip, b.name);
      log('vault fallback wrap stored (approve-only entry ready)');
      return sendJson(res, 200, { ok: true });
    }

    /* ---- forgot-password: claim approval -> session (public, one-time, code-gated) ---- */
    if (u === '/api/access-claim' && req.method === 'POST') {
      const body = await readJson(req, 4096).catch(() => ({}));
      const id = String(body.id || '').replace(/[^a-f0-9]/gi, '').slice(0, 64);
      const rec = pendingReq.get(id);
      if (!rec) return sendJson(res, 404, { ok: false, error: 'درخواست یافت نشد' });
      if (rec.status === 'denied') return sendJson(res, 403, { ok: false, status: 'denied', error: 'ادمین این درخواست را رد کرد' });
      if (rec.status !== 'approved') return sendJson(res, 409, { ok: false, status: rec.status, error: 'درخواست هنوز تایید نشده' });
      if (rec.consumed || Date.now() > (rec.claimExp || 0)) return sendJson(res, 410, { ok: false, status: 'consumed', error: 'مهلت ورود تمام شد — درخواست جدید بدهید' });
      /* v19: pre-migration vault cannot hand out the key in a zero-knowledge
         way — the claim waits until the vault is migrated */
      if (authMode() !== 'new')
        return sendJson(res, 409, { ok: false, status: 'waitup', error: 'گاوصندوق هنوز ارتقا نکرده — ادمین باید یک بار با رمز وارد شود؛ بعد از آن کد کار می‌کند' });
      /* v18: the one-time code from the Telegram card is REQUIRED; the chat
         key never travels from the server — only a wrap does.
         v20.1: if no live session sealed the wrap yet, the server-assisted
         fallback wrap (uploaded by any logged-in session at login time) lets
         the claim complete with NOTHING but the admin's approve tap. */
      const codeIn = String(body.code || '').trim().toUpperCase();
      if (!claimCode || claimCode.reqId !== id || (!claimCode.wrap && !state.vaultFallback) || Date.now() > claimCode.exp)
        return sendJson(res, 409, { ok: false, error: 'کد هنوز فعال نشده — چند لحظه بعد دوباره امتحان کنید' });
      const h = crypto.createHash('sha256').update(codeIn).digest('hex');
      if (h !== claimCode.hash) {
        recordLoginFail(ip);
        return sendJson(res, 401, { ok: false, error: 'کد اشتباه است' });
      }
      rec.consumed = true;
      const viaFallback = !claimCode.wrap && !!state.vaultFallback;
      const wrap = viaFallback ? state.vaultFallback : claimCode.wrap;
      const fk = viaFallback ? fbKekB64() : null;
      claimCode = null;                      // one-time
      log(`access-claim ${id.slice(0, 8)}… OK for "${rec.name}" from ${ip}${viaFallback ? ' [fallback]' : ''}`);
      noteLogin('claim', ip, rec.name, rec.code);
      const tok = makeToken();
      const srec = registerSession(tok, 'claim', { name: rec.name, code: rec.code, ip, dev: rec.dev });
      if (srec) { srec.notified = true; reentryArm(ip, rec.name); adminNotify(sessionCard(srec)).catch(() => {}); }   /* v24 */
      return sendJson(res, 200, {
        ok: true, tok, name: rec.name, mode: 'claim', wrap, fk,
        legacyWrap: (state.auth && state.auth.legacyWrap) || null,
        legacyTag: (state.auth && state.auth.legacyTag) || null,
        legacyName: (state.auth && state.auth.legacyName) || null,
      });
    }

    /* ---- v27 fingerprint login (public half): options + verify ----
       The gate asks for options by name, the browser signs the challenge
       with the platform key, and the server verifies the ES256 signature
       against the stored JWK before issuing a session + fallback wrap. */
    if (u === '/api/finger/auth-options' && req.method === 'POST') {
      if (ipBlock.has(ip)) return sendJson(res, 403, { error: 'forbidden' });
      if (!loginGate(ip).ok) return sendJson(res, 429, { error: 'قفل ورود فعال است' });
      const body = await readJson(req, 2048).catch(() => ({}));
      const f = state.finger;
      if (!f || !f.credId || !f.jwk) return sendJson(res, 404, { ok: false, error: 'اثر انگشتی ثبت نشده است' });
      const nl = sanitizeName(body.name).toLowerCase();
      if (nl && nl !== f.nameLower) return sendJson(res, 404, { ok: false, error: 'برای این نام اثر انگشتی ثبت نشده' });
      const chal = crypto.randomBytes(32).toString('base64url');
      fingerChal.set(chal, { phase: 'auth', nameLower: f.nameLower, exp: Date.now() + 120000 });
      return sendJson(res, 200, { ok: true, challenge: chal, rpId: reqHost(req), timeout: 60000,
        userVerification: 'required', allowCredentials: [{ type: 'public-key', id: f.credId }] });
    }
    if (u === '/api/finger/auth-verify' && req.method === 'POST') {
      if (ipBlock.has(ip)) return sendJson(res, 403, { error: 'forbidden' });
      if (!loginGate(ip).ok) return sendJson(res, 429, { error: 'قفل ورود فعال است' });
      const body = await readJson(req, 24 * 1024).catch(() => ({}));
      const f = state.finger;
      const deny = (msg) => { recordLoginFail(ip); log('finger-verify FAIL from', ip, msg || ''); return sendJson(res, 401, { ok: false, error: msg || 'تایید اثر انگشت ناموفق بود' }); };
      if (!f || !f.credId || !f.jwk) return deny('no credential');
      const rr = body.response || {};
      const cd = clientDataOf(rr.clientDataJSON);
      if (!cd || cd.type !== 'webauthn.get') return deny('bad clientData');
      const ch = fingerChal.get(String(cd.challenge || ''));
      if (!ch || ch.phase !== 'auth' || ch.exp < Date.now() || ch.nameLower !== f.nameLower) return deny('challenge');
      fingerChal.delete(String(cd.challenge));
      if (!originOk(cd, req)) return deny('origin');
      const ad = bufOf(rr.authenticatorData);
      if (!ad || ad.length < 37) return deny('authData');
      if (!ad.subarray(0, 32).equals(crypto.createHash('sha256').update(reqHost(req)).digest())) return deny('rpId');
      if (!(ad[32] & 0x01) || !(ad[32] & 0x04)) return deny('flags');            // UP + UV required
      if (!safeEq(String(body.id || ''), f.credId)) return deny('credId');
      const sig = bufOf(rr.signature);
      const cHash = crypto.createHash('sha256').update(bufOf(rr.clientDataJSON)).digest();
      let jwk = null; try { jwk = JSON.parse(f.jwk); } catch {}
      if (!sig || !sig.length || !jwk || !es256Verify(jwk, Buffer.concat([ad, cHash]), sig)) return deny('signature');
      const newCnt = ad.readUInt32BE(33);
      if (newCnt !== 0) {                          // 0 = counter unsupported (platform keys) — skip
        if (newCnt <= (f.counter || 0)) return deny('counter-clone');
        f.counter = newCnt; saveData();
      }
      if (authMode() !== 'new' || !state.vaultFallback) {
        return sendJson(res, 409, { ok: false, error: 'کلید پشتیبان آماده نیست — یک بار با رمز وارد شوید تا ورود با اثر انگشت فعال شود' });
      }
      loginClear(ip);
      const nm = f.name;
      log('finger login OK from ' + ip);
      noteLogin('finger', ip, nm);
      const tok = makeToken();
      const srec = registerSession(tok, 'finger', { name: nm, ip, dev: 'اثر انگشت' });
      if (srec) { srec.notified = true; reentryArm(ip, nm); adminNotify(sessionCard(srec)).catch(() => {}); }
      return sendJson(res, 200, { ok: true, tok, name: nm, mode: 'finger',
        wrap: state.vaultFallback, fk: fbKekB64(),
        legacyWrap: (state.auth && state.auth.legacyWrap) || null,
        legacyTag: (state.auth && state.auth.legacyTag) || null,
        legacyName: (state.auth && state.auth.legacyName) || null });
    }

    /* ---- v29 trusted-device login (public half): challenge + verify ----
       The browser proves possession of the EC private key (wrapped under
       the user's local pattern/PIN) over a single-use server nonce. */
    if (u === '/api/device/challenge' && req.method === 'POST') {
      if (ipBlock.has(ip)) return sendJson(res, 403, { error: 'forbidden' });
      if (!statusRateOk(ip)) return sendJson(res, 429, { ok: false, error: 'تلاش‌ها زیاد بود' });
      const body = await readJson(req, 2048).catch(() => ({}));
      const devId = String(body.devId || '').toLowerCase().replace(/[^a-f0-9]/g, '').slice(0, 64);
      const d = state.devices[devId];
      if (!d || d.revoked) return sendJson(res, 404, { ok: false, error: 'این دستگاه مورد اعتماد نیست' });
      const nonce = crypto.randomBytes(24).toString('base64url');
      devChal.set(nonce, { devId, exp: Date.now() + 120000 });
      return sendJson(res, 200, { ok: true, nonce, exp: Date.now() + 120000 });
    }
    if (u === '/api/device/login' && req.method === 'POST') {
      if (ipBlock.has(ip)) return sendJson(res, 403, { error: 'forbidden' });
      if (!loginGate(ip).ok) return sendJson(res, 429, { ok: false, error: 'قفل ورود فعال است' });
      const body = await readJson(req, 8192).catch(() => ({}));
      const deny = (msg) => { recordLoginFail(ip); log('device-login FAIL from', ip, msg || ''); return sendJson(res, 401, { ok: false, error: msg || 'ورود با دستگاه ناموفق بود' }); };
      const devId = String(body.devId || '').toLowerCase().replace(/[^a-f0-9]/g, '').slice(0, 64);
      const nonce = String(body.nonce || '');
      const ch = devChal.get(nonce);
      if (!ch || ch.devId !== devId || ch.exp < Date.now()) return deny('challenge');
      devChal.delete(nonce);                       // single-use
      const d = state.devices[devId];
      if (!d || d.revoked) return deny('unknown device');
      let jwk = null; try { jwk = JSON.parse(d.jwk); } catch {}
      const sig = bufOf(String(body.sig || ''));
      if (!jwk || !sig || !sig.length || !devVerify(jwk, Buffer.from(nonce, 'utf8'), sig)) return deny('signature');
      if (authMode() !== 'new' || !state.vaultFallback) {
        return sendJson(res, 409, { ok: false, error: 'کلید پشتیبان آماده نیست — یک بار با رمز وارد شوید' });
      }
      loginClear(ip);
      d.lastUsedAt = Date.now();
      d.ip = ip;
      saveData();
      log('device login OK from ' + ip + ' (' + (d.label || devId.slice(0, 8)) + ')');
      noteLogin('device', ip, d.name);
      const tok = makeToken();
      const srec = registerSession(tok, 'device', { name: d.name, ip, dev: d.label || 'دستگاه اعتمادشده' });
      if (srec) { srec.notified = true; reentryArm(ip, d.name); adminNotify(sessionCard(srec)).catch(() => {}); }
      touchLastSeen(d.nameLower || d.name);
      return sendJson(res, 200, { ok: true, tok, name: d.name, mode: 'device',
        wrap: state.vaultFallback, fk: fbKekB64(),
        legacyWrap: (state.auth && state.auth.legacyWrap) || null,
        legacyTag: (state.auth && state.auth.legacyTag) || null,
        legacyName: (state.auth && state.auth.legacyName) || null });
    }

    /* ---- test-only hooks (never enabled in production) ---- */
    if (TEST_MODE && u.startsWith('/__test/')) {
      if (req.method !== 'POST') return sendJson(res, 405, {});
      const b = await readJson(req, 2048).catch(() => ({}));
      if (u === '/__test/arq-decide') {
        const r2 = await resolveRequest(String(b.id || ''), b.decision === 'a' ? 'a' : 'd');
        return sendJson(res, r2.code === 'ok' ? 200 : 409, { ok: r2.code });
      }
      if (u === '/__test/arq-state') {
        const rec = pendingReq.get(String(b.id || ''));
        if (!rec) return sendJson(res, 404, { ok: false });
        return sendJson(res, 200, { id: rec.id, status: rec.status, consumed: !!rec.consumed, exp: rec.exp, name: rec.name, dev: rec.dev || '', ip: rec.ip, code: rec.code || '' });
      }
      if (u === '/__test/card') {
        const rec0 = { id: 'x', dev: String(b.dev || ''), ip: '1.2.3.4', code: sanitizeCode(b.code) };
        return sendJson(res, 200, { ok: true, code: rec0.code, txt: accessCardText(String(b.name || 'تست'), rec0) });
      }
      if (u === '/__test/tokcheck') {
        return sendJson(res, 200, { ok: true, valid: verifyToken(String(b.tok || '')) });
      }
      if (u === '/__test/disk') {
        diskForcePct = Math.max(0, Math.min(99, Number(b.pct) || 0));
        diskAlertAt = 0;
        const d = diskUsage();
        return sendJson(res, 200, { ok: true, forced: diskForcePct > 0, pct: d ? Math.round(d.pct * 10) / 10 : -1 });
      }
      if (u === '/__test/monitor') {
        const sum = await monitorTick('test');
        return sendJson(res, 200, { ok: true, action: sum.action, pct: Math.round(sum.pct * 10) / 10, replies: lastBotReplies.slice() });
      }
      if (u === '/__test/cmd') {
        lastBotReplies.length = 0;
        const fakeMsg = { message_id: 1, from: { id: Number(state.adminId) || 0, first_name: 'test' }, chat: { id: Number(state.adminId) || 0, type: 'private' } };
        await handleCommand(fakeMsg, String(b.text || '/help'));
        return sendJson(res, 200, { ok: true, replies: lastBotReplies.slice() });
      }
      if (u === '/__test/replies') {   // v15: read bot notifications (login cards etc.)
        return sendJson(res, 200, { ok: true, replies: lastBotReplies.slice() });
      }
      if (u === '/__test/sessions') {  // v15: inspect the registry
        return sendJson(res, 200, { ok: true, sidSeq: state.sidSeq, sessions: sessionsForDisk() });
      }
      if (u === '/__test/tgdel') {     // v17: deleteMessage calls captured
        return sendJson(res, 200, { ok: true, deletes: lastTgDeletes.slice() });
      }
      if (u === '/__test/tgout') {     // v18: every outgoing TG call captured
        return sendJson(res, 200, { ok: true, out: lastTgOut.slice() });
      }
      if (u === '/__test/flush') {     // v18: force the mirror aggregator to flush
        await flushMirror(true);
        return sendJson(res, 200, { ok: true, queued: mirrorQ.length });
      }
      if (u === '/__test/claim-code') { // v18: inspect the pending claim code (tests only)
        return sendJson(res, 200, { ok: true, has: !!claimCode, code: claimCode ? claimCode.code : null, wrap: !!(claimCode && claimCode.wrap), reqId: claimCode ? claimCode.reqId : null });
      }
      if (u === '/__test/backup') {    // v19: trigger the encrypted backup (test hook)
        const r = await runBackup('تستی');
        return sendJson(res, 200, Object.assign({ ok: true }, r));
      }
      if (u === '/__test/merged-mids') { // v19: inspect merged TG mids (tests only)
        return sendJson(res, 200, { ok: true, merged: [...tgMergedMids] });
      }
      if (u === '/__test/tgcache') {   // v20: seed the disk cache (tests only)
        const fid = String(b.fid || '');
        const buf = Buffer.from(String(b.b64 || ''), 'base64');
        if (!fid || !buf.length) return sendJson(res, 400, { ok: false });
        if (b.ram) tgFiles.set(rid(), { fid, buf, mime: String(b.mime || 'image/webp'), size: buf.length, lastTouch: Date.now() });
        else tgDiskPut(fid, buf, String(b.mime || 'image/webp'));
        return sendJson(res, 200, { ok: true, bytes: tgDiskBytes });
      }
      if (u === '/__test/ipblock') {   // v20: inspect/manipulate the ban list (tests only)
        if (b.add) ipBlock.set(String(b.add), Date.now());
        if (b.del) ipBlock.delete(String(b.del));
        return sendJson(res, 200, { ok: true, blocked: [...ipBlock.keys()] });
      }
      if (u === '/__test/arq-pending') { // v18: list pending access-request ids (tests only)
        return sendJson(res, 200, { ok: true, pending: [...pendingReq.values()].filter(r => r.status === 'pending').map(r => ({ id: r.id, name: r.name })) });
      }
      if (u === '/__test/finger-decide') {   // v27: admin decision without Telegram (tests only)
        const r2 = resolveFingerRequest(String(b.id || ''), b.decision === 'a' ? 'a' : 'd');
        return sendJson(res, r2.code === 'ok' ? 200 : 409, { ok: r2.code });
      }
      if (u === '/__test/finger-state') {    // v27: inspect fingerprint state (tests only)
        return sendJson(res, 200, { ok: true, finger: state.finger, reqs: [...fingerReqs.values()].map(r => ({ id: r.id, name: r.name, status: r.status })) });
      }
      if (u === '/__test/dev-decide') {      // v29: admin decision on a device request (tests only)
        const r2 = resolveDeviceRequest(String(b.id || ''), b.decision === 'a' ? 'a' : 'd');
        return sendJson(res, r2.code === 'ok' ? 200 : 409, { ok: r2.code });
      }
      if (u === '/__test/dev-state') {       // v29: inspect device state (tests only)
        return sendJson(res, 200, { ok: true,
          devices: Object.fromEntries(Object.entries(state.devices).map(([k, d]) => [k, { label: d.label, name: d.name, revoked: !!d.revoked, lastUsedAt: d.lastUsedAt }])),
          reqs: [...devReqs.values()].map(r => ({ id: r.id, devId: r.devId, label: r.label, status: r.status })) });
      }
      if (u === '/__test/authstate') {  // v18: migration state (v21: + rekey info)
        return sendJson(res, 200, { ok: true, mode: authMode(), hasPw: !!PASSWORD, hasLegacyWrap: !!(state.auth && state.auth.legacyWrap),
          hasFallback: !!(state.vaultFallback && state.vaultFallback.iv && state.vaultFallback.c),
          recorded: (state.password && state.password.p) || '', credSynced: (state.password && state.password.p) ? credMatches(state.password.p) : null });
      }
      if (u === '/__test/mirror') {    // v17: simulate a finished site→TG mirror (any mid — mirrors production semantics incl. in-flight races)
        const mid = String(b.mid || '');
        const tgm = Number(b.tgm) || 777;
        mirrorSet(mid, tgm);
        return sendJson(res, 200, { ok: true, tgm });
      }
      if (u === '/__test/bridge') {    // v17: simulate an incoming TG text message
        const tgm = Number(b.tgm) || 555;
        await bridgeInText(String(b.text || 'سلام از تلگرام'), {
          message_id: tgm, text: String(b.text || ''),
          from: { id: Number(state.adminId) || 0, first_name: 'test' },
          chat: { id: Number(state.adminId) || 0, type: 'private' },
        });
        const last = messages[messages.length - 1];
        return sendJson(res, 200, { ok: true, id: last.id, tgm });
      }
      return sendJson(res, 404, {});
    }

    /* authenticated API */
    if (u.startsWith('/api/')) {
      if (tooManyApi(req)) return sendJson(res, 429, { error: 'rate limited' });
      let auth = String(req.headers['authorization'] || '').replace(/^Bearer\s+/i, '');
      if (!auth && u === '/api/stream') {
        // EventSource cannot set headers — it carries a 30s ONE-TIME ticket (?tk=)
        try {
          const qs = new URL(req.url, 'http://x').searchParams;
          const rec = streamTickets.get(String(qs.get('tk') || ''));
          if (rec && rec.exp > Date.now()) { streamTickets.delete(String(qs.get('tk'))); auth = rec.tok; }
        } catch {}
      }
      if (!verifyToken(auth)) return sendJson(res, 401, { error: 'unauthorized' });

      /* --- stream --- */
      if (u === '/api/stream' && req.method === 'GET') {
        res.writeHead(200, {
          'Content-Type': 'text/event-stream; charset=utf-8',
          'Cache-Control': 'no-cache, no-transform',
          Connection: 'keep-alive',
          'X-Accel-Buffering': 'no',
        });
        res.write('retry: 1500\n');
        res.write(':ok\n\n');
        sseWrite(res, Object.assign({ type: 'presence' }, presenceCount()));
        sseWrite(res, { type: 'title', title: state.siteTitle });   // v15: live brand
        res.sessSid = (sessions.get(auth) || {}).sid || null;       // v15: who is this?
        sseClients.add(res);
        /* v20: session lifecycle — open notify on the first live connection */
        try {
          const srec0 = sessions.get(auth);
          const devQ = new URL(req.url, 'http://x').searchParams.get('dev') || '';
          sessOpen(srec0, devQ, req.headers['user-agent']);
          reentryArm(ip, srec0 && srec0.name);   /* v24: keep the re-entry window alive while active */
          touchLastSeen(srec0 && srec0.name);    /* v29: opening the chat counts as activity */
        } catch {}
        /* v19: a pending claim that still lacks its CK wrap is re-pushed to
           every fresh session — e.g. the first password login (migration)
           arrives AFTER the admin approved a pre-migration request, and this
           is what lets that very session seal the key for the waiter */
        if (claimCode && !claimCode.wrap && claimCode.exp > Date.now()) {
          sseWrite(res, { type: 'claim', id: claimCode.reqId, code: claimCode.code, exp: claimCode.exp });
        }
        presenceTick();
        /* v25: 15s heartbeat — Iranian mobile CGNAT idle-out can be as low as
           30-45s; a beat every 15s keeps the mapping alive and detects silent
           socket death within one watchdog cycle */
        const keepalive = setInterval(() => { try { res.write(':hb\n\n'); } catch {} }, 15000);
        req.on('close', () => {
          clearInterval(keepalive);
          sseClients.delete(res);
          if (res.sessSid) sessClose(res.sessSid, '');   // v20: maybe «نشست بسته شد»
          presenceTick();
        });
        return;
      }

      /* --- history --- */
      if (u === '/api/history' && req.method === 'GET') {
        return sendJson(res, 200, {
          messages: messages.slice(-HISTORY_WINDOW).map(publicMsg),
          presence: presenceCount(),
          sitePersona: state.sitePersona,
          tgPersona: state.tgPersona,
          profiles: state.profiles,          // v18: per display-name profiles
          legacySender: state.legacySender,  // v18: label of pre-v18 site messages
          lastSeen: { tg: state.lastSeen.tg || 0, users: state.lastSeen.users },  // v29
        });
      }

      /* --- send message --- */
      if (u === '/api/send' && req.method === 'POST') {
        const body = await readJson(req, MAX_JSON_BODY);
        const iv = String(body.iv || ''), c = String(body.c || '');
        const meta = body.meta && typeof body.meta === 'object' ? body.meta : {};
        if (!iv || !c || c.length > MAX_RAW_BLOB / 2) return sendJson(res, 400, { error: 'bad payload' });
        const kind = ['text', 'image', 'video', 'voice', 'audio', 'sticker', 'gif', 'file'].includes(meta.k) ? meta.k : 'text';
        if (kind !== 'text' && meta.blob && typeof meta.blob === 'string' && !blobs.has(meta.blob)) {
          /* cloud stickers live on disk, not in the RAM blob map */
          if (!(String(meta.blob).startsWith('stk:') && stkFind(String(meta.blob).slice(4)))) {
            return sendJson(res, 400, { error: 'blob missing — upload first' });
          }
        }
        const cleanMeta = {
          k: kind,
          from: typeof meta.from === 'string' ? meta.from.slice(0, 24) : '',
          un: sanitizeName(meta.un),                        // v18: sender display name
          name: sanitizeName(meta.name),
          rt: typeof meta.rt === 'string' ? meta.rt.slice(0, 48) : undefined,
          blob: typeof meta.blob === 'string' ? meta.blob.slice(0, 64) : undefined,
          w: Number(meta.w) > 0 ? Number(meta.w) : undefined,
          h: Number(meta.h) > 0 ? Number(meta.h) : undefined,
          dur: Number(meta.dur) > 0 ? Math.round(Number(meta.dur)) : undefined,
          size: Number(meta.size) > 0 ? Number(meta.size) : undefined,
        };
        const m = pushMessage({
          id: nextId(), ts: Date.now(),
          iv: iv.slice(0, 64), c: c.slice(0, MAX_TEXT_CIPHER * 8),
          t: null, meta: cleanMeta, reacts: null,
        });
        broadcast({ type: 'msg', m: publicMsg(m) });
        touchLastSeen(cleanMeta.un || cleanMeta.name, (sessions.get(auth) || {}).name);   // v29
        return sendJson(res, 200, { id: m.id, ts: m.ts });
      }

      /* --- encrypted blob store (POST or PUT) --- */
      if (u === '/api/blob' && (req.method === 'POST' || req.method === 'PUT')) {
        const buf = await readRaw(req, MAX_RAW_BLOB).catch(e => { throw Object.assign(e, { code: e.code || 400 }); });
        let env;
        try { env = JSON.parse(buf.toString('utf8')); } catch { return sendJson(res, 400, { error: 'bad envelope' }); }
        if (!env.iv || !env.c || !env.miv || !env.mc) return sendJson(res, 400, { error: 'envelope fields missing' });
        const bid = rid();
        blobs.set(bid, {
          env: { iv: env.iv.slice(0, 32), c: String(env.c).slice(0, MAX_RAW_BLOB), miv: env.miv.slice(0, 32), mc: String(env.mc).slice(0, 512) },
          size: Math.ceil(String(env.c).length * 0.75),
          lastTouch: Date.now(),
        });
        budgetEvict(blobs, 'blob');
        return sendJson(res, 200, { bid });
      }

      if (u.startsWith('/api/blob/') && req.method === 'GET') {
        const bid = u.slice('/api/blob/'.length);
        const rec = blobs.get(bid);
        if (!rec) return sendJson(res, 404, { error: 'not found' });
        rec.lastTouch = Date.now();
        /* v25: immutable — one bid = one encrypted envelope, forever */
        return sendJson(res, 200, rec.env, 'immutable');
      }

      /* --- cloud stickers (client-encrypted, persisted on disk, all devices) --- */
      if (u === '/api/stickers' && req.method === 'GET') {
        return sendJson(res, 200, { stickers });
      }

      /* --- v24: global GIF search (Tenor SSR scrape, 10-min cache) --- */
      if (u === '/api/gifsearch' && req.method === 'GET') {
        const qs = new URL(req.url, 'http://x').searchParams;
        const q = String(qs.get('q') || '').trim().slice(0, 60);
        const page = Math.max(1, Math.min(9, Number(qs.get('page')) || 1));
        try {
          const items = await gifSearch(q, page);
          return sendJson(res, 200, { ok: true, items });
        } catch (e) {
          log('gifsearch fail:', e.message);
          return sendJson(res, 502, { ok: false, error: 'مخزن گیف موقتاً در دسترس نیست — کمی بعد دوباره امتحان کن' });
        }
      }
      /* --- v24: GIF bytes proxy (allowlist tenor CDN, disk-cached) --- */
      if (u === '/api/giffetch' && req.method === 'GET') {
        const qs = new URL(req.url, 'http://x').searchParams;
        const target = String(qs.get('u') || '');
        if (!GIF_HOST_OK.test(target)) return sendJson(res, 400, { error: 'bad url' });
        const ck = 'gif:' + crypto.createHash('sha1').update(target).digest('hex');
        const mime0 = /\.mp4(\?|$)/.test(target) ? 'video/mp4' : 'image/gif';
        const serve = (buf) => {
          /* v25: immutable — tenor media URLs are write-once; 7-day client
             cache turns every repeat preview into a zero-byte hit */
          res.writeHead(200, { 'Content-Type': mime0, 'Cache-Control': 'private, max-age=604800, immutable', 'Content-Length': buf.length });
          res.end(buf);
        };
        const dk = tgDiskGet(ck);
        if (dk) return serve(dk.buf);
        const up = await fetch(target, { headers: { 'User-Agent': GIF_UA }, signal: AbortSignal.timeout(20000) });
        if (!up.ok) return sendJson(res, 502, { error: 'gif fetch failed' });
        const buf = Buffer.from(await up.arrayBuffer());
        if (buf.length > GIF_FETCH_CAP) return sendJson(res, 413, { error: 'gif too large' });
        tgDiskPut(ck, buf, mime0);
        return serve(buf);
      }

      if (u === '/api/stickers' && (req.method === 'PUT' || req.method === 'POST')) {
        const buf = await readRaw(req, 8 * 1024 * 1024).catch(e => { throw Object.assign(e, { code: e.code || 400 }); });
        let env;
        try { env = JSON.parse(buf.toString('utf8')); } catch { return sendJson(res, 400, { error: 'bad envelope' }); }
        if (!env.iv || !env.c || !env.miv || !env.mc) return sendJson(res, 400, { error: 'envelope fields missing' });
        if (env.kind !== undefined && env.kind !== 'sticker' && env.kind !== 'gif') return sendJson(res, 400, { error: 'bad kind' });
        if (stickers.length >= 120) return sendJson(res, 409, { error: 'sticker storage full' });
        const kind = env.kind === 'gif' ? 'gif' : 'sticker';
        const id = rid();
        fs.mkdirSync(path.join(DATA_DIR, 'stickers'), { recursive: true });
        fs.writeFileSync(path.join(DATA_DIR, 'stickers', id + '.json'), JSON.stringify({
          iv: String(env.iv).slice(0, 32), c: String(env.c).slice(0, 12 * 1024 * 1024),
          miv: String(env.miv).slice(0, 32), mc: String(env.mc).slice(0, 512),
        }));
        const srec = { id, kind, ts: Date.now(), size: Math.ceil(String(env.c).length * 0.75) };
        stickers.push(srec); saveStickers();
        return sendJson(res, 200, { id, ts: srec.ts });
      }
      if (u.startsWith('/api/stickers/') && req.method === 'GET') {
        const id = u.slice('/api/stickers/'.length);
        if (!stkFind(id)) return sendJson(res, 404, { error: 'not found' });
        try {
          /* v25: immutable — sticker ids are write-once */
          return sendJson(res, 200, JSON.parse(fs.readFileSync(path.join(DATA_DIR, 'stickers', id + '.json'), 'utf8')), 'immutable');
        } catch { return sendJson(res, 404, { error: 'not found' }); }
      }
      if (u.startsWith('/api/stickers/') && req.method === 'DELETE') {
        const id = u.slice('/api/stickers/'.length);
        const i = stickers.findIndex(s => s.id === id);
        if (i < 0) return sendJson(res, 404, { error: 'not found' });
        stickers.splice(i, 1); saveStickers();
        try { fs.unlinkSync(path.join(DATA_DIR, 'stickers', id + '.json')); } catch {}
        return sendJson(res, 200, { ok: true });
      }

      /* --- telegram file passthrough --- */
      if (u.startsWith('/api/tgfile/') && req.method === 'GET') {
        const fid = u.slice('/api/tgfile/'.length);
        let rec = tgFiles.get(fid);
        if (!rec) {
          const dk = tgDiskGet(fid);   // v20: L2 disk fallback
          if (dk) { rec = { buf: dk.buf, mime: dk.mime, size: dk.size, lastTouch: Date.now() }; tgFiles.set(rid(), Object.assign({ fid }, rec)); }
        }
        if (!rec) return sendJson(res, 404, { error: 'not found' });
        rec.lastTouch = Date.now();
        res.writeHead(200, {
          'Content-Type': rec.mime || 'application/octet-stream',
          /* v25: immutable — telegram file_ids resolve to the same bytes; 7-day
             cache spares slow networks on every sticker/gif re-render */
          'Cache-Control': 'private, max-age=604800, immutable',
          'Content-Length': rec.buf.length,
        });
        return res.end(rec.buf);
      }

      /* --- mirror text to telegram — v18: through the anti-spam aggregator ---
         v19: {edit:true} edits the already-mirrored TG copy in place instead
         of posting a duplicate (skipped for merged batches / over rate cap) */
      if (u === '/api/mirror/text' && req.method === 'POST') {
        const body = await readJson(req);
        const mid = String(body.mid || '');
        const msg = messages.find(x => x.id === mid);
        const text = String(body.text || '').slice(0, 1100);
        if (!state.adminId) return sendJson(res, 502, { ok: false, error: 'bot not linked yet' });
        if (!msg && !text) return sendJson(res, 400, { error: 'nothing to mirror' });
        if (body.edit) {
          const tgm = sentTgMid.get(mid);
          if (tgm && tgMergedMids.has(tgm)) return sendJson(res, 200, { ok: true, edited: false, skipped: 'merged' });
          if (tgm) {
            const now = Date.now();
            if (now - editSendsMin.t0 > 60000) { editSendsMin.n = 0; editSendsMin.t0 = now; }
            if (editSendsMin.n >= 15) return sendJson(res, 200, { ok: true, edited: false, skipped: 'rate' });
            editSendsMin.n++;
            tgEnqueue(() => tgCall('editMessageText', {
              chat_id: state.adminId, message_id: tgm, text: text.slice(0, 1024),
            })).catch((e) => log('mirror edit fail:', e.message));
            return sendJson(res, 200, { ok: true, edited: true });
          }
          /* no mirror mapping (digest/merged-tail/offline) — queue as fresh */
        }
        mirrorEnqueueText(mid, text, (msg && msg.meta) || {});
        deliveredFlag(mid);
        return sendJson(res, 200, { ok: true, queued: true });
      }

      /* --- mirror media bytes straight to telegram (never stored) --- */
      /* --- v26 instant lock: the site lock button must end the session NOW —
             revoke this exact token AND disarm the 300-min same-IP re-entry
             window, so a reload lands on the gate instead of silently
             sliding back in --- */
      if (u === '/api/lock' && req.method === 'POST') {
        const rec = sessions.get(auth);
        if (rec) { rec.revoked = true; saveData(); }
        reentry.delete(ip);
        const mySid = rec && rec.sid;
        log('instant lock: session #' + (mySid || '?') + ' revoked, re-entry disarmed for ' + ip);
        return sendJson(res, 200, { ok: true });
      }

      /* ---- v27 fingerprint: status / request / register / remove (authed) ---- */
      if (u === '/api/finger/status' && req.method === 'GET') {
        const rec0 = sessions.get(auth);
        const nl = sanitizeName(rec0 && rec0.name).toLowerCase();
        const f = state.finger;
        let st = 'none';
        if (f && f.nameLower === nl) st = f.credId ? 'active' : 'await-reg';
        else if (f && f.credId) st = 'other-active';
        if (st === 'none') {
          for (const r of fingerReqs.values()) if (r.status === 'pending' && r.nameLower === nl) { st = 'pending'; break; }
        }
        return sendJson(res, 200, { ok: true, mode: authMode(), state: st, name: (f && f.name) || '', created: (f && f.created) || 0 });
      }
      if (u === '/api/finger/req' && req.method === 'POST') {
        const rec0 = sessions.get(auth);
        const nm = sanitizeName(rec0 && rec0.name);
        if (!nm || nm.length < 2) return sendJson(res, 400, { ok: false, error: 'اول یک نام نمایشی در تنظیمات ذخیره کنید، بعد درخواست بدهید' });
        if (authMode() !== 'new') return sendJson(res, 409, { ok: false, error: 'گاوصندوق هنوز به حالت صفر-دانش ارتقا نیافته است' });
        const nl = nm.toLowerCase();
        if (state.finger && state.finger.credId) return sendJson(res, 409, { ok: false, state: 'active', error: 'ورود با اثر انگشت همین حالا فعال است' });
        if (state.finger && state.finger.nameLower === nl && !state.finger.credId)
          return sendJson(res, 200, { ok: true, state: 'await-reg' });   // approved earlier — go register
        for (const r of fingerReqs.values()) if (r.status === 'pending' && r.nameLower === nl)
          return sendJson(res, 429, { ok: false, error: 'درخواست قبلی‌ات هنوز در انتظار تایید ادمین است' });
        const rl = reqRateOk(ip);
        if (!rl.ok) return sendJson(res, 429, { ok: false, error: 'تلاش‌ها زیاد بود — بعداً دوباره امتحان کنید' });
        const dn = deny24.get(ip);
        if (dn && Date.now() - dn < DENY_BLOCK_MS) return sendJson(res, 429, { ok: false, error: 'درخواست قبلی‌ات رد شد — بعداً امتحان کنید' });
        const noBridge = !TG_TOKEN || !state.adminId;
        if (noBridge && !TEST_MODE) return sendJson(res, 503, { ok: false, error: 'ربات تلگرام هنوز متصل نیست — با ادمین تماس بگیرید' });
        const id = crypto.randomBytes(16).toString('hex');
        const dev = String(req.headers['user-agent'] || '').replace(/[\u0000-\u001f<>]/g, ' ').trim().slice(0, 60);
        const rec = { id, name: nm, nameLower: nl, dev, ip, status: 'pending', ts: Date.now(), exp: Date.now() + REQ_TTL, msgId: null, cardText: '' };
        if (!noBridge) {
          try { await sendFingerCard(rec); }
          catch (e) { log('finger card fail:', e.message); return sendJson(res, 502, { ok: false, error: 'ارسال درخواست به ربات ناموفق بود — دوباره تلاش کنید' }); }
        }
        fingerReqs.set(id, rec);
        log('finger-request ' + id.slice(0, 8) + '… by "' + nm + '" from ' + ip);
        return sendJson(res, 200, { ok: true, id, exp: rec.exp, state: 'pending' });
      }
      if (u === '/api/finger/reg-options' && req.method === 'GET') {
        const rec0 = sessions.get(auth);
        const nl = sanitizeName(rec0 && rec0.name).toLowerCase();
        const f = state.finger;
        if (!f || f.nameLower !== nl || f.credId) return sendJson(res, 409, { ok: false, error: 'ثبت اثر انگشت در دسترس نیست — اول ادمین باید تایید کند' });
        const chal = crypto.randomBytes(32).toString('base64url');
        fingerChal.set(chal, { phase: 'reg', nameLower: nl, exp: Date.now() + 120000 });
        return sendJson(res, 200, {
          ok: true,
          rp: { id: reqHost(req), name: state.siteTitle || 'Panda Chat' },
          user: { id: f.uh, name: f.name, displayName: f.name },
          challenge: chal,
          pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
          timeout: 60000,
          attestation: 'none',
          authenticatorSelection: { authenticatorAttachment: 'platform', residentKey: 'preferred', userVerification: 'required' },
        });
      }
      if (u === '/api/finger/reg-verify' && req.method === 'POST') {
        const rec0 = sessions.get(auth);
        const nl = sanitizeName(rec0 && rec0.name).toLowerCase();
        const f = state.finger;
        if (!f || f.nameLower !== nl || f.credId) return sendJson(res, 409, { ok: false, error: 'ثبت اثر انگشت در دسترس نیست' });
        const body = await readJson(req, 48 * 1024).catch(() => ({}));
        const rr = body.response || {};
        const cd = clientDataOf(rr.clientDataJSON);
        if (!cd || cd.type !== 'webauthn.create') return sendJson(res, 401, { ok: false, error: 'ثبت ناموفق بود' });
        const ch = fingerChal.get(String(cd.challenge || ''));
        if (!ch || ch.phase !== 'reg' || ch.exp < Date.now() || ch.nameLower !== nl)
          return sendJson(res, 401, { ok: false, error: 'چالش منقضی شد — دوباره تلاش کنید' });
        fingerChal.delete(String(cd.challenge));
        if (!originOk(cd, req)) return sendJson(res, 401, { ok: false, error: 'origin نامعتبر' });
        let att = null, ad = null;
        try {
          att = cborParse(bufOf(rr.attestationObject));
          ad = Buffer.from(att.authData);
        } catch {}
        if (!att || !ad || ad.length < 37) return sendJson(res, 401, { ok: false, error: 'attestation نامعتبر است' });
        if (!ad.subarray(0, 32).equals(crypto.createHash('sha256').update(reqHost(req)).digest()))
          return sendJson(res, 401, { ok: false, error: 'rpId نامعتبر است' });
        if (!(ad[32] & 0x01) || !(ad[32] & 0x04) || !(ad[32] & 0x40))
          return sendJson(res, 401, { ok: false, error: 'فلگ‌های احراز کافی نیست (نیاز به UP+UV+AT)' });
        let parsed = null;
        try { parsed = webauthnCred(ad); } catch {}
        if (!parsed || !parsed.credId || !parsed.credId.length || !parsed.cose)
          return sendJson(res, 401, { ok: false, error: 'credential نامعتبر است' });
        let jwk = null;
        try { jwk = coseToJwk(parsed.cose); }
        catch { return sendJson(res, 401, { ok: false, error: 'الگوریتم کلید پشتیبانی نمی‌شود (فقط ES256/P-256)' }); }
        if (att.fmt === 'packed' && att.attStmt && att.attStmt.alg === -7) {
          /* self-attestation or x5c — verify when the material is present */
          try {
            const cHash = crypto.createHash('sha256').update(bufOf(rr.clientDataJSON)).digest();
            const signed = Buffer.concat([ad, cHash]);
            let okSig = false;
            if (Array.isArray(att.attStmt.x5c) && att.attStmt.x5c.length) {
              const key = crypto.createPublicKey({ key: Buffer.from(att.attStmt.x5c[0]), format: 'der', type: 'spki' });
              okSig = crypto.verify('sha256', signed, key, Buffer.from(att.attStmt.sig));
            } else {
              okSig = es256Verify(jwk, signed, Buffer.from(att.attStmt.sig));
            }
            if (!okSig) return sendJson(res, 401, { ok: false, error: 'امضای attestation نامعتبر است' });
          } catch { return sendJson(res, 401, { ok: false, error: 'attestation قابل بررسی نبود' }); }
        } else if (att.fmt !== 'none') {
          return sendJson(res, 401, { ok: false, error: 'فرمت attestation پشتیبانی نمی‌شود: ' + String(att.fmt).slice(0, 20) });
        }
        f.credId = parsed.credId.toString('base64url');
        f.jwk = JSON.stringify(jwk);
        f.counter = ad.readUInt32BE(33);
        f.regAt = Date.now();
        saveData();
        log('finger registered for "' + f.name + '" (cred ' + f.credId.slice(0, 8) + '…)');
        adminNotify('\u{1F590} اثر انگشت برای «' + f.name + '» ثبت شد — از این به بعد می‌تواند بدون رمز وارد شود.').catch(() => {});
        broadcastSafe({ type: 'finger', status: 'registered', name: f.name });
        return sendJson(res, 200, { ok: true });
      }
      if (u === '/api/finger/remove' && req.method === 'POST') {
        const rec0 = sessions.get(auth);
        const nl = sanitizeName(rec0 && rec0.name).toLowerCase();
        const f = state.finger;
        if (!f) return sendJson(res, 404, { ok: false });
        if (nl && f.nameLower !== nl) return sendJson(res, 403, { ok: false, error: 'این اثر انگشت متعلق به نام دیگری است' });
        state.finger = null;
        saveData();
        log('finger removed (by "' + (rec0 && rec0.name) + '")');
        adminNotify('\u{1F5D1} ورود با اثر انگشت غیرفعال شد (توسط «' + (rec0 && rec0.name || '?') + '»).').catch(() => {});
        broadcastSafe({ type: 'finger', status: 'removed' });
        return sendJson(res, 200, { ok: true });
      }

      /* ---- v29 trusted device (authed): request / status / list / revoke ---- */
      if (u === '/api/device/req' && req.method === 'POST') {
        const rec0 = sessions.get(auth);
        const nm = sanitizeName(rec0 && rec0.name);
        if (!nm || nm.length < 2) return sendJson(res, 400, { ok: false, error: 'اول یک نام نمایشی در تنظیمات ذخیره کنید، بعد درخواست بدهید' });
        if (authMode() !== 'new') return sendJson(res, 409, { ok: false, error: 'گاوصندوق هنوز به حالت صفر-دانش ارتقا نیافته است' });
        if (!state.vaultFallback) return sendJson(res, 409, { ok: false, error: 'کلید پشتیبان آماده نیست — یک بار با رمز وارد شوید' });
        const body = await readJson(req, 16 * 1024).catch(() => ({}));
        const devId = String(body.devId || '').toLowerCase().replace(/[^a-f0-9]/g, '').slice(0, 64);
        if (devId.length < 16) return sendJson(res, 400, { ok: false, error: 'شناسه دستگاه نامعتبر است' });
        let pub = null;
        try { pub = JSON.parse(String(body.pub || '')); } catch {}
        if (!pub || pub.kty !== 'EC' || pub.crv !== 'P-256' || !pub.x || !pub.y)
          return sendJson(res, 400, { ok: false, error: 'کلید عمومی نامعتبر است' });
        const pubJwk = JSON.stringify({ kty: 'EC', crv: 'P-256', x: String(pub.x).slice(0, 64), y: String(pub.y).slice(0, 64) });
        const label = devLabel(body.label) || 'دستگاه نامشخص';
        const existing = state.devices[devId];
        if (existing && !existing.revoked && existing.jwk === pubJwk)
          return sendJson(res, 200, { ok: true, state: 'approved' });   // idempotent
        if (existing && existing.revoked)
          return sendJson(res, 403, { ok: false, state: 'revoked', error: 'اعتماد این دستگاه توسط ادمین لغو شده است' });
        for (const r of devReqs.values()) if (r.status === 'pending' && r.devId === devId)
          return sendJson(res, 200, { ok: true, state: 'pending', id: r.id, exp: r.exp });
        const nl = nm.toLowerCase();
        const rl = reqRateOk(ip);
        if (!rl.ok) return sendJson(res, 429, { ok: false, error: 'تلاش‌ها زیاد بود — بعداً دوباره امتحان کنید' });
        const dn = deny24.get(ip);
        if (dn && Date.now() - dn < DENY_BLOCK_MS) return sendJson(res, 429, { ok: false, error: 'درخواست قبلی‌ات رد شد — بعداً امتحان کنید' });
        const noBridge = !TG_TOKEN || !state.adminId;
        if (noBridge && !TEST_MODE) return sendJson(res, 503, { ok: false, error: 'ربات تلگرام هنوز متصل نیست — با ادمین تماس بگیرید' });
        const id = crypto.randomBytes(16).toString('hex');
        const ua = devLabel(req.headers['user-agent']);
        const rec = { id, devId, pub: pubJwk, label, name: nm, nameLower: nl, ua, ip,
                      status: 'pending', ts: Date.now(), exp: Date.now() + REQ_TTL, msgId: null, cardText: '' };
        if (!noBridge) {
          try { await sendDeviceCard(rec); }
          catch (e) { log('device card fail:', e.message); return sendJson(res, 502, { ok: false, error: 'ارسال درخواست به ربات ناموفق بود — دوباره تلاش کنید' }); }
        }
        devReqs.set(id, rec);
        log('device-request ' + id.slice(0, 8) + '… "' + label + '" by "' + nm + '" from ' + ip);
        return sendJson(res, 200, { ok: true, id, exp: rec.exp, state: 'pending' });
      }
      if (u === '/api/device/status' && req.method === 'POST') {
        const body = await readJson(req, 2048).catch(() => ({}));
        const devId = String(body.devId || '').toLowerCase().replace(/[^a-f0-9]/g, '').slice(0, 64);
        if (!devId) return sendJson(res, 400, { ok: false, error: 'devId لازم است' });
        const d = state.devices[devId];
        if (d && !d.revoked) return sendJson(res, 200, { ok: true, state: 'approved', name: d.name, label: d.label, lastUsedAt: d.lastUsedAt, createdAt: d.createdAt });
        if (d && d.revoked) return sendJson(res, 200, { ok: true, state: 'revoked' });
        for (const r of devReqs.values()) {
          if (r.devId !== devId) continue;
          if (r.status === 'pending') return sendJson(res, 200, { ok: true, state: 'pending', exp: r.exp });
          if (r.status === 'denied' && Date.now() - r.ts < DENY_BLOCK_MS) return sendJson(res, 200, { ok: true, state: 'denied' });
        }
        return sendJson(res, 200, { ok: true, state: 'none' });
      }
      if (u === '/api/devices' && req.method === 'GET') {
        const list = Object.values(state.devices)
          .sort((a, b) => (b.approvedAt || 0) - (a.approvedAt || 0))
          .map(d => ({ devId: d.id, label: d.label, name: d.name, ip: d.ip,
                       createdAt: d.createdAt, approvedAt: d.approvedAt, lastUsedAt: d.lastUsedAt, revoked: !!d.revoked }));
        const pend = [...devReqs.values()].filter(r => r.status === 'pending')
          .map(r => ({ id: r.id, label: r.label, name: r.name, exp: r.exp }));
        return sendJson(res, 200, { ok: true, devices: list, pending: pend });
      }
      if (u === '/api/device/revoke' && req.method === 'POST') {
        const body = await readJson(req, 2048).catch(() => ({}));
        const devId = String(body.devId || '').toLowerCase().replace(/[^a-f0-9]/g, '').slice(0, 64);
        const d = state.devices[devId];
        if (!d) return sendJson(res, 404, { ok: false, error: 'دستگاه پیدا نشد' });
        delete state.devices[devId];
        saveData();
        log('device revoked:', devId.slice(0, 8), 'by "' + (sessions.get(auth) || {}).name + '"');
        adminNotify('\u{1F5D1} اعتماد دستگاه «' + (d.label || '?') + '» لغو شد — دیگر بدون رمز وارد نمی\u200cشود.').catch(() => {});
        broadcastSafe({ type: 'device', devId, status: 'revoked' });
        return sendJson(res, 200, { ok: true });
      }

      if (u === '/api/mirror/media' && req.method === 'POST') {
        if (!state.adminId) return sendJson(res, 502, { ok: false, error: 'bot not linked yet' });
        const mid = String(req.headers['x-vault-mid'] || '');
        const kind = String(req.headers['x-vault-kind'] || 'file');
        const mime = String(req.headers['x-vault-mime'] || 'application/octet-stream');
        const nm = decodeURIComponent(String(req.headers['x-vault-name'] || 'file'));
        const buf = await readRaw(req, MAX_MIRROR_MEDIA);
        if (!buf.length) return sendJson(res, 400, { error: 'empty body' });
        if (!tgRateTick()) {
          /* anti-spam: over the per-minute cap the media is NOT mirrored;
             a digest line tells the admin how much stayed in the site */
          digestPending++;
          return sendJson(res, 200, { ok: true, skipped: 'rate' });
        }
        const src = messages.find(x => x.id === mid);
        const cap = decodeURIComponent(String(req.headers['x-vault-cap'] || '')).replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, 1000);
        await mirrorMedia(kind, nm.replace(/[\/\\]/g, '-'), mime, buf, mid, (src && src.meta) || {}, cap);
        deliveredFlag(mid);
        return sendJson(res, 200, { ok: true });
      }

      /* --- chat action (typing/record indicator in TG) --- */
      if (u === '/api/typing' && req.method === 'POST') {
        const body = await readJson(req).catch(() => ({}));
        const act = body.rec ? 'record_voice' : 'typing';
        if (state.adminId) tgEnqueue(() => tgCall('sendChatAction', { chat_id: state.adminId, action: act })).catch(() => {});
        return sendJson(res, 200, { ok: true });
      }

      /* --- edit / delete / react / seen --- */
      if (u === '/api/edit' && req.method === 'POST') {
        const b = await readJson(req);
        const m = messages.find(x => x.id === String(b.id));
        if (!m) return sendJson(res, 404, { error: 'not found' });
        m.iv = String(b.iv || m.iv || '').slice(0, 64);
        m.c = String(b.c || '').slice(0, MAX_TEXT_CIPHER * 8);
        m.ed = true;
        broadcast({ type: 'edit', id: m.id, iv: m.iv, c: m.c });
        /* v30: notify the admin bot chat about the edit (mirror copy is updated by the client call) */
        {
          const _s = sessions.get(String(req.headers['authorization'] || '').replace(/^Bearer\s+/i, ''));
          editDeleteNotice('edit', (_s && _s.name) || (m.meta && m.meta.un) || '', 1);
        }
        return sendJson(res, 200, { ok: true });
      }
      if (u === '/api/delete' && req.method === 'POST') {
        const b = await readJson(req);
        const ids = Array.isArray(b.ids) ? b.ids.map(String).slice(0, 100) : [];
        const tgMids = [];
        for (const id of ids) {
          const i = messages.findIndex(x => x.id === id);
          if (i >= 0) { const mm = messages[i]; if (mm.meta && mm.meta.blob) blobs.delete(mm.meta.blob); messages.splice(i, 1); }
          /* v17: the telegram mirror (or the original TG message) dies here too */
          const tgm = sentTgMid.get(id) || recvToTg.get(id);
          if (tgm) { sentTgMid.delete(id); recvToTg.delete(id); tgMapRecv.delete(tgm); tgMids.push(tgm); }
        }
        if (ids.length) {
          broadcast({ type: 'del', ids });
          /* v30: notify the admin bot chat about the deletion */
          const _s = sessions.get(String(req.headers['authorization'] || '').replace(/^Bearer\s+/i, ''));
          editDeleteNotice('del', (_s && _s.name) || 'کاربر', ids.length);
        }
        for (const tgm of tgMids) tgDeleteMirror(tgm);
        return sendJson(res, 200, { ok: true, tgSynced: tgMids.length });
      }
      if (u === '/api/pin' && req.method === 'POST') {   /* v30: pin important messages */
        const b = await readJson(req);
        const m = messages.find(x => x.id === String(b.id));
        if (!m) return sendJson(res, 404, { error: 'not found' });
        m.pin = !!b.pin;
        broadcast({ type: 'pin', id: m.id, pin: m.pin });
        return sendJson(res, 200, { ok: true, pin: m.pin });
      }
      if (u === '/api/sessions' && req.method === 'GET') {   /* v30: session management panel */
        const _tok = String(req.headers['authorization'] || '').replace(/^Bearer\s+/i, '');
        const cur = sessions.get(_tok);
        const list = [...sessions.values()].sort((a, b2) => b2.t - a.t).slice(0, 20).map(r => ({
          sid: r.sid, t: r.t, exp: r.exp, kind: r.kind, name: r.name || '', code: r.code || '',
          ip: r.ip || '', dev: r.dev || '', revoked: !!r.revoked,
          live: !!(sessLive.get(r.sid) && sessLive.get(r.sid).conns > 0),
          current: !!(cur && cur.sid === r.sid),
        }));
        return sendJson(res, 200, { sessions: list });
      }
      if (u === '/api/sessions/revoke' && req.method === 'POST') {   /* v30: remote logout */
        const b = await readJson(req);
        const r = revokeSession(String(b.sid || ''));
        if (!r) return sendJson(res, 404, { error: 'not found' });
        if (!r.already && state.adminId) {
          adminNotify('🚪 نشست #' + r.rec.sid + ' از پنل سایت اخراج شد' + (r.rec.name ? ' · ' + r.rec.name : '')).catch(() => {});
        }
        return sendJson(res, 200, { ok: true, already: !!r.already });
      }
      if (u === '/api/react' && req.method === 'POST') {
        const b = await readJson(req);
        const m = messages.find(x => x.id === String(b.id));
        if (!m) return sendJson(res, 404, { error: 'not found' });
        m.reacts = b.clear ? null : { iv: String(b.riv || '').slice(0, 64), c: String(b.rc || '=').slice(0, 512) };
        broadcast({ type: 'react', id: m.id, reacts: m.reacts });
        return sendJson(res, 200, { ok: true });
      }
      if (u === '/api/seen' && req.method === 'POST') {
        await readJson(req).catch(() => ({}));
        broadcast({ type: 'seen', by: 'site' });
        return sendJson(res, 200, { ok: true });
      }

      /* --- wipe all --- */
      if (u === '/api/history' && req.method === 'DELETE') {
        wipeSite();
        return sendJson(res, 200, { ok: true });
      }

      /* --- personas (v18: per display-name profiles) --- */
      if (u === '/api/profile' && req.method === 'GET') {
        return sendJson(res, 200, { profiles: state.profiles, tg: state.tgPersona, site: state.sitePersona });
      }

      /* telegram-side persona photo bytes (auth via fetch) */
      if (u === '/api/tgphoto' && req.method === 'GET') {
        if (!state.tgPhotoBuf) return sendJson(res, 404, { error: 'no photo' });
        res.writeHead(200, {
          'Content-Type': state.tgPhotoMime || 'image/jpeg',
          'Cache-Control': 'private, max-age=300',
          'Content-Length': state.tgPhotoBuf.length,
        });
        return res.end(state.tgPhotoBuf);
      }
      if (u === '/api/profile' && req.method === 'POST') {
        const b = await readJson(req, 3 * 1024 * 1024);
        const name = sanitizeName(b.name);
        if (!name) return sendJson(res, 400, { error: 'نام نامعتبر است' });
        const key = name.toLowerCase();
        const prof = state.profiles[key] || { name, photo: '', updated: 0 };
        prof.name = name;
        if (typeof b.photo === 'string') {
          if (b.photo && !/^data:image\/(png|jpe?g|webp|gif);base64,/i.test(b.photo))
            return sendJson(res, 400, { error: 'photo must be a data-url image' });
          if (b.photo && b.photo.length > 1.5 * 1024 * 1024)
            return sendJson(res, 413, { error: 'photo too large (max 1.5MB)' });
          prof.photo = b.photo || '';
        }
        prof.updated = Date.now();
        state.profiles[key] = prof;
        saveData();
        broadcastSafe({ type: 'profile', side: 'user', name: prof.name, photo: prof.photo || '' });
        notifyProfileToTg(prof).catch(() => {});   // v18: photo card to the bot PV
        return sendJson(res, 200, { ok: true, profile: prof });
      }

      /* --- password rotate from settings UI (v18 verifier-based) --- */
      if (u === '/api/admin/revoke' && req.method === 'POST') {
        const b = await readJson(req, 64 * 1024);
        /* legacy mode: verify old password directly (pre-migration only) */
        if (authMode() === 'legacy') {
          const oldPw = String(b.oldPw || '');
          if (!passwordOk(oldPw)) return sendJson(res, 403, { ok: false, error: 'رمز فعلی اشتباه است' });
          if (!b.newPw) return sendJson(res, 200, { ok: true, rotated: false });
          try {
            const pr = await setPassword(String(b.newPw));
            revokeAllSessions();
            return sendJson(res, 200, { ok: true, rotated: true, persisted: !!pr.persisted, legacy: true });
          } catch (e) {
            return sendJson(res, 400, { ok: false, error: e.message });
          }
        }
        /* new mode is served by POST /api/password (verifier-based) */
        return sendJson(res, 409, { ok: false, error: 'use /api/password' });
      }

      return sendJson(res, 404, { error: 'unknown api' });
    }

    /* static & fallback */
    return serveStatic(req, res, req.url);

  } catch (e) {
    const code = e.code && Number.isInteger(e.code) ? e.code : 500;
    log('router err:', e.message, '<-', req.method, req.url);
    try { sendJson(res, code, { error: e.message }); } catch {}
  }
});

/* ------------------------- boot ------------------------- */
loadData();
if (!KEY_SALT) { console.error('FATAL: KEY_SALT env missing'); process.exit(1); }
if (!PASSWORD && !PASSWORD_HASH && !state.auth) { console.error('FATAL: no credential (PASSWORD/PASSWORD_HASH env or migrated auth)'); process.exit(1); }
const healedPw = healStoredPassword();   // v21 boot auto-heal (owner notified after listen)

server.keepAliveTimeout = 65000;
server.headersTimeout = 66000;
server.on('connection', (sock) => { sock.setNoDelay(true); sock.setKeepAlive(true, 30000); });

server.listen(PORT, () => {
  log(`vault-chat ${VERSION} listening on port ${PORT}`);
  log(`bridge ${TG_TOKEN ? 'armed' : 'OFF'} · admin ${state.adminId || 'unset (first /start binds)'}`);
  setupWebhook();
  syncBotCommands();
  /* v21: if a recorded password never made it into the login credential (the
     pre-v21 bug), heal it now and tell the owner access is restored */
  if (healedPw && healedPw.healed) {
    const rk = healedPw.rekeyed;
    setTimeout(() => adminNotify('🔧 تعمیر خودکار ' + VERSION + ': رمزی که قبلاً با /pass ست کرده بودی روی ورود سایت اعمال نشده بود — اکنون فعال شد.\n✅ همین حالا می‌توانی با همان رمز وارد شوی.'
      + (rk ? '\n♻️ کلید چت بازسازی و پیام‌های قبلی پاک شدند (رمز قدیمی قابل بازیابی نبود).' : '\n🔐 کلید چت دست‌نخورده ماند.')
      + '\nℹ️ دیدن رمز فعلی: /password').catch(() => {}), 4000);
  }
  /* first disk check shortly after boot, then every DISK_CHECK_MS */
  setTimeout(() => monitorTick('boot').catch(e => log('disk monitor err:', e.message)), 90 * 1000);
});

process.on('SIGTERM', () => {
  log('SIGTERM — flushing state & closing');
  try { flushSave(); } catch {}
  try { server.close(() => process.exit(0)); } catch {}
  setTimeout(() => process.exit(0), 2500);
});
process.on('SIGINT', () => {
  log('SIGINT — flushing state & closing');
  try { flushSave(); } catch {}
  try { server.close(() => process.exit(0)); } catch {}
  setTimeout(() => process.exit(0), 2500);
});
/* v29: an uncaught exception leaves the process in an unknown state —
   log it, force the pending data.json write to disk, then exit so the
   supervisor (Railway) restarts us clean instead of serving a broken state. */
process.on('uncaughtException', (e) => {
  log('uncaught:', (e && e.stack) || e);
  try { flushSave(); } catch {}
  setTimeout(() => process.exit(1), 50);
});
process.on('unhandledRejection', (e) => { log('unhandled:', e && e.stack || e); });
