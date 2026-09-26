'use strict';
/* ============================================================
 * Panda Chat v18 client — Telegram-like E2EE chat (ZERO-KNOWLEDGE)
 * The chat key (CK) is generated in the browser and NEVER sent to
 * the server. Login sends only a PBKDF2 verifier; the CK arrives
 * wrapped (AES-GCM under a password-derived KEK the server never
 * sees). Old pre-v18 history is decrypted with a legacy key that
 * comes wrapped UNDER the CK. Multi-user: bubbles go right/left by
 * a per-session tag; sender name rides along (Telegram-group style).
 * Telegram-side is plaintext (tagged). Fresh IV per message/blob.
 * ============================================================ */
(() => {
  const $ = (id) => document.getElementById(id);
  const app = $('app'), thread = $('thread'), scroller = $('scroller');
  const input = $('input'), sendBtn = $('sendBtn'), micBtn = $('micBtn');
  const charcount = $('charcount'), statusLine = $('statusLine'), statusText = $('statusText');
  const toasts = $('toasts');

  const WORDS = ['Luna','Sable','Orbit','Nova','Echo','Iris','Comet','Delta','Aurora','Zephyr','Mango','Kiwi','Pixel','Quartz','Tango','Umbra'];
  const REACTS = ['👍','❤️','😂','😮','😢','🙏'];

  /* ------------------------- prefs ------------------------- */
  const _n = (k, d) => { const v = Number(localStorage.getItem(k)); return Number.isFinite(v) && v !== 0 ? v : d; };
  const prefs = {
    theme: localStorage.getItem('vault_theme') || 'auto',
    font: localStorage.getItem('vault_font') || 'Vazirmatn',
    fsize: _n('vault_fsize', 100),
    wall: localStorage.getItem('vault_wall') || '',          // '' | gradient-preset | dataURL
    wallBlur: _n('vault_wallBlur', 3),
    wallDim: _n('vault_wallDim', 35),
    name: localStorage.getItem('vault_displayName') || '',
  };
  const WALL_PRESETS = [
    '',
    'linear-gradient(135deg,#3a2440,#241a2e 60%,#4a2c48)',
    'linear-gradient(160deg,#ffe4f0,#ffd0e6)',
    'linear-gradient(145deg,#382848,#5c3160)',
    'radial-gradient(900px at 30% 20%, #7a3f64, #241a2e)',
    'linear-gradient(150deg,#fdeef6,#ffd8ea)',
    'linear-gradient(150deg,#f3e7fa,#ffd9ec 60%,#ffe9f3)',
    'linear-gradient(140deg,#ffe9f3,#e8e2ff 55%,#dff3ff)',
  ];

  function applyPrefs() {
    if (!['auto', 'light', 'dark', 'black'].includes(prefs.theme)) prefs.theme = 'dark';   /* v30 */
    document.documentElement.setAttribute('data-theme', prefs.theme);
    const meta = document.querySelector('meta[name=theme-color]');
    const mq = matchMedia('(prefers-color-scheme: dark)');
    const dark = prefs.theme === 'dark' || prefs.theme === 'black' || (prefs.theme === 'auto' && mq.matches);
    if (meta) meta.content = prefs.theme === 'black' ? '#000000' : (dark ? '#241a2e' : '#fdf1f6');
    if (prefs.font === 'system') {
      document.documentElement.style.setProperty('--app-font', "system-ui,-apple-system,'Segoe UI',Tahoma,sans-serif");
    } else {
      document.documentElement.style.setProperty('--app-font', `'${prefs.font}',system-ui,sans-serif`);
    }
    document.documentElement.style.setProperty('--z', String(prefs.fsize / 100));
    applyWall();
    syncSettingsUI();
  }
  let mediaMq = matchMedia('(prefers-color-scheme: dark)');
  mediaMq.addEventListener('change', () => { if (prefs.theme === 'auto') applyPrefs(); });

  function applyWall() {
    const has = !!prefs.wall;
    const wl = $('wallLayer');
    scroller.classList.toggle('has-wall', has);
    document.documentElement.classList.toggle('wall-on', has);   /* header goes frosted */
    if (has) {
      // the wall lives on a fixed full-viewport layer so the header is covered too
      wl.style.backgroundImage = prefs.wall.startsWith('data:')
        ? `url("${prefs.wall}")`
        : prefs.wall;
      wl.classList.add('on');
      document.documentElement.style.setProperty('--wall-blur', prefs.wallBlur + 'px');
      document.documentElement.style.setProperty('--wall-dimk', String(prefs.wallDim / 100));
    } else {
      wl.style.backgroundImage = '';
      wl.classList.remove('on');
    }
  }

  /* ------------------------- crypto ------------------------- */
  const te = new TextEncoder(), td = new TextDecoder();
  const b64 = {
    enc(buf) { const u = new Uint8Array(buf); let s = ''; for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode.apply(null, u.subarray(i, i + 0x8000)); return btoa(s); },
    dec(s) { return Uint8Array.from(atob(s), c => c.charCodeAt(0)); },
  };
  /* v27: base64url (WebAuthn wire format) */
  const b64uEnc = (buf) => b64.enc(buf).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const b64uDec = (s) => { s = String(s || '').replace(/-/g, '+').replace(/_/g, '/'); return b64.dec(s + '==='.slice((s.length + 3) % 4)); };
  async function deriveKey(pw, saltB64) {
    const base = await crypto.subtle.importKey('raw', te.encode(pw), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: b64.dec(saltB64), iterations: 250000, hash: 'SHA-256' },
      base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }
  /* v18: raw PBKDF2 (for verifier + KEK derivation) */
  async function pbkdf2Raw(pw, saltB64, iter) {
    const base = await crypto.subtle.importKey('raw', te.encode(pw), 'PBKDF2', false, ['deriveBits']);
    return crypto.subtle.deriveBits({ name: 'PBKDF2', salt: b64.dec(saltB64), iterations: iter || 250000, hash: 'SHA-256' }, base, 256);
  }
  async function hkdfWrapKey(rawBits, info) {
    const base = await crypto.subtle.importKey('raw', rawBits, 'HKDF', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: te.encode(info) },
      base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }
  /* extractable=true: the claim-wrap helper needs exportKey(aesKey); the raw
     bytes already live in sessionStorage anyway, so this adds no exposure */
  const importAesRaw = (raw) => crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);
  async function aesEnc(key, data) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    return { iv: b64.enc(iv), c: b64.enc(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data)) };
  }
  async function aesDec(key, ivB64, cB64) {
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64.dec(ivB64) }, key, b64.dec(cB64));
  }
  async function encryptBuf(data) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, data);
    return { iv: b64.enc(iv), c: b64.enc(ct) };
  }
  async function decryptBuf(ivB64, cB64) {
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64.dec(ivB64) }, aesKey, b64.dec(cB64));
  }
  /* decrypt trying the chat key first, then the legacy (pre-v18) key */
  async function decryptBufAny(ivB64, cB64) {
    try { return await decryptBuf(ivB64, cB64); }
    catch (e) {
      if (legacyKey) return crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64.dec(ivB64) }, legacyKey, b64.dec(cB64));
      throw e;
    }
  }
  const encText = (t) => encryptBuf(te.encode(t));
  const decText = async (iv, c) => td.decode(await decryptBufAny(iv, c));

  /* ------------------------- state ------------------------- */
  const state = {
    tgPersona: { name: 'تلگرام', photo: '' },
    sitePersona: { name: prefs.name || '', photo: '' },
    profiles: {},          // v18: nameLower -> {name, photo, updated}
    legacySender: null,    // v18: {tag, name} of pre-v18 site messages
  };
  let siteTitle = 'Panda Chat';   // v15: live brand from the server (/title command)
  function applyTitle(t) {
    t = String(t || '').trim();
    if (!t) return;
    siteTitle = t;
    try { document.title = t + ' — گفت‌وگوی رمزشده'; } catch {}
    const bt = $('brandTitle'); if (bt) bt.textContent = t;
    const ab = $('aboutLine');
    if (ab) ab.innerHTML = '';
    if (ab) {
      const b1 = document.createElement('b'); b1.textContent = t + ' v2';
      ab.appendChild(b1);
      ab.appendChild(document.createTextNode(' · رمزنگاری AES-GCM سمت کاربر'));
      ab.appendChild(document.createElement('br'));
      ab.appendChild(document.createTextNode('پل ربات تلگرام فعال است؛ پیام‌های تلگرامی رمزنگاری سرتاسری ندارند.'));
    }
  }
  let aesKey = null, myTag = '', myFp = '';
  let legacyKey = null;              // pre-v18 key (unwrapped locally, never sent)
  let restoredLogin = false;
  let es = null, connected = false;
  let bridgeOn = true, adminLinked = null;
  const seenIds = new Set();
  const msgs = new Map();              // id -> message object
  const order = [];                    // insertion order of ids
  const mediaUrls = new Map();         // blobId|fid -> objectURL
  const urlOf = (key) => mediaUrls.get(key);
  let ctxMode = null;                  // {mode:'reply'|'edit', id}
  let unread = 0;
  let lastTypingSent = 0;

  /* ------------------------- utils ------------------------- */
  const faTime = (ts) => { try { return new Date(ts).toLocaleTimeString('fa-IR', { hour: '2-digit', minute: '2-digit' }); } catch { return ''; } };

  /* v24 — Android BACK closes the keyboard / panels / sheets instead of leaving the site.
     Whenever the keyboard (or any full-screen layer) opens we plant one history
     entry; every back press pops it, closes the top-most layer, and re-plants —
     only when nothing is left open does back actually leave. */
  function uiGuardPush() {
    try { if (!(history.state && history.state.ui)) history.pushState({ ui: 1 }, ''); } catch {}
  }
  addEventListener('popstate', () => {
    const ae = document.activeElement;
    if (ae && (ae.tagName === 'TEXTAREA' || ae.tagName === 'INPUT') && document.documentElement.classList.contains('kb-open')) {
      try { ae.blur(); } catch {}                    // closes the on-screen keyboard
      setTimeout(uiGuardPush, 0);
      return;
    }
    let closed = false;
    if (panel && panel.classList.contains('on')) { closePanel(); closed = true; }
    if (!closed) {
      const ovs = [...document.querySelectorAll('.sheet-overlay.on')];
      if (ovs.length) {
        const ov = ovs[ovs.length - 1];
        ov.classList.remove('on');
        if (ov.id === 'msgSheet') sheetTargetId = null;
        closed = true;
      }
    }
    if (!closed) {
      const lb = $('lightbox');
      if (lb && !lb.hidden) { lb.hidden = true; $('lbHolder').innerHTML = ''; closed = true; }
    }
    if (!closed) {
      const mp = $('menuPop'), pp = $('peerPop');
      if (mp && mp.classList.contains('on')) { mp.classList.remove('on'); closed = true; }
      else if (pp && pp.classList.contains('on')) { pp.classList.remove('on'); closed = true; }
    }
    if (closed) setTimeout(uiGuardPush, 0);        // keep guarding while layers remain
  });
  function toast(text, kind, ms) {
    const el = document.createElement('div');
    el.className = 'toast' + (kind ? ' ' + kind : '');
    el.textContent = text;
    toasts.appendChild(el);
    setTimeout(() => { el.classList.add('out'); setTimeout(() => el.remove(), 320); }, ms || 2600);
  }
  function setPing() {}
  function playPing() {
    try {
      const ac = playPing.ac || (playPing.ac = new AudioContext());
      const o = ac.createOscillator(), g = ac.createGain();
      o.connect(g); g.connect(ac.destination);
      o.frequency.value = 830; g.gain.setValueAtTime(.07, ac.currentTime);
      g.gain.exponentialRampToValueAtTime(.0001, ac.currentTime + .2);
      o.start(); o.stop(ac.currentTime + .22);
    } catch {}
  }
  const API = (path, opt) => {
    const o = Object.assign({ cache: 'no-store' }, opt || {});
    o.headers = Object.assign({}, tok ? { Authorization: 'Bearer ' + tok } : {}, o.headers || {});
    /* v25: hard 25s timeout for every API call that has no signal yet — on
       filtered/slow Iranian networks requests can hang forever; failing fast
       lets the retry path and the UI recover instead of freezing */
    if (!o.signal) {
      const ctl = new AbortController();
      const tmr = setTimeout(() => ctl.abort(), 25000);
      o.signal = ctl.signal;
      const p = fetch(path, o);
      return p.finally(() => clearTimeout(tmr));
    }
    return fetch(path, o);
  };
  let tok = sessionStorage.getItem('vault_tok') || '';

  /* ---- resilient fetch with timeout + retries (fixes flaky entry errors) ---- */
  const sleep = (ms) => new Promise(r => setTimeout(r, ms));
  async function fetchRetry(path, opt, tries) {
    const max = tries || 3;
    let lastErr = null;
    for (let i = 0; i < max; i++) {
      const ctl = new AbortController();
      const tmr = setTimeout(() => ctl.abort(), 12000);
      try {
        const o = Object.assign({}, opt || {}, { signal: ctl.signal });
        const r = await fetch(path, o);
        clearTimeout(tmr);
        if (r.status >= 500 && i < max - 1) { await sleep(650 * (i + 1)); continue; }
        return r;
      } catch (e) {
        clearTimeout(tmr);
        lastErr = e;
        if (i < max - 1) await sleep(650 * (i + 1));
      }
    }
    throw lastErr || new Error('network');
  }

  /* ---- visual viewport sync: keeps composer above the mobile keyboard ----
     Works on every phone model: --vvh always tracks the REAL visible height,
     with a self-healing re-check because iOS often drops resize events.   */
  let vhSyncTmr = 0;
  function vpHeight() { const vv = window.visualViewport; return vv ? vv.height : window.innerHeight; }
  function applyVh() {
    const h = vpHeight();
    document.documentElement.style.setProperty('--vvh', h + 'px');
    if (window.visualViewport) app.classList.add('vv');
    const kb = Math.max(0, Math.round(window.innerHeight - h - (window.visualViewport ? window.visualViewport.offsetTop : 0)));
    document.documentElement.style.setProperty('--kb', kb + 'px');
    const open = kb > 90;
    document.documentElement.classList.toggle('kb-open', open);
    if (!open && (window.scrollY || window.scrollX)) scrollTo(0, 0);
    /* self-heal: if the viewport changed again right after us, re-sync */
    const snap = h + ':' + window.innerHeight;
    clearTimeout(vhSyncTmr);
    vhSyncTmr = setTimeout(() => { if (vpHeight() + ':' + window.innerHeight !== snap) applyVh(); }, 350);
  }
  function bindViewportEvents() {
    const vv = window.visualViewport;
    if (vv) {
      vv.addEventListener('resize', applyVh);
      vv.addEventListener('scroll', applyVh);
    }
    addEventListener('resize', () => { applyVh(); autosize(); }, { passive: true });
    addEventListener('orientationchange', () => { setTimeout(applyVh, 60); setTimeout(applyVh, 350); setTimeout(applyVh, 900); });
    screen.orientation && screen.orientation.addEventListener && screen.orientation.addEventListener('change', () => { setTimeout(applyVh, 250); setTimeout(applyVh, 800); });
    /* keyboard show/hide sometimes fires no viewport event (esp. iOS) —
       catch it via focus and re-sync a few times */
    document.addEventListener('focusin', (e) => {
      const t = e.target;
      if (t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA')) { setTimeout(applyVh, 80); setTimeout(applyVh, 400); }
    }, true);
    document.addEventListener('focusout', () => { setTimeout(applyVh, 100); setTimeout(() => { applyVh(); if (!document.documentElement.classList.contains('kb-open')) scrollTo(0, 0); }, 450); }, true);
    /* network come back → reconnect the stream instantly */
    addEventListener('online', () => { applyVh(); updateNetBanner(); if (aesKey && (!connected || !es || es.readyState === 2)) connectStream(); flushOutbox(); });
    addEventListener('offline', () => updateNetBanner());
    addEventListener('offline', () => { connected = false; composeStatus(lastPresence); });
  }

  /* day chip */
  function dayChipLabel(ts) {
    const d = new Date(ts), today = new Date();
    const same = (a, b) => a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();
    const yest = new Date(today); yest.setDate(today.getDate() - 1);
    if (same(d, today)) return 'امروز';
    if (same(d, yest)) return 'دیروز';
    return d.toLocaleDateString('fa-IR', { year: 'numeric', month: 'long', day: 'numeric' });
  }
  function ensureDayChip(ts) {
    const chips = thread.querySelectorAll('.day-chip');
    const lastChip = chips[chips.length - 1];
    const needInsert = !lastChip || lastChip.__label !== dayChipLabel(ts);
    if (!needInsert) return;
    // remove upcoming chip duplication: when inserting into middle (history backfill), just append
    const chip = document.createElement('div'); chip.className = 'day-chip';
    chip.innerHTML = '<span></span>'; chip.firstChild.textContent = dayChipLabel(ts);
    chip.__label = dayChipLabel(ts);
    thread.appendChild(chip);
  }

  /* linkify with XSS-safe nodes */
  function linkify(el, text) {
    el.textContent = '';
    const re = /(https?:\/\/[^\s<>"')\]]+)/g;
    let last = 0, m;
    while ((m = re.exec(text)) !== null) {
      if (m.index > last) el.appendChild(document.createTextNode(text.slice(last, m.index)));
      const a = document.createElement('a');
      a.className = 'linkified'; a.href = m[1]; a.target = '_blank'; a.rel = 'noopener noreferrer nofollow';
      a.textContent = m[1]; el.appendChild(a);
      last = m.index + m[1].length;
    }
    if (last < text.length) el.appendChild(document.createTextNode(text.slice(last)));
  }

  /* ============================================================
     MEDIA SOURCING & RENDERING
     ============================================================ */
  async function mediaSource(meta) {
    if (meta.blob && String(meta.blob).indexOf('stk:') === 0) {
      const rec = await stickerSource(String(meta.blob).slice(4));   /* cloud sticker/gif */
      return { url: rec.url, mime: rec.mime };
    }
    if (meta.blob) {
      const key = meta.blob;
      if (!mediaUrls.has(key)) {
        const j = await API('/api/blob/' + key).then(r => { if (!r.ok) throw 0; return r.json(); });
        const bytes = await decryptBuf(j.iv, j.c);
        let mime = 'application/octet-stream';
        try { mime = td.decode(await decryptBuf(j.miv, j.mc)) || mime; } catch {}
        mediaUrls.set(key, URL.createObjectURL(new Blob([bytes], { type: mime })));
        mediaUrls.set(key + ':mime', mime);
      }
      return { url: mediaUrls.get(key), mime: mediaUrls.get(key + ':mime') || '' };
    }
    if (meta.fid) {
      const key = 'tg:' + meta.fid;
      if (!mediaUrls.has(key)) {
        const r = await API('/api/tgfile/' + meta.fid);
        if (!r.ok) throw 0;
        const blob = await r.blob();
        mediaUrls.set(key, URL.createObjectURL(blob));
        mediaUrls.set(key + ':mime', blob.type);
      }
      return { url: mediaUrls.get(key), mime: mediaUrls.get(key + ':mime') || '' };
    }
    throw new Error('no media ref');
  }

  function el(html) { const t = document.createElement('template'); t.innerHTML = html.trim(); return t.content.firstElementChild; }

  function buildVoicePlayer(meta, src, mine) {
    const seed = [...String(meta.fid || meta.blob || 'x')].reduce((a, c) => a * 31 + c.charCodeAt(0) | 0, 7);
    const bars = Array.from({ length: 24 }, (_, i) => {
      const h = 18 + Math.abs(Math.sin(seed * (i + 3))) * 82;
      return `<i style="--w:${h.toFixed(0)}"></i>`;
    }).join('');
    const row = el(`<div class="voice-row">
      <button class="vp-play" type="button"><svg viewBox="0 0 24 24"><path d="M8 5.5v13l11-6.5z"/></svg></button>
      <div class="vp-mid"><div class="wave-bars">${bars}</div>
        <div class="vp-line"><span class="vp-time">۰:۰۰</span><div class="vp-track"><div class="vp-fill"></div></div></div>
      </div></div>`);
    const audio = new Audio(); audio.src = src.url; audio.preload = 'metadata';
    const btn = row.querySelector('.vp-play'), fill = row.querySelector('.vp-fill'),
          barsEl = row.querySelector('.wave-bars'), tEl = row.querySelector('.vp-time');
    const fmtD = (s) => Math.floor(s / 60) + ':' + String(Math.floor(s % 60)).padStart(2, '0');
    btn.onclick = () => {
      if (audio.paused) {
        document.querySelectorAll('audio').forEach(a => { try { a.pause(); } catch {} });
        document.querySelectorAll('.vp-play.playing').forEach(b => b.classList.remove('playing'));
        row.querySelectorAll('audio.vp-audio2').forEach(a => a.pause());
        audio.play(); btn.classList.add('playing');
      } else { audio.pause(); btn.classList.remove('playing'); }
    };
    audio.addEventListener('timeupdate', () => {
      const d = audio.duration;
      if (Number.isFinite(d) && d > 0) fill.style.width = (audio.currentTime / d * 100).toFixed(1) + '%';
      for (let i = 0; i < barsEl.children.length; i++)
        barsEl.children[i].classList.toggle('past', (i / barsEl.children.length) < (fill.style.width ? parseFloat(fill.style.width) / 100 : 0));
      tEl.textContent = faDigits(fmtD(audio.currentTime));
    });
    audio.addEventListener('ended', () => { btn.classList.remove('playing'); fill.style.width = '0%'; tEl.textContent = faDigits('0:00'); });
    return { row, audio };
  }
  const faNums = '۰۱۲۳۴۵۶۷۸۹';
  const faDigits = (s) => String(s).replace(/\d/g, d => faNums[+d]);
  /* v29: Persian relative time («۳ دقیقه پیش») for real last-seen display */
  function faAgo(ts) {
    const t = Number(ts) || 0;
    if (!t) return 'نامعلوم';
    const d = Date.now() - t;
    if (d < 0) return 'همین حالا';
    if (d < 60 * 1000) return 'همین حالا';
    const m = Math.floor(d / 60000);
    if (m < 60) return faDigits(m) + ' دقیقه پیش';
    const h = Math.floor(m / 60);
    if (h < 24) return faDigits(h) + ' ساعت پیش';
    const days = Math.floor(h / 24);
    if (days === 1) return 'دیروز';
    if (days < 7) return faDigits(days) + ' روز پیش';
    try { return new Date(t).toLocaleDateString('fa-IR'); } catch { return ''; }
  }
  /* v29: real last-seen snapshots (from /api/history + presence events) */
  const lastSeen = { tg: 0, users: {} };
  function paintSeen() {
    const el = $('ppSeen');
    if (el) {
      const on = lastPresence && lastPresence.tg;
      el.textContent = 'آخرین فعالیت: ' + faAgo(lastSeen.tg)
        + (on ? ' · آنلاین 🟢' : '');
    }
    const ds = $('devLastSeen');
    if (ds && ds.dataset.html) ds.innerHTML = ds.dataset.html;
  }
  setInterval(() => { try { paintSeen(); } catch {} }, 60000);

  /* long-press (or right-click) on a gif/sticker in chat -> save to device */
  function saveMediaFromUrl(url, name, mime) {
    fetch(url).then(r => r.blob()).then(b => {
      const a = document.createElement('a');
      a.href = URL.createObjectURL(b);
      const ext = (((mime || b.type || '').split('/')[1] || 'gif').split('+')[0]);
      a.download = name + '.' + (ext === 'jpeg' ? 'jpg' : ext);
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(a.href), 4000);
      if (navigator.vibrate) try { navigator.vibrate(18); } catch {}
      toast('ذخیره شد ✓', 'ok');
    }).catch(() => toast('ذخیره ناموفق', 'err'));
  }
  function addHoldToSave(node, name, mime, m) {
    let tmr = null, sx = 0, sy = 0;
    const cancel = () => { if (tmr) { clearTimeout(tmr); tmr = null; } };
    const openMenu = () => { tmr = null; openMediaHoldSheet({ url: node.src, name, mime, m }); };
    node.addEventListener('pointerdown', (e) => {
      sx = e.clientX; sy = e.clientY; cancel();
      tmr = setTimeout(openMenu, 550);
    });
    node.addEventListener('pointermove', (e) => {
      if (tmr && (Math.abs(e.clientX - sx) > 12 || Math.abs(e.clientY - sy) > 12)) cancel();
    });
    node.addEventListener('pointerup', cancel);
    node.addEventListener('pointercancel', cancel);
    node.addEventListener('pointerleave', cancel);
    node.addEventListener('contextmenu', (e) => { e.preventDefault(); e.stopPropagation(); openMenu(); });
    node.style.webkitTouchCallout = 'none';
    node.style.userSelect = 'none';
    node.style.webkitUserSelect = 'none';
  }

  /* v20: sticker/gif hold menu — options sheet (device save / cloud save /
     resend). The file itself already lives on the server disk (tgcache), so
     saving costs no extra Telegram download and re-sends are instant. */
  const mediaHoldSheet = $('mediaHoldSheet');
  let mediaHoldCtx = null;
  function openMediaHoldSheet(ctx) {
    mediaHoldCtx = ctx;
    if (navigator.vibrate) try { navigator.vibrate(14); } catch {}
    $('mhCloud').style.display = (ctx.m && ctx.m.meta && String(ctx.m.meta.blob || '').indexOf('stk:') === 0) ? 'none' : '';
    $('mhDelete').style.display = (ctx.m && ctx.m.id) ? '' : 'none';
    mediaHoldSheet.classList.add('on');
    uiGuardPush();
  }
  mediaHoldSheet.addEventListener('click', (e) => { if (e.target === mediaHoldSheet) mediaHoldSheet.classList.remove('on'); });
  $('mhSave').onclick = () => {
    mediaHoldSheet.classList.remove('on');
    if (mediaHoldCtx) saveMediaFromUrl(mediaHoldCtx.url, mediaHoldCtx.name, mediaHoldCtx.mime);
  };
  $('mhCancel').onclick = () => mediaHoldSheet.classList.remove('on');
  $('mhDelete').onclick = () => {
    mediaHoldSheet.classList.remove('on');
    const ctx = mediaHoldCtx; if (!ctx || !ctx.m || !ctx.m.id) return;
    confirmDialog('حذف این رسانه؟', 'این استیکر/گیف برای همه حذف می‌شود.', 'حذف کن', async () => {
      await API('/api/delete', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ids: [String(ctx.m.id)] }) }).catch(() => {});
    });
  };
  $('mhCloud').onclick = async () => {
    mediaHoldSheet.classList.remove('on');
    if (!mediaHoldCtx) return;
    if (!aesKey) { toast('ابتدا وارد شو', 'err'); return; }
    if ((stickerList || []).length >= STK_CAP) { toast('ظرفیت استیکر پر است', 'err'); return; }
    try {
      toast('در حال ذخیره در ابر…');
      const b = await (await fetch(mediaHoldCtx.url)).blob();
      const bytes = new Uint8Array(await b.arrayBuffer());
      const mime = b.type || mediaHoldCtx.mime || 'image/webp';
      const kind = (mime === 'image/gif' || /^video\//.test(mime)) ? 'gif' : 'sticker';
      const dEnc = await encryptBuf(bytes);
      const mEnc = await encryptBuf(te.encode(mime));
      const r = await API('/api/stickers', { method: 'PUT', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ kind, iv: dEnc.iv, c: dEnc.c, miv: mEnc.iv, mc: mEnc.c }) });
      if (!r.ok) { toast(r.status === 409 ? 'ظرفیت استیکر پر است' : 'ذخیره ناموفق', 'err'); return; }
      const j = await r.json();
      stickerList = stickerList || [];
      stickerList.push({ id: j.id, kind, ts: j.ts, size: bytes.length });
      stickerUrls.set(j.id, { url: URL.createObjectURL(new Blob([bytes], { type: mime })), mime });
      paintStickers();
      toast(kind === 'gif' ? 'گیف در ابر ذخیره شد ✓' : 'استیکر در ابر ذخیره شد ✓', 'ok');
    } catch { toast('ذخیره ناموفق', 'err'); }
  };
  $('mhResend').onclick = async () => {
    mediaHoldSheet.classList.remove('on');
    const ctx = mediaHoldCtx; if (!ctx || !ctx.m) return;
    const m = ctx.m;
    const reply = ctxMode && ctxMode.mode === 'reply' ? ctxMode.id : undefined;
    hideCtxBanner();
    try {
      const kind = m.meta && m.meta.k === 'gif' ? 'gif' : 'sticker';
      const meta = { k: kind, from: myTag, un: prefs.name || '' };
      if (m.meta && String(m.meta.blob || '').indexOf('stk:') === 0) {
        meta.blob = m.meta.blob;                        /* cloud sticker — zero bytes */
      } else {
        /* TG-origin sticker/gif — re-upload the cached bytes as an encrypted blob */
        const { url, mime } = await mediaSource(m.meta);
        const b = await (await fetch(url)).blob();
        const bytes = new Uint8Array(await b.arrayBuffer());
        const dEnc = await encryptBuf(bytes);
        const mEnc = await encryptBuf(te.encode(b.type || mime || 'application/octet-stream'));
        const r2 = await API('/api/blob', { method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ iv: dEnc.iv, c: dEnc.c, miv: mEnc.iv, mc: mEnc.c }) });
        if (!r2.ok) throw 0;
        const j2 = await r2.json();
        meta.blob = j2.bid;
      }
      if (reply) meta.rt = reply;
      const nEnc = await encText(kind === 'gif' ? 'گیف' : 'استیکر');
      const r = await API('/api/send', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ iv: nEnc.iv, c: nEnc.c, meta }) });
      if (!r.ok) throw 0;
      const j = await r.json();
      onIncoming({ id: j.id, ts: j.ts, iv: nEnc.iv, c: nEnc.c, meta, reacts: null });
      /* mirror bytes to TG (best-effort, same as normal sticker send) */
      try {
        const src = await mediaSource(m.meta);
        const b = await (await fetch(src.url)).blob();
        await fetch('/api/mirror/media', { method: 'POST',
          headers: Object.assign({ 'Content-Type': 'application/octet-stream',
            'x-vault-mid': j.id, 'x-vault-kind': kind,
            'x-vault-mime': encodeURIComponent(src.mime || 'image/webp'),
            'x-vault-name': encodeURIComponent(kind === 'gif' ? 'gif-resend' : 'sticker-resend') },
            tok ? { Authorization: 'Bearer ' + tok } : {}),
          body: b }).then(rr => { if (rr.ok) { const mm = msgs.get(j.id); if (mm) { mm.dl = true; paintTicks(); } } });
      } catch {}
    } catch { toast('ارسال ناموفق', 'err'); }
  };

  /* attach decrypted media into bubble — anchor = stable insertion point so a
     v24 caption (inserted BEFORE the async media resolves) always lands UNDER it */
  function attachMedia(msgEl, m, meta, anchor) {
    const at = anchor || null;
    mediaSource(meta).then(({ url, mime }) => {
      const k = meta.k;
      if (k === 'sticker') {
        const saveName = (meta.blob ? 'sticker-' + String(meta.blob).slice(-6) : 'sticker');
        const isTgs = /x-tgs|lottie/i.test(mime) || /\.tgs$/i.test(meta.name || '');
        if (isTgs) {
          /* v18: vector-animated (.tgs) — elegant placeholder card (light) */
          const card = el('<div class="tgs-card"><div class="tg-emoji">🎞</div><div class="tg-name"></div><a class="tg-dl" download>ذخیره فایل</a></div>');
          card.querySelector('.tg-name').textContent = 'استیکر متحرک تلگرام';
          const dl = card.querySelector('.tg-dl');
          dl.href = url; dl.download = saveName + '.tgs';
          msgEl.insertBefore(card, at);
        } else if (/^video\//.test(mime) || /\.webm$/i.test(meta.name || '')) {
          const v = document.createElement('video');
          v.className = 'media'; v.autoplay = true; v.loop = true; v.muted = true; v.playsInline = true;
          v.style.width = '120px'; v.style.borderRadius = '12px'; v.src = url;
          v.classList.add('vwait');
          v.addEventListener('loadeddata', () => v.classList.remove('vwait'), { once: true });
          setTimeout(() => v.classList.remove('vwait'), 6000);
          addHoldToSave(v, saveName, mime, m);
          msgEl.insertBefore(v, at);
        } else {
          const img = document.createElement('img'); img.className = 'media'; img.src = url;
          addHoldToSave(img, saveName, mime, m);
          msgEl.insertBefore(img, at);
        }
        msgEl.classList.add('sticker-bubble');
      } else if (k === 'image' && !meta.round) {
        const img = document.createElement('img'); img.className = 'media media-img';
        img.loading = 'lazy'; img.alt = ''; img.src = url;
        img.onclick = () => openLightbox(url, 'image', meta.name || 'photo.jpg');
        msgEl.insertBefore(img, at);
      } else if ((k === 'video' || k === 'gif')) {
        if (k === 'gif' && /image\/gif/i.test(mime)) {
          /* real .gif file — <img> autoplays it natively */
          const img = document.createElement('img');
          img.className = 'media media-img'; img.alt = ''; img.src = url;
          addHoldToSave(img, 'gif-' + String(meta.blob || 'chat').slice(-6), mime, m);
          msgEl.insertBefore(img, at);
        } else {
          const holder = document.createElement('div');
          const v = document.createElement('video');
          v.className = 'media'; v.controls = k !== 'gif'; v.preload = 'metadata'; v.playsInline = true;
          if (k === 'gif') { v.muted = true; v.loop = true; v.autoplay = true; }
          v.src = url;
          /* v26: no black flash — reveal only after the first frame is real */
          v.classList.add('vwait');
          v.addEventListener('loadeddata', () => v.classList.remove('vwait'), { once: true });
          setTimeout(() => v.classList.remove('vwait'), 6000);
          /* v24 fix: GIF videos (TG animations / tenor mp4) get the hold menu too
             (they were the only media without ذخیره — the save button existed
             for webp stickers and image-gifs only) */
          if (k === 'gif') addHoldToSave(v, 'gif-' + String(meta.blob || meta.fid || 'chat').slice(-6), mime, m);
          if (meta.round) { holder.classList.add('video-round'); }
          holder.appendChild(v);
          msgEl.insertBefore(holder, at);
        }
      } else if (k === 'voice') {
        const { row } = buildVoicePlayer(meta, { url }, false);
        msgEl.insertBefore(row, at);
      } else if (k === 'audio') {
        const wrap2 = document.createElement('div');
        wrap2.innerHTML = `<div class="audio-artist">🎵 <span></span></div>`;
        wrap2.querySelector('.audio-artist span').textContent = meta.name || 'آهنگ';
        const a = document.createElement('audio'); a.className = 'native-audio'; a.controls = true; a.preload = 'metadata'; a.src = url;
        wrap2.appendChild(a);
        msgEl.insertBefore(wrap2, at);
      } else { // file
        const chip = el(`<div class="file-chip">
          <div class="f-ic"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"><path d="M13 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V9z"/><path d="M13 2v7h7"/></svg></div>
          <div class="f-meta"><div class="f-name"></div><small></small><a class="dl-btn" download>دانلود</a></div>
        </div>`);
        chip.querySelector('.f-name').textContent = meta.name || 'فایل رمزشده';
        chip.querySelector('small').textContent = bytesHuman(meta.size || 0);
        chip.querySelector('.dl-btn').href = url; chip.querySelector('.dl-btn').download = meta.name || 'file';
        msgEl.insertBefore(chip, at);
      }
      requestAnimationFrame(() => scrollDown(false));
    }).catch(() => {
      const miss = el('<div class="media-missing">📎 رسانه در دسترس نیست</div>');
      msgEl.insertBefore(miss, at);
    });
  }
  const bytesHuman = (b) => {
    if (!b) return '';
    const u = ['بایت','کیلوبایت','مگابایت']; let i = 0, n = b;
    while (n >= 1024 && i < 2) { n /= 1024; i++; }
    return faDigits(n.toFixed(n < 10 && i > 0 ? 1 : 0)) + ' ' + u[i];
  };

  function openLightbox(url, kind, name) {
    const lb = $('lightbox'), hold = $('lbHolder'), dl = $('lbDl');
    hold.innerHTML = kind === 'image'
      ? `<img alt="">` : `<video controls autoplay playsinline style="max-height:84vh"></video>`;
    (kind === 'image' ? hold.querySelector('img') : hold.querySelector('video')).src = url;
    dl.href = url; dl.download = name || 'media';
    lb.hidden = false;
    uiGuardPush();
  }
  $('lbClose').onclick = () => { $('lightbox').hidden = true; $('lbHolder').innerHTML = ''; };
  $('lightbox').onclick = (e) => { if (e.target === $('lightbox')) $('lbClose').click(); };

  /* ============================================================
     MESSAGE RENDERING
     ============================================================ */
  const isMine = (m) => !!(m.meta && m.meta.from && m.meta.from !== 'tg' && m.meta.from === myTag);

  function scrollDown(force) {
    const nearBottom = scroller.scrollHeight - scroller.scrollTop - scroller.clientHeight < 200;
    if (force || nearBottom) requestAnimationFrame(() => { scroller.scrollTop = scroller.scrollHeight; });
  }

  function findEl(id) { return thread.querySelector(`.msg-wrap[data-id="${CSS.escape(id)}"]`); }
  function flash(elx) {
    elx.classList.remove('flash-hl'); void elx.offsetWidth;
    elx.classList.add('flash-hl');
    setTimeout(() => elx.classList.remove('flash-hl'), 950);
  }
  async function decTextSafe(iv, c) { try { return await decText(iv, c); } catch { return ''; } }

  function resolveQuote(q, rtid, m) {
    const KMAP = { image: '\u{1F5BC} عکس', video: '\u{1F3AC} ویدیو', voice: '\u{1F399} ویس', audio: '\u{1F3B5} آهنگ', file: '\u{1F4CE} فایل', sticker: '\u2728 استیکر', gif: '\u{1F39E} گیف' };
    const paint = (nm, tx, gone) => {
      q.innerHTML = '<span class="rq-t">↩</span><span class="rq-wrap"><b class="rq-name"></b><span class="rq-b"></span></span>';
      q.querySelector('.rq-name').textContent = nm;
      q.querySelector('.rq-b').textContent = tx;
      if (gone) q.classList.add('qgone');
    };
    const kindLabel = (mm) => (mm && mm.k && mm.k !== 'text') ? (KMAP[mm.k] || '') : '';
    const src = msgs.get(rtid);
    if (!src) {
      if (m.meta && m.meta.rx) paint('پیام نقل‌قول‌شده', String(m.meta.rx).slice(0, 90), true);
      else paint('پاسخ', 'پیام دیگر در دسترس نیست', true);
      return;
    }
    const nm = (src.meta && src.meta.tg)
      ? (state.tgPersona.name || 'تلگرام')
      : ((src.meta && src.meta.name) ? src.meta.name : 'سایت');
    if (src.iv == null && src.t != null) {
      paint(nm, kindLabel(src.meta) || String(src.t).slice(0, 90));
      return;
    }
    decTextSafe(src.iv, src.c).then((t) => {
      const lab = kindLabel(src.meta);
      paint(nm, (t && t.slice(0, 90)) || lab || '…');
    }).catch(() => paint(nm, kindLabel(src.meta) || '…'));
  }

  function tickSvg(mine, m) {
    if (!mine) return '';
    const dbl = m.dl;
    return `<span class="tick ${dbl ? 'dbl' : ''} ${m.read ? 'read' : ''}"><svg viewBox="0 0 24 11"><path d="${dbl ? 'M1.5 5.8l3.4 3.4L12 2M10 7.6l1.6 1.6L22.5 2.5M15.5 5.8c0 0 .2-.3 0 0' : 'M3 5.5l4 4L18 2'}"/></svg></span>`;
  }

  function renderReacts(wrap, m) {
    wrap.querySelectorAll('.reacts-row').forEach(x => x.remove());
    if (!m.reacts || m.reacts.c === '=') return;
    decTextSafe(m.reacts.iv, m.reacts.c).then(txt => {
      if (!txt.trim()) return;
      const row = document.createElement('div'); row.className = 'reacts-row';
      for (const ch of txt.split(/(?=\p{Extended_Pictographic})/u)) {
        if (!ch.trim()) continue;
        const pill = document.createElement('span'); pill.className = 'react-pill'; pill.textContent = ch;
        row.appendChild(pill);
      }
      wrap.appendChild(row);
    });
  }

  /* ---------------- v30: pinned messages ---------------- */
  function kindLabelOf(m) {
    const KMAP = { image: '\u{1F5BC} عکس', video: '\u{1F3AC} ویدیو', voice: '\u{1F399} ویس', audio: '\u{1F3B5} آهنگ', file: '\u{1F4CE} فایل', sticker: '\u2728 استیکر', gif: '\u{1F39E} گیف' };
    return (m && m.meta && m.meta.k && KMAP[m.meta.k]) || '';
  }
  function paintPinFlag(wrap, m) {
    if (!wrap) return;
    const host = wrap.querySelector('.msg'); if (!host) return;
    let f = host.querySelector('.pin-flag');
    if (m && m.pin) {
      if (!f) { f = document.createElement('span'); f.className = 'pin-flag'; f.title = 'سنجاق‌شده'; f.textContent = '📌'; host.appendChild(f); }
    } else if (f) f.remove();
  }
  function jumpToMsg(id) {
    const elx = findEl(id);
    if (!elx) { toast('این پیام در تاریخچهٔ بارگذاری‌شده نیست', 'err'); return; }
    elx.scrollIntoView({ behavior: 'smooth', block: 'center' });
    flash(elx);
  }
  function resolvePinned() {
    const bar = $('pinBar'); if (!bar) return;
    const pins = order.filter(id => { const mm = msgs.get(id); return mm && mm.pin; });
    if (!pins.length) { bar.hidden = true; bar.dataset.jump = ''; return; }
    const lastId = pins[pins.length - 1];
    const m = msgs.get(lastId);
    bar.hidden = false; bar.dataset.jump = lastId;
    const cnt = $('pinCount');
    cnt.hidden = pins.length < 2;
    cnt.textContent = faDigits(pins.length);
    $('pinPrev').textContent = '…';
    msgTextPreview(m).then(t => {
      const cur = msgs.get(bar.dataset.jump); if (!cur || cur.id !== m.id) return;
      $('pinPrev').textContent = senderNameOf(m) + ': ' + ((t && t.slice(0, 90)) || kindLabelOf(m) || 'پیام');
    }).catch(() => {});
  }
  $('pinBar').onclick = (e) => {
    if (e.target.closest('#pinListBtn')) return;
    const id = $('pinBar').dataset.jump; if (id) jumpToMsg(id);
  };
  $('pinListBtn').onclick = () => {
    const pins = order.filter(id => { const mm = msgs.get(id); return mm && mm.pin; });
    const box = $('pinListItems'); box.textContent = '';
    for (const id of pins.slice().reverse()) {
      const m = msgs.get(id); if (!m) continue;
      const row = document.createElement('button'); row.type = 'button'; row.className = 'search-hit';
      const nm = document.createElement('b'); nm.textContent = senderNameOf(m);
      const tm = document.createElement('small'); tm.textContent = faTime(m.ts);
      const sn = document.createElement('span'); sn.textContent = '…';
      msgTextPreview(m).then(t => { sn.textContent = (t && t.slice(0, 110)) || kindLabelOf(m) || 'پیام'; }).catch(() => {});
      row.append(nm, tm, sn);
      row.onclick = () => { $('pinSheet').classList.remove('on'); jumpToMsg(id); };
      box.appendChild(row);
    }
    $('pinSheet').classList.add('on'); uiGuardPush();
  };
  $('pinClose').onclick = () => $('pinSheet').classList.remove('on');
  $('pinSheet').addEventListener('click', (e) => { if (e.target === $('pinSheet')) $('pinSheet').classList.remove('on'); });

  /* v16: who does this message belong to (Telegram-group style) */
  function senderNameOf(m) {
    if (m.meta && m.meta.tg) return (m.meta.name || state.tgPersona.name || 'تلگرام');
    if (m.meta && m.meta.un) return m.meta.un;
    if (m.meta && m.meta.name && m.meta.k === 'text') return m.meta.name;
    if (state.legacySender && m.meta && m.meta.from && m.meta.from === state.legacySender.tag) return state.legacySender.name || 'کاربر قبلی';
    return 'کاربر سایت';
  }
  const AV_COLORS = ['#7c5cff', '#00a884', '#f0954f', '#e0568c', '#3f9efc', '#b8a23a', '#9a6bff', '#4fc3a1', '#e07b54', '#5aa9e6'];
  function avColor(name) { let h = 0; for (const c of String(name || '?')) h = (h * 31 + c.charCodeAt(0)) | 0; return AV_COLORS[Math.abs(h) % AV_COLORS.length]; }

  function bubbleNode(m, mine, idx) {
    ensureDayChip(m.ts);
    msgs.set(m.id, m);

    const wrap = document.createElement('div');
    wrap.className = 'msg-wrap' + (mine ? ' out' : '') +
      ((idx % 14 === 0) ? '' : '');
    wrap.dataset.id = String(m.id);
    wrap.style.setProperty('--dly', Math.min(idx * 14, 220) + 'ms');

    /* v18: compute grouping ONCE (isFirstOfGroup is stateful!) */
    const firstOfGroup = isFirstOfGroup(m);

    /* avatar column — v18: every sender (telegram or another site user) */
    if (!mine) {
      const isTg = !!(m.meta && m.meta.tg);
      const nm = senderNameOf(m);
      const av = document.createElement('div'); av.className = 'mavatar';
      let imgSet = false;
      if (isTg) {
        const peerU = urlOf('persona:tg');
        if (peerU) { av.textContent = ''; const im = document.createElement('img'); im.src = peerU; av.appendChild(im); imgSet = true; }
      } else {
        const prof = state.profiles[String(nm).toLowerCase()];
        if (prof && prof.photo) { av.textContent = ''; const im = document.createElement('img'); im.src = prof.photo; av.appendChild(im); imgSet = true; }
      }
      if (!imgSet) { av.textContent = String(nm || '?').slice(0, 1); av.style.background = avColor(nm); }
      av.style.visibility = 'visible';
      if (firstOfGroup) wrap.classList.add('show-av', 'gap-above');
      wrap.appendChild(av);
    }

    const msg = document.createElement('div'); msg.className = 'msg';
    if (!mine && m.meta && m.meta.k !== 'sticker' && firstOfGroup) {
      const nm = senderNameOf(m);
      const sl = document.createElement('div'); sl.className = 'sender-label'; sl.textContent = nm;
      sl.style.color = avColor(nm);
      msg.appendChild(sl);
    }

    /* reply quote */
    if (m.meta && m.meta.rt) {
      const q = el('<div class="reply-quote"><span class="rq-t">↩</span><span class="rq-b"></span></div>');
      q.onclick = () => {
        const target = findEl(m.meta.rt);
        if (target) { target.scrollIntoView({ behavior: 'smooth', block: 'center' }); flash(target); }
      };
      msg.appendChild(q);
      resolveQuote(q, m.meta.rt, m);
    }

    /* body vs media: anything carrying a blob or a telegram file id is media;
       a sticker without refs is the legacy big-emoji sticker; 1-8 emoji = jumbo */
    const msgKind = (m.meta && m.meta.k) || 'text';
    const isMediaMsg = !!(m.meta && (m.meta.blob || m.meta.fid)) ||
      ['image', 'video', 'voice', 'audio', 'file', 'gif', 'sticker'].includes(msgKind);
    if (!isMediaMsg) {
      const body = document.createElement('div'); body.className = 'body';
      body.textContent = m.iv ? '…' : (m.t || '');
      if (m.iv) {
        decText(m.iv, m.c).then(t => {
          if (msgKind === 'sticker') { body.textContent = t; }
          else {
            linkify(body, t);
            const cps = [...t];
            const jumboRe = /^(?:\p{Extended_Pictographic}|\p{Emoji_Component}|\uFE0F|\u200D)+$/u;
            if (cps.length >= 1 && cps.length <= 8 && jumboRe.test(t)) msg.classList.add('sticker-bubble');
          }
        }).catch(() => {
          body.textContent = '🔒 پیام با کلید دیگری رمز شده';
          body.classList.add('undecryptable');
        });
      }
      if (msgKind === 'sticker') msg.classList.add('sticker-bubble');
      msg.appendChild(body);
    }

    /* media (blob stickers included — this fixes “sticker doesn’t show”) */
    if (isMediaMsg) {
      const anchor = document.createElement('i'); anchor.className = 'media-anchor'; anchor.hidden = true;
      msg.appendChild(anchor);
      /* v24: caption under media — text rides in iv/c like any message.
         Stickers (and the bare «استیکر/گیف» label of legacy sends) never show
         a caption — Telegram has no sticker captions either. */
      if (m.iv || (m.t && !m.meta.tg)) {
        const cap = document.createElement('div'); cap.className = 'media-cap';
        msg.insertBefore(cap, anchor);
        const isStk = msgKind === 'sticker';
        if (m.iv) {
          decTextSafe(m.iv, m.c).then(t => {
            if (t && !isStk && !/^(استیکر|گیف)$/.test(t.trim())) linkify(cap, t); else cap.remove();
          }).catch(() => cap.remove());
        } else if (m.t) {
          if (!isStk) cap.textContent = m.t; else cap.remove();
        } else cap.remove();
      }
      attachMedia(msg, m, m.meta, anchor);
    }

    /* meta row */
    const metaR = el(`<div class="meta">
      <span class="edited-tag" ${m.ed ? '' : 'hidden'}>ویرایش‌شده</span>
      ${(m.meta && m.meta.tg) ? '<span class="notag">تلگرام</span>' : ''}
      <span class="time">${faTime(m.ts)}</span>
      ${tickSvg(mine, m)}
    </div>`);
    msg.appendChild(metaR);
    wrap.appendChild(msg);

    renderReacts(wrap, m);
    paintPinFlag(wrap, m);   /* v30 */

    /* interactions */
    bindMsgActions(wrap, m);

    thread.appendChild(wrap);
    requestAnimationFrame(() => scrollDown(false));
    return wrap;
  }

  let lastSenderKey = null, lastTs = 0;
  function isFirstOfGroup(m) {
    const key = (m.meta && m.meta.from) || 'x';
    const res = key !== lastSenderKey || (m.ts - lastTs) > 300000;
    lastSenderKey = key; lastTs = m.ts;
    return res;
  }

  /* ============================================================
     ACTIONS (reply/edit/delete/react/copy)
     ============================================================ */
  const msgSheet = $('msgSheet');
  let sheetTargetId = null;

  function armReply(m) {
    if (!m) return;
    ctxMode = { mode: 'reply', id: m.id };
    msgTextPreview(m).then(t => showCtxBanner('پاسخ به پیام', t.slice(0, 90)));
    if (matchMedia('(hover:hover)').matches) input.focus();
  }

  function bindMsgActions(wrap, m) {
    wrap.addEventListener('contextmenu', (e) => { e.preventDefault(); openSheet(m); });

    /* desktop quick actions */
    if (matchMedia('(hover:hover)').matches) {
      const ha = el('<div class="hover-actions"><button type="button" title="پاسخ">↩</button></div>');
      ha.querySelector('button').addEventListener('click', (ev) => { ev.stopPropagation(); armReply(m); });
      wrap.appendChild(ha);
    }

    /* mobile: long-press => sheet · horizontal pan => telegram-style reply */
    let pressT = null, activePtr = null, sx = 0, sy = 0, axis = null, dragging = false, lastDx = 0;
    const inner = wrap.querySelector('.msg');
    const ghost = document.createElement('div');
    ghost.className = 'swipe-ghost'; ghost.textContent = '↩';
    wrap.appendChild(ghost);

    const clearPress = () => { if (pressT) { clearTimeout(pressT); pressT = null; } };
    const endDrag = (ok) => {
      if (!dragging) return;
      dragging = false;
      const dxv = lastDx || 0;
      wrap.classList.remove('swiping', 'armed');
      if (inner) inner.style.transform = '';
      if (ok && Math.abs(dxv) >= 48) {
        wrap.style.setProperty('--swipe-dx', dxv.toFixed(0) + 'px');
        wrap.classList.add('release-ok');
        setTimeout(() => { wrap.classList.remove('release-ok'); wrap.style.removeProperty('--swipe-dx'); }, 340);
        try { navigator.vibrate && navigator.vibrate(12); } catch {}
        armReply(m);
      }
      lastDx = 0;
    };
    wrap.addEventListener('pointerdown', (e) => {
      if (e.pointerType === 'mouse') return;
      if (e.target.closest('a,.reply-quote,.vp-play,.native-audio,video,img.media,input,textarea,.hover-actions,.up-progress,.file-chip')) return;
      activePtr = e.pointerId; sx = e.clientX; sy = e.clientY; axis = null;
      clearPress();
      pressT = setTimeout(() => { openSheet(m); clearPress(); }, 480);
    });
    wrap.addEventListener('pointermove', (e) => {
      if (e.pointerId !== activePtr) return;
      const mx = e.clientX - sx, my = e.clientY - sy;
      if (!axis) {
        if (Math.abs(mx) < 8 && Math.abs(my) < 8) return;
        if (Math.abs(mx) > Math.abs(my) * 1.2) axis = 'h';
        else { axis = 'v'; clearPress(); return; }
        dragging = true; clearPress();
        try { wrap.setPointerCapture(activePtr); } catch {}
        wrap.classList.add('swiping');
      }
      if (axis === 'h' && dragging) {
        lastDx = Math.max(-96, Math.min(96, mx));
        if (inner) inner.style.transform = `translateX(${lastDx}px)`;
        wrap.classList.toggle('armed', Math.abs(lastDx) >= 52);
      }
    });
    wrap.addEventListener('pointerup', (e) => {
      if (e.pointerId !== activePtr) return;
      activePtr = null; clearPress(); endDrag(axis === 'h'); axis = null;
    });
    wrap.addEventListener('pointercancel', (e) => {
      if (e.pointerId !== activePtr) return;
      activePtr = null; clearPress(); endDrag(false); axis = null;
    });
    wrap.addEventListener('dblclick', () => openSheet(m));
  }

  function openSheet(m) {
    sheetTargetId = m.id;
    $('msEdit').style.display = (isMine(m) && m.meta && m.meta.k === 'text' && m.iv) ? '' : 'none';
    $('msCopy').style.display = (m.iv || m.t != null) ? '' : 'none';
    $('msPinTxt').textContent = m.pin ? 'برداشتن سنجاق' : 'سنجاق کردن';
    msgSheet.classList.add('on');
    uiGuardPush();
  }
  msgSheet.addEventListener('click', (e) => { if (e.target === msgSheet) msgSheet.classList.remove('on'); });

  function hideCtxBanner() { ctxMode = null; $('ctxBanner').classList.remove('on'); }
  function showCtxBanner(title, preview) {
    $('ctxTitle').textContent = title; $('ctxPreview').textContent = preview || '';
    $('ctxBanner').classList.add('on');
  }
  $('ctxClose').onclick = hideCtxBanner;

  async function msgTextPreview(m) {
    if (m.iv) return decTextSafe(m.iv, m.c);
    return (m.t || '').slice(0, 100);
  }

  $('msReply').onclick = () => {
    msgSheet.classList.remove('on');
    armReply(msgs.get(sheetTargetId));
  };
  $('msCopy').onclick = async () => {
    msgSheet.classList.remove('on');
    const m = msgs.get(sheetTargetId); if (!m) return;
    try { await navigator.clipboard.writeText(await msgTextPreview(m)); toast('کپی شد ✓', 'ok'); }
    catch { toast('کپی ناموفق', 'err'); }
  };
  $('msEdit').onclick = () => {
    msgSheet.classList.remove('on');
    const m = msgs.get(sheetTargetId); if (!m) return;
    ctxMode = { mode: 'edit', id: m.id };
    decTextSafe(m.iv, m.c).then(t => { input.value = t; autosize(); updateSendState(); showCtxBanner('ویرایش پیام', t.slice(0, 90)); input.focus(); });
  };
  $('msDelete').onclick = () => {
    msgSheet.classList.remove('on');
    const id = sheetTargetId;
    confirmDialog('حذف پیام؟', 'این پیام برای همه حذف می‌شود.', 'حذف کن', async () => {
      await API('/api/delete', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ids: [id] }) }).catch(() => {});
    });
  };
  $('msPin').onclick = () => {   /* v30: pin/unpin via the message sheet */
    msgSheet.classList.remove('on');
    const m = msgs.get(sheetTargetId); if (!m) return;
    API('/api/pin', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id: m.id, pin: !m.pin }) }).catch(() => {});
  };

  /* reactions */
  /* v16 — tiny emoji sparks that fly out from the tap point (telegram-style, quick) */
  function reactBurst(x, y, emo) {
    try {
      if (matchMedia('(prefers-reduced-motion: reduce)').matches) return;
      const host = document.createElement('div');
      host.className = 'react-burst';
      host.style.left = x + 'px'; host.style.top = y + 'px';
      for (let i = 0; i < 7; i++) {
        const p = document.createElement('i');
        p.textContent = emo;
        const a = (Math.PI * 2 * i) / 7 + Math.random() * 0.55;
        const d = 30 + Math.random() * 32;
        p.style.setProperty('--tx', (Math.cos(a) * d).toFixed(1) + 'px');
        p.style.setProperty('--ty', (Math.sin(a) * d - 20).toFixed(1) + 'px');
        p.style.setProperty('--td', Math.round(Math.random() * 90) + 'ms');
        host.appendChild(p);
      }
      document.body.appendChild(host);
      setTimeout(() => host.remove(), 850);
    } catch {}
  }
  const rr = $('msReacts');
  for (const emo of REACTS) {
    const b = document.createElement('button'); b.textContent = emo;
    b.onclick = (e) => {
      msgSheet.classList.remove('on');
      /* v16: sparks fly from the bubble the reaction lands on (fallback: tap point) */
      const w = findEl(sheetTargetId);
      let x = e.clientX, y = e.clientY;
      if (w) {
        const r = w.getBoundingClientRect();
        x = r.left + r.width / 2; y = Math.max(r.top + 12, 70);
      }
      reactBurst(x, y, emo);
      toggleReaction(msgs.get(sheetTargetId), emo);
    };
    rr.appendChild(b);
  }
  async function toggleReaction(m, emo) {
    if (!m) return;
    let cur = '';
    if (m.reacts && m.reacts.c !== '=') cur = await decTextSafe(m.reacts.iv, m.reacts.c);
    const has = cur.includes(emo);
    let next = has ? cur.replace(emo, '') : (cur + emo).slice(0, 12);
    const payload = next.trim() === '' ? null : await encText(next);
    const body = payload ? { id: m.id, riv: payload.iv, rc: payload.c } : { id: m.id, clear: true };
    API('/api/react', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }).catch(() => {});
  }

  function applyReact(id, reacts) {
    const m = msgs.get(id); if (!m) return;
    m.reacts = reacts;
    const w = findEl(id);
    if (w) renderReacts(w, m);
  }

  function confirmDialog(title, bodyText, okLabel, cb) {
    $('cfTitle').textContent = title; $('cfBody').textContent = bodyText;
    $('cfOk').textContent = okLabel || 'باشه';
    const ov = $('confirmOv'); ov.hidden = false; ov.classList.add('on');
    const closeCf = () => { ov.classList.remove('on'); ov.hidden = true; };
    $('cfOk').onclick = () => { closeCf(); cb(); };
    $('cfCancel').onclick = closeCf;
    ov.onclick = (e) => { if (e.target === ov) closeCf(); };
  }

  /* ============================================================
     SSE
     ============================================================ */
  function setStatus(text, typing) {
    statusText.textContent = text;
    statusLine.classList.toggle('typing', !!typing);
    statusLine.querySelector('.tdots').hidden = !typing;
  }
  function composeStatus(presence) {
    if (!connected) {
      const longDown = streamDownAt && Date.now() - streamDownAt > 9000;
      return setStatus(longDown ? 'اتصال قطع شد — در حال تلاش مجدد…' : 'در حال اتصال…', false);
    }
    if (adminLinked === false) return setStatus('ربات وصل نیست — در تلگرام /start بزنید', false);
    const tgAlive = presence && presence.tg;
    if (presence && presence.typingFrom === 'tg') return setStatus('در حال نوشتن…', true);
    setStatus(tgAlive ? 'آنلاین · پل تلگرام فعال 🔒' : 'آنلاین · رمزنگاری فعال 🔒', false);
  }
  let typingHideTmr = null;

  /* weak-network banner: visible when offline or the stream has been down >6s */
  function updateNetBanner() {
    const b = $('netBanner');
    if (!b) return;
    let msg = '';
    if (app.classList.contains('on')) {
      if (!navigator.onLine) msg = '🔌 اینترنت قطع است — پیام‌ها در صف ذخیره می‌شوند';
      else if (!connected && streamDownAt && Date.now() - streamDownAt > 6000) msg = '📶 اتصال ضعیف — در حال تلاش برای اتصال مجدد…';
    }
    if (msg) { b.textContent = msg; b.classList.add('on'); } else b.classList.remove('on');
  }
  setInterval(updateNetBanner, 2500);

  let streamDownAt = 0, esAttempts = 0, esReconnTmr = 0;
  async function connectStream() {
    clearTimeout(esReconnTmr);
    if (es) try { es.close(); } catch {}
    lastStreamBeat = Date.now();
    /* v18: the session token never appears in URLs — fetch a 30s one-time
       ticket first (EventSource cannot set headers) */
    let tk = '';
    try {
      const tr = await API('/api/ticket', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
      if (tr.status === 401) { sessionInvalid(); return; }
      const tj = await tr.json();
      tk = tj.t || '';
    } catch {}
    if (!tk) {
      esAttempts = Math.min(esAttempts + 1, 5);
      clearTimeout(esReconnTmr);
      esReconnTmr = setTimeout(connectStream, 1200 + 400 * esAttempts);
      return;
    }
    es = new EventSource('/api/stream?tk=' + encodeURIComponent(tk) + '&dev=' + encodeURIComponent(deviceLabel()));
    es.onopen = () => {
      const wasDown = !connected || streamDownAt;
      connected = true; esAttempts = 0; streamDownAt = 0; lastStreamBeat = Date.now();
      composeStatus(lastPresence);
      updateNetBanner();
      /* pull anything that was missed while the line was down */
      if (wasDown && aesKey) refreshHistory(false).catch(() => {});
      if (wasDown) flushOutbox();
    };
    es.onerror = () => {
      if (!streamDownAt) streamDownAt = Date.now();
      connected = false; composeStatus(lastPresence); updateNetBanner();
      /* a consumed/failed ticket can never reconnect by itself — always take
         over with our own short capped backoff */
      try { es && es.close(); } catch {}
      es = null;
      esAttempts = Math.min(esAttempts + 1, 5);
      const wait = Math.min(6000, 400 * Math.pow(2, esAttempts)) + Math.random() * 400;
      clearTimeout(esReconnTmr);
      esReconnTmr = setTimeout(connectStream, wait);
    };
    es.onmessage = (ev) => {
      lastStreamBeat = Date.now();
      let d; try { d = JSON.parse(ev.data); } catch { return; }
      switch (d.type) {
        case 'msg': {
          onIncoming(d.m);
          break;
        }
        case 'edit': {
          const w = findEl(d.id);
          if (w) {
            const body = w.querySelector('.body');
            decTextSafe(d.iv, d.c).then(t => linkify(body, t));
            const m = msgs.get(d.id); if (m) { m.iv = d.iv; m.c = d.c; m.ed = true; }
            const et = w.querySelector('.edited-tag'); if (et) et.hidden = false;
          }
          break;
        }
        case 'del': (d.ids || []).forEach(removeById); resolvePinned(); break;
        case 'purge': (d.ids || []).forEach(removeById); resolvePinned(); break;
        case 'wipe':
          thread.innerHTML = ''; msgs.clear(); order.length = 0;
          lastSenderKey = null;
          try { outbox.length = 0; persistOutbox(); paintOutbox(); } catch {}   /* v27: /clear must also drop the offline queue */
          resolvePinned();
          toast('همه پیام‌ها پاک شدند 🧹');
          break;
        case 'react': applyReact(d.id, d.reacts); break;
        case 'pin': {   /* v30: live pin/unpin from any device */
          const pm = msgs.get(d.id);
          if (pm) { pm.pin = !!d.pin; paintPinFlag(findEl(d.id), pm); resolvePinned(); }
          break;
        }
        case 'seen':
          // peer opened/interacted: mark my recent outgoing as read
          order.forEach(id => { const m = msgs.get(id); if (m && isMine(m)) m.read = true; });
          paintTicks();
          break;
        case 'update': {
          const m = msgs.get(d.id);
          if (m && d.patch) Object.assign(m, d.patch);
          paintTicks();
          break;
        }
        case 'profile': {
          if (d.side === 'tg') { state.tgPersona.name = d.name || state.tgPersona.name; state.tgPersona.photo = d.photo || ''; }
          else if (d.side === 'user') {
            /* v18: per-name profile updated somewhere */
            const key = String(d.name || '').toLowerCase();
            if (key) {
              state.profiles[key] = Object.assign({}, state.profiles[key] || {}, { name: d.name, photo: d.photo || '', updated: Date.now() });
            }
            if (d.name === prefs.name) { /* my other device */ }
          }
          updatePeerHeader();
          repaintAvatars();   /* v28: live persona/profile change must reach bubbles too */
          toast(d.side === 'tg' ? 'پروفایل ربات آپدیت شد' : 'پروفایل «' + (d.name || '?') + '» آپدیت شد');
          break;
        }
        case 'claim': {
          /* v18: an access request was approved — as an authorized session we
             turn the ephemeral code into an opaque CK wrap (CK never leaves) */
          (async () => {
            try {
              if (!aesKey || !d.code || !d.id) return;
              const bits = await crypto.subtle.digest('SHA-256', te.encode('claim:' + d.code));
              const wk = await hkdfWrapKey(new Uint8Array(bits), 'ck-wrap-v1');
              const wrap = await aesEnc(wk, new Uint8Array(await crypto.subtle.exportKey('raw', aesKey)));
              await API('/api/claim-wrap', { method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ id: d.id, code: d.code, wrap }) });
            } catch { /* best effort */ }
          })();
          break;
        }
        case 'finger': {
          /* v27: fingerprint-login lifecycle events (approve/deny/register/remove) */
          if (d.status === 'approved') toast('✋ ادمین ورود با اثر انگشت را تایید کرد — از تنظیمات ثبتش کنید', 'ok', 6000);
          else if (d.status === 'denied') toast('❌ درخواست اثر انگشت توسط ادمین رد شد', 'err', 5000);
          else if (d.status === 'registered') toast('اثر انگشت این دستگاه ثبت شد ✓', 'ok', 4500);
          else if (d.status === 'removed') toast('ورود با اثر انگشت غیرفعال شد');
          fingerRefresh();
          break;
        }
        case 'device': {
          /* v29: trusted-device lifecycle (approve/deny/revoke from Telegram) */
          if (d.status === 'approved' && (!d.devId || d.devId === devIdGet()))
            toast('📱 ادمین این دستگاه را تایید کرد — بدون رمز وارد شوید ✓', 'ok', 6000);
          else if (d.status === 'denied' && (!d.devId || d.devId === devIdGet()))
            toast('❌ درخواست اعتماد دستگاه توسط ادمین رد شد', 'err', 5000);
          else if (d.status === 'revoked' && d.devId && d.devId === devIdGet()) {
            try { localStorage.removeItem(DEV_PRIV_KEY); } catch {}
            try { localStorage.removeItem(DEV_PUB_KEY); } catch {}
            toast('⛔ اعتماد این دستگاه لغو شد', 'err', 5000);
          } else if (d.status === 'revoked') toast('⛔ اعتماد یک دستگاه لغو شد');
          try { devRefresh(); } catch {}
          try { updDevGateBtn(); } catch {}
          break;
        }
        case 'title': {
          /* v15: admin changed the brand with /title — apply live */
          if (d.title) { applyTitle(d.title); toast('عنوان سایت: ' + d.title); }
          break;
        }
        case 'revoked': {
          /* server-side revocation (/revoke, /pass, /revoke<sid>): kill the local
             session too, so the reload lands on the gate before any 401 comes back */
          (async () => { try { await clearStoredSession(); } catch {} try { sessionStorage.removeItem('vault_tok'); } catch {} })();
          toast(d.single ? '⛔ این نشست توسط ادمین اخراج شد' : '🔒 نشست پایان یافت — دوباره وارد شوید', 'err', 4200);
          setTimeout(() => location.reload(), 1600);
          break;
        }
        case 'presence':
          adminLinked = d.adminLinked !== undefined ? d.adminLinked : adminLinked;
          lastPresence = d;
          if (d.tgSeen) { lastSeen.tg = d.tgSeen; paintSeen(); }   /* v29: live TG last-seen */
          composeStatus(d);
          $('presenceDot').classList.toggle('on', (d.n || 0) >= 2);
          break;
      }
      if (d.type === 'typing' && Date.now() - (d.at || 0) < 5000) {
        setStatus('در حال نوشتن…', true);
        clearTimeout(typingHideTmr);
        typingHideTmr = setTimeout(() => composeStatus(lastPresence), 3600);
      }
    };

    /* heartbeat watchdog: force a fast reconnect when the stream silently dies
       v25: 30s (2 missed 15s beats) — Iranian CGNAT kills idle sockets quietly */
    if (hbTimer) clearInterval(hbTimer);
    hbTimer = setInterval(() => {
      if (!es || !connected) return;
      if (Date.now() - lastStreamBeat > 30000) {
        try { es.close(); } catch {}
        connected = false;
        if (!streamDownAt) streamDownAt = Date.now();
        composeStatus(lastPresence);
        es = null;
        setTimeout(connectStream, 300);
      }
    }, 5000);
  }
  let lastPresence = {};
  let hbTimer = null, lastStreamBeat = 0;

  function onIncoming(m) {
    if (seenIds.has(m.id)) return;
    seenIds.add(m.id);
    order.push(m.id);
    msgs.set(m.id, m);
    const mine = isMine(m);
    lastSenderKey = null; // force grouping calc from history end — approximate
    bubbleNode(m, mine, order.length % 400);
    scrollDown(false);
    if (!mine) {
      if (document.visibilityState !== 'visible') {
        unread++; paintJump();
        playPing();
        msgTextPreview(m).then(t => notifyIncoming(m, t));
      } else {
        API('/api/seen', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' }).catch(() => {});
      }
    }
  }

  function removeById(id) {
    const elx = findEl(id);
    if (elx) { elx.classList.add('removing'); setTimeout(() => elx.remove(), 280); }
    seenIds.delete(id); msgs.delete(id);
    const i = order.indexOf(id); if (i >= 0) order.splice(i, 1);
  }

  function paintTicks() {
    order.forEach(id => {
      const m = msgs.get(id); if (!m || !isMine(m)) return;
      const w = findEl(id); if (!w) return;
      const t = w.querySelector('.tick'); if (!t) return;
      t.className = 'tick' + (m.dl ? ' dbl' : '') + (m.read ? ' read' : '');
      t.innerHTML = `<svg viewBox="0 0 ${m.dl ? 24 : 20} 11"><path d="${m.dl ? 'M1.5 5.8l3.4 3.4L12 2M10.4 7.5l1.6 1.6L22.6 2.4M15.7 5.9c-.3-.4-.6-.2-.4.1.2.2.5 0 .3-.3-.2-.2-.6 0-.3.4' : 'M3 5.5l4 4L18 2'}"/></svg>`;
    });
  }

  /* ============================================================
     HISTORY & PEER HEADER
     ============================================================ */
  async function refreshHistory(initial) {
    try {
      const r = await API('/api/history');
      if (r.status === 401) { sessionInvalid(); return; }   /* token dead -> back to gate */
      if (!r.ok) return;
      const h = await r.json();
      state.tgPersona = h.tgPersona || state.tgPersona;
      state.sitePersona = h.sitePersona || state.sitePersona;
      state.profiles = h.profiles || state.profiles;          // v18
      state.legacySender = h.legacySender || state.legacySender; // v18
      lastSenderKey = null;   // v18: fresh grouping per history pass
      updatePeerHeader();
      for (const mm of h.messages) {
        if (seenIds.has(mm.id)) continue;
        seenIds.add(mm.id); order.push(mm.id);
        const mine = !!(mm.meta && mm.meta.from && mm.meta.from !== 'tg' && mm.meta.from === myTag);
        bubbleNode(mm, mine, initial ? order.length : 400);
      }
      $('presenceDot').classList.toggle('on', (h.presence && h.presence.n >= 2));
      adminLinked = !!(h.presence && h.presence.tg) || adminLinked;
      composeStatus(h.presence);
      if (h.lastSeen) {                        /* v29: real snapshots — refresh popover */
        if (h.lastSeen.tg) lastSeen.tg = h.lastSeen.tg;
        if (h.lastSeen.users) lastSeen.users = h.lastSeen.users;
        paintSeen();
      }
      scrollDown(initial);
      setTimeout(() => scrollDown(false), 350);
      resolvePinned();   /* v30: restore the pinned banner after every history pass */
    } catch {}
  }

  function updatePeerHeader() {
    const p = state.tgPersona;
    let phUrl = null;
    if (p.photo === '__tgphoto__') phUrl = urlOf('persona:tg') || '/__needfetch';
    else if (p.photo && p.photo.startsWith('data:')) phUrl = p.photo;
    if (phUrl && phUrl !== '/__needfetch') {
      $('peerPhotoImg').src = phUrl; $('peerPhotoImg').hidden = false;
      document.querySelector('.avatar-fallback').style.display = 'none';
    } else {
      $('peerPhotoImg').hidden = true;
      document.querySelector('.avatar-fallback').style.display = '';
      if (phUrl === '/__needfetch') loadTgPhoto();
    }
    if (p.name) {
      const h = $('peerName');
      h.firstChild.nodeValue = p.name + ' ';
      $('ppName').textContent = p.name;
    }
    if ($('ppSub')) $('ppSub').textContent = bridgeOn
      ? 'پل ربات تلگرام فعال · پیام‌های تلگرامی رمزنگاری سرتاسری ندارند'
      : 'پل ربات غیرفعال';
    paintSeen();   /* v29: live last-seen line under the peer sub */
    applyPeerPopAvatar();
  }
  async function loadTgPhoto() {
    try {
      const r = await API('/api/tgphoto');
      if (!r.ok) return;
      const b = await r.blob();
      mediaUrls.set('persona:tg', URL.createObjectURL(b));
      updatePeerHeader();
      repaintAvatars();   /* v28: bubbles painted before the photo landed */
    } catch {}
  }
  function applyPeerPopAvatar() {
    const pp = $('ppAvatar');
    const u = urlOf('persona:tg');
    pp.innerHTML = '';
    if (u) { const i = new Image(); i.src = u; i.style.cssText = 'width:100%;height:100%;object-fit:cover'; pp.appendChild(i); }
    else pp.textContent = '🛡';
  }

  /* v28: backfill avatar photos onto already-painted bubbles.
     History is painted the moment the socket opens, but the persona / profile
     photo blob arrives a beat later (async fetch) — bubbles kept the letter
     fallback forever (header showed the photo, messages did not). This walks
     every painted message and swaps the real photo in when it exists. */
  function repaintAvatars() {
    for (const id of order) {
      const m = msgs.get(id);
      if (!m || isMine(m)) continue;
      const wrap = thread.querySelector('[data-id="' + CSS.escape(String(id)) + '"]');
      if (!wrap) continue;
      const av = wrap.querySelector('.mavatar');
      if (!av) continue;
      const isTg = !!(m.meta && m.meta.tg);
      const nm = senderNameOf(m);
      let u = null;
      if (isTg) u = urlOf('persona:tg') || null;
      else {
        const prof = state.profiles[String(nm).toLowerCase()];
        if (prof && prof.photo) u = prof.photo;
      }
      if (!u) continue;
      const im = av.querySelector('img');
      if (im) { if (im.getAttribute('src') !== u) im.src = u; }
      else {
        av.textContent = '';
        const nim = document.createElement('img');
        nim.src = u;
        av.appendChild(nim);
        av.style.background = '';
      }
    }
  }

  /* ============================================================
     COMPOSER
     ============================================================ */
  function autosize() {
    input.style.height = 'auto';
    input.style.height = Math.min(input.scrollHeight, 132) + 'px';
  }
  function updateSendState() {
    const has = input.value.trim().length > 0;
    sendBtn.disabled = !has || !aesKey;
    sendBtn.classList.toggle('hidden-mic-btn', false);
    micBtn.classList.toggle('hidden-mic', has);
  }
  input.addEventListener('input', () => {
    autosize(); updateSendState(); paintCount();
    if (!ctxMode && Date.now() - lastTypingSent > 4200 && aesKey) {
      lastTypingSent = Date.now();
      API('/api/typing', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' }).catch(() => {});
    }
  });
  input.addEventListener('keydown', (e) => {
    if (e.isComposing || e.keyCode === 229) return;   /* IME safety */
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); submitComposer(); }
  });
  sendBtn.addEventListener('click', submitComposer);

  let busy = false;
  async function submitComposer() {
    const text = input.value.trim();
    if (!text || !aesKey || busy) return;
    busy = true;
    /* v16: quick dock pop (edit path stays calm) */
    if (!(ctxMode && ctxMode.mode === 'edit')) {
      sendBtn.classList.remove('pop'); void sendBtn.offsetWidth; sendBtn.classList.add('pop');
    }

    if (ctxMode && ctxMode.mode === 'edit') {
      const m = msgs.get(ctxMode.id); hideCtxBanner();
      if (m) {
        const pay = await encText(text);
        await API('/api/edit', { method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ id: m.id, iv: pay.iv, c: pay.c }) }).catch(() => {});
        /* v19: the TG mirror copy is EDITED in place instead of duplicated */
        mirrorOut(m.id, text, m.meta, true);
      }
      resetComposer(); busy = false; return;
    }

    const meta = ctxMode && ctxMode.mode === 'reply'
      ? { k: 'text', rt: ctxMode.id, from: myTag, un: prefs.name || '' }
      : { k: 'text', from: myTag, un: prefs.name || '' };
    hideCtxBanner();

    const parts = splitForSend(text);
    let sent = 0, failMsg = null;
    try {
      for (let i = 0; i < parts.length; i++) {
        const pay = await encText(parts[i]);
        const r = await API('/api/send', { method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ iv: pay.iv, c: pay.c, meta }) });
        if (r.status === 429) { failMsg = 'کمی آهسته‌تر — محدودیت ارسال'; break; }
        if (!r.ok) { failMsg = 'ارسال ناموفق'; break; }
        const j = await r.json();
        onIncoming({ id: j.id, ts: j.ts, iv: pay.iv, c: pay.c, meta, reacts: null });
        paintTicks();
        mirrorOut(j.id, parts[i], meta);
        sent++;
        if (i < parts.length - 1) await new Promise(res => setTimeout(res, 280));
      }
    } catch { failMsg = 'خطای شبکه در ارسال'; }
    if (failMsg) {
      const rest = parts.slice(sent);
      if (rest.length) {
        queueOutbox(rest);   /* weak net: queue now, auto-send when the line returns */
        toast('📬 ' + faDigits(rest.length) + ' بخش در صف ارسال — با وصل‌شدن اینترنت می‌رود', 'ok', 3600);
      } else toast(failMsg, 'err');
      resetComposer();
      busy = false; return;
    }
    resetComposer();
    busy = false; input.focus();
  }
  function resetComposer() { input.value = ''; autosize(); updateSendState(); charcount.textContent = ''; }
  window.addEventListener('resize', autosize);

  /* ---- long messages: split into <=1024-char parts, sent in order ---- */
  const MSG_PART = 1024, MSG_MAX = 8192;
  function splitForSend(t) {
    if (t.length <= MSG_PART) return [t];
    const parts = []; let s = t;
    while (s.length > MSG_PART && parts.length < 40) {
      let cut = s.lastIndexOf('\n', MSG_PART);          /* prefer a line break */
      if (cut < MSG_PART * 0.5) cut = s.lastIndexOf(' ', MSG_PART); /* then a space */
      if (cut < MSG_PART * 0.5) cut = MSG_PART;          /* hard cut as last resort */
      parts.push(s.slice(0, cut));
      s = s.slice(cut).replace(/^[ \t]+/, '');
    }
    if (s) parts.push(s);
    return parts;
  }
  function paintCount() {
    const n = input.value.length;
    if (!n) { charcount.textContent = ''; return; }
    const extra = n > MSG_PART ? ' • ' + faDigits(Math.ceil(n / MSG_PART)) + ' بخش' : '';
    charcount.textContent = faDigits(n) + '/۸۱۹۲' + extra;
    charcount.classList.toggle('hot', n > MSG_MAX - 300);
  }

  /* ---- keep --dock-h synced to the REAL dock height so no message can
         hide behind the floating dock; if the user is at the bottom,
         keep them pinned across dock growth, resize and rotation ---- */
  const zone = document.querySelector('.composer-zone');
  let pinned = true;   /* live "user is at bottom" flag (120px tolerance) */
  let pinLock = 0;     /* during resize/rotation the browser re-anchors scrollTop and
                          fires scroll events mid-chat — ignore those, keep the flag */
  scroller.addEventListener('scroll', () => {
    if (Date.now() < pinLock) return;
    pinned = scroller.scrollHeight - scroller.scrollTop - scroller.clientHeight < 120;
  }, { passive: true });
  function syncDockH() {
    const h = Math.round(zone.getBoundingClientRect().height);
    if (h > 0) document.documentElement.style.setProperty('--dock-h', h + 'px');
    requestAnimationFrame(() => {
      if (pinned) { pinLock = Date.now() + 400; scroller.scrollTop = scroller.scrollHeight; }
    });
  }
  if ('ResizeObserver' in window) {
    new ResizeObserver(syncDockH).observe(zone);
    new ResizeObserver(syncDockH).observe(scroller);  /* rotation / keyboard / --vvh changes */
  }
  window.addEventListener('resize', () => { pinLock = Date.now() + 500; syncDockH(); });
  window.addEventListener('orientationchange', () => { pinLock = Date.now() + 600; setTimeout(syncDockH, 150); });
  syncDockH();

  /* plaintext mirrors to telegram (best effort) — v19: isEdit edits the
     already-mirrored TG copy in place (server decides; graceful fallback) */
  async function mirrorOut(mid, text, meta, isEdit) {
    try {
      const r = await API('/api/mirror/text', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mid, text: String(text).slice(0, 1024), edit: !!isEdit }) });
      if (r.ok) { const m = msgs.get(mid); if (m) { m.dl = true; paintTicks(); } }
      void meta;
    } catch { /* offline bot */ }
  }

  /* ---- offline outbox: messages typed while the net is down, auto-sent on reconnect ---- */
  let outbox = [];
  try { outbox = JSON.parse(localStorage.getItem('vault_outbox') || '[]') || []; } catch { outbox = []; }
  let flushing = false;
  function persistOutbox() { try { localStorage.setItem('vault_outbox', JSON.stringify(outbox)); } catch {} }
  function paintOutbox() {
    const chip = $('outboxChip');
    if (!chip) return;
    if (!outbox.length) { chip.hidden = true; return; }
    chip.hidden = false;
    chip.textContent = '📬 ' + faDigits(outbox.length) + ' پیام در صف ارسال — وقتی نت بیاد ارسال میشه';
  }
  function queueOutbox(parts) {
    for (const p of parts) outbox.push({ t: p, ts: Date.now() });
    if (outbox.length > 40) outbox = outbox.slice(-40);
    persistOutbox(); paintOutbox();
  }
  async function flushOutbox() {
    if (flushing || !aesKey || !outbox.length || !navigator.onLine) return;
    flushing = true;
    try {
      while (outbox.length) {
        const item = outbox[0];
        const pay = await encText(item.t);
        const r = await API('/api/send', { method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ iv: pay.iv, c: pay.c, meta: { k: 'text', from: myTag } }) });
        if (r.status === 400 || r.status === 404) {   /* poison payload: drop it */
          outbox.shift(); persistOutbox(); paintOutbox();
          continue;
        }
        if (r.status === 401) { sessionInvalid(); break; }
        if (!r.ok) break;                            /* still down / rate-limited */
        const j = await r.json();
        onIncoming({ id: j.id, ts: j.ts, iv: pay.iv, c: pay.c, meta: { k: 'text', from: myTag, un: prefs.name || '' }, reacts: null });
        paintTicks();
        mirrorOut(j.id, item.t, { k: 'text' });
        outbox.shift(); persistOutbox(); paintOutbox();
        if (outbox.length) await new Promise(res => setTimeout(res, 350));
      }
      if (!outbox.length) toast('همهٔ پیام‌های صف ارسال شد ✓', 'ok');
    } catch { /* still offline — retried by the next trigger */ }
    flushing = false;
  }
  setInterval(() => { if (outbox.length && app.classList.contains('on')) flushOutbox(); }, 20000);
  $('outboxChip').onclick = () => flushOutbox();

  /* ============================================================
     ATTACHMENTS / UPLOAD PIPELINE
     ============================================================ */
  const KIND_CAPS = { image: 15, video: 50, voice: 25, audio: 40, file: 45 };

  function classify(f) {
    if (f.type.startsWith('image/')) return 'image';
    if (f.type.startsWith('video/')) return 'video';
    if (f.type.startsWith('audio/')) return 'voice';
    return 'file';
  }

  $('attachBtn').onclick = () => { $('attachSheet').classList.add('on'); uiGuardPush(); };
  $('attachSheet').addEventListener('click', (e) => {
    if (e.target === $('attachSheet')) $('attachSheet').classList.remove('on');
  });
  document.querySelectorAll('#attachSheet [data-act]').forEach(btn => {
    btn.addEventListener('click', () => {
      const act = btn.dataset.act;
      $('attachSheet').classList.remove('on');
      if (act === 'gallery') $('fileInput').click();
      else if (act === 'music') $('musicInput').click();
      else if (act === 'file') $('docInput').click();
      else if (act === 'sticker') { openPanel('sticker'); }
    });
  });
  for (const id of ['fileInput', 'musicInput', 'docInput']) {
    $(id).addEventListener('change', async (e) => {
      const files = Array.from(e.target.files || []);
      e.target.value = '';
      if (!files.length) return;
      let kindOverride = null;
      if (id === 'musicInput') kindOverride = 'audio';
      else if (id === 'docInput') kindOverride = 'file';
      stageMedia(files, kindOverride);   /* v24: stage first — caption optional, then send */
    });
  }

  /* ============================================================
     v24 CAPTION STAGING — picked media lands in a compact bar above the
     composer: bytes upload immediately (progress in the bar), the user can
     type a caption, then one tap sends everything. First item carries the
     caption (telegram-album style); it is mirrored to TG via x-vault-cap.
     ============================================================ */
  const capBar = $('capBar'), capInput = $('capInput'), capSendBtn = $('capSend'),
        capNameEl = $('capName'), capStateEl = $('capState'), capIconEl = $('capIcon');
  let capBatch = null;
  const KIND_ICON = { image: '🖼', video: '🎬', voice: '🎤', audio: '🎵', file: '📎' };
  function hideCapBar() { capBar.hidden = true; capBar.classList.remove('on'); capBatch = null; }
  $('capCancel').onclick = () => { hideCapBar(); toast('لغو شد'); };
  capInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); sendCapBatch(); } });
  capSendBtn.onclick = sendCapBatch;

  function stageMedia(files, kindOverride) {
    if (!aesKey) { toast('اول وارد شوید', 'err'); return; }
    const list = files.slice(0, 6);
    capBatch = { items: [], total: list.length, reply: (ctxMode && ctxMode.mode === 'reply') ? ctxMode.id : undefined, dead: false };
    hideCtxBanner();
    capBar.hidden = false; capBar.classList.add('on');
    capInput.value = '';
    capSendBtn.disabled = true;
    capIconEl.textContent = KIND_ICON[kindOverride || classify(list[0])] || '📎';
    capNameEl.textContent = list.length > 1 ? faDigits(list.length) + ' فایل انتخاب شد' : (list[0].name || 'فایل');
    capStateEl.textContent = 'در حال آماده‌سازی…';
    (async () => {
      for (let i = 0; i < list.length; i++) {
        if (capBatch.dead) return;
        const f = list[i];
        const k = kindOverride || classify(f);
        const capMB = (KIND_CAPS[k] || 30);
        if (f.size > capMB * 1048576) { capStateEl.textContent = 'خطا: حجم ' + (f.name || 'فایل') + ' بیش از حد (' + faNums2(capMB) + 'MB)'; toast('حجم بیش از حد مجاز', 'err'); capBatch.dead = true; setTimeout(hideCapBar, 1600); return; }
        try {
          capStateEl.textContent = 'آپلود ' + faDigits(i + 1) + ' از ' + faDigits(list.length) + '…';
          const item = await uploadOne(f, k, (p) => {
            if (!capBatch || capBatch.dead) return;
            capStateEl.textContent = 'آپلود ' + faDigits(i + 1) + ' از ' + faDigits(list.length) + ' — ' + faDigits(Math.round(p * 100)) + '٪';
          });
          if (!capBatch || capBatch.dead) return;
          capBatch.items.push(item);
        } catch (er) {
          if (capBatch) { capBatch.dead = true; capStateEl.textContent = 'آپلود ناموفق — دوباره تلاش کنید'; }
          toast('آپلود ناموفق: ' + (er && er.message ? er.message : ''), 'err');
          setTimeout(() => { if (capBatch && capBatch.dead) hideCapBar(); }, 1800);
          return;
        }
      }
      if (capBatch && !capBatch.dead) {
        capStateEl.textContent = 'آمادهٔ ارسال ✓ — کپشن اختیاری است';
        capSendBtn.disabled = false;
        try { capInput.focus(); } catch {}
      }
    })();
  }
  const faNums2 = faDigits;   /* readability alias */

  async function sendCapBatch() {
    if (!capBatch || !capBatch.items.length || !aesKey) return;
    const batch = capBatch;
    const cap = capInput.value.trim().slice(0, 900);
    capSendBtn.disabled = true;
    capStateEl.textContent = 'در حال ارسال…';
    let sent = 0;
    try {
      for (let i = 0; i < batch.items.length; i++) {
        const it = batch.items[i];
        const text = (i === 0 && cap) ? cap : (it.file.name || it.kind).slice(0, 120);
        const nEnc = await encText(text);
        const meta = { k: it.kind, from: myTag, un: prefs.name || '', blob: it.bid, name: (it.file.name || it.kind).slice(0, 120), mime: it.file.type, size: it.file.size };
        if (batch.reply) meta.rt = batch.reply;
        const r = await API('/api/send', { method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ iv: nEnc.iv, c: nEnc.c, meta }) });
        if (r.status === 429) { toast('کمی آهسته‌تر — محدودیت ارسال', 'err'); break; }
        if (!r.ok) throw new Error('send failed');
        const j = await r.json();
        onIncoming({ id: j.id, ts: j.ts, iv: nEnc.iv, c: nEnc.c, meta, reacts: null });
        sent++;
        /* mirror plaintext bytes to telegram — caption on the first item only */
        try {
          const rr = await fetch('/api/mirror/media', {
            method: 'POST',
            headers: Object.assign({
              'Content-Type': 'application/octet-stream',
              'x-vault-mid': j.id,
              'x-vault-kind': it.kind,
              'x-vault-mime': encodeURIComponent(it.file.type || ''),
              'x-vault-name': encodeURIComponent((it.file.name || 'file').slice(0, 90)),
              'x-vault-cap': encodeURIComponent(i === 0 ? cap : ''),
            }, tok ? { Authorization: 'Bearer ' + tok } : {}),
            body: it.file,
          });
          if (rr.ok) { const m2 = msgs.get(j.id); if (m2) { m2.dl = true; paintTicks(); } }
        } catch {}
      }
    } catch { toast('ارسال ناموفق', 'err'); }
    hideCapBar();
    if (sent) toast(faDigits(sent) + ' مورد ارسال شد ✓', 'ok');
  }

  /* upload ONE file: compress if image → encrypt (data+mime in parallel) →
     PUT /api/blob. Returns {bid, file, kind}. Shared by caption staging + voice. */
  async function uploadOne(f, k, onProg) {
    let file = f;
    if (k === 'image') file = await compressImage(f);
    const bytes = new Uint8Array(await file.arrayBuffer());
    const [dEnc, mEnc] = await Promise.all([
      encryptBuf(bytes),
      encryptBuf(te.encode(file.type || 'application/octet-stream')),
    ]);
    const payload = JSON.stringify({ iv: dEnc.iv, c: dEnc.c, miv: mEnc.iv, mc: mEnc.c });
    let j = null, upErr = null;
    for (let att = 0; att < 2; att++) {
      try {
        j = await xhrPut('/api/blob', payload, onProg, { 'Content-Type': 'application/octet-stream' });
        upErr = null;
        break;
      } catch (er) {
        upErr = er;
        if (att === 0) await sleep(900);
      }
    }
    if (!j || !j.bid) throw (upErr || new Error('upload failed'));
    mediaUrls.set(j.bid, URL.createObjectURL(new Blob([bytes], { type: file.type })));
    return { bid: j.bid, file, kind: k };
  }

  async function compressImage(file) {
    /* v18: gentler compression — only big images, larger canvas, higher quality */
    if (!/^image\/(png|jpe?g|webp)/.test(file.type) || file.size < 2.5 * 1024 * 1024) return file;
    try {
      const img = await createImageBitmap(file);
      const scale = Math.min(1, 2400 / Math.max(img.width, img.height));
      const cv = new OffscreenCanvas(Math.round(img.width * scale), Math.round(img.height * scale));
      cv.getContext('2d').drawImage(img, 0, 0);
      const blob = await cv.convertToBlob({ type: 'image/jpeg', quality: .88 });
      if (blob.size < file.size) return new File([blob], (file.name || 'photo') + '.jpg', { type: 'image/jpeg' });
    } catch {}
    return file;
  }

  /* XHR with progress ring bubble */
  function xhrPut(url, blob, onProg, headers) {
    return new Promise((resolve, reject) => {
      const x = new XMLHttpRequest();
      x.open('PUT', url);
      if (tok) x.setRequestHeader('Authorization', 'Bearer ' + tok);
      for (const [k, v] of Object.entries(headers || {})) x.setRequestHeader(k, v);
      x.upload.onprogress = (e) => { if (e.lengthComputable && onProg) onProg(e.loaded / e.total); };
      x.onload = () => (x.status >= 200 && x.status < 300) ? resolve(JSON.parse(x.responseText || '{}')) : reject(new Error('HTTP ' + x.status));
      x.onerror = () => reject(new Error('network'));
      x.send(blob);
    });
  }

  async function sendMediaFile(f, kindOverride) {
    /* v24: kept for the voice path (voice notes have no captions in Telegram) */
    const k = kindOverride || classify(f);
    const capMB = KIND_CAPS[k] || 30;
    if (f.size > capMB * 1048576) { toast(`حجم بیش از حد مجاز (${capMB} مگابایت)`, 'err'); return; }
    const reply = ctxMode && ctxMode.mode === 'reply' ? ctxMode.id : undefined;
    hideCtxBanner();
    try {
      let item;
      try {
        item = await uploadOne(f, k, null);
      } catch (er) { throw (er || new Error('upload failed')); }
      const file = item.file;
      const nEnc = await encText((file.name || 'فایل').slice(0, 120));
      const metaPayload = { k, from: myTag, un: prefs.name || '', blob: item.bid, name: (file.name || 'فایل').slice(0, 120), mime: file.type, size: file.size };
      if (reply) metaPayload.rt = reply;
      const r = await API('/api/send', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ iv: nEnc.iv, c: nEnc.c, meta: metaPayload }) });
      if (!r.ok) throw new Error('send failed');
      const jj = await r.json();
      onIncoming({ id: jj.id, ts: jj.ts, iv: nEnc.iv, c: nEnc.c, meta: metaPayload, reacts: null });
      /* 3) mirror plaintext bytes to telegram */
      try {
        const rr2 = await fetch('/api/mirror/media', {
          method: 'POST',
          headers: Object.assign({
            'Content-Type': 'application/octet-stream',
            'x-vault-mid': jj.id,
            'x-vault-kind': k,
            'x-vault-mime': encodeURIComponent(file.type || ''),
            'x-vault-name': encodeURIComponent((file.name || 'file').slice(0, 90)),
            'x-vault-cap': encodeURIComponent(''),
          }, tok ? { Authorization: 'Bearer ' + tok } : {}),
          body: file,
        });
        if (rr2.ok) { const m2 = msgs.get(jj.id); if (m2) { m2.dl = true; paintTicks(); } }
      } catch {}
    } catch (e) {
      toast(e.message === 'network' ? 'خطای شبکه در آپلود' : 'ارسال رسانه ناموفق: ' + e.message, 'err');
    }
  }

  /* ============================================================
     VOICE RECORDER
     ============================================================ */
  let recorder = null, recChunks = [], recStart = 0, recTmr = null;
  $('micBtn').onclick = startRecording;
  async function startRecording() {
    if (recorder) return stopRecording(true);
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      let mimePick = '';
      for (const mm of ['audio/webm;codecs=opus', 'audio/webm', 'audio/mp4']) {
        if (MediaRecorder.isTypeSupported(mm)) { mimePick = mm; break; }
      }
      recorder = new MediaRecorder(stream, mimePick ? { mimeType: mimePick } : undefined);
      recChunks = []; recStart = Date.now();
      recorder.ondataavailable = ev => { if (ev.data.size) recChunks.push(ev.data); };
      recorder.onstop = () => { stream.getTracks().forEach(t => t.stop()); finalizeRec(); };
      recorder.start();
      $('recBar').classList.add('on');
      $('recWave').innerHTML = Array.from({ length: 22 }, (_, i) =>
        `<i style="--wh:${20 + ((i * 37) % 75)}%;animation-delay:${(i % 7) * .09}s"></i>`).join('');
      API('/api/typing', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{"rec":1}' }).catch(() => {});
      recTmr = setInterval(() => {
        const s = Math.floor((Date.now() - recStart) / 1000);
        $('recTime').textContent = faDigits(Math.floor(s / 60) + ':' + String(s % 60).padStart(2, '0'));
        if (s >= 600) stopRecording(true);
      }, 250);
    } catch { toast('دسترسی به میکروفون داده نشد', 'err'); }
  }
  function stopRecording(sendFlag) {
    if (!recorder) return;
    recorder.__send = sendFlag;
    clearInterval(recTmr);
    $('recBar').classList.remove('on');
    try { recorder.stop(); } catch {}
  }
  $('recStop').onclick = () => stopRecording(true);
  $('recBar').addEventListener('pointerdown', (e) => { window.__recX = e.clientX; });
  $('recBar').addEventListener('pointermove', (e) => {
    if (window.__recX !== undefined && Math.abs(e.clientX - window.__recX) > 90) { window.__recX = undefined; stopRecording(false); toast('ضبط لغو شد'); }
  });
  $('recBar').addEventListener('pointerup', () => { window.__recX = undefined; });

  async function finalizeRec() {
    const dur = (Date.now() - recStart) / 1000;
    const wasSend = recorder.__send;
    recorder = null;
    if (!wasSend || !recChunks.length || dur < 0.7) return;
    const blob = new Blob(recChunks, { type: recChunks[0].type || 'audio/webm' });
    const ext = /mp4/.test(blob.type) ? '.m4a' : '.webm';
    await sendMediaFile(new File([blob], 'voice-' + Date.now() + ext, { type: blob.type }), dur > 0 ? 'voice' : 'voice');
  }

  /* ============================================================
     EMOJI / STICKER PANEL
     ============================================================ */
  const panel = $('emojiPanel');
  function switchTab(name) {
    panel.querySelectorAll('.tab').forEach(t => t.classList.toggle('on', t.dataset.tab === name));
    panel.querySelectorAll('.pane').forEach(p => p.classList.toggle('on', p.dataset.pane === name));
  }
  panel.querySelectorAll('.tab').forEach(t => {
    t.onclick = () => {
      switchTab(t.dataset.tab);
      if (t.dataset.tab === 'sticker') loadStickers();   /* lazy-load on every entry */
      else buildEmojiPane();
    };
  });

  /* panel open/close — Telegram-style: panel slides up, the dock rides on top of it */
  function openPanel(name) {
    if (document.activeElement === input) input.blur();   // dismiss keyboard so panel sits on the real bottom
    const tabName = name === 'sticker' ? 'sticker' : 'emoji';
    switchTab(tabName);
    if (tabName === 'emoji') buildEmojiPane(); else loadStickers();
    panel.classList.add('on');
    zone.classList.add('panel-on');   // dock floats right above the panel, input always visible
    uiGuardPush();
  }
  function closePanel() {
    panel.classList.remove('on');
    zone.classList.remove('panel-on');
  }
  $('emojiBtn').onclick = () => {
    if (panel.classList.contains('on')) closePanel(); else openPanel('emoji');
  };
  /* tapping the input closes the panel and gives focus back to the keyboard (Telegram behavior) */
  input.addEventListener('focus', () => { if (panel.classList.contains('on')) closePanel(); });
  /* v24: keyboard opened anywhere → plant the back-guard so BACK closes it, not the site */
  document.addEventListener('focusin', (e) => {
    const t = e.target;
    if (t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA') && $('app').classList.contains('on')) uiGuardPush();
  }, true);

  /* ============================================================
     EMOJI PANEL — Telegram-style: 9 categories, search, recents
     ============================================================ */
  const EMOJI_DATA = window.EMOJI_DATA || [];
  /* Persian → English keyword expansion so search works in Farsi too */
  const FAKW = {
    'قلب':'heart', 'عشق':'love', 'خنده':'laugh joy', 'گریه':'cry sad', 'لبخند':'smile',
    'بوسه':'kiss', 'عصبانی':'angry', 'خواب':'sleep', 'فکر':'think', 'چشم':'eye',
    'دست':'hand wave', 'لایک':'thumbs up', 'دیسلایک':'thumbs down', 'مشت':'fist',
    'عضله':'muscle', 'دعا':'pray', 'آتش':'fire', 'ستاره':'star', 'درخشش':'sparkles',
    'ماه':'moon', 'خورشید':'sun', 'ابر':'cloud', 'باران':'rain', 'برف':'snow',
    'رنگین':'rainbow', 'گل':'flower rose', 'درخت':'tree', 'گربه':'cat', 'سگ':'dog',
    'پرنده':'bird', 'پروانه':'butterfly', 'ماهی':'fish', 'خرس':'bear', 'قهوه':'coffee',
    'چای':'tea', 'پیتزا':'pizza', 'برگر':'burger', 'کیک':'cake', 'تولد':'birthday',
    'هدیه':'gift', 'جشن':'party', 'موسیقی':'music', 'هدفون':'headphone', 'فوتبال':'soccer',
    'بازی':'game', 'موبایل':'phone', 'لپتاپ':'laptop', 'دوربین':'camera', 'قفل':'lock',
    'کلید':'key', 'الماس':'diamond', 'پول':'money', 'راکت':'rocket', 'هواپیما':'airplane',
    'ماشین':'car', 'قطار':'train', 'خانه':'house', 'چراغ':'light', 'کتاب':'book',
    'مداد':'pencil', 'زنگ':'bell', 'ساعت':'clock', 'پرچم':'flag', 'عروسی':'wedding'
  };
  const escAttr = (s) => String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');
  const emojiPane = $('emojiPane'), emojiScroll = $('emojiScroll'), catTabs = $('catTabs'),
        emojiSearch = $('emojiSearch'), esClear = $('emojiSearchClear');
  let emojiBuilt = false;
  /* XSS hardening (v29): emojiTile output goes straight into innerHTML, so
     EVERY caller must pass through escHtml — recent-emoji entries come from
     localStorage and are attacker-forgeable (poisoned storage = stored XSS). */
  const escHtml = (s) => String(s).replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const emojiTile = (e) => '<button type="button">' + escHtml(e) + '</button>';

  function getRecentEmoji() {
    try {
      const a = JSON.parse(localStorage.getItem('vault_recentEmoji') || '[]');
      if (!Array.isArray(a)) return [];
      /* only short strings survive — anything else was tampered with */
      return a.filter(x => typeof x === 'string' && x.length > 0 && x.length <= 16).slice(0, 32);
    } catch { return []; }
  }
  function paintRecent() {
    const rec = getRecentEmoji();
    const sec = emojiScroll.querySelector('section[data-cat="recent"]');
    const tab = catTabs.querySelector('.cat-tab[data-cat="recent"]');
    if (!sec || !tab) return;
    sec.hidden = !rec.length; tab.hidden = !rec.length;
    sec.querySelector('.egrid').innerHTML = rec.map(emojiTile).join('');
  }
  function pushRecentEmoji(e) {
    if (!e) return;
    let r = getRecentEmoji().filter(x => x !== e);
    r.unshift(e); r = r.slice(0, 32);
    localStorage.setItem('vault_recentEmoji', JSON.stringify(r));
    paintRecent();
  }

  function buildEmojiPane() {
    if (emojiBuilt) return;
    emojiBuilt = true;
    const rec = getRecentEmoji();
    const parts = ['<section class="ecat" data-cat="recent"' + (rec.length ? '' : ' hidden') +
      '><h6>🕒 اخیراً</h6><div class="egrid">' + rec.map(emojiTile).join('') + '</div></section>'];
    for (const g of EMOJI_DATA) {
      parts.push('<section class="ecat" data-cat="' + g.slug + '"><h6>' + g.icon + ' ' + g.fa +
        '</h6><div class="egrid">' + g.items.map(it => emojiTile(it[0])).join('') + '</div></section>');
    }
    emojiScroll.innerHTML = parts.join('');
    const tabs = ['<button type="button" class="cat-tab on" data-cat="recent" title="اخیراً"' +
      (rec.length ? '' : ' hidden') + '>🕒</button>'];
    for (const g of EMOJI_DATA) {
      tabs.push('<button type="button" class="cat-tab" data-cat="' + g.slug + '" title="' + escAttr(g.fa) + '">' + g.icon + '</button>');
    }
    catTabs.innerHTML = tabs.join('');
  }

  /* insert on tap — one delegated listener for all ~3.4k buttons */
  emojiScroll.addEventListener('click', (e) => {
    const b = e.target.closest('.egrid button');
    if (!b) return;
    input.value = (input.value + b.textContent).slice(0, MSG_MAX);
    input.dispatchEvent(new Event('input'));
    pushRecentEmoji(b.textContent);
  });

  /* scroll-spy: highlight the category under the view */
  function setActiveCat(slug) {
    catTabs.querySelectorAll('.cat-tab').forEach(t => t.classList.toggle('on', t.dataset.cat === slug));
  }
  let spyRaf = null;
  emojiScroll.addEventListener('scroll', () => {
    if (spyRaf) return;
    spyRaf = requestAnimationFrame(() => {
      spyRaf = null;
      if (emojiSearch.value.trim()) return;
      const st = emojiScroll.scrollTop + 96;
      let cur = null;
      emojiScroll.querySelectorAll('section.ecat').forEach(s => {
        if (!s.hidden && s.offsetTop <= st) cur = s;
      });
      if (cur) setActiveCat(cur.dataset.cat);
    });
  }, { passive: true });

  catTabs.addEventListener('click', (e) => {
    const t = e.target.closest('.cat-tab');
    if (!t) return;
    if (emojiSearch.value) { emojiSearch.value = ''; esClear.hidden = true; applyEmojiFilter(); }
    const sec = emojiScroll.querySelector('section[data-cat="' + t.dataset.cat + '"]');
    if (!sec) return;
    emojiScroll.classList.add('cv-off');          /* force real layout for an exact jump */
    emojiScroll.scrollTop = Math.max(0, sec.offsetTop - 2);
    setActiveCat(t.dataset.cat);
    requestAnimationFrame(() => requestAnimationFrame(() => emojiScroll.classList.remove('cv-off')));
  });

  /* search — English names + Persian keyword expansion */
  let searchTmr = null;
  emojiSearch.addEventListener('input', () => {
    esClear.hidden = !emojiSearch.value;
    clearTimeout(searchTmr);
    searchTmr = setTimeout(applyEmojiFilter, 110);
  });
  esClear.onclick = () => { emojiSearch.value = ''; esClear.hidden = true; applyEmojiFilter(); emojiSearch.focus(); };
  function applyEmojiFilter() {
    emojiScroll.querySelectorAll('section[data-cat="search"], .emoji-none').forEach(n => n.remove());
    const q = emojiSearch.value.trim().toLowerCase();
    const secs = emojiScroll.querySelectorAll('section.ecat');
    if (!q) {
      secs.forEach(s => { s.hidden = s.dataset.cat === 'recent' && !s.querySelector('.egrid button'); });
      emojiScroll.scrollTop = 0;
      return;
    }
    let extra = '';
    for (const [fa, en] of Object.entries(FAKW)) {
      if (q.indexOf(fa) !== -1) { extra = ' ' + en; break; }
    }
    const words = (q + extra).split(/\s+/).filter(Boolean);
    const hits = [];
    outer:
    for (const g of EMOJI_DATA) {
      for (const it of g.items) {
        const n = it[1].toLowerCase();
        for (const w of words) {
          if (n.indexOf(w) !== -1) { hits.push(it[0]); if (hits.length >= 96) break outer; break; }
        }
      }
    }
    secs.forEach(s => { s.hidden = true; });
    if (hits.length) {
      const sec = document.createElement('section');
      sec.className = 'ecat'; sec.dataset.cat = 'search';
      sec.innerHTML = '<h6>🔎 نتایج جستجو</h6><div class="egrid">' + hits.map(emojiTile).join('') + '</div>';
      emojiScroll.appendChild(sec);
    } else {
      const d = document.createElement('div');
      d.className = 'emoji-none';
      d.textContent = 'ایموجی‌ای با این عبارت پیدا نشد';
      emojiScroll.appendChild(d);
    }
  }

  /* ============================================================
     STICKER / GIF CLOUD — encrypted at rest, shared across devices
     ============================================================ */
  const stickerPane = $('stickerPane'), stickerGrid = $('stickerGrid'),
        stkEmpty = $('stkEmpty');
  let stickerList = null;
  const stickerUrls = new Map();
  const STK_CAP = 120, STK_FILE_CAP = 4.5 * 1048576;

  async function stickerSource(id) {
    if (stickerUrls.has(id)) return stickerUrls.get(id);
    const j = await API('/api/stickers/' + id).then(r => { if (!r.ok) throw 0; return r.json(); });
    const bytes = await decryptBuf(j.iv, j.c);
    let mime = 'application/octet-stream';
    try { mime = td.decode(await decryptBuf(j.miv, j.mc)) || mime; } catch {}
    const rec = { url: URL.createObjectURL(new Blob([bytes], { type: mime })), mime };
    stickerUrls.set(id, rec);
    return rec;
  }

  async function loadStickers(force) {
    if (stickerList && !force) return stickerList;
    try {
      const r = await API('/api/stickers');
      if (!r.ok) throw 0;
      stickerList = (await r.json()).stickers || [];
      paintStickers();
    } catch { toast('دریافت استیکرها ناموفق بود — تب را دوباره باز کن', 'err'); }
    return stickerList;
  }

  function paintStickers() {
    const list = stickerList || [];
    stkEmpty.hidden = !!list.length;
    const addSvg = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 5v14M5 12h14"/></svg>';
    const tiles = ['<button type="button" class="stk-item stk-add" title="افزودن استیکر یا گیف">' + addSvg + '</button>'];
    for (const s of list) {
      tiles.push('<button type="button" class="stk-item" data-id="' + escAttr(s.id) + '" data-kind="' + escAttr(s.kind) + '">' +
        '<span class="stk-x">×</span>' + (s.kind === 'gif' ? '<span class="stk-badge">GIF</span>' : '') + '</button>');
    }
    stickerGrid.innerHTML = tiles.join('');
    for (const s of list) {
      stickerSource(s.id).then(src => {
        const t = stickerGrid.querySelector('.stk-item[data-id="' + s.id + '"]');
        if (t && !t.querySelector('img, video')) {
          /* v26: repo gifs are mp4 — an <img> fed with an mp4 blob rendered
             as an EMPTY tile (the reported bug); animated previews now */
          if (/^video\//.test(src.mime || '')) {
            const v = document.createElement('video');
            v.muted = true; v.loop = true; v.autoplay = true; v.playsInline = true; v.preload = 'metadata';
            v.src = src.url;
            v.addEventListener('loadeddata', () => v.classList.add('vready'), { once: true });
            t.insertBefore(v, t.firstChild);
          } else {
            const im = new Image(); im.loading = 'lazy'; im.alt = ''; im.src = src.url;
            t.insertBefore(im, t.firstChild);
          }
        }
      }).catch(() => {});
    }
  }

  stickerGrid.addEventListener('click', async (e) => {
    const x = e.target.closest('.stk-x');
    if (x) {
      const tile = x.closest('.stk-item');
      const id = tile && tile.dataset.id;
      if (!id) return;
      const r = await API('/api/stickers/' + id, { method: 'DELETE' }).catch(() => null);
      if (r && r.ok) {
        stickerList = (stickerList || []).filter(s => s.id !== id);
        const rec = stickerUrls.get(id);
        if (rec) { URL.revokeObjectURL(rec.url); stickerUrls.delete(id); }
        paintStickers();
        toast('حذف شد ✓', 'ok');
      } else toast('حذف ناموفق', 'err');
      return;
    }
    if (e.target.closest('.stk-add')) { $('stkInput').click(); return; }
    const tile = e.target.closest('.stk-item[data-id]');
    if (!tile || stickerPane.classList.contains('stk-pane-edit')) return;
    sendCloudSticker({ id: tile.dataset.id, kind: tile.dataset.kind });
  });

  $('stkEdit').onclick = () => {
    const on = stickerPane.classList.toggle('stk-pane-edit');
    $('stkEdit').classList.toggle('on', on);
    toast(on ? 'حالت مدیریت — روی × بزن تا حذف شود' : 'حالت مدیریت خاموش شد');
  };

  $('stkInput').addEventListener('change', async (e) => {
    const f = e.target.files[0]; e.target.value = '';
    if (!f) return;
    if (!/^image\/(png|jpeg|webp|gif)$/.test(f.type)) { toast('فقط PNG / JPG / WebP / GIF', 'err'); return; }
    if (f.size > STK_FILE_CAP) { toast('حجم بیش از حد مجاز (۴٫۵ مگابایت)', 'err'); return; }
    if ((stickerList || []).length >= STK_CAP) { toast('ظرفیت استیکر پر است', 'err'); return; }
    try {
      toast('در حال ذخیره…');
      const bytes = new Uint8Array(await f.arrayBuffer());
      const dEnc = await encryptBuf(bytes);
      const mEnc = await encryptBuf(te.encode(f.type));
      const kind = f.type === 'image/gif' ? 'gif' : 'sticker';
      const r = await API('/api/stickers', { method: 'PUT', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ kind, iv: dEnc.iv, c: dEnc.c, miv: mEnc.iv, mc: mEnc.c }) });
      if (!r.ok) { toast(r.status === 409 ? 'ظرفیت استیکر پر است' : 'ذخیره ناموفق', 'err'); return; }
      const j = await r.json();
      stickerList = stickerList || [];
      stickerList.push({ id: j.id, kind, ts: j.ts, size: f.size });
      stickerUrls.set(j.id, { url: URL.createObjectURL(new Blob([bytes], { type: f.type })), mime: f.type });
      paintStickers();
      toast(kind === 'gif' ? 'گیف ذخیره شد ✓' : 'استیکر ذخیره شد ✓', 'ok');
    } catch { toast('ذخیره ناموفق', 'err'); }
  });

  async function sendCloudSticker(rec) {
    if (!aesKey) return;
    const reply = ctxMode && ctxMode.mode === 'reply' ? ctxMode.id : undefined;
    hideCtxBanner();
    try {
      const kind = rec.kind === 'gif' ? 'gif' : 'sticker';
      const meta = { k: kind, from: myTag, un: prefs.name || '', blob: 'stk:' + rec.id };
      if (reply) meta.rt = reply;
      const nEnc = await encText(kind === 'gif' ? 'گیف' : 'استیکر');
      const r = await API('/api/send', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ iv: nEnc.iv, c: nEnc.c, meta }) });
      if (!r.ok) throw 0;
      const j = await r.json();
      onIncoming({ id: j.id, ts: j.ts, iv: nEnc.iv, c: nEnc.c, meta, reacts: null });
      closePanel();
      /* best-effort plaintext mirror to telegram */
      try {
        const src = await stickerSource(rec.id);
        const b = await (await fetch(src.url)).blob();
        await fetch('/api/mirror/media', {
          method: 'POST',
          headers: Object.assign({
            'Content-Type': 'application/octet-stream',
            'x-vault-mid': j.id, 'x-vault-kind': kind,
            'x-vault-mime': encodeURIComponent(src.mime || 'image/png'),
            'x-vault-name': encodeURIComponent('sticker-' + String(rec.id).slice(-6)),
          }, tok ? { Authorization: 'Bearer ' + tok } : {}),
          body: b,
        }).then(rr => { if (rr.ok) { const m = msgs.get(j.id); if (m) { m.dl = true; paintTicks(); } } });
      } catch {}
    } catch { toast('ارسال ناموفق', 'err'); }
  }

  /* ============================================================
     v24 GLOBAL GIF REPOSITORY (Tenor) — search + trending inside the
     sticker pane. Tap = download via the server proxy → auto-save to the
     encrypted cloud sticker vault (when ≤4.5MB) → send. The mp4 variant
     is preferred when sending (3-10× smaller than the .gif).
     ============================================================ */
  const gifPaneEl = $('gifPane'), gifGrid = $('gifGrid'), gifSearchIn = $('gifSearch'),
        gifStateEl = $('gifState'), gifClearBtn = $('gifSearchClear');
  let gifModeOn = false, gifTmr = null, gifSeq = 0, gifPage = 1, gifQuery = '', gifBusy = false, gifEnd = false, gifSending = false;
  function setGifMode(on) {
    gifModeOn = on;
    $('stkTabMine').classList.toggle('on', !on);
    $('stkTabGif').classList.toggle('on', on);
    gifPaneEl.hidden = !on;
    $('stickerScroll').style.display = on ? 'none' : '';
    $('stkEdit').style.visibility = on ? 'hidden' : '';
    if (on) {
      stickerPane.classList.remove('stk-pane-edit');
      if (!gifGrid.children.length) loadGifs('', 1, false);
      setTimeout(() => gifSearchIn && gifSearchIn.focus({ preventScroll: true }), 250);
    }
  }
  $('stkTabMine').onclick = () => setGifMode(false);
  $('stkTabGif').onclick = () => setGifMode(true);
  function gifStateMsg(t) { gifStateEl.hidden = !t; gifStateEl.textContent = t || ''; }
  async function loadGifs(q, page, append) {
    if (gifBusy) return;
    gifBusy = true;
    const seq = ++gifSeq;
    gifStateMsg(page > 1 ? 'در حال دریافت بیشتر…' : 'در حال دریافت…');
    try {
      const r = await API('/api/gifsearch?q=' + encodeURIComponent(q) + '&page=' + page);
      if (seq !== gifSeq) return;
      const j = await r.json().catch(() => ({ ok: false }));
      if (!j.ok) { gifStateMsg(j.error || 'دریافت ناموفق — دوباره امتحان کن'); return; }
      const items = j.items || [];
      gifEnd = items.length < 8;
      if (!append) gifGrid.innerHTML = '';
      if (!items.length && !append) gifStateMsg('چیزی پیدا نشد — عبارت دیگری امتحان کن');
      else if (gifEnd) gifStateMsg(append ? '— همه نمایش داده شد —' : '');
      else gifStateMsg('');
      for (const it of items) gifGrid.appendChild(gifTile(it));
    } catch {
      if (seq === gifSeq) gifStateMsg('خطای شبکه — دوباره امتحان کن');
    } finally { gifBusy = false; }
  }
  /* v25: previews load through OUR server proxy (/api/giffetch) — never
     directly from media.tenor.com, which is filtered on Iranian networks.
     The mp4 variant is preferred (3-10× smaller than the .gif) and rendered
     as a looping muted <video>. /api/* needs the Bearer session token which
     <video src> cannot carry, so on intersect we authed-fetch → blob →
     objectURL (the SW still caches the proxy response cache-first, so repeat
     previews cost zero bytes). Tiles attach lazily via IntersectionObserver
     and pause when off-screen — a page of 60 gifs costs almost nothing on
     slow mobile data. */
  function attachPreview(b) {
    const m = b.querySelector('video, img');
    if (!m || m.dataset.busy || m.getAttribute('src')) return;
    const ds = m.dataset.src; if (!ds) return;
    m.dataset.busy = '1';
    API(ds).then(async (r) => {
      if (!r.ok) return;
      const m2 = m;
      m2.src = URL.createObjectURL(await r.blob());
      m2.classList.add('vwait');
      m2.addEventListener('loadeddata', () => m2.classList.remove('vwait'), { once: true });
      setTimeout(() => m2.classList.remove('vwait'), 6000);
      if (m2.tagName === 'VIDEO') m2.play().catch(() => {});
    }).catch(() => {}).finally(() => { delete m.dataset.busy; });
  }
  const gifLazy = ('IntersectionObserver' in window)
    ? new IntersectionObserver((ents) => {
        for (const en of ents) {
          if (en.isIntersecting) {
            attachPreview(en.target);
            const v = en.target.querySelector('video');
            if (v && v.getAttribute('src')) v.play().catch(() => {});
          } else {
            const v = en.target.querySelector('video');
            if (v) try { v.pause(); } catch {}
          }
        }
      }, { root: gifPaneEl, rootMargin: '420px 0px' })
    : null;
  function gifTile(it) {
    const b = el('<button type="button" class="gif-item"><span class="gif-cap"></span></button>');
    const prox = (u) => '/api/giffetch?u=' + encodeURIComponent(u);
    const cap = b.querySelector('.gif-cap');
    cap.textContent = it.t || '';
    if (it.m) {                                   /* small mp4 → looping video */
      const v = document.createElement('video');
      v.muted = true; v.loop = true; v.autoplay = true; v.playsInline = true;
      v.preload = 'none'; v.dataset.src = prox(it.m);
      b.prepend(v);
    } else {                                      /* gif-only fallback → img */
      const img = document.createElement('img');
      img.alt = ''; img.loading = 'lazy'; img.dataset.src = prox(it.u);
      b.prepend(img);
    }
    if (gifLazy) gifLazy.observe(b);
    else attachPreview(b);                        /* very old browsers: load now */
    b.onclick = () => sendGifFromRepo(it);
    return b;
  }
  async function sendGifFromRepo(it) {
    if (!aesKey) { toast('اول وارد شو', 'err'); return; }
    if (gifSending) return;
    gifSending = true;
    toast('در حال آماده‌سازی گیف…');
    try {
      const src = it.m || it.u;
      const r0 = await API('/api/giffetch?u=' + encodeURIComponent(src));
      if (!r0.ok) throw 0;
      const blob = await r0.blob();
      const bytes = new Uint8Array(await blob.arrayBuffer());
      const mime = blob.type || (/\.mp4($|\?)/.test(src) ? 'video/mp4' : 'image/gif');
      const reply = ctxMode && ctxMode.mode === 'reply' ? ctxMode.id : undefined;
      hideCtxBanner();
      /* auto-save to the cloud vault (owner rule: every sent repo-gif is kept) */
      let cloudId = null;
      if (bytes.length <= STK_FILE_CAP && (stickerList || []).length < STK_CAP) {
        try {
          const dEnc = await encryptBuf(bytes), mEnc = await encryptBuf(te.encode(mime));
          const r = await API('/api/stickers', { method: 'PUT', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ kind: 'gif', iv: dEnc.iv, c: dEnc.c, miv: mEnc.iv, mc: mEnc.c }) });
          if (r.ok) {
            const j2 = await r.json();
            cloudId = j2.id;
            stickerList = stickerList || [];
            stickerList.push({ id: j2.id, kind: 'gif', ts: j2.ts, size: bytes.length });
            stickerUrls.set(j2.id, { url: URL.createObjectURL(new Blob([bytes], { type: mime })), mime });
            paintStickers();
          }
        } catch {}
      }
      const kind = 'gif';
      const meta = { k: kind, from: myTag, un: prefs.name || '' };
      if (cloudId) meta.blob = 'stk:' + cloudId;
      else {
        const dEnc = await encryptBuf(bytes), mEnc = await encryptBuf(te.encode(mime));
        const r2 = await API('/api/blob', { method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ iv: dEnc.iv, c: dEnc.c, miv: mEnc.iv, mc: mEnc.c }) });
        if (!r2.ok) throw 0;
        meta.blob = (await r2.json()).bid;
        meta.mime = mime; meta.size = bytes.length;
      }
      if (reply) meta.rt = reply;
      const nEnc = await encText((it.t || 'گیف').slice(0, 120));
      const r3 = await API('/api/send', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ iv: nEnc.iv, c: nEnc.c, meta }) });
      if (!r3.ok) throw 0;
      const j3 = await r3.json();
      onIncoming({ id: j3.id, ts: j3.ts, iv: nEnc.iv, c: nEnc.c, meta, reacts: null });
      closePanel();
      /* best-effort plaintext mirror to telegram */
      try {
        await fetch('/api/mirror/media', {
          method: 'POST',
          headers: Object.assign({
            'Content-Type': 'application/octet-stream',
            'x-vault-mid': j3.id, 'x-vault-kind': 'gif',
            'x-vault-mime': encodeURIComponent(mime),
            'x-vault-name': encodeURIComponent('gif-' + String(cloudId || 'repo').slice(-6)),
          }, tok ? { Authorization: 'Bearer ' + tok } : {}),
          body: blob,
        }).then(rr => { if (rr.ok) { const m = msgs.get(j3.id); if (m) { m.dl = true; paintTicks(); } } });
      } catch {}
      toast(cloudId ? 'گیف ارسال و در ابر ذخیره شد ✓' : 'گیف ارسال شد ✓', 'ok');
    } catch { toast('ارسال گیف ناموفق', 'err'); }
    gifSending = false;
  }
  gifSearchIn.addEventListener('input', () => {
    gifClearBtn.hidden = !gifSearchIn.value;
    clearTimeout(gifTmr);
    gifTmr = setTimeout(() => {
      gifQuery = gifSearchIn.value.trim();
      gifPage = 1;
      loadGifs(gifQuery, 1, false);
    }, 420);
  });
  gifClearBtn.onclick = () => { gifSearchIn.value = ''; gifClearBtn.hidden = true; gifQuery = ''; gifPage = 1; loadGifs('', 1, false); };
  gifSearchIn.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); clearTimeout(gifTmr); gifQuery = gifSearchIn.value.trim(); gifPage = 1; loadGifs(gifQuery, 1, false); } });
  gifPaneEl.addEventListener('scroll', () => {
    if (gifModeOn && !gifBusy && !gifEnd && gifPaneEl.scrollHeight - gifPaneEl.scrollTop - gifPaneEl.clientHeight < 260) {
      gifPage++;
      loadGifs(gifQuery, gifPage, true);
    }
  }, { passive: true });

  /* ============================================================
     v30: CLIENT-SIDE SEARCH (E2EE — decrypt on demand, tab-only)
     + SESSION MANAGEMENT PANEL (list logins, remote logout)
     ============================================================ */
  const searchSheet = $('searchSheet');
  const searchCache = new Map();   /* msgId -> plaintext (this tab only) */
  let histSearchTmr = null;
  function normText(s) {
    return String(s || '')
      .replace(/[\u200c\u200e\u200f\u064B-\u0652\u0670]/g, '')
      .replace(/ك/g, 'ک').replace(/ي/g, 'ی').replace(/أ/g, 'ا').replace(/إ/g, 'ا').replace(/ؤ/g, 'و').replace(/ة/g, 'ه')
      .toLowerCase();
  }
  function escRe(s) { return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
  async function plainOf(m) {
    if (searchCache.has(m.id)) return searchCache.get(m.id);
    let t = '';
    try { t = m.iv ? await decTextSafe(m.iv, m.c) : String(m.t || ''); } catch { t = ''; }
    searchCache.set(m.id, t);
    return t;
  }
  function openSearch() { searchSheet.classList.add('on'); uiGuardPush(); setTimeout(() => $('searchInput').focus(), 90); }
  function closeSearch() { searchSheet.classList.remove('on'); }
  $('searchBtn').onclick = openSearch;
  $('searchClose').onclick = closeSearch;
  searchSheet.addEventListener('click', (e) => { if (e.target === searchSheet) closeSearch(); });
  $('searchInput').addEventListener('input', () => { clearTimeout(histSearchTmr); histSearchTmr = setTimeout(runSearch, 220); });
  async function runSearch() {
    const raw = $('searchInput').value.trim();
    const q = normText(raw);
    const box = $('searchResults'); const metaL = $('searchMeta');
    box.textContent = '';
    if (q.length < 2) { metaL.textContent = raw ? 'حداقل ۲ کاراکتر بنویس…' : 'متنی بنویس — تاریخچه همین‌جا (فقط در همین تب) رمزگشایی می‌شود.'; return; }
    metaL.textContent = 'در حال جستجو…';
    const hits = [];
    for (let i = order.length - 1; i >= 0 && hits.length < 80; i--) {
      const m = msgs.get(order[i]); if (!m) continue;
      const isMedia = m.meta && m.meta.k && m.meta.k !== 'text';
      if (isMedia && !m.iv) continue;   /* media without caption has no searchable text */
      const plain = await plainOf(m);
      if (!plain || !normText(plain).includes(q)) continue;
      hits.push({ m, plain });
    }
    metaL.textContent = hits.length ? faDigits(hits.length) + ' نتیجه' : 'چیزی پیدا نشد';
    let re = null;
    try { if (raw) re = new RegExp(escRe(raw), 'i'); } catch {}
    for (const { m, plain } of hits.slice(0, 50)) {
      const row = document.createElement('button'); row.type = 'button'; row.className = 'search-hit';
      const nm = document.createElement('b'); nm.textContent = senderNameOf(m);
      const tm = document.createElement('small'); tm.textContent = faTime(m.ts);
      const sn = document.createElement('span');
      const hay = normText(plain);
      const idx = hay.indexOf(q);
      const mm2 = re ? re.exec(plain) : null;
      const mAt = mm2 ? mm2.index : idx;
      const mLen = mm2 ? mm2[0].length : q.length;
      const s0 = Math.max(0, mAt - 34);
      if (s0 > 0) sn.append(document.createTextNode('…'));
      sn.append(document.createTextNode(plain.slice(s0, mAt)));
      const mk = document.createElement('mark'); mk.textContent = plain.slice(mAt, mAt + mLen); sn.append(mk);
      const rest = plain.slice(mAt + mLen, mAt + mLen + 76);
      sn.append(document.createTextNode(rest));
      if (mAt + mLen + 76 < plain.length) sn.append(document.createTextNode('…'));
      row.append(nm, tm, sn);
      row.onclick = () => { closeSearch(); jumpToMsg(m.id); };
      box.appendChild(row);
    }
  }

  const SESS_KIND_ICON = { pw: '🔑', claim: '🎟', finger: '🖐', device: '📱', reentry: '↩️' };
  async function sessRefresh() {
    const list = $('sessList'); if (!list) return;
    list.textContent = '';
    const hint = document.createElement('small'); hint.className = 'hint'; hint.textContent = 'در حال دریافت…';
    list.appendChild(hint);
    try {
      const r = await API('/api/sessions');
      if (!r.ok) { hint.textContent = 'دریافت ناموفق — دوباره تلاش کنید.'; return; }
      const j = await r.json();
      list.textContent = '';
      const rows = (j.sessions || []).filter(s => !s.revoked);
      if (!rows.length) { const e2 = document.createElement('small'); e2.className = 'hint'; e2.textContent = 'نشست فعالی ثبت نشده است.'; list.appendChild(e2); return; }
      for (const s of rows) {
        const row = document.createElement('div'); row.className = 'sess-row' + (s.current ? ' cur' : '');
        const ic = document.createElement('span'); ic.className = 'sess-ic'; ic.textContent = SESS_KIND_ICON[s.kind] || '🔑';
        const main = document.createElement('div'); main.className = 'sess-main';
        const l1 = document.createElement('b'); l1.textContent = (s.name || 'بدون نام') + (s.current ? ' — این دستگاه ✓' : '');
        const l2 = document.createElement('small');
        l2.textContent = (s.live ? '🟢 آنلاین' : '⚪ آفلاین') + ' · ' + faAgo(s.t) + (s.ip ? ' · IP ' + s.ip : '') + (s.dev ? ' · ' + s.dev : '');
        main.append(l1, l2);
        row.append(ic, main);
        if (!s.current) {
          const btn = document.createElement('button'); btn.type = 'button'; btn.className = 'mini-btn ghost sess-kill'; btn.textContent = 'اخراج';
          btn.onclick = () => confirmDialog('اخراج نشست #' + faDigits(s.sid) + '؟', 'آن دستگاه بلافاصله از چت خارج می‌شود.', 'اخراج کن', async () => {
            try {
              await API('/api/sessions/revoke', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ sid: s.sid }) });
              toast('نشست اخراج شد 🚪', 'ok');
            } catch { toast('خطای شبکه', 'err'); }
            sessRefresh();
          });
          row.appendChild(btn);
        }
        list.appendChild(row);
      }
    } catch { hint.textContent = 'خطای شبکه'; }
  }
  $('sessReloadBtn').onclick = sessRefresh;

  /* ============================================================
     SETTINGS SHEET
     ============================================================ */
  const setSheet = $('settingsSheet');
  function syncSettingsUI() {
    document.querySelectorAll('#themeSeg button').forEach(b => b.classList.toggle('on', b.dataset.v === prefs.theme));
    document.querySelectorAll('#fontGrid button').forEach(b => b.classList.toggle('on', b.dataset.f === prefs.font));
    setSlider($('fontSize'), prefs.fsize);
    $('fsVal').textContent = faDigits(prefs.fsize) + '٪';
    setSlider($('wallBlur'), prefs.wallBlur);
    setSlider($('wallDim'), prefs.wallDim);
    $('settingsName').value = prefs.name;
    renderWallPresets();
    loadProfilePreview();
  }
  document.querySelectorAll('#themeSeg button').forEach(b => {
    b.onclick = () => { prefs.theme = b.dataset.v; localStorage.setItem('vault_theme', prefs.theme); applyPrefs(); };
  });
  document.querySelectorAll('#fontGrid button').forEach(b => {
    b.onclick = () => { prefs.font = b.dataset.f; localStorage.setItem('vault_font', prefs.font); applyPrefs(); };
  });
  /* ============================================================
     v24 ANTI-SCROLL SLIDERS — the three settings sliders (محو، تاریکی،
     اندازهٔ فونت) changed value whenever the user scrolled over them.
     Native <input type=range> grabs every touch. The custom .r2 slider only
     reacts when the drag STARTS ON THE THUMB (±26px); touches on the track
     are ignored and the page scrolls normally.
     ============================================================ */
  const sliderRegs = new Map();   // el -> {min,max,step,val,onInput}
  function initSlider(el, min, max, step, onInput) {
    el.classList.add('r2');
    el.setAttribute('role', 'slider');
    el.setAttribute('aria-valuemin', String(min));
    el.setAttribute('aria-valuemax', String(max));
    el.innerHTML = '<div class="r2-track"><div class="r2-fill"></div><div class="r2-thumb"></div></div>';
    const reg = { min, max, step, val: min, onInput };
    sliderRegs.set(el, reg);
    const rtl = (document.documentElement.dir || 'rtl') === 'rtl';
    const thumb = el.querySelector('.r2-thumb');
    function paint() {
      const p = (reg.val - min) / (max - min) * 100;
      el.querySelector('.r2-fill').style.width = p + '%';
      thumb.style[rtl ? 'right' : 'left'] = p + '%';
      thumb.style.transform = 'translate(' + (rtl ? '50%' : '-50%') + ',-50%)';
      el.setAttribute('aria-valuenow', String(reg.val));
    }
    function setVal(v, fire) {
      const s = reg.step || 1;
      reg.val = Math.round(Math.min(max, Math.max(min, v)) / s) * s;
      paint();
      if (fire && reg.onInput) reg.onInput(reg.val);
    }
    let dragging = false, moved = false;
    el.addEventListener('pointerdown', (e) => {
      const r = el.getBoundingClientRect();
      const p = Math.min(1, Math.max(0, (reg.val - min) / (max - min)));
      const rtl2 = (document.documentElement.dir || 'rtl') === 'rtl';
      const tx = rtl2 ? r.right - p * r.width : r.left + p * r.width;   /* thumb center x */
      if (Math.abs(e.clientX - tx) > 26) return;   /* NOT on the thumb → let the page scroll */
      dragging = true; moved = false;
      try { el.setPointerCapture(e.pointerId); } catch {}
      e.preventDefault();
    });
    el.addEventListener('pointermove', (e) => {
      if (!dragging) return;
      moved = true;
      const r = el.getBoundingClientRect();
      const rtl2 = (document.documentElement.dir || 'rtl') === 'rtl';
      const ratio = Math.min(1, Math.max(0, rtl2 ? (r.right - e.clientX) / r.width : (e.clientX - r.left) / r.width));
      setVal(min + (max - min) * ratio, true);
    });
    const stop = () => { if (dragging && moved && navigator.vibrate) try { navigator.vibrate(8); } catch {} dragging = false; };
    el.addEventListener('pointerup', stop);
    el.addEventListener('pointercancel', stop);
    el.addEventListener('keydown', (e) => {
      const inc = e.key === 'ArrowLeft' || e.key === 'ArrowUp';   /* RTL: left grows */
      const dec = e.key === 'ArrowRight' || e.key === 'ArrowDown';
      if (!inc && !dec) return;
      e.preventDefault();
      setVal(reg.val + (inc ? 1 : -1) * (reg.step || 1), true);
    });
    reg.__setVal = setVal;
    reg.__paint = paint;
    paint();
  }
  function setSlider(el, v) {
    const reg = sliderRegs.get(el);
    if (!reg) return;
    reg.val = Math.min(reg.max, Math.max(reg.min, v));
    reg.__paint();
  }
  initSlider($('wallBlur'), 0, 12, 1, (v) => {
    prefs.wallBlur = v; localStorage.setItem('vault_wallBlur', String(v)); applyPrefs();
  });
  initSlider($('wallDim'), 0, 80, 5, (v) => {
    prefs.wallDim = v; localStorage.setItem('vault_wallDim', String(v)); applyPrefs();
  });
  initSlider($('fontSize'), 90, 125, 5, (v) => {
    prefs.fsize = v; localStorage.setItem('vault_fsize', String(v)); applyPrefs();
  });

  function renderWallPresets() {
    const rowEl = $('wallPresets'); rowEl.innerHTML = '';
    WALL_PRESETS.forEach((g) => {
      const b = document.createElement('button'); b.type = 'button';
      b.title = 'پس‌زمینه پیش‌فرض';
      if (g) b.style.backgroundImage = g;
      else b.style.background = 'repeating-linear-gradient(45deg,var(--panel-2),var(--panel-2) 6px,var(--compose) 6px,var(--compose) 12px)';
      b.classList.toggle('on', prefs.wall === g);
      b.onclick = () => { prefs.wall = g; localStorage.setItem('vault_wall', g); applyWall(); renderWallPresets(); };
      rowEl.appendChild(b);
    });
    if (prefs.wall.startsWith('data:')) {
      const b = document.createElement('button');
      b.style.backgroundImage = `url("${prefs.wall}")`; b.classList.add('on');
      rowEl.appendChild(b);
    }
  }
  $('pickWallBtn').onclick = () => $('wallInput').click();
  $('wallInput').addEventListener('change', async (e) => {
    const f = e.target.files[0]; e.target.value = '';
    if (!f) return;
    try {
      const dataUrl = await resizeToDataUrl(f, 1600, .8);
      prefs.wall = dataUrl; localStorage.setItem('vault_wall', dataUrl);
      applyWall(); renderWallPresets(); toast('پس‌زمینه اعمال شد ✓', 'ok');
    } catch { toast('خواندن عکس ناموفق بود', 'err'); }
  });
  $('removeWallBtn').onclick = () => {
    prefs.wall = ''; localStorage.removeItem('vault_wall'); applyWall(); renderWallPresets();
  };
  function resizeToDataUrl(file, maxSide, q) {
    return new Promise((res, rej) => {
      const rd = new FileReader();
      rd.onload = () => {
        const img = new Image();
        img.onload = () => {
          const scale = Math.min(1, maxSide / Math.max(img.width, img.height));
          const cv = document.createElement('canvas');
          cv.width = Math.round(img.width * scale); cv.height = Math.round(img.height * scale);
          cv.getContext('2d').drawImage(img, 0, 0, cv.width, cv.height);
          res(cv.toDataURL('image/jpeg', q || .85));
        };
        img.onerror = rej; img.src = rd.result;
      };
      rd.onerror = rej; rd.readAsDataURL(file);
    });
  }

  /* profile persona — v18: per display-name profile */
  let pendingProfileData = null;
  const myNameLower = () => String(prefs.name || '').toLowerCase();
  function loadProfilePreview() {
    const prof = state.profiles[myNameLower()] || {};
    const photo = prof.photo || '';
    if (photo) {
      $('profilePreview').src = photo; $('profilePreview').hidden = false;
      $('profilePlaceholder').style.display = 'none';
    } else {
      $('profilePreview').hidden = true; $('profilePlaceholder').style.display = '';
    }
    const nmEl = $('settingsName');
    if (nmEl && !nmEl.value) nmEl.value = prefs.name || '';
  }
  $('pickProfileBtn').onclick = () => $('profileInput').click();
  $('profileInput').addEventListener('change', async (e) => {
    const f = e.target.files[0]; e.target.value = '';
    if (!f) return;
    if (f.size > 4 * 1048576) { toast('عکس خیلی بزرگ است', 'err'); return; }
    try {
      pendingProfileData = await resizeToDataUrl(f, 480, .84);
      $('profilePreview').src = pendingProfileData; $('profilePreview').hidden = false;
      $('profilePlaceholder').style.display = 'none';
    } catch { toast('خواندن عکس ناموفق بود', 'err'); }
  });
  $('removeProfileBtn').onclick = () => {
    pendingProfileData = '';
    $('profilePreview').hidden = true; $('profilePlaceholder').style.display = '';
  };
  async function saveProfile() {
    const newName = $('settingsName').value.trim().slice(0, 30);
    if (newName) {
      prefs.name = newName;
      localStorage.setItem('vault_displayName', prefs.name);
      state.sitePersona.name = prefs.name;
    }
    if (pendingProfileData !== null) {
      try {
        const r = await API('/api/profile', { method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: prefs.name, photo: pendingProfileData }) });
        if (!r.ok) { toast('ذخیره پروفایل ناموفق', 'err'); return; }
        const j = await r.json().catch(() => ({}));
        if (j.profile) state.profiles[myNameLower()] = j.profile;   // v18: per-name profile
        pendingProfileData = null;
        /* v18: the server mirrors the photo card to the bot PV automatically */
        toast(profToastText(), 'ok');
      } catch { toast('خطای شبکه', 'err'); return; }
    } else {
      toast('تنظیمات ذخیره شد ✓', 'ok');
    }
  }
  function profToastText() { return 'پروفایل ذخیره شد ✓ — کارت عکس به ربات تلگرام هم رفت'; }
  $('changePwBtn').onclick = async () => {
    const oldPw = $('oldPwInput').value, n1 = $('newPwInput').value, n2 = $('newPwConfirm').value;
    if (!oldPw || !n1) { toast('رمز فعلی و رمز جدید را وارد کنید', 'err'); return; }
    if (n1.length < 4) { toast('رمز جدید حداقل ۴ کاراکتر', 'err'); return; }
    if (n1 !== n2) { toast('تکرار رمز مطابقت ندارد', 'err'); return; }
    try {
      /* v18: verifier-based rotation — the passwords themselves never leave
         the device; only PBKDF2 verifiers and the new CK wrap are uploaded.
         The chat key (CK) stays the same, so all devices keep reading. */
      const hello = await (await fetchRetry('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ mode: 'hello' }) }, 2)).json();
      if (!hello || hello.mode !== 'new' || !hello.saltA) {
        /* pre-migration vault: keep the legacy rotation path */
        const r0 = await API('/api/admin/revoke', { method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ oldPw, newPw: n1 }) });
        const j0 = await r0.json();
        if (j0.ok && j0.rotated) { toast('✅ رمز عوض شد — دوباره وارد شوید', 'ok'); setTimeout(() => location.reload(), 1400); }
        else toast('خطا: ' + (j0.error || 'ناموفق'), 'err');
        return;
      }
      const oldVerifier = b64.enc(await pbkdf2Raw(oldPw, hello.saltA, 250000));
      const newSaltA = b64.enc(crypto.getRandomValues(new Uint8Array(16)));
      const newSaltB = b64.enc(crypto.getRandomValues(new Uint8Array(16)));
      const newVerifier = b64.enc(await pbkdf2Raw(n1, newSaltA, 250000));
      const kek = await hkdfWrapKey(await pbkdf2Raw(n1, newSaltB, 250000), 'ck-wrap-v1');
      const ckRaw = new Uint8Array(await crypto.subtle.exportKey('raw', aesKey));
      const newPwWrap = await aesEnc(kek, ckRaw);
      const r = await API('/api/password', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        /* v21: newPw rides along (HTTPS-only) so the SERVER-side admin panel
           (the Telegram bot) always knows the current access password — the
           owner directive: /password must never lie. Message E2EE is unaffected:
           only verifiers + the CK wrap were already being uploaded anyway. */
        body: JSON.stringify({ oldVerifier, newVerifier, newSaltA, newSaltB, newPwWrap, newPw: n1, name: prefs.name, dev: deviceLabel() }) });
      const j = await r.json();
      if (j.ok && j.tok) {
        tok = j.tok; sessionStorage.setItem('vault_tok', tok);
        let prevWrap = null;
        try { prevWrap = (JSON.parse(sessionStorage.getItem('vault_sess2') || 'null') || {}).legacyWrap || null; } catch {}
        saveSession({ ck: b64.enc(ckRaw), legacyWrap: prevWrap });
        toast('✅ رمز عوض شد (بدون تغییر کلید چت) — نشست‌های دیگر باید دوباره وارد شوند', 'ok', 5000);
        connectStream();
      } else {
        toast('خطا: ' + (j.error || 'ناموفق'), 'err');
      }
    } catch (e) { toast('خطای شبکه', 'err'); }
  };
  /* v24: both save buttons (top + bottom) persist everything and close; the
     bottom one REPLACED the old «بستن» per the owner request */
  const saveSettings = () => saveProfile().finally(() => setSheet.classList.remove('on'));
  $('settingsSave').onclick = saveSettings;
  $('settingsSaveTop').onclick = saveSettings;
  setSheet.addEventListener('click', (e) => {
    if (e.target === setSheet) saveProfile().finally(() => setSheet.classList.remove('on'));
  });
  $('mSettings').onclick = () => { closeMenus(); syncSettingsUI(); setSheet.classList.add('on'); uiGuardPush(); fingerRefresh(); devRefresh(); lockRefresh(); sessRefresh(); };

  /* ============================================================
     v29 دستگاه مورد اعتماد + قفل شخصی (الگو/پین)
     Design:
       · هر مرورگر یک EC P-256 keypair می‌سازد؛ نیمی عمومی (pub) به سرور
         می‌رود (پس از تایید ادمین در تلگرام) و نیمهٔ خصوصی (priv) فقط در
         localStorage همین گوشی می‌ماند — و همیشه زیر قفل شخصی (الگو یا
         پین، PBKDF2→AES-GCM) رمزشده است.
       · ورود بدون رمز: قفل باز می‌شود → کلید خصوصی رمزگشایی → چالش سرور
         امضا می‌شود → نشست + wrap کلید چت. فراموشی قفل = ورود با رمز اصلی.
     ============================================================ */
  const DEV_ID_KEY = 'vault_devid', DEV_PUB_KEY = 'vault_devpub', DEV_PRIV_KEY = 'vault_devpriv';
  const DEV_LOCK_KEY = 'vault_devlock';
  function devIdGet() {
    let id = '';
    try { id = localStorage.getItem(DEV_ID_KEY) || ''; } catch {}
    if (!/^[a-f0-9]{32}$/.test(id)) {
      id = Array.from(crypto.getRandomValues(new Uint8Array(16)), x => x.toString(16).padStart(2, '0')).join('');
      try { localStorage.setItem(DEV_ID_KEY, id); } catch {}
    }
    return id;
  }
  function devLockGet() {
    try { return JSON.parse(localStorage.getItem(DEV_LOCK_KEY) || 'null'); } catch { return null; }
  }
  function lockHas() { const L = devLockGet(); return !!(L && L.k && L.n && (L.t === 'pat' || L.t === 'pin')); }
  async function lockKek(secret, saltB64) {
    return hkdfWrapKey(await pbkdf2Raw(secret, saltB64, 250000), 'dev-lock-v1');
  }
  async function lockSeal(secret, type, privJwkObj) {
    /* wrap the EC private JWK under the user's personal lock (fresh salts/iv) */
    const s1 = b64.enc(crypto.getRandomValues(new Uint8Array(16)));
    const s2 = b64.enc(crypto.getRandomValues(new Uint8Array(16)));
    const kek = await lockKek(secret + '￨' + s1, s2);
    const w = await aesEnc(kek, te.encode(JSON.stringify(privJwkObj)));
    return { v: 1, t: type, k: s1, n: s2, iv: w.iv, c: w.c };
  }
  async function lockOpen(secret) {
    /* returns the unwrapped EC private JWK object, or throws on a wrong lock */
    const L = devLockGet();
    if (!L || !L.k || !L.n || !L.iv || !L.c) throw new Error('no-lock');
    const kek = await lockKek(secret + '￨' + L.k, L.n);
    const raw = await aesDec(kek, L.iv, L.c);
    return JSON.parse(td.decode(raw));
  }
  async function devPubOnly() {
    try { return JSON.parse(localStorage.getItem(DEV_PUB_KEY) || 'null'); } catch { return null; }
  }
  function devHasKeys() {
    try { return !!(localStorage.getItem(DEV_PRIV_KEY) && localStorage.getItem(DEV_PUB_KEY)); } catch { return false; }
  }
  /* v31 FIX: lockRefresh was called in four places but never defined — every
     settings-open / device-lifecycle update threw a silent ReferenceError and
     killed the calls after it (incl. the new sessions panel). Real impl: */
  function lockRefresh() {
    const ic = $('lockIc'), tx = $('lockStateTxt'), setB = $('lockSetBtn'), clr = $('lockClearBtn');
    if (!ic || !tx || !setB || !clr) return;
    const has = lockHas();
    ic.textContent = has ? '🔏' : '🔓';
    tx.textContent = has ? 'قفل شخصی فعال است — ورود بدون رمز با الگو/پین ✓' : 'الگو یا پین برای ورود بدون رمز';
    setB.hidden = has;
    clr.hidden = !has;
  }
  async function devRefresh() {
    try {
      const tx = $('devStateTxt'), ic = $('devIc'), rq = $('devReqBtn'), rm = $('devRemoveBtn'), nw = $('devNewRow'), ds = $('devLastSeen');
      if (!tx) return;
      const j = await (await API('/api/devices', { method: 'GET' })).json().catch(() => ({}));
      const mine = devIdGet();
      const devs = (j && j.devices) || [];
      const own = devs.find(d => d.devId === mine);
      const pend = ((j && j.pending) || []).filter(p => (p.name || '').toLowerCase() === (prefs.name || '').toLowerCase());
      const hasLoc = devHasKeys() || lockHas();
      if (own) {
        ic.textContent = '✅';
        rq.hidden = true; rm.hidden = false; nw.hidden = true;
        tx.textContent = 'این دستگاه مورد اعتماد است ✓ — با «ورود با این دستگاه» بدون رمز وارد می‌شوید.';
        const seen = 'آخرین ورود با این دستگاه: ' + faAgo(own.lastUsedAt);
        if (ds) { ds.textContent = seen; ds.dataset.html = ''; }
      } else if (hasLoc && pend.length) {
        ic.textContent = '⏳';
        rq.hidden = false; rq.textContent = 'در انتظار تایید ادمین…'; rq.disabled = true;
        rm.hidden = false; nw.hidden = true;
        tx.textContent = 'درخواست به ربات رفت — در تلگرام با ✅ تایید کنید.';
      } else if (hasLoc) {
        ic.textContent = '📱';
        rq.hidden = false; rq.textContent = 'درخواست اعتماد به این دستگاه'; rq.disabled = false;
        rm.hidden = false; nw.hidden = true;
        tx.textContent = 'کلید این دستگاه آماده است — درخواست را بفرستید تا ادمین تایید کند.';
      } else {
        ic.textContent = '📱';
        rq.hidden = false; rq.textContent = 'درخواست اعتماد به این دستگاه'; rq.disabled = false;
        rm.hidden = true; nw.hidden = true;
        tx.textContent = lockHas() ? 'قفل شخصی فعال است — حالا اعتماد این دستگاه را درخواست کنید.'
          : 'بدون رمز وارد شوید: اول قفل شخصی (الگو/پین) تعیین کنید، بعد اعتماد دستگاه را بخواهید.';
      }
      if (ds && !own) { ds.textContent = ''; ds.dataset.html = ''; }
    } catch { /* sheet closed / offline — retry on next open */ }
  }
  /* ---- v29 lock overlay: shared pattern-grid + PIN pad ----
     Modes (set by the caller through lockUi.onDone):
       'unlock' — verify existing lock, then onDone(secret)
       'setup'  — pick type, enter twice, then onDone(secret, type)   */
  const lockUi = { onDone: null, mode: 'unlock', type: 'pat', first: null, cur: [], fails: 0 };
  function patReset() {
    lockUi.cur = [];
    const g = $('patGrid');
    if (!g) return;
    g.innerHTML = '';
    const NS = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(NS, 'svg');
    svg.setAttribute('viewBox', '0 0 100 100');
    svg.id = 'patSvg';
    g.appendChild(svg);
    for (let i = 0; i < 9; i++) {
      const b = document.createElement('button');
      b.type = 'button'; b.className = 'pat-dot'; b.dataset.i = String(i);
      b.setAttribute('aria-label', 'نقطه ' + (i + 1));
      g.appendChild(b);
    }
  }
  function patDotCenter(i) {
    const g = $('patGrid');
    const b = g && g.querySelector('[data-i="' + i + '"]');
    if (!b || !g) return null;
    const gr = g.getBoundingClientRect(), br = b.getBoundingClientRect();
    return { x: (br.left + br.width / 2 - gr.left) / gr.width * 100, y: (br.top + br.height / 2 - gr.top) / gr.height * 100 };
  }
  function patPaint(extra) {
    const svg = $('patSvg');
    if (!svg) return;
    while (svg.firstChild) svg.removeChild(svg.firstChild);
    const NS = 'http://www.w3.org/2000/svg';
    const pts = lockUi.cur.map(patDotCenter).filter(Boolean);
    if (extra) pts.push(extra);
    const g = $('patGrid');
    (g ? Array.from(g.querySelectorAll('.pat-dot')) : []).forEach(d => {
      d.classList.toggle('hit', lockUi.cur.indexOf(+d.dataset.i) >= 0);
    });
    for (let i = 1; i < pts.length; i++) {
      const ln = document.createElementNS(NS, 'line');
      ln.setAttribute('x1', pts[i - 1].x); ln.setAttribute('y1', pts[i - 1].y);
      ln.setAttribute('x2', pts[i].x); ln.setAttribute('y2', pts[i].y);
      ln.setAttribute('stroke', '#ec6fa8'); ln.setAttribute('stroke-width', '3.2');
      ln.setAttribute('stroke-linecap', 'round'); ln.setAttribute('opacity', '.9');
      svg.appendChild(ln);
    }
  }
  function patAdd(i) {
    if (lockUi.cur.indexOf(i) >= 0) return;
    lockUi.cur.push(i);
    if (navigator.vibrate) { try { navigator.vibrate(8); } catch {} }
    patPaint();
  }
  function lockMsg(t, err) {
    const m = $('devLockMsg');
    if (!m) return;
    m.textContent = t || ''; m.classList.toggle('err', !!err);
  }
  function lockShow(mode, hint) {
    lockUi.mode = mode; lockUi.first = null; lockUi.fails = 0;
    lockMsg('');
    $('devLockTitle').textContent = mode === 'setup' ? '🔏 تعیین قفل شخصی' : '🔏 قفل شخصی';
    $('devLockHint').textContent = hint || (mode === 'setup' ? 'اول نوع قفل را انتخاب کنید' : 'برای ورود، قفل شخصی را وارد کنید');
    const L = devLockGet();
    const savedType = (L && (L.t === 'pat' || L.t === 'pin')) ? L.t : 'pat';
    lockUi.type = mode === 'setup' ? 'pat' : savedType;
    $('lockTypeRow').hidden = mode !== 'setup';
    $('lockPinInput').hidden = (mode === 'setup') || lockUi.type !== 'pin';
    $('lockPinInput').value = '';
    $('patGrid').hidden = lockUi.type !== 'pat';
    $('devLockOk').hidden = lockUi.type !== 'pin';
    patReset();
    $('devLockOv').hidden = false;
    if (mode !== 'setup' && lockUi.type === 'pin') setTimeout(() => { try { $('lockPinInput').focus(); } catch {} }, 60);
  }
  function lockHide() { $('devLockOv').hidden = true; lockUi.onDone = null; }
  function lockSubmitPat() {
    const seq = lockUi.cur.join(',');
    if (lockUi.cur.length < 4) { lockMsg('الگو باید حداقل ۴ نقطه باشد', true); return; }
    if (lockUi.mode === 'setup') { lockSetupStep('pat:' + seq); return; }
    lockUnlockStep('pat:' + seq);
  }
  function lockSetupStep(secret) {
    if (!lockUi.first) {
      lockUi.first = secret; patReset(); $('lockPinInput').value = '';
      $('devLockHint').textContent = lockUi.type === 'pat' ? 'یک بار دیگر همان الگو را بکشید' : 'یک بار دیگر همان پین را وارد کنید';
      lockMsg(''); return;
    }
    if (secret !== lockUi.first) {
      lockUi.first = null; patReset(); $('lockPinInput').value = '';
      lockMsg('یکسان نبود — دوباره از اول', true); return;
    }
    const cb = lockUi.onDone; lockHide();
    if (cb) { try { cb(secret, lockUi.type); } catch {} }
  }
  async function lockUnlockStep(secret) {
    try {
      await lockOpen(secret);
      lockUi.fails = 0;
      const cb = lockUi.onDone; lockHide();
      if (cb) { try { await cb(secret); } catch {} }
    } catch {
      lockUi.fails++;
      patReset(); $('lockPinInput').value = '';
      lockMsg(lockUi.fails >= 3 ? 'اشتباه است — اگر یادت نیست با رمز اصلی وارد شو' : 'اشتباه است — دوباره', true);
    }
  }
  function lockSubmitPin() {
    const v = $('lockPinInput').value.replace(/\D/g, '').slice(0, 8);
    if (!/^[0-9]{4,8}$/.test(v)) { lockMsg('پین باید ۴ تا ۸ رقم باشد', true); return; }
    if (lockUi.mode === 'setup') { lockSetupStep('pin:' + v); return; }
    lockUnlockStep('pin:' + v);
  }
  function lockSetType(t) {
    lockUi.type = t; lockUi.first = null; lockMsg('');
    $('patGrid').hidden = t !== 'pat';
    $('lockPinInput').hidden = t !== 'pin';
    $('lockPinInput').value = '';
    $('devLockOk').hidden = t !== 'pin';
    $('devLockHint').textContent = t === 'pat'
      ? 'الگو را بکشید (حداقل ۴ نقطه)، بعد دوباره تکرار کنید'
      : 'یک پین ۴ تا ۸ رقمی وارد کنید، بعد دوباره تکرار کنید';
    patReset();
  }
  /* pattern drag: pointer capture on the grid, dots light up as the finger passes */
  (function patBind() {
    const g = $('patGrid');
    if (!g) return;
    let drawing = false;
    const idxAt = (cx, cy) => {
      const dots = g.querySelectorAll('.pat-dot');
      for (const d of dots) {
        const r = d.getBoundingClientRect();
        const rad = Math.max(22, r.width);
        if (Math.abs(cx - (r.left + r.width / 2)) < rad && Math.abs(cy - (r.top + r.height / 2)) < rad) return +d.dataset.i;
      }
      return -1;
    };
    const posPct = (cx, cy) => {
      const gr = g.getBoundingClientRect();
      return { x: (cx - gr.left) / gr.width * 100, y: (cy - gr.top) / gr.height * 100 };
    };
    g.addEventListener('pointerdown', (e) => {
      if ($('devLockOv').hidden || g.hidden) return;
      drawing = true;
      try { g.setPointerCapture(e.pointerId); } catch {}
      const i = idxAt(e.clientX, e.clientY);
      if (i >= 0) patAdd(i);
      e.preventDefault();
    });
    g.addEventListener('pointermove', (e) => {
      if (!drawing) return;
      const i = idxAt(e.clientX, e.clientY);
      if (i >= 0) patAdd(i);
      else patPaint(posPct(e.clientX, e.clientY));
    });
    const end = (e) => {
      if (!drawing) return;
      drawing = false;
      patPaint();
      if (lockUi.cur.length) setTimeout(lockSubmitPat, 180);
    };
    g.addEventListener('pointerup', end);
    g.addEventListener('pointercancel', () => { drawing = false; patPaint(); });
  })();
  $('lockTypePat').onclick = () => lockSetType('pat');
  $('lockTypePin').onclick = () => lockSetType('pin');
  $('devLockOk').onclick = lockSubmitPin;
  $('lockPinInput').addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); lockSubmitPin(); } });
  $('devLockCancel').onclick = lockHide;

  /* ---- trusted-device enrollment / removal (settings) ---- */
  async function devEnsureKeys(secret, type) {
    /* keypair for THIS browser (generated once, stored under the personal lock) */
    let pub = await devPubOnly(), priv = null;
    try { priv = JSON.parse(localStorage.getItem(DEV_PRIV_KEY) || 'null'); } catch { priv = null; }
    if (pub && pub.kty === 'EC' && priv && priv.d) return { pub, fresh: false };
    const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    pub = await crypto.subtle.exportKey('jwk', kp.publicKey);
    priv = await crypto.subtle.exportKey('jwk', kp.privateKey);
    pub = { kty: 'EC', crv: 'P-256', x: pub.x, y: pub.y };
    try {
      localStorage.setItem(DEV_PUB_KEY, JSON.stringify(pub));
      localStorage.setItem(DEV_PRIV_KEY, JSON.stringify(priv));
      try { localStorage.setItem(DEV_LOCK_KEY, JSON.stringify(await lockSeal(secret, type, priv))); } catch {}
    } catch {}
    return { pub, fresh: true };
  }
  let devBusy = false;
  $('devReqBtn').onclick = async () => {
    if (devBusy) return;
    const locked = lockHas();
    const go = async (secret, type) => {
      devBusy = true;
      try {
        const { pub } = await devEnsureKeys(secret, type);
        const r = await API('/api/device/req', { method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ devId: devIdGet(), pub: JSON.stringify(pub), label: deviceLabel() }) });
        const j = await r.json().catch(() => ({}));
        if (j.ok && j.state === 'approved') toast('این دستگاه از قبل مورد اعتماد است ✓', 'ok');
        else if (j.ok) toast('درخواست اعتماد به ربات رفت 📱 — در تلگرام با ✅ تایید کنید', 'ok', 6000);
        else toast(j.error || 'درخواست ناموفق بود', 'err', 5000);
      } catch { toast('خطای شبکه', 'err'); }
      devBusy = false;
      devRefresh(); lockRefresh(); updDevGateBtn();
    };
    if (locked) {
      lockUi.onDone = (secret) => go(secret, (devLockGet() || {}).t || 'pat');
      lockShow('unlock', 'برای اعتماد به این دستگاه، قفل شخصی را وارد کنید');
    } else {
      lockUi.onDone = (secret, type) => go(secret, type);
      lockShow('setup');
    }
  };
  $('devRemoveBtn').onclick = () => {
    confirmDialog('لغو اعتماد این دستگاه؟', 'بعد از این، ورود بدون رمز از این گوشی ممکن نخواهد بود؛ کلید دستگاه هم پاک می‌شود.', 'لغو اعتماد', async () => {
      try {
        await API('/api/device/revoke', { method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ devId: devIdGet() }) }).catch(() => {});
      } catch {}
      try { localStorage.removeItem(DEV_PRIV_KEY); } catch {}
      try { localStorage.removeItem(DEV_PUB_KEY); } catch {}
      toast('اعتماد این دستگاه لغو شد');
      devRefresh(); updDevGateBtn();
    });
  };
  $('lockSetBtn').onclick = () => {
    lockUi.onDone = async (secret, type) => {
      try {
        /* re-wrap the existing device key under the new lock (fresh salts) */
        let priv = null;
        try { priv = JSON.parse(localStorage.getItem(DEV_PRIV_KEY) || 'null'); } catch { priv = null; }
        if (!priv || !priv.d) {
          const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
          priv = await crypto.subtle.exportKey('jwk', kp.privateKey);
          const pub = await crypto.subtle.exportKey('jwk', kp.publicKey);
          try {
            localStorage.setItem(DEV_PRIV_KEY, JSON.stringify(priv));
            localStorage.setItem(DEV_PUB_KEY, JSON.stringify({ kty: 'EC', crv: 'P-256', x: pub.x, y: pub.y }));
          } catch {}
        }
        try { localStorage.setItem(DEV_LOCK_KEY, JSON.stringify(await lockSeal(secret, type, priv))); } catch {}
        toast('قفل شخصی فعال شد 🔏', 'ok');
      } catch { toast('ثبت قفل ناموفق بود', 'err'); }
      devRefresh(); lockRefresh(); updDevGateBtn();
    };
    lockShow('setup');
  };
  $('lockClearBtn').onclick = () => {
    confirmDialog('حذف قفل شخصی؟', 'ورود بدون رمز از این گوشی غیرفعال می‌شود (کلید دستگاه پاک می‌شود).', 'حذف قفل', () => {
      try { localStorage.removeItem(DEV_LOCK_KEY); } catch {}
      try { localStorage.removeItem(DEV_PRIV_KEY); } catch {}
      try { localStorage.removeItem(DEV_PUB_KEY); } catch {}
      toast('قفل شخصی حذف شد');
      devRefresh(); lockRefresh(); updDevGateBtn();
    });
  };

  /* ============================================================
     v27 ورود با اثر انگشت (settings half)
     request → admin TG approval → register this device → login later
     with navigator.credentials.get() (no password typed).
     ============================================================ */
  let fingerBusy = false;
  async function fingerRefresh() {
    try {
      const j = await (await API('/api/finger/status')).json();
      const st = j.state || 'none';
      const reqB = $('fingerReqBtn'), regB = $('fingerRegBtn'), rmB = $('fingerRemoveBtn'), tx = $('fingerStateTxt'), ic = $('fingerIc');
      if (!reqB) return;
      reqB.hidden = !(st === 'none' || st === 'other-active');
      reqB.disabled = st === 'pending';
      reqB.textContent = st === 'pending' ? 'در انتظار تایید ادمین…' : 'درخواست فعال‌سازی';
      regB.hidden = st !== 'await-reg';
      rmB.hidden = st !== 'active';
      ic.textContent = st === 'active' ? '✅' : st === 'await-reg' ? '✋' : '🖐';
      if (st === 'active') tx.textContent = 'فعال است ✓' + (j.name ? ' برای «' + j.name + '»' : '') + ' — روی همین دستگاه بدون تایپ رمز وارد می‌شوید.';
      else if (st === 'await-reg') tx.textContent = 'ادمین تایید کرد ✓ — حالا اثر انگشت خود را روی این دستگاه ثبت کنید.';
      else if (st === 'pending') tx.textContent = 'درخواست به ادمین ارسال شد؛ از تلگرام تایید می‌شود.';
      else if (st === 'other-active') tx.textContent = 'ورود با اثر انگشت برای نام دیگری فعال است.';
      else tx.textContent = 'با تایید ادمین می‌توانید بدون تایپ رمز، فقط با اثر انگشت وارد شوید (ویژه همین دستگاه).';
    } catch { /* sheet may be closed / net down — retry on next open */ }
  }
  $('fingerReqBtn').onclick = async () => {
    if (fingerBusy) return; fingerBusy = true;
    try {
      const r = await API('/api/finger/req', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({}) });
      const j = await r.json().catch(() => ({}));
      if (j.ok && j.state === 'await-reg') toast('قبلاً تایید شده — اثر انگشت را ثبت کنید', 'ok');
      else if (j.ok) toast('درخواست فعال‌سازی برای ادمین ارسال شد ✋', 'ok', 4200);
      else toast(j.error || 'درخواست ناموفق بود', 'err', 5000);
    } catch { toast('خطای شبکه', 'err'); }
    fingerBusy = false;
    fingerRefresh();
  };
  async function fingerRegister() {
    if (!(window.PublicKeyCredential && navigator.credentials)) { toast('مرورگر شما از ورود با اثر انگشت پشتیبانی نمی‌کند', 'err'); return; }
    $('fingerRegBtn').disabled = true;
    try {
      const j0 = await (await API('/api/finger/reg-options')).json();
      if (!j0.ok) { toast(j0.error || 'ثبت اثر انگشت در دسترس نیست', 'err'); return; }
      const cred = await navigator.credentials.create({ publicKey: {
        challenge: b64uDec(j0.challenge),
        rp: j0.rp,
        user: { id: b64uDec(j0.user.id), name: j0.user.name, displayName: j0.user.displayName },
        pubKeyCredParams: j0.pubKeyCredParams,
        timeout: j0.timeout || 60000,
        attestation: j0.attestation || 'none',
        authenticatorSelection: j0.authenticatorSelection,
      } });
      if (!cred) throw new Error('no-cred');
      const rr = cred.response;
      const r = await API('/api/finger/reg-verify', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: cred.id, rawId: b64uEnc(cred.rawId),
          response: { clientDataJSON: b64uEnc(rr.clientDataJSON), attestationObject: b64uEnc(rr.attestationObject) } }) });
      const j = await r.json().catch(() => ({}));
      if (j.ok) toast('✅ اثر انگشت ثبت شد — از این به بعد بدون رمز وارد می‌شوید', 'ok', 5200);
      else toast(j.error || 'ثبت اثر انگشت ناموفق بود', 'err', 5200);
    } catch (e) {
      if (e && e.name === 'InvalidStateError') toast('این دستگاه قبلاً برای اثر انگشت ثبت شده', 'err');
      else if (e && (e.name === 'NotAllowedError' || e.name === 'AbortError')) toast('ثبت اثر انگشت لغو شد', 'err');
      else if (e && e.name === 'NotSupportedError') toast('این دستگاه اثر انگشت وب را پشتیبانی نمی‌کند', 'err');
      else if (e && e.name === 'SecurityError') toast('به دلیل محدودیت امنیتی مرورگر ممکن نیست', 'err');
      else toast('ثبت اثر انگشت ناموفق بود', 'err');
    }
    $('fingerRegBtn').disabled = false;
    fingerRefresh();
  }
  $('fingerRegBtn').onclick = fingerRegister;
  $('fingerRemoveBtn').onclick = () => {
    confirmDialog('غیرفعال‌سازی ورود با اثر انگشت؟', 'بعد از این، ورود بدون رمز ممکن نخواهد بود.', 'غیرفعال کن', async () => {
      try {
        const r = await API('/api/finger/remove', { method: 'POST' });
        const j = await r.json().catch(() => ({}));
        toast(j.ok ? 'ورود با اثر انگشت غیرفعال شد' : (j.error || 'ناموفق بود'), j.ok ? 'ok' : 'err');
      } catch { toast('خطای شبکه', 'err'); }
      fingerRefresh();
    });
  };

  /* header menus */
  function closeMenus() { $('menuPop').classList.remove('on'); $('peerPop').classList.remove('on'); }
  $('menuBtn').onclick = (ev) => { ev.stopPropagation(); $('peerPop').classList.remove('on'); $('menuPop').classList.toggle('on'); };
  $('peerAvatar').onclick = (ev) => { ev.stopPropagation(); $('menuPop').classList.remove('on'); updatePeerHeader(); $('peerPop').classList.toggle('on'); };
  document.addEventListener('click', (e) => {
    if (!$('menuPop').contains(e.target)) $('menuPop').classList.remove('on');
    if (!$('peerPop').contains(e.target) && !$('peerAvatar').contains(e.target)) $('peerPop').classList.remove('on');
    if (!panel.contains(e.target) && !$('emojiBtn').contains(e.target)) closePanel();
  });
  /* instant lock: kill the 6h session and return to the gate.
     v26: also tell the SERVER — revoke this token AND disarm the 300-min
     same-IP re-entry window, otherwise a reload silently slid back in */
  $('lockBtn').onclick = async () => {
    try { es && es.close(); } catch {}
    try {
      const ctl = new AbortController();
      const tmr = setTimeout(() => ctl.abort(), 3500);   /* never let a bad net keep the vault open */
      await fetch('/api/lock', { method: 'POST', headers: tok ? { Authorization: 'Bearer ' + tok } : {}, signal: ctl.signal }).catch(() => {});
      clearTimeout(tmr);
    } catch {}
    await clearStoredSession();
    try { sessionStorage.clear(); } catch {}
    location.reload();
  };

  $('themeBtn').onclick = () => {
    const cyc = { dark: 'light', light: 'black', black: 'auto', auto: 'dark' };   /* v30: AMOLED black added */
    prefs.theme = cyc[prefs.theme] || 'dark';
    localStorage.setItem('vault_theme', prefs.theme);
    applyPrefs();
    toast('تم: ' + ({ dark: 'تیره 🌙', light: 'روشن ☀️', black: 'سیاه مطلق 🖤', auto: 'خودکار ⚙️' })[prefs.theme]);
  };
  $('mWipe').onclick = () => {
    closeMenus();
    confirmDialog('پاک کردن کل چت؟', 'برای همهٔ طرفین پاک می‌شود و غیرقابل بازگشت است.', 'پاک کن', async () => {
      try {
        await API('/api/history', { method: 'DELETE' });
        thread.innerHTML = ''; msgs.clear(); order.length = 0; seenIds.clear();
        toast('همه پیام‌ها پاک شدند 🧹');
      } catch { toast('خطای شبکه', 'err'); }
    });
  };
  $('mLogout').onclick = () => {
    closeMenus();
    confirmDialog('خروج از گفتگو؟', 'کلیدها از حافظه پاک می‌شوند.', 'خروج', () => {
      sessionStorage.clear(); location.reload();
    });
  };

  /* jump / unread */
  scroller.addEventListener('scroll', () => {
    const farUp = scroller.scrollHeight - scroller.scrollTop - scroller.clientHeight > 420;
    $('jumpBtn').hidden = !farUp;
  }, { passive: true });
  function paintJump() {
    const badge = $('unreadBadge');
    if (unread > 0) { badge.hidden = false; badge.textContent = faDigits(unread > 99 ? '+۹۹' : unread); }
    else badge.hidden = true;
  }
  $('jumpBtn').onclick = () => { unread = 0; paintJump(); scroller.scrollTo({ top: scroller.scrollHeight, behavior: 'smooth' }); };
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') {
      unread = 0; paintJump();
      applyVh();
      /* instant reconnect + quick reconcile when coming back.
         v25: also force a reconnect when the socket LOOKS open but the last
         beat is stale — Iranian mobile networks silently kill background
         sockets while readyState stays OPEN */
      if (aesKey) {
        const stale = connected && es && Date.now() - lastStreamBeat > 20000;
        if (!connected || !es || es.readyState === 2 || stale) connectStream();
        refreshHistory(false);
      }
    } else {
      API('/api/seen', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' }).catch(() => {});
    }
  });

  /* eye toggle */
  $('eyeBtn').onclick = () => {
    const pwEl = $('pw');
    pwEl.type = pwEl.type === 'password' ? 'text' : 'password';
  };

  /* ============================================================
     LOGIN / SESSION
     ============================================================ */
  const gate = $('gate');

  /* ---- 6h device session: the CryptoKey lives in IndexedDB (structured-clonable,
         not readable as bytes), the marker+timestamp live in localStorage ---- */
  /* v18 session: keys live ONLY in sessionStorage (dies with the tab).
     Old v17 IndexedDB storage is purged on boot. */
  function purgeLegacyKeyStores() {
    try { localStorage.removeItem('vault_sess'); } catch {}
    try { if (indexedDB.deleteDatabase) indexedDB.deleteDatabase('vault_kv'); } catch {}
  }
  function saveSession(extra) {
    try {
      sessionStorage.setItem('vault_sess2', JSON.stringify({
        tok, ts: Date.now(), fp: myFp, tag: myTag, name: prefs.name || '',
        ck: (extra && extra.ck) || null,
        legacyWrap: (extra && extra.legacyWrap) || null,
      }));
    } catch { /* private mode etc. — session just won't persist */ }
  }
  function clearStoredSession() {
    try { sessionStorage.removeItem('vault_sess2'); } catch {}
    try { sessionStorage.removeItem('vault_tok'); } catch {}
  }
  function sessionInvalid() { clearStoredSession(); try { sessionStorage.clear(); } catch {} location.reload(); }
  function tryRestoreSession() {
    purgeLegacyKeyStores();
    try {
      const s = JSON.parse(sessionStorage.getItem('vault_sess2') || 'null');
      if (!s || !s.tok || !s.ck) return;
      tok = s.tok; myTag = s.tag || ''; myFp = s.fp || '';
      if (s.name) { prefs.name = s.name; state.sitePersona.name = s.name; }
      (async () => {
        try {
          aesKey = await importAesRaw(b64.dec(s.ck));
          if (s.legacyWrap) {
            try { legacyKey = await importAesRaw(await aesDec(aesKey, s.legacyWrap.iv, s.legacyWrap.c)); } catch {}
          }
          restoredLogin = true;
          startApp();          /* history 401 inside will call sessionInvalid() if the token died */
        } catch { try { sessionStorage.clear(); } catch {} }
      })();
    } catch { clearStoredSession(); }
  }


  $('gateForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const pwEl = $('pw');
    const pw = pwEl.value;
    if (!pw) { shakeGate(); return; }
    const dn = $('displayName').value.trim().slice(0, 30);
    if (dn) { prefs.name = dn; localStorage.setItem('vault_displayName', dn); state.sitePersona.name = dn; }
    $('enterBtn').disabled = true;
    document.querySelector('.lock-wrap').classList.add('busy');
    $('gateMsg').classList.remove('err'); $('gateMsg').textContent = 'در حال باز کردن قفل…';
    try {
      /* v15: name + device ride along — they appear ONLY in the admin's Telegram
         login card so a stranger's login is instantly visible and kickable */
      /* v18 step 1: probe the auth mode (new zero-knowledge vs pre-migration).
         v20.2: a failed probe (network/ban) NO LONGER falls through to the
         legacy login — that showed a misleading «رمز اشتباه است» when the
         real problem was connectivity or an IP block. Server error texts
         (e.g. the IP-ban 403, the lock minutes on 429) show verbatim. */
      let hello = null;
      try {
        const hr = await fetchRetry('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ mode: 'hello' }) }, 2);
        if (hr.status === 403) {
          const je = await hr.json().catch(() => ({}));
          document.querySelector('.lock-wrap').classList.remove('busy');
          showGateError(je.error || 'دسترسی این آی‌پی موقتاً مسدود شده است');
          return;
        }
        hello = await hr.json().catch(() => null);
      } catch { hello = null; }
      if (!hello || !hello.mode) {
        document.querySelector('.lock-wrap').classList.remove('busy');
        showGateError('ارتباط با سرور برقرار نشد — اینترنت یا فیلترشکن را بررسی کنید');
        return;
      }
      if (hello.mode === 'new' && hello.saltA) {
        /* zero-knowledge login: only a PBKDF2 verifier leaves the device */
        const verifier = b64.enc(await pbkdf2Raw(pw, hello.saltA, 250000));
        const r = await fetchRetry('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ mode: 'ver', verifier, name: dn, dev: deviceLabel() }) }, 3);
        document.querySelector('.lock-wrap').classList.remove('busy');
        if (r.status === 429 || r.status === 403) { const je = await r.json().catch(() => ({})); showGateError(je.error || 'تلاش بیش از حد — چند دقیقه دیگر امتحان کنید'); return; }
        if (r.status === 401) { showGateError('رمز اشتباه است'); return; }
        if (!r.ok) { showGateError('خطای سرور — دوباره تلاش کنید'); return; }
        const d = await r.json();
        tok = d.tok; sessionStorage.setItem('vault_tok', tok);
        const kek = await hkdfWrapKey(await pbkdf2Raw(pw, d.saltB, 250000), 'ck-wrap-v1');
        const ckRaw = await aesDec(kek, d.pwWrap.iv, d.pwWrap.c);
        aesKey = await importAesRaw(ckRaw);
        if (d.legacyWrap) { try { legacyKey = await importAesRaw(await aesDec(aesKey, d.legacyWrap.iv, d.legacyWrap.c)); } catch {} }
        /* v18: stable per-device identity — NEVER adopt legacyTag here (that
           belongs to the migration device only); keep this device's tag or
           make a fresh one */
        myTag = localStorage.getItem('vault_tag') || rndTag();
        localStorage.setItem('vault_tag', myTag);
        myFp = await ckFingerprint(ckRaw);
        if (d.legacyName && !dn) { prefs.name = d.legacyName; localStorage.setItem('vault_displayName', prefs.name); }
        sessionStorage.removeItem('vault_recid');
        saveSession({ ck: b64.enc(ckRaw), legacyWrap: d.legacyWrap || null });
        startApp();
        return;
      }
      /* pre-migration (legacy) login — transparently upgrade to zero-knowledge */
      const r = await fetchRetry('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ pw, name: dn, dev: deviceLabel() }) }, 3);
      document.querySelector('.lock-wrap').classList.remove('busy');
      if (r.status === 429 || r.status === 403) { const je = await r.json().catch(() => ({})); showGateError(je.error || 'تلاش بیش از حد — چند دقیقه دیگر امتحان کنید'); return; }
      if (r.status === 401) { showGateError('رمز اشتباه است'); return; }
      if (!r.ok) { showGateError('خطای سرور — دوباره تلاش کنید'); return; }
      const data = await r.json();
      tok = data.tok; sessionStorage.setItem('vault_tok', tok);
      /* derive the legacy key one last time — then re-key everything to a
         browser-generated chat key the server can never see */
      const legacyRaw = new Uint8Array(await pbkdf2Raw(pw, data.salt));   // same bits deriveKey() would wrap
      const d2 = new Uint8Array(await crypto.subtle.digest('SHA-256', te.encode('vault-id:' + data.salt + ':' + pw)));
      const legacyTag = Array.from(d2.slice(4, 12), x => x.toString(16).padStart(2, '0')).join('');
      const ckRaw = crypto.getRandomValues(new Uint8Array(32));
      const saltA = b64.enc(crypto.getRandomValues(new Uint8Array(16)));
      const saltB = b64.enc(crypto.getRandomValues(new Uint8Array(16)));
      const verifier = b64.enc(await pbkdf2Raw(pw, saltA, 250000));
      const kek = await hkdfWrapKey(await pbkdf2Raw(pw, saltB, 250000), 'ck-wrap-v1');
      const pwWrap = await aesEnc(kek, ckRaw);
      const ckKey = await importAesRaw(ckRaw);
      const legacyWrap = await aesEnc(ckKey, legacyRaw);
      $('gateMsg').textContent = 'ارتقای امنیتی (رمزنگاری صفر-دانش)…';
      const r2 = await API('/api/upgrade', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ verifier, saltA, saltB, pwWrap, legacyWrap, legacyTag, legacyName: dn || null }) });
      if (!r2.ok) {
        const j2 = await r2.json().catch(() => ({}));
        if (j2 && j2.error === 'already migrated') {
          /* another device migrated first — redo the hello/ver flow */
          $('enterBtn').disabled = false;
          document.querySelector('.lock-wrap').classList.remove('busy');
          $('gateForm').requestSubmit();
          return;
        }
        showGateError('ارتقا ناموفق — دوباره تلاش کنید');
        return;
      }
      const up = await r2.json();
      tok = up.tok; sessionStorage.setItem('vault_tok', tok);
      aesKey = ckKey;
      legacyKey = await importAesRaw(legacyRaw);
      myTag = up.legacyTag || legacyTag;
      localStorage.setItem('vault_tag', myTag);   // migration device keeps the legacy identity
      myFp = await ckFingerprint(ckRaw);
      sessionStorage.removeItem('vault_recid');
      saveSession({ ck: b64.enc(ckRaw), legacyWrap });
      toast('🔐 ارتقا به رمزنگاری صفر-دانش انجام شد — کلید فقط در مرورگر شماست', 'ok', 5000);
      startApp();
    } catch {
      showGateError('ارتباط برقرار نشد — چند بار تلاش کردیم؛ اینترنت را بررسی کنید');
      document.querySelector('.lock-wrap').classList.remove('busy');
    }
  });
  const rndTag = () => Array.from(crypto.getRandomValues(new Uint8Array(6)), x => x.toString(16).padStart(2, '0')).join('');
  async function ckFingerprint(ckRaw) {
    const d = new Uint8Array(await crypto.subtle.digest('SHA-256', ckRaw));
    return WORDS[((d[0] << 8) | d[1]) % WORDS.length] + '-' + WORDS[((d[2] << 8) | d[3]) % WORDS.length];
  }
  function showGateError(msg) {
    $('gateMsg').textContent = '❌ ' + msg; $('gateMsg').classList.add('err');
    $('enterBtn').disabled = false; $('pw').value = ''; $('pw').focus(); shakeGate();
  }
  function shakeGate() {
    const card = document.querySelector('.gate-card');
    card.classList.remove('shake'); void card.offsetWidth; card.classList.add('shake');
  }

  /* v16 — hero flight: clone the panda tile, fly it up while the card settles */
  function pandaFlight() {
    try {
      const lw = document.querySelector('#gateForm .lock-wrap');
      if (!lw) return;
      const r = lw.getBoundingClientRect();
      const t = document.documentElement.dataset.theme;
      const dark = t === 'dark' || (t === 'auto' && matchMedia('(prefers-color-scheme: dark)').matches);
      const cl = document.createElement('div');
      cl.className = 'flight-panda' + (dark ? ' dark' : '');
      cl.style.left = r.left + 'px'; cl.style.top = r.top + 'px';
      cl.style.width = r.width + 'px'; cl.style.height = r.height + 'px';
      document.body.appendChild(cl);
      requestAnimationFrame(() => requestAnimationFrame(() => cl.classList.add('go')));
      setTimeout(() => cl.remove(), 950);
    } catch {}
  }

  function startApp() {
    input.disabled = false;
    autosize();
    updateSendState();
    applyVh();
    refreshHistory(true);
    connectStream();
    setInterval(() => refreshHistory(false), 120000);
    regSW();
    updNotifUI();
    updInstallUI();
    ensureVaultFallback();   /* v20.1: approve-tap-only entry needs this */
    paintOutbox();
    if (restoredLogin) {                       /* resume: keep the plain quick fade */
      gate.classList.add('hidden');
      app.classList.add('on');
    } else {                                   /* fresh login: panda flight handover */
      pandaFlight();
      gate.classList.add('takeoff');
      setTimeout(() => app.classList.add('on'), 240);
      setTimeout(() => gate.classList.add('hidden'), 460);
    }
    toast(restoredLogin ? '🔐 نشست شما بازیابی شد — تا ۶ ساعت رمز نمی‌خواهد' : 'اتصال رمزنگاری‌شده برقرار شد 🔐 · اثر انگشت: ' + myFp, 'ok', 4200);
    setTimeout(() => scrollDown(true), 700);
    if (matchMedia('(hover:hover)').matches) input.focus();
  }

  /* v20.1: make sure the server holds a fallback wrap of CK (CK encrypted
     under the server-derived fallback KEK) so a freshly approved passwordless
     user can enter even when the admin approves from Telegram with no site
     tab open. Idempotent — every login re-ensures it silently. */
  async function ensureVaultFallback() {
    try {
      if (!aesKey || !tok) return;
      const kr = await API('/api/vault-fallback-key');
      if (!kr.ok) return;
      const kj = await kr.json();
      if (!kj.k) return;
      const fkKey = await crypto.subtle.importKey('raw', b64.dec(kj.k), { name: 'AES-GCM' }, false, ['encrypt']);
      const raw = new Uint8Array(await crypto.subtle.exportKey('raw', aesKey));
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, fkKey, raw);
      await API('/api/vault-fallback', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ iv: b64.enc(iv), c: b64.enc(ct), name: prefs.name || '' }) });   /* v24: + name arms re-entry */
    } catch { /* best-effort — the session-seal path still works without it */ }
  }

  /* v16 — empty-state welcome: visible only while the thread has no bubbles */
  const emptyState = $('emptyState');
  if (emptyState && 'MutationObserver' in window) {
    const updEmpty = () => { emptyState.hidden = !!thread.querySelector('.msg-wrap'); };
    new MutationObserver(updEmpty).observe(thread, { childList: true, subtree: false });
    updEmpty();
  }

  /* ============================================================
     NOTIFICATIONS (service-worker backed)
     ============================================================ */
  let swReg = null;
  function regSW() {
    if (!('serviceWorker' in navigator)) return;
    // purge legacy registrations (older script URLs) so no zombie worker survives
    navigator.serviceWorker.getRegistrations().then(regs => {
      regs.forEach(r => {
        const s = r.active || r.installing || r.waiting;
        if (s && !/sw\.js(\?|$)/.test(s.scriptURL)) { try { r.unregister(); } catch {} }
      });
    }).catch(() => {});
    // updateViaCache:'none' => SW update checks bypass HTTP cache entirely
    navigator.serviceWorker.register('/sw.js', { updateViaCache: 'none', scope: '/' }).then(r => {
      swReg = r;
      let reloaded = false;
      r.addEventListener('updatefound', () => {
        const nw = r.installing; if (!nw) return;
        nw.addEventListener('statechange', () => {
          // a brand-new worker took over while this page was on an older one: refresh once
          if (nw.state === 'activated' && navigator.serviceWorker.controller && !reloaded) {
            reloaded = true;
            setTimeout(() => location.reload(), 120);
          }
        });
      });
    }).catch(() => {});
  }
  const notifPrefOn = () => localStorage.getItem('vault_notif') !== 'off';
  function updNotifUI() {
    const perm = ('Notification' in window) ? Notification.permission : 'denied';
    const on = notifPrefOn() && perm === 'granted';
    $('mNotif').textContent = on ? '🔔 اعلان‌ها: روشن' : '🔔 اعلان‌ها: خاموش';
    const bt = $('notifToggle');
    if (!('Notification' in window)) {
      bt.textContent = 'مرورگر شما از اعلان پشتیبانی نمی‌کند'; bt.disabled = true;
    } else if (perm === 'granted') {
      bt.textContent = notifPrefOn() ? 'اعلان فعال است ✓' : 'اعلان خاموش است';
    } else if (perm === 'denied') {
      bt.textContent = 'اعلان در مرورگر مسدود شده'; bt.disabled = true;
    } else bt.textContent = 'فعال‌سازی اعلان پیام‌ها';
    $('notifHint').textContent = perm === 'granted'
      ? (on ? 'وقتی سایت در پس‌زمینه باشد، پیام جدید اعلان می‌گیرد.' : 'اعلان‌ها از منو خاموش شده‌اند.')
      : 'برای اطلاع از پیام جدید وقتی سایت باز نیست، اعلان را فعال کنید.';
  }
  async function enableNotifs() {
    if (!('Notification' in window)) { toast('مرورگر شما اعلان ندارد', 'err'); return; }
    let p = Notification.permission;
    if (p === 'default') { try { p = await Notification.requestPermission(); } catch {} }
    if (p === 'granted') { localStorage.setItem('vault_notif', 'on'); toast('اعلان‌ها فعال شد 🔔', 'ok'); }
    else toast('اجازهٔ اعلان داده نشد — از تنظیمات مرورگر هم می‌شود', 'err');
    updNotifUI();
  }
  $('notifToggle').onclick = enableNotifs;
  $('mNotif').onclick = () => {
    closeMenus();
    const on = notifPrefOn() && ('Notification' in window) && Notification.permission === 'granted';
    if (on) { localStorage.setItem('vault_notif', 'off'); toast('اعلان‌ها خاموش شد'); }
    else enableNotifs();
  };
  function notifyIncoming(m, previewTxt) {
    if (!notifPrefOn()) return;
    try { navigator.vibrate && navigator.vibrate([40, 30, 40]); } catch {}
    if (!('Notification' in window) || Notification.permission !== 'granted') return;
    /* v24: dedicated high-contrast notification icon (panda face on brand
       gradient) — the full brand tile turned to mush at shade size */
    const opts = {
      body: (previewTxt || 'رسانه جدید').slice(0, 140),
      tag: 'vault-' + m.id,
      icon: '/notificon.png?v=28',
      badge: '/notificon-96.png?v=28',
      dir: 'rtl', lang: 'fa',
      renotify: true, silent: true,
      data: { url: '/' },
    };
    if (swReg && swReg.showNotification) swReg.showNotification(siteTitle + ' · پیام جدید', opts).catch(() => {});
    else {
      try {
        const n = new Notification('پیام جدید', opts);
        n.onclick = () => { window.focus(); n.close(); };
      } catch {}
    }
  }

  /* ============================================================
     PWA INSTALL / REPAIR / UNINSTALL (v24)
     - Install no longer disappears after install: it is replaced by
       «تعمیر برنامه» (clear caches + fresh SW + reload) and «حذف برنامه»
       (guided uninstall) — both in the menu and in the settings sheet.
     ============================================================ */
  let deferredPrompt = null;
  const installedStandalone = () => matchMedia('(display-mode:standalone)').matches || navigator.standalone === true;
  addEventListener('beforeinstallprompt', (e) => {
    e.preventDefault();
    deferredPrompt = e;
    updInstallUI();
  });
  addEventListener('appinstalled', () => {
    deferredPrompt = null;
    updInstallUI();
    toast(siteTitle + ' نصب شد 🎉 — دکمهٔ نصب حالا «تعمیر/حذف» است', 'ok', 4200);
  });
  function updInstallUI() {
    const inst = installedStandalone();
    $('mInstall').hidden = inst;
    $('mRepairApp').hidden = !inst;
    /* install buttons: visible pre-install (prompt or guided instructions);
       after install they hand over to repair/uninstall */
    $('installAppBtn').hidden = inst;
    $('repairAppBtn').hidden = !inst;
    $('uninstallAppBtn').hidden = !inst;
  }
  async function promptInstall() {
    if (installedStandalone()) {
      toast('برنامه همین حالا نصب است — از «تعمیر» یا «حذف» استفاده کن');
      updInstallUI();
      return;
    }
    if (!deferredPrompt) {
      toast('از منوی مرورگر گزینهٔ «افزودن به صفحهٔ اصلی» را انتخاب کنید');
      return;
    }
    try {
      deferredPrompt.prompt();
      await deferredPrompt.userChoice;
      deferredPrompt = null;
      updInstallUI();
    } catch {}
  }
  $('mInstall').onclick = () => { closeMenus(); promptInstall(); };
  $('installAppBtn').onclick = promptInstall;
  /* v24: repair = purge every cache + fresh service worker + reload (fixes a
     wedged installed app without losing the session) */
  async function repairApp() {
    toast('در حال تعمیر برنامه…');
    try { if (swReg) await swReg.unregister(); } catch {}
    try {
      const ks = await caches.keys();
      await Promise.all(ks.map(k => caches.delete(k)));
    } catch {}
    try { sessionStorage.setItem('vault_repair', '1'); } catch {}
    setTimeout(() => location.reload(), 500);
  }
  $('mRepairApp').onclick = () => { closeMenus(); repairApp(); };
  $('repairAppBtn').onclick = repairApp;
  $('uninstallAppBtn').onclick = () => {
    const android = /Android/i.test(navigator.userAgent);
    const ios = /iPhone|iPad/i.test(navigator.userAgent);
    confirmDialog('حذف برنامه',
      android ? 'آیکون برنامه را روی صفحهٔ اصلی نگه دارید → «حذف نصب». (در Chrome: منوی ⋮ ← «حذف برنامه…» هم هست). بعد از حذف، سایت دوباره در مرورگر باز می‌شود.'
      : ios ? 'آیکون برنامه را روی صفحهٔ اصلی نگه دارید → «حذف برنامه» → تأیید.'
      : 'در Chrome دسکتاپ: نوار نشانی ← آیکون نصب ← «حذف برنامه» (یا chrome://apps).',
      'متوجه شدم', () => {});
  };

  /* ============================================================
     FORGOT PASSWORD — request entry without a password
     Admin approves/denies in Telegram within 30 minutes.
     The request card also carries a short device fingerprint
     (model · os · browser) so the admin knows who is asking.
     ============================================================ */
  function deviceLabel() {
    try {
      const ua = navigator.userAgent || '';
      let model = '', os = '', br = '';
      const and = /Android\s([\d.]+)/.exec(ua);
      if (and) {
        os = 'Android ' + and[1].split('.')[0];
        const mm = /Android[^;]*;\s*([^;)]+?)(?:\s+Build\/|\))/.exec(ua);
        model = mm ? mm[1].trim().replace(/\s+/g, ' ') : '';
      } else if (/iPhone/.test(ua)) {
        os = 'iOS ' + ((/OS (\d+)[_.]/.exec(ua) || [])[1] || '');
        model = 'iPhone';
      } else if (/iPad/.test(ua)) {
        os = 'iPadOS'; model = 'iPad';
      } else if (/Windows NT/.test(ua)) {
        os = /Windows NT 10\.0/.test(ua) ? 'Windows 10/11' : 'Windows';
      } else if (/Mac OS X/.test(ua)) {
        os = 'macOS ' + ((/Mac OS X (\d+)[_.]/.exec(ua) || [])[1] || '');
      } else if (/Linux/.test(ua)) os = 'Linux';
      /* v20: UA-CH gives the real Android model when the UA hides it */
      const uad = navigator.userAgentData;
      if (uad && uad.model && !model) model = String(uad.model).trim().slice(0, 24);
      if (/Edg\//.test(ua)) br = 'Edge';
      else if (/OPR\//.test(ua)) br = 'Opera';
      else if (/SamsungBrowser/.test(ua)) br = 'Samsung Internet';
      else if (/FxiOS\//.test(ua)) br = 'Firefox';
      else if (/CriOS\//.test(ua)) br = 'Chrome';
      else if (/Firefox\//.test(ua)) br = 'Firefox';
      else if (/Chrome\//.test(ua)) br = 'Chrome';
      else if (/Safari\//.test(ua)) br = 'Safari';
      return [model, os, br].filter(Boolean).join(' · ').slice(0, 60);
    } catch { return ''; }
  }
  /* v20: extra request context for the admin card (informational only) */
  function deviceXtra(visits) {
    try {
      const parts = [];
      try { parts.push('🕐 ' + new Date().toLocaleTimeString('fa-IR', { hour: '2-digit', minute: '2-digit' })); } catch {}
      try { parts.push('🖥 ' + screen.width + '×' + screen.height); } catch {}
      if (navigator.language) parts.push('🌍 ' + String(navigator.language).slice(0, 10));
      try { const tz = Intl.DateTimeFormat().resolvedOptions().timeZone; if (tz) parts.push('⏱ ' + String(tz).slice(0, 28)); } catch {}
      const uad2 = navigator.userAgentData;
      if (uad2 && uad2.model) parts.push('📱 ' + String(uad2.model).slice(0, 24));
      if (visits > 1) parts.push('🔁 بازدید ' + faDigits(String(visits)) + 'م');
      return parts.join(' · ').slice(0, 140);
    } catch { return ''; }
  }

  const gateFormEl = $('gateForm'), recoverCard = $('recoverCard'), recWaiting = $('recWaiting');
  let recPollTmr = null, recCdTmr = null, recBusyFlag = false;
  let recReqId = sessionStorage.getItem('vault_recid') || '';

  $('forgotBtn').onclick = () => {
    gateFormEl.hidden = true; recoverCard.hidden = false;
    $('recMsg').textContent = ''; $('recMsg').classList.remove('err');
    /* device fingerprint is collected silently and shown ONLY in the admin's
       Telegram card — never rendered to the user here */
    setTimeout(() => $('recName').focus(), 350);
  };
  $('recBackBtn').onclick = () => { stopRecTimers(); backToMain(); };
  function backToMain() {
    recoverCard.hidden = true; gateFormEl.hidden = false;
    recReset();
  }
  function recReset() {
    recWaiting.hidden = true;
    recWaiting.querySelector('.spinner').style.display = '';
    $('recSubmit').hidden = false; $('recSubmit').disabled = false;
    $('recName').disabled = false; $('recCode').disabled = false;
  }
  function recErr(t) {
    $('recMsg').textContent = '❌ ' + t;
    $('recMsg').classList.add('err');
    recoverCard.classList.remove('shake'); void recoverCard.offsetWidth; recoverCard.classList.add('shake');
  }
  recoverCard.addEventListener('submit', recSubmitReq);
  async function recSubmitReq(e) {
    e.preventDefault();
    if (recBusyFlag) return;
    const name = $('recName').value.trim().slice(0, 30);
    if (name.length < 2) { recErr('نام را وارد کنید (حداقل ۲ حرف)'); return; }
    /* اسم رمز — optional alias typed by the user, shown only in the admin's card */
    const code = $('recCode').value.trim().replace(/[\u0000-\u001f<>]/g, '').slice(0, 30);
    /* v20: visit counter — the admin sees whether this device asked before */
    const visits = Number(localStorage.getItem('vault_visits') || '0') + 1;
    try { localStorage.setItem('vault_visits', String(visits)); } catch {}
    recBusyFlag = true;
    $('recMsg').classList.remove('err'); $('recMsg').textContent = 'در حال ارسال به ربات…';
    $('recSubmit').disabled = true;
    try {
      const r = await fetchRetry('/api/access-request', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, code, dev: deviceLabel(), xtra: deviceXtra(visits) }),
      }, 3);
      const j = await r.json().catch(() => ({}));
      if (!r.ok) {
        recErr(j.error || ('خطا کد ' + r.status));
        $('recSubmit').disabled = false; recBusyFlag = false;
        return;
      }
      recReqId = j.id;
      sessionStorage.setItem('vault_recid', j.id);
      startRecWaiting(j.exp);
    } catch {
      recErr('ارتباط برقرار نشد — دوباره تلاش کنید');
      $('recSubmit').disabled = false;
    }
    recBusyFlag = false;
  }

  function startRecWaiting(exp) {
    $('recSubmit').hidden = true;
    $('recName').disabled = true; $('recCode').disabled = true;
    recWaiting.hidden = false;
    recWaiting.querySelector('.spinner').style.display = '';
    $('stepSent').className = 'step done';
    $('stepDecide').className = 'step on';
    $('stepDone').className = 'step';
    $('recMsg').textContent = ''; $('recMsg').classList.remove('err');

    clearInterval(recCdTmr); clearInterval(recPollTmr);
    const cd = $('recCountdown');
    const tick = () => {
      const left = Math.max(0, exp - Date.now());
      const s = Math.ceil(left / 1000);
      cd.textContent = faDigits(String(Math.floor(s / 60)).padStart(2, '0') + ':' + String(s % 60).padStart(2, '0'));
      cd.classList.toggle('low', left < 5 * 60000);
      if (left <= 0) finishWaiting('⌛ زمان تصمیم‌گیری تمام شد — دوباره تلاش کنید');
    };
    tick();
    recCdTmr = setInterval(tick, 1000);
    recPollTmr = setInterval(pollRec, 2500);

    async function pollRec() {
      if (document.hidden || !recReqId) return;
      try {
        const r = await fetch('/api/access-status/' + recReqId, { cache: 'no-store' });
        if (r.status === 404) { finishWaiting('درخواست یافت نشد — دوباره تلاش کنید'); return; }
        const j = await r.json();
        if (j.status === 'approved') {
          $('stepDecide').className = 'step done';
          $('stepDone').className = 'step on';
          /* v20: fully automatic entry — the claim code arrives with the poll
             (only the browser holding the unguessable request id gets it) and
             the key wrap is sealed by any live session. No code typing at all. */
          const m = $('recMsg');
          if (j.cc && (j.ready || j.fb)) {
            m.classList.remove('err');
            m.textContent = '✅ تایید شد — در حال ورود خودکار…';
            if (!autoClaimBusy) { autoClaimBusy = true; doClaim(j.cc); }
          } else if (!m.classList.contains('err')) {
            m.textContent = '✅ تایید شد — ادمین یک بار سایت را باز کند تا کلید فعال شود…';
            if (!j.cc && !claimShown) { claimShown = true; showClaimInput(); }
          }
        } else if (j.status === 'denied') finishWaiting('❌ ادمین این درخواست را رد کرد — تا ۲۴ ساعت امکان درخواست جدید نیست.');
        else if (j.status === 'expired' || j.status === 'gone') finishWaiting('⌛ این درخواست منقضی شد — درخواست جدید بدهید.');
      } catch {}
    }
    pollRec();
  }

  /* v18 claim: after approval the admin's TG card shows a one-time code —
     the chat key arrives ONLY wrapped under that code (zero-knowledge).
     v20: the code is fetched automatically with the status poll (cc field)
     and never shown to the user — typing it is only a hidden fallback. */
  let claimShown = false, autoClaimArmed = false, autoClaimBusy = false;
  function showClaimInput() {
    const cw = $('claimCodeWrap');
    if (cw) {
      cw.hidden = false;
      recWaiting.querySelector('.spinner').style.display = 'none';
      $('recMsg').classList.remove('err');
      $('recMsg').textContent = '⏳ در انتظار فعال‌سازی کلید…';
      setTimeout(() => $('claimCode') && $('claimCode').focus(), 200);
    }
  }
  async function doClaim(codeOverride) {
    const code = (codeOverride || (($('claimCode') || {}).value || '')).trim().toUpperCase();
    if (!code) { $('recMsg').textContent = 'کد را وارد کنید'; $('recMsg').classList.add('err'); return; }
    try {
      const r = await fetch('/api/access-claim', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: recReqId, code }),
      });
      const j = await r.json().catch(() => ({}));
      if (r.ok && j.ok && j.wrap) {
        stopRecTimers();
        sessionStorage.removeItem('vault_recid');
        tok = j.tok; sessionStorage.setItem('vault_tok', tok);
        /* v20.1: two wrap kinds — session-sealed (unwrap under the claim code)
           or server-assisted fallback (unwrap with the KEK carried over HTTPS;
           the admin's TG approval was the authorization gate) */
        let ckRaw = null;
        try {
          if (j.fk) {
            const fkKey = await crypto.subtle.importKey('raw', b64.dec(j.fk), { name: 'AES-GCM' }, false, ['decrypt']);
            ckRaw = await aesDec(fkKey, j.wrap.iv, j.wrap.c);
          } else {
            const bits = await crypto.subtle.digest('SHA-256', te.encode('claim:' + code));
            const wk = await hkdfWrapKey(new Uint8Array(bits), 'ck-wrap-v1');
            ckRaw = await aesDec(wk, j.wrap.iv, j.wrap.c);
          }
        } catch {}
        if (!ckRaw) {
          $('recMsg').classList.add('err');
          $('recMsg').textContent = '❌ بازکردن کلید ناموفق بود — دوباره تلاش کنید';
          autoClaimBusy = false;
          return;
        }
        aesKey = await importAesRaw(ckRaw);
        if (j.legacyWrap) { try { legacyKey = await importAesRaw(await aesDec(aesKey, j.legacyWrap.iv, j.legacyWrap.c)); } catch {} }
        myTag = localStorage.getItem('vault_tag') || rndTag();
        localStorage.setItem('vault_tag', myTag);
        myFp = await ckFingerprint(ckRaw);
        prefs.name = j.name || prefs.name || ''; localStorage.setItem('vault_displayName', prefs.name);
        state.sitePersona.name = prefs.name;
        saveSession({ ck: b64.enc(ckRaw), legacyWrap: j.legacyWrap || null });
        recWaiting.querySelector('.spinner').style.display = 'none';
        $('recCountdown').textContent = '✓';
        $('recMsg').classList.remove('err');
        $('recMsg').textContent = 'تایید شد! در حال ورود…';
        setTimeout(startApp, 750);
        return;
      }
      $('recMsg').classList.add('err');
      if (j.status === 'waitup' || /فعال نشده/.test(j.error || '')) {
        /* v19/v20: key not sealed yet — keep the code and auto-retry the
           moment the status poll reports ready */
        $('recMsg').textContent = '⏳ ' + (j.error || 'کلید هنوز فعال نشده — منتظر بمان…');
        autoClaimArmed = true;
        autoClaimBusy = false;
      } else {
        $('recMsg').textContent = '❌ ' + (j.error || 'امکان ورود نبود — کد را دوباره بررسی کنید');
      }
    } catch {
      $('recMsg').classList.add('err');
      $('recMsg').textContent = '❌ ارتباط قطع شد — دوباره تلاش کنید';
    }
  }
  const claimBtn = $('claimGoBtn');
  if (claimBtn) claimBtn.onclick = doClaimContinue;
  function doClaimContinue() { doClaim(); }
  const claimInput = $('claimCode');
  if (claimInput) claimInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); doClaimContinue(); } });

  function finishWaiting(msg) {
    stopRecTimers();
    sessionStorage.removeItem('vault_recid');
    recErr(msg);
    $('recCountdown').textContent = '—';
    $('recSubmit').hidden = false; $('recSubmit').disabled = false;
    $('recName').value = ''; $('recName').disabled = false;
    $('recCode').value = ''; $('recCode').disabled = false;
  }
  function stopRecTimers() { clearInterval(recPollTmr); clearInterval(recCdTmr); recPollTmr = recCdTmr = null; }

  /* resume an in-flight request after page reload */
  (async function resumeRecRequest() {
    if (!recReqId) return;
    try {
      const r = await fetch('/api/access-status/' + recReqId, { cache: 'no-store' });
      if (!r.ok) { sessionStorage.removeItem('vault_recid'); return; }
      const j = await r.json();
      if (j.status !== 'pending') { sessionStorage.removeItem('vault_recid'); return; }
      gateFormEl.hidden = true; recoverCard.hidden = false;
      $('recName').value = ''; $('recCode').value = '';
      startRecWaiting(j.exp);
    } catch {}
  })();

  /* ============================================================
     v27 ورود با اثر انگشت (gate half) — the button only appears when the
     server reports a registered credential (health). Login: options →
     platform fingerprint → verify → session + fallback CK wrap unwrap.
     ============================================================ */
  function fingerGateBtn(show) { const b = $('fingerLoginBtn'); if (b) b.hidden = !show; }
  async function fingerLogin() {
    const btn = $('fingerLoginBtn');
    if (!(window.PublicKeyCredential && navigator.credentials)) { showGateError('مرورگر شما از ورود با اثر انگشت پشتیبانی نمی‌کند'); return; }
    btn.disabled = true;
    $('gateMsg').classList.remove('err');
    $('gateMsg').textContent = 'در انتظار اثر انگشت…';
    try {
      const name = $('displayName').value.trim().slice(0, 30);
      const r0 = await fetchRetry('/api/finger/auth-options', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name }) }, 2);
      const j0 = await r0.json().catch(() => ({}));
      if (!r0.ok || !j0.ok) { showGateError(j0.error || 'ورود با اثر انگشت در دسترس نیست'); btn.disabled = false; return; }
      const cred = await navigator.credentials.get({ publicKey: {
        challenge: b64uDec(j0.challenge),
        rpId: j0.rpId,
        userVerification: j0.userVerification || 'required',
        timeout: j0.timeout || 60000,
        allowCredentials: (j0.allowCredentials || []).map(c => ({ id: b64uDec(c.id), type: c.type || 'public-key' })),
      } });
      if (!cred) throw new Error('no-cred');
      const rr = cred.response;
      const r = await fetchRetry('/api/finger/auth-verify', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, id: cred.id,
          response: { clientDataJSON: b64uEnc(rr.clientDataJSON), authenticatorData: b64uEnc(rr.authenticatorData), signature: b64uEnc(rr.signature) } }) }, 2);
      const j = await r.json().catch(() => ({}));
      if (!r.ok || !j.ok || !j.wrap || !j.fk) {
        showGateError(j.error || 'تایید اثر انگشت ناموفق بود');
        btn.disabled = false;
        return;
      }
      const fkKey = await crypto.subtle.importKey('raw', b64.dec(j.fk), { name: 'AES-GCM' }, false, ['decrypt']);
      const ckRaw = await aesDec(fkKey, j.wrap.iv, j.wrap.c);
      tok = j.tok; sessionStorage.setItem('vault_tok', tok);
      aesKey = await importAesRaw(ckRaw);
      if (j.legacyWrap) { try { legacyKey = await importAesRaw(await aesDec(aesKey, j.legacyWrap.iv, j.legacyWrap.c)); } catch {} }
      myTag = localStorage.getItem('vault_tag') || rndTag();
      localStorage.setItem('vault_tag', myTag);
      myFp = await ckFingerprint(ckRaw);
      if (j.name) { prefs.name = j.name; localStorage.setItem('vault_displayName', prefs.name); state.sitePersona.name = prefs.name; }
      sessionStorage.removeItem('vault_recid');
      saveSession({ ck: b64.enc(ckRaw), legacyWrap: j.legacyWrap || null });
      startApp();
    } catch (e) {
      $('gateMsg').classList.add('err');
      $('gateMsg').textContent = (e && e.name === 'NotAllowedError')
        ? 'اثر انگشت تایید نشد یا لغو شد — دوباره امتحان کنید'
        : 'ورود با اثر انگشت ناموفق بود — با رمز وارد شوید';
      btn.disabled = false;
    }
  }
  const fingerGateBtnEl = $('fingerLoginBtn');
  if (fingerGateBtnEl) fingerGateBtnEl.onclick = fingerLogin;

  /* ---- v29 passwordless login from a trusted device (gate) ---- */
  function updDevGateBtn() {
    const b = $('devLoginBtn');
    if (!b) return;
    b.hidden = !(lockHas() && devHasKeys());
  }
  async function devGateEnter(secret) {
    const btn = $('devLoginBtn');
    btn.disabled = true;
    $('gateMsg').classList.remove('err');
    $('gateMsg').textContent = 'در حال ورود با این دستگاه…';
    try {
      const priv = await lockOpen(secret);
      const c0 = await fetchRetry('/api/device/challenge', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ devId: devIdGet() }) }, 2);
      const ch = await c0.json().catch(() => ({}));
      if (!c0.ok || !ch.ok || !ch.nonce) {
        if (c0.status === 404) {
          try { localStorage.removeItem(DEV_PRIV_KEY); } catch {}
          try { localStorage.removeItem(DEV_PUB_KEY); } catch {}
          updDevGateBtn(); devRefresh();
          throw new Error('اعتماد این دستگاه لغو شده — با رمز وارد شوید');
        }
        throw new Error(ch.error || 'چالش ناموفق بود');
      }
      const key = await crypto.subtle.importKey('jwk', priv, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
      const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, te.encode(ch.nonce));
      const r = await fetchRetry('/api/device/login', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ devId: devIdGet(), nonce: ch.nonce, sig: b64uEnc(sig) }) }, 2);
      const j = await r.json().catch(() => ({}));
      if (!r.ok || !j.ok || !j.tok || !j.wrap || !j.fk) throw new Error(j.error || 'ورود با دستگاه ناموفق بود');
      const fkKey = await crypto.subtle.importKey('raw', b64.dec(j.fk), { name: 'AES-GCM' }, false, ['decrypt']);
      const ckRaw = await aesDec(fkKey, j.wrap.iv, j.wrap.c);
      tok = j.tok; sessionStorage.setItem('vault_tok', tok);
      aesKey = await importAesRaw(ckRaw);
      if (j.legacyWrap) { try { legacyKey = await importAesRaw(await aesDec(aesKey, j.legacyWrap.iv, j.legacyWrap.c)); } catch {} }
      myTag = localStorage.getItem('vault_tag') || rndTag();
      localStorage.setItem('vault_tag', myTag);
      myFp = await ckFingerprint(ckRaw);
      if (j.name) { prefs.name = j.name; localStorage.setItem('vault_displayName', prefs.name); state.sitePersona.name = prefs.name; }
      sessionStorage.removeItem('vault_recid');
      saveSession({ ck: b64.enc(ckRaw), legacyWrap: j.legacyWrap || null });
      toast('📱 ورود با این دستگاه انجام شد — بدون رمز', 'ok', 4200);
      startApp();
    } catch (e) {
      showGateError((e && e.message) || 'ورود با دستگاه ناموفق بود');
      btn.disabled = false;
    }
  }
  $('devLoginBtn').onclick = () => {
    lockUi.onDone = (secret) => devGateEnter(secret);
    lockShow('unlock', 'برای ورود بدون رمز، قفل شخصی را وارد کنید');
  };

  /* v24: passwordless re-entry — same IP within 300 minutes of the last
     session enters with zero typing (server hands out the fallback wrap) */
  async function tryReentry() {
    try {
      const r = await fetch('/api/reentry', { cache: 'no-store' });
      if (!r.ok) return false;
      const j = await r.json();
      if (!j.ok || !j.tok || !j.wrap || !j.fk) return false;
      const fkKey = await crypto.subtle.importKey('raw', b64.dec(j.fk), { name: 'AES-GCM' }, false, ['decrypt']);
      const ckRaw = await aesDec(fkKey, j.wrap.iv, j.wrap.c);
      tok = j.tok; sessionStorage.setItem('vault_tok', tok);
      aesKey = await importAesRaw(ckRaw);
      myTag = localStorage.getItem('vault_tag') || rndTag();
      localStorage.setItem('vault_tag', myTag);
      myFp = await ckFingerprint(ckRaw);
      if (j.name && !prefs.name) { prefs.name = j.name; localStorage.setItem('vault_displayName', prefs.name); state.sitePersona.name = prefs.name; }
      restoredLogin = true;
      startApp();
      toast('🔁 بازگشت خودکار انجام شد — تا ۳۰۰ دقیقه از همین آی‌پی رمز لازم نیست', 'ok', 4600);
      return true;
    } catch { return false; }
  }

  /* quiet connectivity probe on the lock screen (fewer scary errors) */
  let healthFails = 0, loginInFlight = false;
  gateFormEl.addEventListener('submit', () => { loginInFlight = true; setTimeout(() => { loginInFlight = false; }, 15000); }, { capture: true });
  setInterval(async () => {
    if (document.hidden || aesKey || loginInFlight) return;
    if ($('app').classList.contains('on')) return;
    const gm = $('gateMsg');
    const ours = gm.textContent.indexOf('اتصال ضعیف') >= 0;
    if (!ours && (gm.textContent || gm.classList.contains('err'))) return;
    try {
      const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), 6000);
      const r = await fetch('/api/health', { signal: ctl.signal, cache: 'no-store' });
      clearTimeout(t);
      if (!r.ok) throw 0;
      healthFails = 0;
      if (ours) gm.textContent = '';
    } catch {
      if (++healthFails >= 2 && !ours && !gm.textContent) {
        gm.classList.remove('err');
        gm.textContent = '⚠️ اتصال ضعیف — منتظر پایداری شبکه…';
      }
    }
  }, 9000);

  /* ------------------------- BOOT ------------------------- */
  applyPrefs();
  bindViewportEvents();
  applyVh();
  updNotifUI();
  regSW();
  tryRestoreSession();   /* 6h device session — skips the gate when valid */
  /* v24: no stored session? probe the 300-min IP re-entry window silently */
  if (!sessionStorage.getItem('vault_sess2')) {
    const gm0 = $('gateMsg');
    const prev0 = gm0.textContent;
    if (!prev0) gm0.textContent = 'در حال بررسی بازگشت خودکار…';
    tryReentry().then(ok => {
      if (!ok && gm0.textContent === 'در حال بررسی بازگشت خودکار…') gm0.textContent = '';
    });
  }
  /* v15: pull the live brand (/title) even before login */
  updDevGateBtn();   /* v29: show the trusted-device button when a sealed key exists */
  fetch('/api/health', { cache: 'no-store' }).then(r => r.ok ? r.json() : null).then(j => {
    if (j && j.title) applyTitle(j.title);
    if (j && j.finger) fingerGateBtn(true);   /* v27: show the fingerprint login button */
  }).catch(() => {});
})();
