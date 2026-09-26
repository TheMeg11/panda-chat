/* Panda Chat v24 service worker — PWA-installable shell + notifications.
   Strategy:
   - /api/* and /manifest.webmanifest  → network ONLY (never cached)
   - navigations                       → network-first, cached shell fallback
   - versioned statics (?v=25 pins)    → stale-while-revalidate (URL is the
     cache key, so every release is a fresh entry — no stale-asset trap)
   - notificationclick                 → focus an open client or open one */
const CACHE = 'vault-v30';
const SHELL = ['/', '/index.html', '/style.css', '/app.js', '/emoji-data.js', '/favicon.png',
  '/manifest.webmanifest', '/icon-192.png', '/icon-512.png', '/panda-light.png', '/panda-dark.png',
  '/notificon.png', '/notificon-96.png'];

self.addEventListener('install', (e) => {
  e.waitUntil((async () => {
    const c = await caches.open(CACHE);
    await Promise.allSettled(SHELL.map(u => c.add(new Request(u, { cache: 'reload' }))));
    await self.skipWaiting();
  })());
});

self.addEventListener('activate', (e) => {
  e.waitUntil((async () => {
    for (const k of await caches.keys()) if (k !== CACHE && k !== CACHE + '-gif') await caches.delete(k);
    await self.clients.claim();
  })());
});

self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== location.origin) return;
  /* v25: gif previews (tenor media via our proxy) are immutable per URL —
     cache-first so repeat views are instant and zero-bandwidth, which is
     exactly what flaky Iranian mobile data needs. Small files only, LRU
     trimmed at 240 entries. */
  if (url.pathname === '/api/giffetch') {
    e.respondWith((async () => {
      const c = await caches.open(CACHE + '-gif');
      const hit = await c.match(req);
      if (hit) return hit;
      try {
        const r = await fetch(req);
        if (r && r.ok && (r.headers.get('Content-Length') || '0') !== '0') {
          c.put(req, r.clone()).catch(() => {});
          const keys = await c.keys();
          if (keys.length > 240) for (const k of keys.slice(0, keys.length - 240)) c.delete(k).catch(() => {});
        }
        return r;
      } catch {
        return hit || Response.error();
      }
    })());
    return;
  }
  /* live API: strictly network — no cache ever */
  if (url.pathname.startsWith('/api/') || url.pathname === '/manifest.webmanifest') return;

  /* navigations: network first so logins land on fresh markup, cache as offline fallback */
  if (req.mode === 'navigate') {
    e.respondWith((async () => {
      try {
        const r = await fetch(req);
        const c = await caches.open(CACHE);
        c.put('/', r.clone()).catch(() => {});
        return r;
      } catch {
        const c = await caches.open(CACHE);
        return (await c.match('/')) || (await c.match('/index.html')) || Response.error();
      }
    })());
    return;
  }

  /* statics: stale-while-revalidate (the ?v= pin makes each release a new key) */
  e.respondWith((async () => {
    const c = await caches.open(CACHE);
    const hit = await c.match(req);
    const net = fetch(req).then((r) => {
      if (r && r.ok) c.put(req, r.clone()).catch(() => {});
      return r;
    }).catch(() => null);
    return hit || (await net) || Response.error();
  })());
});

self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  e.waitUntil((async () => {
    const all = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const cl of all) {
      if ('focus' in cl) return cl.focus();
    }
    return self.clients.openWindow((e.notification.data && e.notification.data.url) || '/');
  })());
});

self.addEventListener('message', (e) => {
  if (e.data === 'skip-waiting') self.skipWaiting();
});
