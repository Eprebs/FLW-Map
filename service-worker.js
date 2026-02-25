const CACHE_NAME = 'flw-hunt-cache-v2';
const CORE_ASSETS = [
  './',
  './index.html',
  './manifest.json'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(CORE_ASSETS)).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys.map(k => {
          if (k !== CACHE_NAME) return caches.delete(k);
        })
      )
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  // Network-first for same-origin core assets to avoid stale app shell
  if (url.origin === self.location.origin) {
    if (CORE_ASSETS.some(path => url.pathname.endsWith(path.replace('./','/')))) {
      event.respondWith(
        fetch(event.request)
          .then(resp => {
            const clone = resp.clone();
            caches.open(CACHE_NAME).then(cache => cache.put(event.request, clone));
            return resp;
          })
          .catch(() => caches.match(event.request))
      );
      return;
    }
  }

  // For map tiles and other requests: network-first with fallback to cache
  if (url.hostname.includes('tile') || url.hostname.includes('arcgisonline.com') || url.hostname.includes('openstreetmap.org')) {
    event.respondWith(
      fetch(event.request)
        .then(resp => {
          const clone = resp.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(event.request, clone));
          return resp;
        })
        .catch(() => caches.match(event.request))
    );
    return;
  }

  // Default: try cache, then network
  event.respondWith(
    caches.match(event.request).then(resp => resp || fetch(event.request))
  );
});