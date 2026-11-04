// HuntAO service worker — low-signal support.
//
// Strategy:
// - Map tiles (Esri / USGS / OSM / OpenTopoMap + same-origin /tiles/):
//   cache-first. Tiles are the payload a hunter needs in the field, so a
//   tile that has been fetched once should load instantly with no signal.
// - App shell + pinned CDN libraries: precached, refreshed network-first.
// - Boundary GeoJSON: network-first, last good copy as fallback.
// - Everything under /api/ (live status, auth, admin, stats) and all
//   non-GET requests: NEVER intercepted. Live status stays live; the
//   frontend keeps its own clearly-labeled "last known" copy on-device.

const SW_VERSION = "v1";
const SHELL_CACHE = `huntao-shell-${SW_VERSION}`;
const TILE_CACHE = `huntao-tiles-${SW_VERSION}`;
const DATA_CACHE = `huntao-data-${SW_VERSION}`;
const KNOWN_CACHES = [SHELL_CACHE, TILE_CACHE, DATA_CACHE];
const TILE_CACHE_MAX_ENTRIES = 9000;

const SHELL_ASSETS = [
  "./",
  "./index.html",
  "./privacy.html",
  "./terms.html",
  "./manifest.webmanifest",
  "./vendor/leaflet-rotate.js",
  "./logo.svg",
  "./icon-192.png",
  "./icon-512.png",
  "./apple-touch-icon.png",
  "./flw_areas.backup.geojson"
];

const TILE_HOST_RE = /(^|\.)(arcgisonline\.com|nationalmap\.gov|openstreetmap\.org|opentopomap\.org)$/;

function isTileRequest(url) {
  if (url.origin === self.location.origin) {
    return url.pathname.startsWith("/tiles/");
  }
  return TILE_HOST_RE.test(url.hostname);
}

function isPinnedCdnAsset(url) {
  // Version-pinned library files: safe to serve cache-first.
  return url.hostname === "unpkg.com";
}

async function trimTileCache() {
  try {
    const cache = await caches.open(TILE_CACHE);
    const keys = await cache.keys();
    if (keys.length <= TILE_CACHE_MAX_ENTRIES) return;
    const excess = keys.length - TILE_CACHE_MAX_ENTRIES;
    // Cache keys come back oldest-first; drop the oldest entries.
    for (let i = 0; i < excess; i++) {
      await cache.delete(keys[i]);
    }
  } catch (e) {
    /* best effort only */
  }
}

self.addEventListener("install", (event) => {
  event.waitUntil(
    (async () => {
      const cache = await caches.open(SHELL_CACHE);
      // Add assets one by one so a single missing file can't fail install.
      await Promise.all(
        SHELL_ASSETS.map(async (asset) => {
          try {
            await cache.add(asset);
          } catch (e) {
            /* optional asset */
          }
        })
      );
      await self.skipWaiting();
    })()
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    (async () => {
      const keys = await caches.keys();
      await Promise.all(
        keys.map((k) => (KNOWN_CACHES.includes(k) ? null : caches.delete(k)))
      );
      await trimTileCache();
      await self.clients.claim();
    })()
  );
});

self.addEventListener("message", (event) => {
  if (event.data && event.data.type === "TRIM_TILE_CACHE") {
    event.waitUntil(trimTileCache());
  }
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET") return;

  let url;
  try {
    url = new URL(req.url);
  } catch (e) {
    return;
  }

  // API + admin always go straight to the network, untouched.
  if (
    url.origin === self.location.origin &&
    (url.pathname.startsWith("/api/") || url.pathname.startsWith("/admin"))
  ) {
    return;
  }

  // Map tiles: cache-first, then network (and remember what we fetched).
  if (isTileRequest(url)) {
    event.respondWith(
      (async () => {
        const cache = await caches.open(TILE_CACHE);
        const hit = await cache.match(req);
        if (hit) return hit;
        const resp = await fetch(req);
        if (resp && (resp.ok || resp.type === "opaque")) {
          cache.put(req, resp.clone()).catch(() => {});
        }
        return resp;
      })()
    );
    return;
  }

  // Pinned CDN libraries (Leaflet etc.): cache-first, they never change.
  if (isPinnedCdnAsset(url)) {
    event.respondWith(
      (async () => {
        const cache = await caches.open(SHELL_CACHE);
        const hit = await cache.match(req);
        if (hit) return hit;
        const resp = await fetch(req);
        if (resp && (resp.ok || resp.type === "opaque")) {
          cache.put(req, resp.clone()).catch(() => {});
        }
        return resp;
      })()
    );
    return;
  }

  // Page navigations: network-first so updates land; cached page offline.
  if (req.mode === "navigate") {
    event.respondWith(
      (async () => {
        const cache = await caches.open(SHELL_CACHE);
        try {
          const resp = await fetch(req);
          if (resp && resp.ok && url.origin === self.location.origin) {
            cache.put(req, resp.clone()).catch(() => {});
          }
          return resp;
        } catch (e) {
          const hit =
            (await cache.match(req)) ||
            (await cache.match("./index.html")) ||
            (await cache.match("./"));
          if (hit) return hit;
          throw e;
        }
      })()
    );
    return;
  }

  // Boundary GeoJSON: network-first, last good copy as fallback.
  if (url.origin === self.location.origin && url.pathname.endsWith(".geojson")) {
    event.respondWith(
      (async () => {
        const cache = await caches.open(DATA_CACHE);
        try {
          const resp = await fetch(req);
          if (resp && resp.ok) {
            cache.put(req, resp.clone()).catch(() => {});
          }
          return resp;
        } catch (e) {
          const hit = await cache.match(req);
          if (hit) return hit;
          throw e;
        }
      })()
    );
    return;
  }

  // Other same-origin static files: network-first, cache fallback.
  if (url.origin === self.location.origin) {
    event.respondWith(
      (async () => {
        const cache = await caches.open(SHELL_CACHE);
        try {
          const resp = await fetch(req);
          if (resp && resp.ok) {
            cache.put(req, resp.clone()).catch(() => {});
          }
          return resp;
        } catch (e) {
          const hit = await cache.match(req);
          if (hit) return hit;
          throw e;
        }
      })()
    );
    return;
  }

  // Everything else (fonts, weather, search APIs): straight to network.
});
