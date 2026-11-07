// HuntAO service worker — low-signal support.
//
// Strategy:
// - Map tiles (Esri / USGS / OSM / OpenTopoMap + same-origin /tiles/):
//   cache-first. Tiles are the payload a hunter needs in the field, so a
//   tile that has been fetched once should load instantly with no signal.
//   If a tile is missing AND the network can't deliver it, the closest
//   cached parent (ancestor) tile is stretched over the spot so the map
//   goes soft instead of blank when zooming past the cached zooms.
// - App shell + pinned CDN libraries: precached, refreshed network-first.
// - Boundary GeoJSON: network-first, last good copy as fallback.
// - Everything under /api/ (live status, auth, admin, stats) and all
//   non-GET requests: NEVER intercepted. Live status stays live; the
//   frontend keeps its own clearly-labeled "last known" copy on-device.

const SW_VERSION = "v3";
const SHELL_CACHE = `huntao-shell-${SW_VERSION}`;
const TILE_CACHE = `huntao-tiles-${SW_VERSION}`;
const DATA_CACHE = `huntao-data-${SW_VERSION}`;
const KNOWN_CACHES = [SHELL_CACHE, TILE_CACHE, DATA_CACHE];
const TILE_CACHE_MAX_ENTRIES = 9000;
const TILE_FALLBACK_MAX_LEVELS = 5;

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
  "./flw_areas.backup.geojson",
  "./flw_fishing_waters.geojson"
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

// -----------------------------
// Tile coordinate helpers (pure functions; covered by a node test).
//
// Two URL shapes are in use:
// - ArcGIS REST endpoints: ".../MapServer/tile/{z}/{y}/{x}" — the three
//   numbers follow a literal "tile" path segment, in z/y/x order.
// - XYZ endpoints (OSM, OpenTopoMap, self-hosted LiDAR):
//   ".../{z}/{x}/{y}.png" — z/x/y order, last segment may carry an
//   extension.
// -----------------------------
function parseTileCoords(url) {
  const parts = url.pathname.split("/").filter((p) => p.length > 0);
  if (parts.length < 3) return null;
  const nums = [];
  for (let i = parts.length - 3; i < parts.length; i++) {
    const m = /^(\d+)(\.[a-z0-9]+)?$/i.exec(parts[i]);
    if (!m) return null;
    nums.push(parseInt(m[1], 10));
  }
  const prev = parts.length >= 4 ? parts[parts.length - 4].toLowerCase() : "";
  if (prev === "tile") {
    return { z: nums[0], y: nums[1], x: nums[2], order: "zyx" };
  }
  return { z: nums[0], x: nums[1], y: nums[2], order: "zxy" };
}

function buildAncestorTileUrl(url, coords, ancestorZ) {
  const scale = Math.pow(2, coords.z - ancestorZ);
  const ax = Math.floor(coords.x / scale);
  const ay = Math.floor(coords.y / scale);
  const parts = url.pathname.split("/").filter((p) => p.length > 0);
  const extMatch = /\.[a-z0-9]+$/i.exec(parts[parts.length - 1]);
  const ext = extMatch ? extMatch[0] : "";
  const vals = coords.order === "zyx" ? [ancestorZ, ay, ax] : [ancestorZ, ax, ay];
  for (let i = 0; i < 3; i++) {
    parts[parts.length - 3 + i] = String(vals[i]) + (i === 2 ? ext : "");
  }
  const out = new URL(url.href);
  out.pathname = "/" + parts.join("/");
  out.search = "";
  return out.href;
}

// Sub-rectangle of the ancestor's 256px image that covers the requested
// tile: the ancestor spans `scale` tiles per axis, so the requested tile
// occupies a (256/scale)px square at offset ((coord mod scale) * size).
function ancestorCropRect(z, x, y, ancestorZ) {
  const scale = Math.pow(2, z - ancestorZ);
  const size = 256 / scale;
  return { sx: (x % scale) * size, sy: (y % scale) * size, size };
}

async function matchTileCache(cache, urlHref) {
  const direct = await cache.match(urlHref);
  if (direct) return direct;
  // Leaflet spreads OSM tiles across a/b/c subdomains; a cached parent
  // may live under a different one than this request would have used.
  try {
    const u = new URL(urlHref);
    if (/(^|\.)tile\.openstreetmap\.org$/.test(u.hostname)) {
      for (const sub of ["a", "b", "c"]) {
        u.hostname = `${sub}.tile.openstreetmap.org`;
        const hit = await cache.match(u.href);
        if (hit) return hit;
      }
    }
  } catch (e) {
    /* best effort only */
  }
  return null;
}

// Last-resort tile: crop the requested tile's region out of the closest
// cached ancestor tile and upscale it to 256x256. Softer than the real
// tile, but the map stays readable instead of going blank offline.
// The derived image is deliberately NOT written back to the cache, so a
// blurry stand-in never shadows the real tile on a later online load.
async function tileFromAncestor(cache, url) {
  try {
    if (typeof createImageBitmap !== "function" || typeof OffscreenCanvas !== "function") {
      return null;
    }
    const coords = parseTileCoords(url);
    if (!coords || coords.z === 0) return null;
    const minZ = Math.max(0, coords.z - TILE_FALLBACK_MAX_LEVELS);
    for (let za = coords.z - 1; za >= minZ; za--) {
      try {
        const ancestorUrl = buildAncestorTileUrl(url, coords, za);
        const hit = await matchTileCache(cache, ancestorUrl);
        if (!hit) continue;
        const blob = await hit.blob();
        if (!blob || blob.size === 0) continue;
        const bitmap = await createImageBitmap(blob);
        const rect = ancestorCropRect(coords.z, coords.x, coords.y, za);
        const canvas = new OffscreenCanvas(256, 256);
        const ctx = canvas.getContext("2d");
        if (!ctx) return null;
        ctx.imageSmoothingEnabled = true;
        ctx.drawImage(bitmap, rect.sx, rect.sy, rect.size, rect.size, 0, 0, 256, 256);
        if (typeof bitmap.close === "function") bitmap.close();
        const type = blob.type && blob.type.indexOf("image/") === 0 ? blob.type : "image/jpeg";
        const out = await canvas.convertToBlob({ type });
        return new Response(out, {
          status: 200,
          headers: { "Content-Type": type }
        });
      } catch (e) {
        /* try the next ancestor up */
      }
    }
  } catch (e) {
    /* fall through: caller returns the original network result */
  }
  return null;
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
  // If the network can't deliver, stretch the closest cached parent tile
  // over the spot instead of leaving a blank square.
  if (isTileRequest(url)) {
    event.respondWith(
      (async () => {
        const cache = await caches.open(TILE_CACHE);
        const hit = await cache.match(req);
        if (hit) return hit;
        let resp = null;
        let fetchError = null;
        try {
          resp = await fetch(req);
        } catch (e) {
          fetchError = e;
        }
        if (resp && (resp.ok || resp.type === "opaque")) {
          cache.put(req, resp.clone()).catch(() => {});
          return resp;
        }
        const derived = await tileFromAncestor(cache, url);
        if (derived) return derived;
        if (resp) return resp;
        throw fetchError || new Error("Tile fetch failed");
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
