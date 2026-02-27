# Hunt AO Geodata Setup (PostGIS + S3 Tiles)

This setup keeps your Render git repo lightweight while serving high-detail contours and hillshade.

## 1) Install geodata Python deps

```bash
pip install -r requirements-geodata.txt
```

## 2) Seed contours into PostGIS

Use any hosted Postgres with PostGIS enabled (Neon + PostGIS, Supabase, Render Postgres + PostGIS extension, etc.).

### Easiest path (no GDAL/geopandas required)

If you hit `gdal-config` / `pyogrio` build errors, use this lightweight seeder instead:

```bash
pip install psycopg2-binary
python scripts/seed_contours_geojson_postgis.py \
  --db-url "postgresql://USER:PASSWORD@HOST:5432/DBNAME" \
  --input "contours_med.geojson" "contours_high.geojson" \
  --table public.contours \
  --if-exists replace
```

Notes:
- This script only needs plain GeoJSON files and PostGIS.
- It auto-creates the table, spatial index, and runs `ANALYZE`.
- It accepts `postgres://`, `postgresql://`, or `postgresql+psycopg2://` URLs.

### Example command

```bash
python scripts/seed_contours_postgis.py \
  --db-url "postgresql+psycopg2://USER:PASSWORD@HOST:5432/DBNAME" \
  --input "raw_data/contours/**/*.geojson" "raw_data/contours/**/*.shp" \
  --table public.contours \
  --if-exists replace
```

### Notes
- Seeder normalizes CRS to EPSG:4326.
- Adds a GIST index on `geom` and runs `ANALYZE`.
- Input supports file paths and glob patterns.

## 3) Run contours API (FastAPI)

For cloud deployment (Render/Railway/Fly), install API-only deps to avoid GDAL build failures:

```bash
pip install -r requirements-contours-api.txt
```

Set env vars:

- `POSTGIS_URL=postgresql+psycopg2://...`
- `CONTOURS_TABLE=public.contours` (optional)
- `CONTOURS_GEOM_COLUMN=geom` (optional)
- `CONTOURS_MAX_FEATURES=20000` (optional)

Start API:

```bash
uvicorn geodata.contours_api:app --host 0.0.0.0 --port 8000
```

### Render settings (recommended)

- Build Command: `pip install -r requirements-contours-api.txt`
- Start Command: `uvicorn geodata.contours_api:app --host 0.0.0.0 --port $PORT`

### Query route

`GET /api/contours?bbox=minLng,minLat,maxLng,maxLat&limit=8000&simplify=0.00005`

- `bbox` is required
- `limit` defaults to 8000
- `simplify` can reduce payload size at lower zooms

## 4) Host hillshade raster tiles in Cloudflare R2 (free-tier friendly)

You can also use Backblaze B2 similarly; R2 is usually easiest for public tile hosting.

### Cloudflare R2 quick steps
1. Create bucket (example: `huntao-hillshade`).
2. Upload tiles with preserved XYZ structure:
   - `hillshade_tiles/{z}/{x}/{y}.png`
3. Expose via public/custom domain (recommended):
   - Example: `https://tiles.hunt-ao.com/hillshade/{z}/{x}/{y}.png`
4. Configure CORS to allow your app origin (`https://hunt-ao.com`).

## 5) Frontend snippets (Leaflet)

### A) Hillshade raster layer from R2/B2

```js
const hillshadeCloud = L.tileLayer(
  "https://tiles.hunt-ao.com/hillshade/{z}/{x}/{y}.png",
  {
    maxZoom: 16,
    opacity: 0.35,
    attribution: "Hillshade"
  }
);
```

### B) Viewport-based contour loading from FastAPI

```js
const CONTOURS_API_BASE = "https://your-contours-api.onrender.com";
let contoursViewportLayer = null;

async function loadContoursForViewport() {
  const bounds = map.getBounds();
  const bbox = [
    bounds.getWest(),
    bounds.getSouth(),
    bounds.getEast(),
    bounds.getNorth()
  ].join(",");

  const zoom = map.getZoom();
  const simplify = zoom >= 15 ? 0 : zoom >= 13 ? 0.00003 : 0.00008;

  const url = `${CONTOURS_API_BASE}/api/contours?bbox=${bbox}&limit=12000&simplify=${simplify}`;
  const fc = await fetch(url, { cache: "no-store" }).then(r => r.json());

  if (contoursViewportLayer) {
    map.removeLayer(contoursViewportLayer);
  }

  contoursViewportLayer = L.geoJSON(fc, {
    style: {
      color: "#b8912e",
      weight: zoom >= 15 ? 1 : 0.7,
      opacity: 0.6
    },
    interactive: false
  }).addTo(map);
}

map.on("moveend", loadContoursForViewport);
map.on("zoomend", loadContoursForViewport);
loadContoursForViewport();
```

## 6) Git safety

`.gitignore` has been updated to block:
- local hillshade/contour raws
- shapefile/geopackage/tiff artifacts
- generated tile exports

This prevents another oversized push to Render/GitHub.
