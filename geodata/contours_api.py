import os
import re
import json
from pathlib import Path
from typing import Any, Dict

from fastapi import FastAPI, HTTPException, Query
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError


DATABASE_URL = os.getenv("POSTGIS_URL", "")
CONTOURS_TABLE = os.getenv("CONTOURS_TABLE", "public.contours")
GEOM_COLUMN = os.getenv("CONTOURS_GEOM_COLUMN", "geom")
MAX_FEATURES = int(os.getenv("CONTOURS_MAX_FEATURES", "20000"))
ALLOW_LOCAL_CONTOUR_SEED = os.getenv("ALLOW_LOCAL_CONTOUR_SEED", "false").lower() in {"1", "true", "yes"}

TABLE_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*$")
COLUMN_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

if not DATABASE_URL:
    raise RuntimeError("POSTGIS_URL environment variable is required")

if not TABLE_PATTERN.match(CONTOURS_TABLE):
    raise RuntimeError("CONTOURS_TABLE contains invalid characters")

if not COLUMN_PATTERN.match(GEOM_COLUMN):
    raise RuntimeError("CONTOURS_GEOM_COLUMN contains invalid characters")

engine = create_engine(DATABASE_URL, future=True)
app = FastAPI(title="Hunt AO Contours API")
PROJECT_ROOT = Path(__file__).resolve().parent.parent


def parse_bbox(bbox: str):
    parts = [p.strip() for p in bbox.split(",")]
    if len(parts) != 4:
        raise ValueError("bbox must be minLng,minLat,maxLng,maxLat")

    min_lng, min_lat, max_lng, max_lat = map(float, parts)

    if not (-180 <= min_lng <= 180 and -180 <= max_lng <= 180):
        raise ValueError("Longitude out of range")
    if not (-90 <= min_lat <= 90 and -90 <= max_lat <= 90):
        raise ValueError("Latitude out of range")
    if min_lng >= max_lng or min_lat >= max_lat:
        raise ValueError("Invalid bbox extents")

    if (max_lng - min_lng) > 3 or (max_lat - min_lat) > 3:
        raise ValueError("bbox too large; request a smaller viewport")

    return min_lng, min_lat, max_lng, max_lat


def _load_local_features(source: str):
    source_map = {
        "med": [PROJECT_ROOT / "contours_med.geojson"],
        "high": [PROJECT_ROOT / "contours_high.geojson"],
        "both": [PROJECT_ROOT / "contours_med.geojson", PROJECT_ROOT / "contours_high.geojson"],
    }

    files = source_map.get(source)
    if not files:
        raise HTTPException(status_code=400, detail="source must be one of: med, high, both")

    features = []
    for path in files:
        if not path.exists():
            continue
        payload = json.loads(path.read_text(encoding="utf-8"))
        file_features = payload.get("features") if isinstance(payload, dict) else None
        if isinstance(file_features, list):
            features.extend(file_features)
    return features


@app.get("/health")
def health() -> Dict[str, Any]:
    status: Dict[str, Any] = {"ok": True, "table": CONTOURS_TABLE}

    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
            exists_sql = text(
                """
                SELECT EXISTS (
                  SELECT 1
                  FROM information_schema.tables
                  WHERE table_schema = :schema_name AND table_name = :table_name
                ) AS table_exists
                """
            )
            schema_name, table_name = (
                CONTOURS_TABLE.split(".", 1) if "." in CONTOURS_TABLE else ("public", CONTOURS_TABLE)
            )
            row = conn.execute(
                exists_sql,
                {"schema_name": schema_name, "table_name": table_name},
            ).first()
            table_exists = bool(row.table_exists) if row else False
            status["table_exists"] = table_exists
            if not table_exists:
                status["ok"] = False
                status["warning"] = "Contours table not found; run seeding script."
    except SQLAlchemyError as err:
        status["ok"] = False
        status["error"] = f"Database connectivity issue: {err.__class__.__name__}"

    return status


@app.get("/api/contours")
def get_contours(
    bbox: str = Query(..., description="minLng,minLat,maxLng,maxLat"),
    limit: int = Query(8000, ge=1, le=MAX_FEATURES),
    simplify: float = Query(0.0, ge=0.0, le=0.01),
):
    try:
        min_lng, min_lat, max_lng, max_lat = parse_bbox(bbox)
    except ValueError as err:
        raise HTTPException(status_code=400, detail=str(err)) from err

    geom_expr = (
        f"CASE WHEN :simplify > 0 "
        f"THEN ST_SimplifyPreserveTopology(t.{GEOM_COLUMN}, :simplify) "
        f"ELSE t.{GEOM_COLUMN} END"
    )

    sql = text(
        f"""
        WITH clipped AS (
          SELECT t.*
          FROM {CONTOURS_TABLE} t
          WHERE ST_Intersects(
            t.{GEOM_COLUMN},
            ST_MakeEnvelope(:min_lng, :min_lat, :max_lng, :max_lat, 4326)
          )
          LIMIT :limit
        )
        SELECT jsonb_build_object(
          'type', 'FeatureCollection',
          'features', COALESCE(jsonb_agg(feature), '[]'::jsonb)
        ) AS fc
        FROM (
          SELECT jsonb_build_object(
            'type', 'Feature',
            'geometry', ST_AsGeoJSON({geom_expr})::jsonb,
            'properties', to_jsonb(clipped) - '{GEOM_COLUMN}'
          ) AS feature
          FROM clipped
        ) q
        """
    )

    with engine.connect() as conn:
        try:
            row = conn.execute(
                sql,
                {
                    "min_lng": min_lng,
                    "min_lat": min_lat,
                    "max_lng": max_lng,
                    "max_lat": max_lat,
                    "limit": limit,
                    "simplify": simplify,
                },
            ).first()
        except SQLAlchemyError as err:
            raise HTTPException(
                status_code=503,
                detail=f"Contours backend not ready: {err.__class__.__name__}",
            ) from err

    if not row:
        return {"type": "FeatureCollection", "features": []}

    return row.fc


@app.get("/admin/seed-local-contours")
@app.post("/admin/seed-local-contours")
def seed_local_contours(source: str = Query("med", description="med, high, or both")):
    if not ALLOW_LOCAL_CONTOUR_SEED:
        raise HTTPException(status_code=403, detail="Local seeding is disabled")

    features = _load_local_features(source)
    if not features:
        raise HTTPException(status_code=400, detail="No local contour features found for requested source")

    schema_name, table_name = (
        CONTOURS_TABLE.split(".", 1) if "." in CONTOURS_TABLE else ("public", CONTOURS_TABLE)
    )

    try:
        with engine.begin() as conn:
            conn.execute(text("CREATE EXTENSION IF NOT EXISTS postgis"))
            conn.execute(text(f'CREATE SCHEMA IF NOT EXISTS "{schema_name}"'))
            conn.execute(
                text(
                    f'''
                    CREATE TABLE IF NOT EXISTS "{schema_name}"."{table_name}" (
                        id BIGSERIAL PRIMARY KEY,
                        properties JSONB,
                        elev DOUBLE PRECISION,
                        {GEOM_COLUMN} geometry(Geometry, 4326)
                    )
                    '''
                )
            )
            conn.execute(text(f'TRUNCATE TABLE "{schema_name}"."{table_name}"'))

            insert_sql = text(
                f'''
                INSERT INTO "{schema_name}"."{table_name}" (properties, elev, {GEOM_COLUMN})
                VALUES (
                    CAST(:properties AS JSONB),
                    :elev,
                    ST_SetSRID(ST_GeomFromGeoJSON(:geometry), 4326)
                )
                '''
            )

            inserted = 0
            for feature in features:
                geometry = feature.get("geometry")
                if not geometry:
                    continue
                properties = feature.get("properties") or {}
                elev_value = None
                for key in ("elev", "ELEV", "elevation", "Elevation", "contour", "CONTOUR"):
                    if key in properties:
                        try:
                            elev_value = float(properties[key])
                        except (TypeError, ValueError):
                            elev_value = None
                        break

                conn.execute(
                    insert_sql,
                    {
                        "properties": json.dumps(properties),
                        "elev": elev_value,
                        "geometry": json.dumps(geometry),
                    },
                )
                inserted += 1

            conn.execute(
                text(
                    f'CREATE INDEX IF NOT EXISTS "{table_name}_geom_gix" '
                    f'ON "{schema_name}"."{table_name}" USING GIST ({GEOM_COLUMN})'
                )
            )
            conn.execute(text(f'ANALYZE "{schema_name}"."{table_name}"'))
    except SQLAlchemyError as err:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to seed local contours: {err.__class__.__name__}",
        ) from err

    return {"ok": True, "source": source, "inserted": inserted, "table": CONTOURS_TABLE}
