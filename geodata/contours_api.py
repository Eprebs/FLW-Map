import os
import re
from typing import Any, Dict

from fastapi import FastAPI, HTTPException, Query
from sqlalchemy import create_engine, text


DATABASE_URL = os.getenv("POSTGIS_URL", "")
CONTOURS_TABLE = os.getenv("CONTOURS_TABLE", "public.contours")
GEOM_COLUMN = os.getenv("CONTOURS_GEOM_COLUMN", "geom")
MAX_FEATURES = int(os.getenv("CONTOURS_MAX_FEATURES", "20000"))

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


@app.get("/health")
def health() -> Dict[str, Any]:
    return {"ok": True, "table": CONTOURS_TABLE}


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

    if not row:
        return {"type": "FeatureCollection", "features": []}

    return row.fc
