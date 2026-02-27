import argparse
import json
import time
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import psycopg2
from psycopg2 import OperationalError
from psycopg2.extras import Json, execute_values


def normalize_db_url(db_url: str) -> str:
    url = db_url.strip()
    if url.startswith("postgresql+psycopg2://"):
        url = "postgresql://" + url[len("postgresql+psycopg2://") :]
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://") :]

    parsed = urlparse(url)
    query_params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query_params.setdefault("sslmode", "require")
    normalized_query = urlencode(query_params)
    return urlunparse(parsed._replace(query=normalized_query))


def connect_with_retry(db_url: str, attempts: int = 8, delay_seconds: float = 2.0):
    last_error: Optional[Exception] = None
    for attempt in range(1, attempts + 1):
        try:
            return psycopg2.connect(db_url)
        except OperationalError as err:
            last_error = err
            if attempt == attempts:
                break
            sleep_for = delay_seconds * attempt
            print(f"Connection failed (attempt {attempt}/{attempts}). Retrying in {sleep_for:.1f}s...")
            time.sleep(sleep_for)
    raise RuntimeError(f"Unable to connect to database after {attempts} attempts: {last_error}")


def split_table_name(table_name: str) -> Tuple[str, str]:
    if "." in table_name:
        schema, table = table_name.split(".", 1)
    else:
        schema, table = "public", table_name
    return schema, table


def pick_elevation(properties: Dict[str, Any]) -> Optional[float]:
    for key in ("elev", "ELEV", "elevation", "Elevation", "contour", "CONTOUR"):
        if key in properties:
            try:
                return float(properties[key])
            except (TypeError, ValueError):
                return None
    return None


def to_rows(features: Iterable[Dict[str, Any]]) -> List[Tuple[Any, Any, Any]]:
    rows: List[Tuple[Any, Any, Any]] = []
    for feature in features:
        geometry = feature.get("geometry")
        if not geometry:
            continue

        properties = feature.get("properties") or {}
        rows.append(
            (
                Json(properties),
                pick_elevation(properties),
                json.dumps(geometry),
            )
        )
    return rows


def chunked(items: List[Tuple[Any, Any, Any]], size: int):
    for idx in range(0, len(items), size):
        yield items[idx : idx + size]


def ensure_schema_and_table(cur, schema: str, table: str):
    cur.execute(f'CREATE SCHEMA IF NOT EXISTS "{schema}"')
    cur.execute(
        f'''
        CREATE TABLE IF NOT EXISTS "{schema}"."{table}" (
            id BIGSERIAL PRIMARY KEY,
            properties JSONB,
            elev DOUBLE PRECISION,
            geom geometry(Geometry, 4326)
        )
        '''
    )


def main():
    parser = argparse.ArgumentParser(
        description="Seed GeoJSON contour files into PostGIS without geopandas/GDAL."
    )
    parser.add_argument("--db-url", required=True, help="Postgres URL")
    parser.add_argument(
        "--input",
        nargs="+",
        default=["contours_med.geojson"],
        help="GeoJSON files to load (default: contours_med.geojson)",
    )
    parser.add_argument(
        "--table",
        default="public.contours",
        help="Destination table in schema.table format",
    )
    parser.add_argument(
        "--if-exists",
        choices=["append", "replace"],
        default="replace",
        help="replace truncates table first; append adds to existing rows",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=1000,
        help="Insert batch size",
    )
    args = parser.parse_args()

    db_url = normalize_db_url(args.db_url)
    schema, table = split_table_name(args.table)

    files = [Path(path) for path in args.input]
    missing = [str(path) for path in files if not path.exists()]
    if missing:
        raise SystemExit(f"Missing input file(s): {', '.join(missing)}")

    with connect_with_retry(db_url) as conn:
        with conn.cursor() as cur:
            try:
                cur.execute("CREATE EXTENSION IF NOT EXISTS postgis")
            except Exception as err:
                print(f"Warning: could not create postgis extension automatically ({err}).")
            ensure_schema_and_table(cur, schema, table)
            if args.if_exists == "replace":
                cur.execute(f'TRUNCATE TABLE "{schema}"."{table}"')
        conn.commit()

    total_rows = 0
    insert_sql = (
        f'INSERT INTO "{schema}"."{table}" (properties, elev, geom) '
        f"VALUES %s"
    )

    for path in files:
        print(f"Reading {path}...")
        payload = json.loads(path.read_text(encoding="utf-8"))
        features = payload.get("features") if isinstance(payload, dict) else None
        if not isinstance(features, list):
            print(f"Skipping {path}: not a valid FeatureCollection")
            continue

        rows = to_rows(features)
        if not rows:
            print(f"Skipping {path}: no valid features")
            continue

        inserted_for_file = 0
        for batch in chunked(rows, args.batch_size):
            batch_inserted = False
            for attempt in range(1, 9):
                try:
                    with connect_with_retry(db_url, attempts=3, delay_seconds=1.5) as conn:
                        with conn.cursor() as cur:
                            execute_values(
                                cur,
                                insert_sql,
                                batch,
                                template="(%s, %s, ST_SetSRID(ST_GeomFromGeoJSON(%s), 4326))",
                            )
                        conn.commit()
                    batch_inserted = True
                    break
                except Exception as err:
                    if attempt == 8:
                        raise RuntimeError(f"Failed to insert batch after retries: {err}") from err
                    wait_time = 1.0 * attempt
                    print(f"Batch insert failed (attempt {attempt}/8). Retrying in {wait_time:.1f}s...")
                    time.sleep(wait_time)

            if batch_inserted:
                inserted_for_file += len(batch)
                total_rows += len(batch)

        print(f"Inserted {inserted_for_file:,} rows from {path.name}")

    with connect_with_retry(db_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                f'CREATE INDEX IF NOT EXISTS "{table}_geom_gix" ON "{schema}"."{table}" USING GIST (geom)'
            )
            cur.execute(f'ANALYZE "{schema}"."{table}"')
        conn.commit()

    print(f"Done. Total inserted rows: {total_rows:,}")


if __name__ == "__main__":
    main()
