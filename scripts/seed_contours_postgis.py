import argparse
import glob
import os
import re
from typing import Iterable, List

import geopandas as gpd
from sqlalchemy import create_engine, text


TABLE_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*$")


def expand_inputs(input_patterns: Iterable[str]) -> List[str]:
    paths: List[str] = []
    for pattern in input_patterns:
        if any(ch in pattern for ch in "*?[]"):
            paths.extend(glob.glob(pattern, recursive=True))
        else:
            paths.append(pattern)

    unique = []
    seen = set()
    for path in paths:
        norm = os.path.normpath(path)
        if norm not in seen and os.path.isfile(norm):
            seen.add(norm)
            unique.append(norm)
    return unique


def split_table_name(table_name: str):
    if not TABLE_PATTERN.match(table_name):
        raise ValueError(
            f"Invalid table name '{table_name}'. Use letters/numbers/_ and optional schema.table format."
        )
    if "." in table_name:
        schema, table = table_name.split(".", 1)
    else:
        schema, table = "public", table_name
    return schema, table


def normalize_contours(df: gpd.GeoDataFrame) -> gpd.GeoDataFrame:
    if df.empty:
        return df

    if df.crs is None:
        df = df.set_crs("EPSG:4326", allow_override=True)
    elif df.crs.to_epsg() != 4326:
        df = df.to_crs("EPSG:4326")

    df = df[df.geometry.notnull()].copy()
    df = df[~df.geometry.is_empty].copy()
    return df


def main():
    parser = argparse.ArgumentParser(
        description="Bulk upload contour files (GeoJSON/Shapefile/GPKG) into PostGIS."
    )
    parser.add_argument(
        "--db-url",
        default=os.getenv("POSTGIS_URL", ""),
        help="PostGIS connection URL, e.g. postgresql+psycopg2://user:pass@host:5432/db",
    )
    parser.add_argument(
        "--input",
        nargs="+",
        required=True,
        help="One or more files or glob patterns (e.g. raw_data/contours/**/*.geojson)",
    )
    parser.add_argument(
        "--table",
        default="public.contours",
        help="Destination table name (schema.table). Default: public.contours",
    )
    parser.add_argument(
        "--if-exists",
        choices=["append", "replace"],
        default="append",
        help="Behavior when table exists. replace will recreate the table.",
    )
    parser.add_argument(
        "--chunksize",
        type=int,
        default=5000,
        help="Bulk insert chunk size.",
    )

    args = parser.parse_args()

    if not args.db_url:
        raise SystemExit("Missing --db-url (or POSTGIS_URL env var).")

    files = expand_inputs(args.input)
    if not files:
        raise SystemExit("No input files matched.")

    schema, table = split_table_name(args.table)
    engine = create_engine(args.db_url, future=True)

    print(f"Seeding {len(files)} file(s) into {schema}.{table}...")

    first_write_mode = args.if_exists
    total_rows = 0

    with engine.begin() as conn:
        conn.execute(text("CREATE EXTENSION IF NOT EXISTS postgis"))

    for path in files:
        print(f"  -> reading {path}")
        gdf = gpd.read_file(path)
        gdf = normalize_contours(gdf)

        if gdf.empty:
            print("     skipped (no valid geometries)")
            continue

        gdf.to_postgis(
            name=table,
            con=engine,
            schema=schema,
            if_exists=first_write_mode,
            index=False,
            chunksize=args.chunksize,
            method="multi",
        )

        first_write_mode = "append"
        total_rows += len(gdf)
        print(f"     uploaded {len(gdf):,} rows")

    if total_rows == 0:
        raise SystemExit("No rows were uploaded.")

    with engine.begin() as conn:
        conn.execute(
            text(
                f"CREATE INDEX IF NOT EXISTS {table}_geom_gix ON {schema}.{table} USING GIST (geom)"
            )
        )
        conn.execute(text(f"ANALYZE {schema}.{table}"))

    print(f"Done. Uploaded {total_rows:,} rows into {schema}.{table}.")


if __name__ == "__main__":
    main()
