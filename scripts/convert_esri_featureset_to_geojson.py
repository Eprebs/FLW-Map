import argparse
import json
import math
from typing import Any, Dict, List, Optional, Tuple


WEB_MERCATOR_WKIDS = {102100, 3857, 102113}
WGS84_WKIDS = {4326}


def mercator_to_wgs84(x: float, y: float) -> Tuple[float, float]:
    lon = (x / 20037508.34) * 180.0
    lat = (y / 20037508.34) * 180.0
    lat = 180.0 / math.pi * (2.0 * math.atan(math.exp(lat * math.pi / 180.0)) - math.pi / 2.0)
    return lon, lat


def extract_wkid(container: Dict[str, Any]) -> Optional[int]:
    sr = container.get("spatialReference")
    if isinstance(sr, dict):
        wkid = sr.get("latestWkid") or sr.get("wkid")
        if isinstance(wkid, int):
            return wkid
    return None


def transform_ring(ring: List[List[float]], wkid: Optional[int]) -> List[List[float]]:
    out = []
    for coord in ring:
        if len(coord) < 2:
            continue
        x, y = float(coord[0]), float(coord[1])
        if wkid in WEB_MERCATOR_WKIDS:
            lon, lat = mercator_to_wgs84(x, y)
            out.append([lon, lat])
        else:
            out.append([x, y])
    return out


def find_featureset(obj: Any) -> Optional[Dict[str, Any]]:
    if isinstance(obj, dict):
        if isinstance(obj.get("features"), list):
            return obj

        if "featureSet" in obj and isinstance(obj["featureSet"], dict):
            fs = obj["featureSet"]
            if isinstance(fs.get("features"), list):
                return fs

        for value in obj.values():
            found = find_featureset(value)
            if found is not None:
                return found

    if isinstance(obj, list):
        for item in obj:
            found = find_featureset(item)
            if found is not None:
                return found

    return None


def normalize_properties(attrs: Dict[str, Any]) -> Dict[str, Any]:
    props = dict(attrs)

    area_name = attrs.get("_Area_ID") or attrs.get("label") or attrs.get("Name") or attrs.get("name")
    area_type = attrs.get("_Type") or attrs.get("Type")

    raw_id = attrs.get("FID")
    if raw_id is None:
        raw_id = attrs.get("OBJECTID")
    if raw_id is None:
        raw_id = attrs.get("Id")

    try:
        area_syskey = int(raw_id) if raw_id is not None else None
    except Exception:
        area_syskey = None

    props["area_name"] = area_name
    props["area_type"] = area_type
    props["area_syskey"] = area_syskey
    return props


def convert(input_path: str, output_path: str) -> None:
    with open(input_path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    featureset = find_featureset(raw)
    if not featureset:
        raise ValueError("Could not find a feature set with a 'features' array in the input JSON.")

    default_wkid = extract_wkid(featureset)
    if default_wkid is None and isinstance(raw, dict):
        default_wkid = extract_wkid(raw)

    out_features = []
    for src_feature in featureset.get("features", []):
        if not isinstance(src_feature, dict):
            continue

        attrs = src_feature.get("attributes") or {}
        geometry = src_feature.get("geometry") or {}

        if not isinstance(geometry, dict):
            continue

        wkid = extract_wkid(geometry) or default_wkid
        rings = geometry.get("rings")

        if not isinstance(rings, list) or not rings:
            continue

        geojson_rings = [transform_ring(ring, wkid) for ring in rings if isinstance(ring, list)]
        geojson_rings = [r for r in geojson_rings if len(r) >= 4]
        if not geojson_rings:
            continue

        out_features.append(
            {
                "type": "Feature",
                "properties": normalize_properties(attrs),
                "geometry": {
                    "type": "Polygon",
                    "coordinates": geojson_rings,
                },
            }
        )

    feature_collection = {
        "type": "FeatureCollection",
        "features": out_features,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(feature_collection, f)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Convert ArcGIS featureSet JSON into GeoJSON with HuntAO area property keys."
    )
    parser.add_argument("--input", required=True, help="Path to ArcGIS JSON response file")
    parser.add_argument("--output", required=True, help="Path to output GeoJSON file")
    args = parser.parse_args()

    convert(args.input, args.output)
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()