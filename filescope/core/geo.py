from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable


def _polygons(geometry: dict[str, Any]) -> Iterable[list[list[list[float]]]]:
    kind = str(geometry.get("type", ""))
    coordinates = geometry.get("coordinates", [])
    if kind == "Polygon":
        yield coordinates
    elif kind == "MultiPolygon":
        yield from coordinates


def _point_in_ring(longitude: float, latitude: float, ring: list[list[float]]) -> bool:
    inside = False
    if len(ring) < 3:
        return False
    previous = ring[-1]
    for current in ring:
        try:
            x1, y1 = float(previous[0]), float(previous[1])
            x2, y2 = float(current[0]), float(current[1])
        except (TypeError, ValueError, IndexError):
            previous = current
            continue
        crosses = (y1 > latitude) != (y2 > latitude)
        if crosses:
            denominator = y2 - y1
            if denominator:
                intersection = (x2 - x1) * (latitude - y1) / denominator + x1
                if longitude < intersection:
                    inside = not inside
        previous = current
    return inside


def _point_in_polygon(longitude: float, latitude: float, polygon: list[list[list[float]]]) -> bool:
    if not polygon or not _point_in_ring(longitude, latitude, polygon[0]):
        return False
    return not any(_point_in_ring(longitude, latitude, hole) for hole in polygon[1:])


@lru_cache(maxsize=4)
def load_world_database(path: str | Path) -> dict[str, Any]:
    database_path = Path(path)
    try:
        value = json.loads(database_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"features": [], "name": "Unavailable", "source": "", "scale": ""}
    if not isinstance(value, dict) or not isinstance(value.get("features"), list):
        return {"features": [], "name": "Invalid database", "source": "", "scale": ""}
    return value


def lookup_country(longitude: float, latitude: float, database_path: str | Path) -> dict[str, str] | None:
    if not (-180.0 <= longitude <= 180.0 and -90.0 <= latitude <= 90.0):
        return None
    database = load_world_database(database_path)
    for feature in database.get("features", []):
        if not isinstance(feature, dict):
            continue
        bbox = feature.get("bbox", [])
        if isinstance(bbox, list) and len(bbox) == 4:
            try:
                if not (float(bbox[0]) <= longitude <= float(bbox[2]) and float(bbox[1]) <= latitude <= float(bbox[3])):
                    continue
            except (TypeError, ValueError):
                pass
        geometry = feature.get("geometry", {})
        if not isinstance(geometry, dict):
            continue
        if any(_point_in_polygon(longitude, latitude, polygon) for polygon in _polygons(geometry)):
            return {
                "Country": str(feature.get("name", "Unknown")),
                "ISO A3": str(feature.get("iso_a3", "")),
                "Continent": str(feature.get("continent", "")),
            }
    return None


def decimal_to_dms(value: float, latitude: bool) -> str:
    absolute = abs(float(value))
    degrees = int(absolute)
    minutes_full = (absolute - degrees) * 60.0
    minutes = int(minutes_full)
    seconds = (minutes_full - minutes) * 60.0
    direction = ("N" if value >= 0 else "S") if latitude else ("E" if value >= 0 else "W")
    return f"{degrees}° {minutes}′ {seconds:.3f}″ {direction}"
