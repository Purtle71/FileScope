from __future__ import annotations

from fractions import Fraction
from pathlib import Path
from typing import Any

from filescope.core.geo import decimal_to_dms, lookup_country
from filescope.core.models import AnalysisResult
from filescope.core.paths import resource_path

from .base import AnalysisPlugin


def _number(value: Any) -> float:
    if isinstance(value, Fraction):
        return float(value)
    if hasattr(value, "numerator") and hasattr(value, "denominator"):
        denominator = float(value.denominator)
        return float(value.numerator) / denominator if denominator else 0.0
    return float(value)


def _text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("ascii", errors="replace").strip("\x00")
    return str(value)


def _dms_to_decimal(value: Any, reference: Any) -> float | None:
    try:
        degrees, minutes, seconds = value
        decimal = _number(degrees) + (_number(minutes) / 60.0) + (_number(seconds) / 3600.0)
    except (TypeError, ValueError, ZeroDivisionError):
        return None
    if _text(reference).upper() in {"S", "W"}:
        decimal = -decimal
    return decimal


def _gps_time(value: Any) -> str:
    try:
        hour, minute, second = value
        second_value = _number(second)
        return f"{int(_number(hour)):02d}:{int(_number(minute)):02d}:{second_value:06.3f} UTC"
    except (TypeError, ValueError):
        return _text(value)


def _gps_ifd(exif: Any, exif_tags: Any) -> dict[int, Any]:
    gps_tag = 34853
    try:
        if hasattr(exif_tags, "IFD"):
            gps_tag = int(exif_tags.IFD.GPSInfo)
    except (AttributeError, TypeError, ValueError):
        gps_tag = 34853
    try:
        value = exif.get_ifd(gps_tag)
        return dict(value) if value else {}
    except Exception:
        raw = exif.get(gps_tag)
        return dict(raw) if isinstance(raw, dict) else {}


def extract_gps_metadata(exif: Any, exif_tags: Any) -> dict[str, Any]:
    gps = _gps_ifd(exif, exif_tags)
    if not gps:
        return {}
    names = getattr(exif_tags, "GPSTAGS", {})
    named = {str(names.get(key, key)): value for key, value in gps.items()}
    latitude = _dms_to_decimal(named.get("GPSLatitude"), named.get("GPSLatitudeRef", "N"))
    longitude = _dms_to_decimal(named.get("GPSLongitude"), named.get("GPSLongitudeRef", "E"))
    if latitude is None or longitude is None:
        return {"GPS decode error": "Latitude or longitude could not be decoded.", "Raw GPS tags": {key: _text(value) for key, value in named.items()}}
    if not (-90.0 <= latitude <= 90.0 and -180.0 <= longitude <= 180.0):
        return {"GPS decode error": "Decoded coordinates are outside the valid latitude/longitude range.", "Raw GPS tags": {key: _text(value) for key, value in named.items()}}

    output: dict[str, Any] = {
        "Latitude": round(latitude, 8),
        "Longitude": round(longitude, 8),
        "Coordinates": f"{latitude:.8f}, {longitude:.8f}",
        "Latitude DMS": decimal_to_dms(latitude, latitude=True),
        "Longitude DMS": decimal_to_dms(longitude, latitude=False),
    }
    altitude = named.get("GPSAltitude")
    if altitude is not None:
        try:
            altitude_value = _number(altitude)
            reference = named.get("GPSAltitudeRef", 0)
            if isinstance(reference, bytes):
                below_sea_level = bool(reference and reference[0] == 1)
            else:
                below_sea_level = int(reference) == 1
            if below_sea_level:
                altitude_value = -altitude_value
            output["Altitude (meters)"] = round(altitude_value, 3)
        except (TypeError, ValueError, ZeroDivisionError):
            output["Altitude"] = _text(altitude)
    if named.get("GPSDateStamp"):
        output["GPS date"] = _text(named["GPSDateStamp"])
    if named.get("GPSTimeStamp"):
        output["GPS time"] = _gps_time(named["GPSTimeStamp"])
    if named.get("GPSImgDirection") is not None:
        try:
            output["Image direction (degrees)"] = round(_number(named["GPSImgDirection"]), 3)
            if named.get("GPSImgDirectionRef"):
                output["Image direction reference"] = _text(named["GPSImgDirectionRef"])
        except (TypeError, ValueError, ZeroDivisionError):
            pass
    if named.get("GPSSpeed") is not None:
        try:
            output["GPS speed"] = round(_number(named["GPSSpeed"]), 3)
            if named.get("GPSSpeedRef"):
                output["GPS speed unit"] = _text(named["GPSSpeedRef"])
        except (TypeError, ValueError, ZeroDivisionError):
            pass
    if named.get("GPSMapDatum"):
        output["Map datum"] = _text(named["GPSMapDatum"])
    if named.get("GPSProcessingMethod"):
        output["Processing method"] = _text(named["GPSProcessingMethod"])
    if named.get("GPSAreaInformation"):
        output["Area information"] = _text(named["GPSAreaInformation"])

    country = lookup_country(longitude, latitude, resource_path("assets", "world_countries.json"))
    if country:
        output.update(country)
    output["Map database"] = "Natural Earth 1:110m offline country boundaries"
    return output


class ImagePlugin(AnalysisPlugin):
    name = "Image metadata parser"
    EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tif", ".tiff", ".ico"}

    def supports(self, path: Path, header: bytes, detected_type: str) -> bool:
        return path.suffix.lower() in self.EXTENSIONS or detected_type.endswith("image") or "image" in detected_type.lower()

    def analyze(self, result: AnalysisResult, header: bytes) -> None:
        try:
            from PIL import ExifTags, Image
        except ImportError:
            result.warnings.append("Pillow is not installed; extended image metadata is unavailable.")
            return
        with Image.open(result.path) as image:
            info = {
                "Format": image.format,
                "Mode": image.mode,
                "Width": image.width,
                "Height": image.height,
                "Frames": getattr(image, "n_frames", 1),
                "Animated": bool(getattr(image, "is_animated", False)),
                "Palette": bool(image.palette),
            }
            for key, value in image.info.items():
                if isinstance(value, (str, int, float, bool)):
                    info[f"Info: {key}"] = value
            result.metadata["Image"] = info
            result.sections["Image metadata"] = info
            exif_rows = []
            try:
                exif = image.getexif()
                for key, value in exif.items():
                    name = ExifTags.TAGS.get(key, str(key))
                    if name == "GPSInfo":
                        value = "GPS IFD (decoded below)"
                    exif_rows.append({"tag": name, "value": _text(value)[:4000]})
                gps = extract_gps_metadata(exif, ExifTags)
                if gps:
                    result.sections["GPS"] = gps
                    result.metadata["GPS"] = gps
                    result.summary["GPS"] = gps.get("Coordinates", "GPS metadata present")
            except Exception as exc:
                result.warnings.append(f"EXIF read warning: {exc}")
            if exif_rows:
                result.sections["EXIF"] = exif_rows
                result.metadata["EXIF tag count"] = len(exif_rows)
