from __future__ import annotations

import sys
from pathlib import Path


def application_root() -> Path:
    bundled_root = getattr(sys, "_MEIPASS", None)
    if bundled_root:
        return Path(bundled_root)
    return Path(__file__).resolve().parents[2]


def resource_path(*parts: str) -> Path:
    return application_root().joinpath(*parts)
