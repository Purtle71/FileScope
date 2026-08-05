from __future__ import annotations

from typing import Any

from .models import AnalysisResult
from .utils import json_safe


def search_result(result: AnalysisResult, query: str, limit: int = 10_000) -> list[dict[str, str]]:
    needle = query.casefold().strip()
    if not needle:
        return []
    rows: list[dict[str, str]] = []

    def walk(value: Any, path: str) -> None:
        if len(rows) >= limit:
            return
        if isinstance(value, dict):
            for key, item in value.items():
                key_path = f"{path}.{key}" if path else str(key)
                if needle in str(key).casefold():
                    rows.append({"location": key_path, "value": str(item)[:1000]})
                walk(item, key_path)
        elif isinstance(value, list):
            for index, item in enumerate(value):
                walk(item, f"{path}[{index}]")
        else:
            text = str(value)
            if needle in text.casefold():
                rows.append({"location": path, "value": text[:4000]})

    walk(json_safe(result.to_dict()), "")
    return rows
