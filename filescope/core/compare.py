from __future__ import annotations

from pathlib import Path
from typing import Any

from .analyzer import FileAnalyzer
from .models import AnalysisResult


def _keyed(rows: Any, key: str = "name") -> dict[str, Any]:
    if not isinstance(rows, list):
        return {}
    output = {}
    for row in rows:
        if isinstance(row, dict) and key in row:
            output[str(row[key])] = row
    return output


def compare_results(left: AnalysisResult, right: AnalysisResult) -> dict[str, Any]:
    comparison: dict[str, Any] = {
        "left": str(left.path),
        "right": str(right.path),
        "same_sha256": left.summary.get("SHA-256") == right.summary.get("SHA-256"),
        "type_changed": left.detected_type != right.detected_type,
        "risk_change": right.risk_score - left.risk_score,
        "metadata_changes": [],
        "added_iocs": {},
        "removed_iocs": {},
        "added_archive_entries": [],
        "removed_archive_entries": [],
        "changed_archive_entries": [],
        "added_permissions": [],
        "removed_permissions": [],
        "added_imports": [],
        "removed_imports": [],
    }
    all_keys = sorted(set(left.metadata) | set(right.metadata), key=str.lower)
    for key in all_keys:
        before = left.metadata.get(key)
        after = right.metadata.get(key)
        if before != after:
            comparison["metadata_changes"].append({"key": key, "before": before, "after": after})
    for category in sorted(set(left.iocs) | set(right.iocs)):
        before = set(left.iocs.get(category, []))
        after = set(right.iocs.get(category, []))
        added = sorted(after - before)
        removed = sorted(before - after)
        if added:
            comparison["added_iocs"][category] = added
        if removed:
            comparison["removed_iocs"][category] = removed

    left_entries = _keyed(left.sections.get("Archive entries"))
    right_entries = _keyed(right.sections.get("Archive entries"))
    comparison["added_archive_entries"] = sorted(set(right_entries) - set(left_entries))
    comparison["removed_archive_entries"] = sorted(set(left_entries) - set(right_entries))
    for name in sorted(set(left_entries) & set(right_entries)):
        if left_entries[name] != right_entries[name]:
            comparison["changed_archive_entries"].append({"name": name, "before": left_entries[name], "after": right_entries[name]})

    def values(result: AnalysisResult, section: str, field: str) -> set[str]:
        rows = result.sections.get(section, [])
        return {str(row.get(field, "")) for row in rows if isinstance(row, dict) and row.get(field)}

    left_permissions = values(left, "Android permissions", "name")
    right_permissions = values(right, "Android permissions", "name")
    comparison["added_permissions"] = sorted(right_permissions - left_permissions)
    comparison["removed_permissions"] = sorted(left_permissions - right_permissions)

    left_imports = {f"{row.get('dll','')}!{row.get('name','')}" for row in left.sections.get("PE imports", []) if isinstance(row, dict)}
    right_imports = {f"{row.get('dll','')}!{row.get('name','')}" for row in right.sections.get("PE imports", []) if isinstance(row, dict)}
    comparison["added_imports"] = sorted(right_imports - left_imports)
    comparison["removed_imports"] = sorted(left_imports - right_imports)
    return comparison


def compare_files(left_path: str | Path, right_path: str | Path, analyzer: FileAnalyzer | None = None) -> dict[str, Any]:
    engine = analyzer or FileAnalyzer()
    return compare_results(engine.analyze(left_path), engine.analyze(right_path))
