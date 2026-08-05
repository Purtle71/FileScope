from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Callable

from .analyzer import FileAnalyzer


def scan_folder(
    folder: str | Path,
    *,
    recursive: bool = True,
    max_files: int = 25_000,
    workers: int = 4,
    analyzer: FileAnalyzer | None = None,
    progress: Callable[[int, int, str], None] | None = None,
    cancel_event: threading.Event | None = None,
) -> list[dict[str, Any]]:
    root = Path(folder).expanduser().resolve()
    if not root.is_dir():
        raise NotADirectoryError(root)
    paths: list[Path] = []
    iterator = root.rglob("*") if recursive else root.glob("*")
    for path in iterator:
        if cancel_event and cancel_event.is_set():
            break
        try:
            if path.is_file():
                paths.append(path)
                if len(paths) >= max_files:
                    break
        except OSError:
            continue
    engine = analyzer or FileAnalyzer(preview_bytes=256 * 1024, string_scan_bytes=8 * 1024 * 1024)
    rows: list[dict[str, Any]] = []

    def analyze_one(path: Path) -> dict[str, Any]:
        try:
            result = engine.analyze(path)
            return {
                "path": str(path),
                "relative_path": str(path.relative_to(root)),
                "name": path.name,
                "extension": path.suffix.lower(),
                "size": path.stat().st_size,
                "detected_type": result.detected_type,
                "sha256": result.summary.get("SHA-256", ""),
                "risk_score": result.risk_score,
                "risk_level": result.risk_label,
                "findings": len(result.findings),
                "parse_status": "OK" if not result.errors else "Partial",
                "errors": "; ".join(result.errors),
            }
        except Exception as exc:
            return {
                "path": str(path),
                "relative_path": str(path.relative_to(root)),
                "name": path.name,
                "extension": path.suffix.lower(),
                "size": path.stat().st_size if path.exists() else 0,
                "detected_type": "Unknown",
                "sha256": "",
                "risk_score": 0,
                "risk_level": "Unknown",
                "findings": 0,
                "parse_status": "Error",
                "errors": str(exc),
            }

    workers = max(1, min(workers, 16))
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="FileScopeScan") as executor:
        future_map = {executor.submit(analyze_one, path): path for path in paths}
        for index, future in enumerate(as_completed(future_map), start=1):
            if cancel_event and cancel_event.is_set():
                for pending in future_map:
                    pending.cancel()
                break
            row = future.result()
            rows.append(row)
            if progress:
                progress(index, len(paths), row["relative_path"])
    rows.sort(key=lambda row: (-int(row.get("risk_score", 0)), str(row.get("relative_path", "")).lower()))
    return rows
