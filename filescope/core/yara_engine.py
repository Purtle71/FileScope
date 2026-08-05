from __future__ import annotations

from pathlib import Path
from typing import Any

MAX_YARA_SCAN_BYTES = 512 * 1024 * 1024


def scan_with_yara(path: str | Path, rule_path: str | Path) -> dict[str, Any]:
    target = Path(path)
    rules_file = Path(rule_path)
    if not target.is_file():
        return {"available": False, "engine": "", "matches": [], "error": "Target file does not exist."}
    if not rules_file.is_file():
        return {"available": False, "engine": "", "matches": [], "error": "YARA rule file does not exist."}
    try:
        import yara_x
    except ImportError as exc:
        return {"available": False, "engine": "", "matches": [], "error": "YARA-X is not installed.", "exception": str(exc)}

    if target.stat().st_size > MAX_YARA_SCAN_BYTES:
        return {
            "available": True,
            "engine": "YARA-X",
            "matches": [],
            "error": f"File is larger than the {MAX_YARA_SCAN_BYTES // (1024 * 1024)} MB in-memory YARA-X safety limit.",
        }

    try:
        source = rules_file.read_text(encoding="utf-8", errors="replace")
        rules = yara_x.compile(source)
        results = rules.scan(target.read_bytes())
        rows = []
        for match in results.matching_rules:
            strings = []
            for pattern in match.patterns:
                for instance in pattern.matches:
                    strings.append(
                        {
                            "identifier": pattern.identifier,
                            "offset": int(instance.offset),
                            "length": int(instance.length),
                            "xor_key": int(getattr(instance, "xor_key", 0)),
                        }
                    )
            rows.append(
                {
                    "rule": match.identifier,
                    "namespace": match.namespace,
                    "tags": list(match.tags),
                    "meta": dict(match.metadata),
                    "strings": strings,
                }
            )
        return {"available": True, "engine": "YARA-X", "matches": rows, "error": ""}
    except Exception as exc:
        return {"available": True, "engine": "YARA-X", "matches": [], "error": str(exc)}


def validate_yara_rule(rule_path: str | Path) -> tuple[bool, str]:
    rules_file = Path(rule_path)
    if not rules_file.is_file():
        return False, "YARA rule file does not exist."
    try:
        import yara_x
    except ImportError:
        return False, "YARA-X is not installed."
    try:
        source = rules_file.read_text(encoding="utf-8", errors="replace")
        yara_x.compile(source)
        return True, "Rule file compiled successfully with YARA-X."
    except Exception as exc:
        return False, str(exc)


def starter_rule_path(base_dir: str | Path) -> Path:
    return Path(base_dir) / "rules" / "starter_rules.yar"
