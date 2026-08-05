from __future__ import annotations

import traceback
from pathlib import Path
from typing import Callable

from filescope.plugins.registry import PLUGINS

from .models import AnalysisResult
from .utils import (
    common_metadata,
    detect_type,
    entropy_profile,
    extract_iocs,
    extract_strings,
    file_hashes,
    human_size,
    looks_text,
    make_hex_dump,
    read_prefix,
)

ProgressCallback = Callable[[int, str], None]


class FileAnalyzer:
    def __init__(self, preview_bytes: int = 1024 * 1024, string_scan_bytes: int = 64 * 1024 * 1024) -> None:
        self.preview_bytes = max(64 * 1024, preview_bytes)
        self.string_scan_bytes = max(1024 * 1024, string_scan_bytes)

    def analyze(self, path: str | Path, progress: ProgressCallback | None = None) -> AnalysisResult:
        file_path = Path(path).expanduser().resolve()
        if not file_path.exists():
            raise FileNotFoundError(file_path)
        if not file_path.is_file():
            raise ValueError(f"Not a file: {file_path}")

        def report(percent: int, message: str) -> None:
            if progress:
                progress(percent, message)

        report(2, "Reading file header")
        header = read_prefix(file_path, min(self.preview_bytes, 2 * 1024 * 1024))
        detected_type, mime_type, extension_mismatch = detect_type(file_path, header)
        result = AnalysisResult(file_path, detected_type=detected_type, mime_type=mime_type)

        report(8, "Reading metadata")
        result.metadata.update(common_metadata(file_path))
        result.summary.update({
            "Detected type": detected_type,
            "MIME type": mime_type,
            "Size": human_size(file_path.stat().st_size),
            "Extension mismatch": extension_mismatch,
        })

        report(15, "Calculating hashes")
        hashes = file_hashes(file_path)
        result.metadata["Hashes"] = hashes
        result.summary["SHA-256"] = hashes["SHA-256"]

        if extension_mismatch:
            result.add_finding(
                "High",
                "Extension does not match file signature",
                f"The filename extension {file_path.suffix or '(none)'} does not match the detected format {detected_type}.",
                22,
                file_path.name,
            )

        report(25, "Calculating entropy")
        result.entropy = entropy_profile(file_path)
        overall_entropy = float(result.entropy.get("overall", 0.0))
        if overall_entropy >= 7.75 and file_path.stat().st_size >= 4096:
            result.add_finding(
                "Medium",
                "Very high file entropy",
                "The file is highly compressed, encrypted, packed, or contains high-entropy data.",
                12,
                f"Entropy {overall_entropy:.4f}/8.0000",
            )

        report(36, "Extracting strings")
        strings, strings_truncated = extract_strings(file_path, max_bytes=self.string_scan_bytes)
        result.strings = strings
        if strings_truncated:
            result.warnings.append(
                f"String extraction was limited to the first {human_size(self.string_scan_bytes)} or the configured result limit."
            )
        result.iocs = extract_iocs(strings)
        command_count = len(result.iocs.get("Commands", []))
        if command_count:
            result.add_finding(
                "Medium",
                "Suspicious command strings detected",
                "Command interpreters or living-off-the-land utility names were found. Context is required before treating this as malicious.",
                min(15, 4 + command_count),
                f"{command_count} matching string(s)",
            )

        report(50, "Building previews")
        result.sections["Hex preview"] = make_hex_dump(header[: self.preview_bytes])
        if looks_text(header):
            text = header.decode("utf-8", errors="replace")
            result.sections["Text preview"] = text

        report(58, "Running format parsers")
        matching = [plugin for plugin in PLUGINS if plugin.supports(file_path, header, detected_type)]
        if not matching:
            result.add_parser("Generic binary parser")
        for index, plugin in enumerate(matching, start=1):
            report(58 + int(34 * index / max(1, len(matching))), f"Running {plugin.name}")
            try:
                plugin.analyze(result, header)
                result.add_parser(plugin.name)
            except Exception as exc:  # plugins must never terminate the whole analysis
                result.errors.append(f"{plugin.name}: {exc}")
                result.sections.setdefault("Parser diagnostics", []).append({
                    "plugin": plugin.name,
                    "error": str(exc),
                    "traceback": traceback.format_exc(limit=6),
                })

        result.summary["Risk score"] = result.risk_score
        result.summary["Risk level"] = result.risk_label
        result.summary["Parsers"] = ", ".join(result.parser_names) or "Generic binary parser"
        result.sections.setdefault("Overview", result.summary)
        result.sections.setdefault("Metadata", result.metadata)
        result.sections.setdefault("Strings", [
            {"offset": item.offset, "encoding": item.encoding, "category": item.category, "value": item.value}
            for item in result.strings
        ])
        result.sections.setdefault("IOCs", result.iocs)
        result.sections.setdefault("Entropy", result.entropy)
        result.sections.setdefault("Security", [
            {
                "severity": finding.severity,
                "title": finding.title,
                "detail": finding.detail,
                "score": finding.score,
                "evidence": finding.evidence,
            }
            for finding in result.findings
        ])
        report(100, "Analysis complete")
        return result
