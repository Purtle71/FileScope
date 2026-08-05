from __future__ import annotations

import csv
import html
import json
from pathlib import Path
from typing import Any

from .models import AnalysisResult
from .utils import flatten_mapping, json_safe


def export_json(result: AnalysisResult, destination: str | Path) -> Path:
    target = Path(destination)
    target.write_text(json.dumps(json_safe(result.to_dict()), indent=2, ensure_ascii=False), encoding="utf-8")
    return target


def export_text(result: AnalysisResult, destination: str | Path) -> Path:
    target = Path(destination)
    lines = [
        "FileScope Analysis Report",
        "=" * 80,
        f"File: {result.path}",
        f"Detected type: {result.detected_type}",
        f"Risk: {result.risk_score}/100 ({result.risk_label})",
        "",
        "SUMMARY",
        "-" * 80,
    ]
    for key, value in result.summary.items():
        lines.append(f"{key}: {value}")
    lines.extend(["", "FINDINGS", "-" * 80])
    for finding in result.findings:
        lines.append(f"[{finding.severity}] {finding.title} (+{finding.score})")
        lines.append(f"  {finding.detail}")
        if finding.evidence:
            lines.append(f"  Evidence: {finding.evidence}")
    lines.extend(["", "METADATA", "-" * 80])
    for key, value in flatten_mapping(result.metadata):
        lines.append(f"{key}: {value}")
    lines.extend(["", "INDICATORS", "-" * 80])
    for category, values in result.iocs.items():
        lines.append(f"{category}:")
        lines.extend(f"  {value}" for value in values)
    target.write_text("\n".join(lines), encoding="utf-8")
    return target


def export_csv(result: AnalysisResult, destination: str | Path) -> Path:
    target = Path(destination)
    with target.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.writer(handle)
        writer.writerow(["Section", "Key", "Value"])
        for key, value in flatten_mapping(result.summary):
            writer.writerow(["Summary", key, value])
        for key, value in flatten_mapping(result.metadata):
            writer.writerow(["Metadata", key, value])
        for index, finding in enumerate(result.findings):
            for key, value in flatten_mapping({"severity": finding.severity, "title": finding.title, "detail": finding.detail, "score": finding.score, "evidence": finding.evidence}):
                writer.writerow([f"Finding {index + 1}", key, value])
        for category, values in result.iocs.items():
            for value in values:
                writer.writerow(["IOC", category, value])
    return target


def export_html(result: AnalysisResult, destination: str | Path) -> Path:
    target = Path(destination)
    def esc(value: Any) -> str:
        return html.escape(str(value))

    findings = "".join(
        f"<article class='finding {esc(item.severity.lower())}'><div><strong>{esc(item.severity)}</strong><span>+{item.score}</span></div><h3>{esc(item.title)}</h3><p>{esc(item.detail)}</p><code>{esc(item.evidence)}</code></article>"
        for item in result.findings
    ) or "<p>No risk findings were generated.</p>"
    metadata_rows = "".join(f"<tr><th>{esc(key)}</th><td>{esc(value)}</td></tr>" for key, value in flatten_mapping(result.metadata))
    ioc_sections = "".join(
        f"<section><h3>{esc(category)}</h3><pre>{esc(chr(10).join(values))}</pre></section>" for category, values in result.iocs.items()
    ) or "<p>No indicators were extracted.</p>"
    document = f"""<!doctype html>
<html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>FileScope report — {esc(result.path.name)}</title>
<style>
:root{{--bg:#08111f;--panel:#101d2e;--panel2:#14243a;--text:#e8f0fb;--muted:#91a5bd;--accent:#11b9d6;--border:#223853;--high:#ff6262;--medium:#ffb84d;--low:#4cc38a}}
*{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 'Segoe UI',Arial,sans-serif}} main{{max-width:1200px;margin:0 auto;padding:34px}} header{{background:linear-gradient(135deg,#10253f,#0d3248);border:1px solid var(--border);border-radius:20px;padding:28px;margin-bottom:22px}} h1{{margin:0 0 8px;font-size:30px}} .muted{{color:var(--muted)}} .score{{font-size:42px;font-weight:800;color:var(--accent)}} .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px}} .card{{background:var(--panel);border:1px solid var(--border);border-radius:16px;padding:20px;margin-bottom:18px}} table{{width:100%;border-collapse:collapse}} th,td{{text-align:left;vertical-align:top;padding:10px;border-bottom:1px solid var(--border)}} th{{width:33%;color:var(--muted)}} .finding{{background:var(--panel2);border-left:4px solid var(--accent);padding:14px;border-radius:10px;margin:10px 0}} .finding.high,.finding.critical{{border-color:var(--high)}} .finding.medium{{border-color:var(--medium)}} .finding.low{{border-color:var(--low)}} .finding div{{display:flex;justify-content:space-between}} pre,code{{white-space:pre-wrap;word-break:break-word;color:#b8eaff}}
</style></head><body><main>
<header><div class='muted'>FileScope analysis report</div><h1>{esc(result.path.name)}</h1><div>{esc(result.detected_type)}</div><div class='score'>{result.risk_score}/100</div><div class='muted'>{esc(result.risk_label)} risk · SHA-256 {esc(result.summary.get('SHA-256',''))}</div></header>
<section class='card'><h2>Findings</h2>{findings}</section>
<section class='card'><h2>Metadata</h2><table>{metadata_rows}</table></section>
<section class='card'><h2>Extracted indicators</h2><div class='grid'>{ioc_sections}</div></section>
</main></body></html>"""
    target.write_text(document, encoding="utf-8")
    return target


def export_report(result: AnalysisResult, destination: str | Path) -> Path:
    suffix = Path(destination).suffix.lower()
    if suffix == ".json":
        return export_json(result, destination)
    if suffix == ".csv":
        return export_csv(result, destination)
    if suffix in {".html", ".htm"}:
        return export_html(result, destination)
    return export_text(result, destination)
