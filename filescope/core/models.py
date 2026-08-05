from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class StringArtifact:
    offset: int
    encoding: str
    value: str
    category: str = "General"


@dataclass(slots=True)
class Finding:
    severity: str
    title: str
    detail: str
    score: int = 0
    evidence: str = ""


@dataclass(slots=True)
class AnalysisResult:
    path: Path
    detected_type: str = "Unknown binary"
    mime_type: str = "application/octet-stream"
    parser_names: list[str] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    sections: dict[str, Any] = field(default_factory=dict)
    strings: list[StringArtifact] = field(default_factory=list)
    iocs: dict[str, list[str]] = field(default_factory=dict)
    entropy: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def risk_score(self) -> int:
        return max(0, min(100, sum(max(0, finding.score) for finding in self.findings)))

    @property
    def risk_label(self) -> str:
        score = self.risk_score
        if score >= 75:
            return "High"
        if score >= 45:
            return "Elevated"
        if score >= 20:
            return "Guarded"
        return "Low"

    def add_finding(self, severity: str, title: str, detail: str, score: int = 0, evidence: str = "") -> None:
        signature = (severity, title, detail, evidence)
        for existing in self.findings:
            if (existing.severity, existing.title, existing.detail, existing.evidence) == signature:
                return
        self.findings.append(Finding(severity, title, detail, score, evidence))

    def add_parser(self, name: str) -> None:
        if name not in self.parser_names:
            self.parser_names.append(name)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "detected_type": self.detected_type,
            "mime_type": self.mime_type,
            "parser_names": list(self.parser_names),
            "summary": self.summary,
            "metadata": self.metadata,
            "sections": self.sections,
            "strings": [asdict(item) for item in self.strings],
            "iocs": self.iocs,
            "entropy": self.entropy,
            "findings": [asdict(item) for item in self.findings],
            "risk_score": self.risk_score,
            "risk_label": self.risk_label,
            "warnings": self.warnings,
            "errors": self.errors,
        }
