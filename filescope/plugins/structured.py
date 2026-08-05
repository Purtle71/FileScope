from __future__ import annotations

import configparser
import csv
import io
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from filescope.core.models import AnalysisResult
from filescope.core.utils import decode_text, looks_text, read_prefix

from .base import AnalysisPlugin


class StructuredTextPlugin(AnalysisPlugin):
    name = "Structured text parser"
    EXTENSIONS = {".txt", ".log", ".json", ".xml", ".csv", ".tsv", ".ini", ".cfg", ".conf", ".yaml", ".yml", ".md", ".py", ".js", ".ts", ".html", ".css", ".ps1", ".bat", ".cmd"}

    def supports(self, path: Path, header: bytes, detected_type: str) -> bool:
        return path.suffix.lower() in self.EXTENSIONS or looks_text(header)

    def analyze(self, result: AnalysisResult, header: bytes) -> None:
        data = read_prefix(result.path, 8 * 1024 * 1024)
        text, encoding = decode_text(data)
        result.metadata["Text encoding"] = encoding
        result.metadata["Line count (preview)"] = text.count("\n") + (1 if text else 0)
        result.metadata["Character count (preview)"] = len(text)
        result.sections["Text preview"] = text
        ext = result.path.suffix.lower()
        if ext in {".ini", ".cfg", ".conf"}:
            self._parse_ini(result, text)
        elif ext in {".csv", ".tsv"}:
            self._parse_delimited(result, text, "\t" if ext == ".tsv" else None)
        elif ext == ".xml":
            self._parse_xml(result, text)
        elif ext == ".json":
            self._parse_json(result, text)
        elif text.lstrip().startswith("{") or (text.lstrip().startswith("[") and not re.match(r"^\[[^]\r\n]+\]\s*(?:\r?\n|$)", text.lstrip())):
            self._parse_json(result, text)
        elif text.lstrip().startswith("<"):
            self._parse_xml(result, text)

    def _parse_json(self, result: AnalysisResult, text: str) -> None:
        try:
            value = json.loads(text)
        except json.JSONDecodeError as exc:
            result.warnings.append(f"JSON parse error at line {exc.lineno}, column {exc.colno}: {exc.msg}")
            return
        result.sections["Structure"] = value
        result.metadata["JSON root type"] = type(value).__name__
        if isinstance(value, dict):
            result.metadata["Top-level keys"] = len(value)
        elif isinstance(value, list):
            result.metadata["Top-level items"] = len(value)

    def _parse_xml(self, result: AnalysisResult, text: str) -> None:
        try:
            root = ET.fromstring(text)
        except ET.ParseError as exc:
            result.warnings.append(f"XML parse error: {exc}")
            return

        def convert(element: ET.Element, depth: int = 0) -> dict[str, Any]:
            node: dict[str, Any] = {"tag": element.tag}
            if element.attrib:
                node["attributes"] = dict(element.attrib)
            if element.text and element.text.strip():
                node["text"] = element.text.strip()[:4000]
            if depth < 40:
                children = [convert(child, depth + 1) for child in list(element)[:5000]]
                if children:
                    node["children"] = children
            return node

        result.sections["Structure"] = convert(root)
        result.metadata["XML root element"] = root.tag
        result.metadata["XML direct children"] = len(list(root))

    def _parse_delimited(self, result: AnalysisResult, text: str, delimiter: str | None) -> None:
        sample = text[:65536]
        if delimiter is None:
            try:
                delimiter = csv.Sniffer().sniff(sample, delimiters=",;|\t").delimiter
            except csv.Error:
                delimiter = ","
        reader = csv.reader(io.StringIO(text), delimiter=delimiter)
        rows = []
        max_columns = 0
        for index, row in enumerate(reader):
            rows.append(row)
            max_columns = max(max_columns, len(row))
            if index >= 4999:
                result.warnings.append("Delimited preview limited to 5,000 rows.")
                break
        result.sections["Structure"] = rows
        result.metadata["Delimiter"] = repr(delimiter)
        result.metadata["Rows (preview)"] = len(rows)
        result.metadata["Maximum columns"] = max_columns

    def _parse_ini(self, result: AnalysisResult, text: str) -> None:
        parser = configparser.ConfigParser(interpolation=None, strict=False)
        try:
            parser.read_string(text)
        except configparser.Error as exc:
            result.warnings.append(f"INI parse error: {exc}")
            return
        value = {section: dict(parser.items(section)) for section in parser.sections()}
        result.sections["Structure"] = value
        result.metadata["INI sections"] = len(value)
