from __future__ import annotations

import csv
import json
import os
import shutil
import sqlite3
import threading
import tarfile
import zipfile
from pathlib import Path
from typing import Any

from PySide6.QtCore import QSettings, Qt, QThreadPool, QUrl, Signal
from PySide6.QtGui import QDesktopServices, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QSplitter,
    QVBoxLayout,
    QWidget,
    QInputDialog,
)

from filescope.core.compare import compare_files
from filescope.core.folder_scan import scan_folder
from filescope.core.global_search import search_result
from filescope.core.models import AnalysisResult
from filescope.core.reports import export_report
from filescope.core.utils import human_size
from filescope.core.yara_engine import scan_with_yara, validate_yara_rule

from .widgets import DataTableWidget, GenericDataPage, JsonTreeWidget, MetricCard, PageShell
from .workers import FunctionWorker


class DashboardPage(PageShell):
    def __init__(self, result: AnalysisResult) -> None:
        super().__init__("Overview", "File identity, type, hashes, parser coverage, and findings.")
        cards = QHBoxLayout()
        cards.addWidget(MetricCard("Risk score", f"{result.risk_score}/100"))
        cards.addWidget(MetricCard("Risk level", result.risk_label))
        cards.addWidget(MetricCard("File size", human_size(result.path.stat().st_size)))
        cards.addWidget(MetricCard("Findings", str(len(result.findings))))
        self.layout.addLayout(cards)

        identity = QFrame()
        identity.setObjectName("card")
        identity_layout = QFormLayout(identity)
        identity_layout.setContentsMargins(18, 16, 18, 16)
        identity_layout.addRow("File", QLabel(str(result.path)))
        identity_layout.addRow("Detected type", QLabel(result.detected_type))
        identity_layout.addRow("MIME type", QLabel(result.mime_type))
        identity_layout.addRow("SHA-256", QLabel(str(result.summary.get("SHA-256", ""))))
        identity_layout.addRow("Parsers", QLabel(", ".join(result.parser_names) or "Generic binary parser"))
        self.layout.addWidget(identity)

        self.findings = DataTableWidget()
        self.findings.set_rows([
            {
                "severity": item.severity,
                "score": item.score,
                "title": item.title,
                "detail": item.detail,
                "evidence": item.evidence,
            }
            for item in result.findings
        ])
        self.layout.addWidget(QLabel("Explainable findings"))
        self.layout.addWidget(self.findings, 1)


class StringsPage(PageShell):
    def __init__(self, result: AnalysisResult) -> None:
        super().__init__("Strings", "ASCII and UTF-16 strings with offsets and filters.")
        controls = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search strings…")
        self.category = QComboBox()
        categories = sorted({item.category for item in result.strings})
        self.category.addItem("All categories")
        self.category.addItems(categories)
        self.minimum = QSpinBox()
        self.minimum.setRange(1, 10000)
        self.minimum.setValue(4)
        copy = QPushButton("Copy visible")
        copy.clicked.connect(self.copy_visible)
        controls.addWidget(self.search, 1)
        controls.addWidget(self.category)
        controls.addWidget(QLabel("Minimum length"))
        controls.addWidget(self.minimum)
        controls.addWidget(copy)
        self.layout.addLayout(controls)
        self.table = DataTableWidget()
        self.table.set_rows([
            {"offset": f"0x{item.offset:X}", "offset_decimal": item.offset, "encoding": item.encoding, "category": item.category, "length": len(item.value), "value": item.value}
            for item in result.strings
        ], max_rows=100_000)
        self.layout.addWidget(self.table, 1)
        self.search.textChanged.connect(self.apply_filter)
        self.category.currentTextChanged.connect(self.apply_filter)
        self.minimum.valueChanged.connect(self.apply_filter)

    def apply_filter(self, *_: Any) -> None:
        needle = self.search.text().casefold().strip()
        category = self.category.currentText()
        minimum = self.minimum.value()
        for row in range(self.table.rowCount()):
            value_item = self.table.item(row, 5)
            category_item = self.table.item(row, 3)
            value = value_item.text() if value_item else ""
            row_category = category_item.text() if category_item else ""
            visible = len(value) >= minimum and (not needle or needle in value.casefold()) and (category == "All categories" or category == row_category)
            self.table.setRowHidden(row, not visible)

    def copy_visible(self) -> None:
        values = []
        for row in range(self.table.rowCount()):
            if not self.table.isRowHidden(row):
                item = self.table.item(row, 5)
                if item:
                    values.append(item.text())
        QApplication.clipboard().setText("\n".join(values))


class SecurityPage(PageShell):
    def __init__(self, result: AnalysisResult) -> None:
        super().__init__("Security", "Risk findings, score contributions, evidence, and parser warnings.")
        summary = QHBoxLayout()
        summary.addWidget(MetricCard("Risk score", f"{result.risk_score}/100"))
        summary.addWidget(MetricCard("High or critical", str(sum(item.severity.lower() in {"high", "critical"} for item in result.findings))))
        summary.addWidget(MetricCard("Warnings", str(len(result.warnings))))
        summary.addWidget(MetricCard("Parser errors", str(len(result.errors))))
        self.layout.addLayout(summary)
        data = [
            {"severity": item.severity, "score": item.score, "title": item.title, "detail": item.detail, "evidence": item.evidence}
            for item in result.findings
        ]
        table = DataTableWidget()
        table.set_rows(data)
        self.layout.addWidget(table, 1)
        diagnostics = JsonTreeWidget()
        diagnostics.set_data({"warnings": result.warnings, "errors": result.errors})
        self.layout.addWidget(diagnostics, 1)


class EntropyGraph(QWidget):
    def __init__(self, blocks: list[dict[str, Any]]) -> None:
        super().__init__()
        self.blocks = blocks
        self.setMinimumHeight(260)

    def paintEvent(self, event: Any) -> None:
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = self.rect().adjusted(42, 18, -18, -36)
        painter.setPen(QPen(self.palette().mid().color(), 1))
        painter.drawRect(rect)
        for value in range(0, 9, 2):
            y = rect.bottom() - (value / 8.0) * rect.height()
            painter.drawLine(rect.left(), int(y), rect.right(), int(y))
            painter.drawText(4, int(y + 5), str(value))
        if not self.blocks:
            painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, "No entropy blocks available")
            return
        path = QPainterPath()
        count = len(self.blocks)
        for index, block in enumerate(self.blocks):
            x = rect.left() + (index / max(1, count - 1)) * rect.width()
            y = rect.bottom() - (float(block.get("entropy", 0.0)) / 8.0) * rect.height()
            if index == 0:
                path.moveTo(x, y)
            else:
                path.lineTo(x, y)
        pen = QPen(self.palette().highlight().color(), 2)
        painter.setPen(pen)
        painter.drawPath(path)
        painter.setPen(self.palette().text().color())
        painter.drawText(rect.left(), self.height() - 8, "File start")
        painter.drawText(rect.right() - 55, self.height() - 8, "File end")


class EntropyPage(PageShell):
    def __init__(self, result: AnalysisResult) -> None:
        super().__init__("Entropy", "Entropy approaching 8.0 can indicate compression, encryption, packing, or naturally dense data.")
        self.layout.addWidget(MetricCard("Overall entropy", f"{float(result.entropy.get('overall', 0.0)):.4f} / 8.0000"))
        self.layout.addWidget(EntropyGraph(result.entropy.get("blocks", [])))
        table = DataTableWidget()
        table.set_rows(result.entropy.get("blocks", []))
        self.layout.addWidget(table, 1)


class IOCPage(PageShell):
    def __init__(self, result: AnalysisResult) -> None:
        super().__init__("Indicators", "Extracted URLs, domains, addresses, hashes, paths, commands, and related values.")
        controls = QHBoxLayout()
        copy = QPushButton("Copy all indicators")
        copy.clicked.connect(self.copy_all)
        vt = QPushButton("Look up SHA-256 on VirusTotal")
        vt.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(f"https://www.virustotal.com/gui/file/{result.summary.get('SHA-256','')}/detection")))
        mb = QPushButton("Look up SHA-256 on MalwareBazaar")
        mb.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(f"https://bazaar.abuse.ch/sample/{result.summary.get('SHA-256','')}/")))
        controls.addWidget(copy)
        controls.addStretch(1)
        controls.addWidget(vt)
        controls.addWidget(mb)
        self.layout.addLayout(controls)
        rows = []
        for category, values in result.iocs.items():
            for value in values:
                rows.append({"category": category, "value": value})
        self.rows = rows
        self.table = DataTableWidget()
        self.table.set_rows(rows)
        self.layout.addWidget(self.table, 1)

    def copy_all(self) -> None:
        QApplication.clipboard().setText("\n".join(f"[{row['category']}] {row['value']}" for row in self.rows))


class NetworkPage(GenericDataPage):
    def __init__(self, result: AnalysisResult) -> None:
        super().__init__("Network", "Network indicators from file contents and parser results.", table_mode=True)
        rows = []
        for category in ("URLs", "Domains", "IPv4"):
            for value in result.iocs.get(category, []):
                rows.append({"source": "Extracted string", "category": category, "value": value})
        for row in result.sections.get("PE imports", []):
            if isinstance(row, dict) and any(term in str(row.get("dll", "")).lower() for term in ("wininet", "winhttp", "ws2_32", "urlmon")):
                rows.append({"source": "PE import", "category": row.get("dll", ""), "value": row.get("name", "")})
        for dex in result.sections.get("DEX", []):
            if not isinstance(dex, dict):
                continue
            for category in ("URLs", "Domains", "IPv4"):
                for value in dex.get("iocs", {}).get(category, []):
                    rows.append({"source": dex.get("name", "DEX"), "category": category, "value": value})
        self.set_data(rows)


class SignaturePage(GenericDataPage):
    def __init__(self, result: AnalysisResult) -> None:
        super().__init__("Signatures", "File hashes, Windows signature data, and Android signing files.")
        self.set_data({
            "Hashes": result.metadata.get("Hashes", {}),
            "Authenticode": result.metadata.get("Authenticode", {}),
            "PE certificate table": result.metadata.get("PE certificate table", {}),
            "Android signing files": result.sections.get("Android signing files", []),
        })


class ResourcePage(PageShell):
    def __init__(self, result: AnalysisResult) -> None:
        super().__init__("Resources", "PE resources and overlay data with extraction controls.")
        self.result = result
        controls = QHBoxLayout()
        extract = QPushButton("Extract selected resource")
        extract.setObjectName("accentButton")
        extract.clicked.connect(self.extract_selected)
        controls.addWidget(extract)
        controls.addStretch(1)
        self.layout.addLayout(controls)
        rows = list(result.sections.get("PE resources", []))
        overlay = result.sections.get("PE overlay")
        if isinstance(overlay, dict):
            rows.append({"type": "PE overlay", "id": "overlay", "language": "", "rva": "", "file_offset": overlay.get("file_offset", -1), "size": overlay.get("size", 0), "codepage": ""})
        self.table = DataTableWidget()
        self.table.set_rows(rows)
        self.layout.addWidget(self.table, 1)

    def extract_selected(self) -> None:
        rows = self.table.selected_row_dicts()
        if not rows:
            QMessageBox.information(self, "Select a resource", "Select one resource row first.")
            return
        row = rows[0]
        try:
            offset = int(row.get("file_offset", "-1"), 0)
            size = int(row.get("size", "0"), 0)
        except ValueError:
            QMessageBox.warning(self, "Invalid resource", "The selected resource does not contain a valid file offset and size.")
            return
        if offset < 0 or size <= 0 or offset + size > self.result.path.stat().st_size:
            QMessageBox.warning(self, "Invalid resource", "The selected resource lies outside the file boundaries.")
            return
        suggested = f"resource_{row.get('type','unknown')}_{row.get('id','unknown')}.bin".replace("/", "_").replace("\\", "_")
        destination, _ = QFileDialog.getSaveFileName(self, "Extract resource", suggested, "All files (*)")
        if not destination:
            return
        with self.result.path.open("rb") as source:
            source.seek(offset)
            Path(destination).write_bytes(source.read(size))


class ArchivePage(PageShell):
    def __init__(self, result: AnalysisResult) -> None:
        super().__init__("Archive", "Archive entries, nested content, safety checks, and extraction.")
        self.result = result
        controls = QHBoxLayout()
        extract = QPushButton("Extract selected")
        extract.setObjectName("accentButton")
        extract.clicked.connect(self.extract_selected)
        controls.addWidget(extract)
        controls.addStretch(1)
        self.layout.addLayout(controls)
        splitter = QSplitter(Qt.Orientation.Vertical)
        self.table = DataTableWidget()
        self.table.set_rows(result.sections.get("Archive entries", []))
        self.tree = JsonTreeWidget()
        self.tree.set_data(result.sections.get("Nested archives", {}))
        splitter.addWidget(self.table)
        splitter.addWidget(self.tree)
        splitter.setSizes([500, 300])
        self.layout.addWidget(splitter, 1)

    def extract_selected(self) -> None:
        names = [row.get("name", "") for row in self.table.selected_row_dicts() if row.get("name")]
        if not names:
            QMessageBox.information(self, "Select entries", "Select one or more archive entries first.")
            return
        destination = QFileDialog.getExistingDirectory(self, "Choose extraction directory")
        if not destination:
            return
        base = Path(destination).resolve()
        extracted = 0
        try:
            if zipfile.is_zipfile(self.result.path):
                with zipfile.ZipFile(self.result.path) as archive:
                    for name in names:
                        info = archive.getinfo(name)
                        target = (base / Path(name.replace("\\", "/"))).resolve()
                        try:
                            contained = os.path.commonpath([str(base), str(target)]) == str(base)
                        except ValueError:
                            contained = False
                        if not contained:
                            continue
                        if info.is_dir():
                            target.mkdir(parents=True, exist_ok=True)
                        else:
                            target.parent.mkdir(parents=True, exist_ok=True)
                            with archive.open(info) as source, target.open("wb") as output:
                                shutil.copyfileobj(source, output)
                            extracted += 1
            elif tarfile.is_tarfile(self.result.path):
                with tarfile.open(self.result.path, "r:*") as archive:
                    members = {member.name: member for member in archive.getmembers()}
                    for name in names:
                        member = members.get(name)
                        if member is None or member.issym() or member.islnk():
                            continue
                        target = (base / Path(name.replace("\\", "/"))).resolve()
                        try:
                            contained = os.path.commonpath([str(base), str(target)]) == str(base)
                        except ValueError:
                            contained = False
                        if not contained:
                            continue
                        if member.isdir():
                            target.mkdir(parents=True, exist_ok=True)
                        elif member.isfile():
                            source = archive.extractfile(member)
                            if source is None:
                                continue
                            target.parent.mkdir(parents=True, exist_ok=True)
                            with source, target.open("wb") as output:
                                shutil.copyfileobj(source, output)
                            extracted += 1
            else:
                QMessageBox.warning(self, "Extraction unavailable", "This archive can be identified, but its contents require an external extraction engine.")
                return
        except Exception as exc:
            QMessageBox.critical(self, "Extraction failed", str(exc))
            return
        QMessageBox.information(self, "Extraction complete", f"Extracted {extracted} file(s) safely.")


class AndroidPage(PageShell):
    def __init__(self, result: AnalysisResult) -> None:
        super().__init__("Android Manifest", "Package metadata, permissions, components, splits, and APK-set extraction.")
        self.result = result
        controls = QHBoxLayout()
        extract = QPushButton("Extract device APK set…")
        extract.setObjectName("accentButton")
        extract.clicked.connect(self.extract_device_set)
        controls.addWidget(extract)
        controls.addStretch(1)
        self.layout.addLayout(controls)
        splitter = QSplitter(Qt.Orientation.Vertical)
        manifest = JsonTreeWidget()
        manifest.set_data({
            "Manifest": result.sections.get("Android manifest", {}),
            "Permissions": result.sections.get("Android permissions", []),
            "Splits": result.sections.get("Android split packages", []),
            "Split manifests": result.sections.get("Android split manifests", []),
        })
        xml = QPlainTextEdit()
        xml.setReadOnly(True)
        xml.setPlainText(str(result.sections.get("Android manifest XML", "No decoded manifest XML is available.")))
        splitter.addWidget(manifest)
        splitter.addWidget(xml)
        splitter.setSizes([500, 250])
        self.layout.addWidget(splitter, 1)

    def extract_device_set(self) -> None:
        rows = self.result.sections.get("Android split packages", [])
        if not isinstance(rows, list) or not rows or not zipfile.is_zipfile(self.result.path):
            QMessageBox.information(self, "No split package set", "This file does not contain an APKS/XAPK/APKM split-package inventory.")
            return
        choices: dict[str, str] = {}
        for dimension, label in (("abi", "ABI"), ("density", "screen density"), ("language", "language")):
            values = sorted({str(row.get("value", "")) for row in rows if isinstance(row, dict) and row.get("dimension") == dimension and row.get("value")})
            if values:
                value, ok = QInputDialog.getItem(self, f"Select {label}", f"Choose the target {label}:", values, 0, False)
                if not ok:
                    return
                choices[dimension] = value
        destination = QFileDialog.getExistingDirectory(self, "Choose APK extraction directory")
        if not destination:
            return
        base = Path(destination).resolve()
        selected = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            kind = row.get("kind")
            dimension = row.get("dimension")
            value = row.get("value")
            if kind == "base" or dimension == "feature" or (dimension in choices and choices[dimension] == value):
                selected.append(str(row.get("name", "")))
        try:
            with zipfile.ZipFile(self.result.path) as archive:
                for name in selected:
                    info = archive.getinfo(name)
                    target = (base / Path(name).name).resolve()
                    if os.path.commonpath([base, target]) != str(base):
                        continue
                    target.write_bytes(archive.read(info))
        except Exception as exc:
            QMessageBox.critical(self, "Extraction failed", str(exc))
            return
        QMessageBox.information(self, "Device APK set extracted", f"Extracted {len(selected)} APK file(s). Install them together with an approved split-APK installer or ADB.")


class OfficePage(PageShell):
    def __init__(self, result: AnalysisResult) -> None:
        super().__init__("Office & PDF", "Document metadata, macros, links, hidden content, embedded files, and attachments.")
        self.result = result
        extract = QPushButton("Extract selected embedded object")
        extract.clicked.connect(self.extract_selected)
        self.layout.addWidget(extract, alignment=Qt.AlignmentFlag.AlignLeft)
        self.tree = JsonTreeWidget()
        self.tree.set_data({key: value for key, value in result.sections.items() if key.startswith("Office") or key.startswith("PDF") or key.startswith("RTF")})
        self.layout.addWidget(self.tree, 1)
        self.embedded = DataTableWidget()
        self.embedded.set_rows(result.sections.get("Office embedded objects", []))
        self.layout.addWidget(self.embedded, 1)

    def extract_selected(self) -> None:
        rows = self.embedded.selected_row_dicts()
        if not rows:
            QMessageBox.information(self, "Select an object", "Select an embedded object first.")
            return
        name = rows[0].get("name", "")
        if not name or not zipfile.is_zipfile(self.result.path):
            return
        destination, _ = QFileDialog.getSaveFileName(self, "Extract embedded object", Path(name).name, "All files (*)")
        if not destination:
            return
        try:
            with zipfile.ZipFile(self.result.path) as archive:
                Path(destination).write_bytes(archive.read(name))
        except Exception as exc:
            QMessageBox.critical(self, "Extraction failed", str(exc))


class SQLitePage(PageShell):
    def __init__(self, result: AnalysisResult) -> None:
        super().__init__("SQLite", "Schemas, table previews, read-only queries, and CSV export.")
        self.result = result
        controls = QHBoxLayout()
        self.table_choice = QComboBox()
        previews = result.sections.get("SQLite tables", {})
        if isinstance(previews, dict):
            self.table_choice.addItems(sorted(previews))
        self.query = QLineEdit()
        self.query.setPlaceholderText("SELECT * FROM table LIMIT 200")
        self.presets = QComboBox()
        self.presets.addItems(["Query presets…", "List database objects", "Show newest rows by rowid", "Android artifact discovery"])
        self.presets.currentTextChanged.connect(self.apply_preset)
        run = QPushButton("Run read-only query")
        run.clicked.connect(self.run_query)
        export = QPushButton("Export visible rows CSV")
        export.clicked.connect(self.export_visible_csv)
        controls.addWidget(self.table_choice)
        controls.addWidget(self.presets)
        controls.addWidget(self.query, 1)
        controls.addWidget(run)
        controls.addWidget(export)
        self.layout.addLayout(controls)
        self.schema = JsonTreeWidget()
        self.schema.set_data(result.sections.get("SQLite schema", []))
        self.table = DataTableWidget()
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(self.schema)
        splitter.addWidget(self.table)
        splitter.setSizes([250, 500])
        self.layout.addWidget(splitter, 1)
        self.table_choice.currentTextChanged.connect(self.show_table)
        if self.table_choice.count():
            self.show_table(self.table_choice.currentText())

    def show_table(self, name: str) -> None:
        previews = self.result.sections.get("SQLite tables", {})
        if isinstance(previews, dict):
            self.table.set_rows(previews.get(name, {}).get("rows", []))


    def apply_preset(self, value: str) -> None:
        if value == "List database objects":
            self.query.setText("SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name LIMIT 5000")
        elif value == "Show newest rows by rowid":
            name = self.table_choice.currentText().replace('"', '""')
            if name:
                self.query.setText(f'SELECT rowid, * FROM "{name}" ORDER BY rowid DESC LIMIT 200')
        elif value == "Android artifact discovery":
            self.table.set_rows(self.result.sections.get("Android database indicators", []))

    def export_visible_csv(self) -> None:
        destination, _ = QFileDialog.getSaveFileName(self, "Export SQLite rows", f"{self.result.path.stem}_rows.csv", "CSV files (*.csv)")
        if not destination:
            return
        if not destination.lower().endswith(".csv"):
            destination += ".csv"
        try:
            with Path(destination).open("w", newline="", encoding="utf-8-sig") as handle:
                writer = csv.writer(handle)
                headers = [self.table.horizontalHeaderItem(index).text() if self.table.horizontalHeaderItem(index) else str(index) for index in range(self.table.columnCount())]
                writer.writerow(headers)
                for row in range(self.table.rowCount()):
                    if self.table.isRowHidden(row):
                        continue
                    writer.writerow([self.table.item(row, column).text() if self.table.item(row, column) else "" for column in range(self.table.columnCount())])
            QMessageBox.information(self, "CSV exported", f"Saved to:\n{destination}")
        except Exception as exc:
            QMessageBox.critical(self, "Export failed", str(exc))

    def run_query(self) -> None:
        sql = self.query.text().strip()
        if not sql:
            return
        first = sql.split(None, 1)[0].upper() if sql.split() else ""
        if first not in {"SELECT", "WITH", "PRAGMA", "EXPLAIN"}:
            QMessageBox.warning(self, "Read-only queries only", "Only SELECT, WITH, PRAGMA, or EXPLAIN statements are allowed.")
            return
        try:
            connection = sqlite3.connect(f"file:{self.result.path.as_posix()}?mode=ro", uri=True)
            connection.row_factory = sqlite3.Row
            try:
                cursor = connection.execute(sql)
                columns = [item[0] for item in cursor.description] if cursor.description else []
                rows = [dict(zip(columns, row)) for row in cursor.fetchmany(5000)]
            finally:
                connection.close()
            self.table.set_rows(rows)
        except Exception as exc:
            QMessageBox.critical(self, "Query failed", str(exc))


class YaraPage(PageShell):
    def __init__(self, result: AnalysisResult, starter_rules: Path) -> None:
        super().__init__("YARA", "Local YARA-X scanning with bundled or custom rules.")
        self.result = result
        self.starter_rules = starter_rules
        controls = QHBoxLayout()
        self.rule_path = QLineEdit(str(starter_rules))
        browse = QPushButton("Browse rules")
        browse.clicked.connect(self.browse)
        validate = QPushButton("Validate")
        validate.clicked.connect(self.validate)
        scan = QPushButton("Scan file")
        scan.setObjectName("accentButton")
        scan.clicked.connect(self.scan)
        controls.addWidget(self.rule_path, 1)
        controls.addWidget(browse)
        controls.addWidget(validate)
        controls.addWidget(scan)
        self.layout.addLayout(controls)
        self.status = QLabel("Ready")
        self.status.setObjectName("pageSubtitle")
        self.layout.addWidget(self.status)
        self.tree = JsonTreeWidget()
        self.layout.addWidget(self.tree, 1)

    def browse(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select YARA rule file", str(self.starter_rules.parent), "YARA rules (*.yar *.yara);;All files (*)")
        if path:
            self.rule_path.setText(path)

    def validate(self) -> None:
        ok, message = validate_yara_rule(self.rule_path.text())
        self.status.setText(message)
        if not ok:
            QMessageBox.warning(self, "YARA validation", message)

    def scan(self) -> None:
        self.status.setText("Scanning…")
        worker = FunctionWorker(scan_with_yara, self.result.path, self.rule_path.text())
        worker.signals.result.connect(self._display)
        worker.signals.error.connect(lambda error: QMessageBox.critical(self, "YARA scan failed", error))
        QThreadPool.globalInstance().start(worker)

    def _display(self, value: dict[str, Any]) -> None:
        self.tree.set_data(value)
        engine = value.get("engine", "YARA")
        error = str(value.get("error", "")).strip()
        if not value.get("available"):
            self.status.setText(error or f"{engine} unavailable")
        elif error:
            self.status.setText(f"{engine}: {error}")
        else:
            self.status.setText(f"{engine} completed with {len(value.get('matches', []))} match(es).")


class FolderScanPage(PageShell):
    def __init__(self) -> None:
        super().__init__("Folder Scan", "Recursive, cancelable folder analysis with sortable results.")
        controls = QHBoxLayout()
        self.folder = QLineEdit()
        self.folder.setPlaceholderText("Choose a folder…")
        browse = QPushButton("Browse")
        browse.clicked.connect(self.browse)
        self.recursive = QCheckBox("Recursive")
        self.recursive.setChecked(True)
        self.max_files = QSpinBox()
        self.max_files.setRange(1, 250000)
        self.max_files.setValue(25000)
        scan = QPushButton("Start scan")
        scan.setObjectName("accentButton")
        scan.clicked.connect(self.scan)
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(self.cancel_scan)
        self._cancel_event: threading.Event | None = None
        controls.addWidget(self.folder, 1)
        controls.addWidget(browse)
        controls.addWidget(self.recursive)
        controls.addWidget(QLabel("Max files"))
        controls.addWidget(self.max_files)
        controls.addWidget(scan)
        controls.addWidget(self.cancel_button)
        self.layout.addLayout(controls)
        self.status = QLabel("Ready")
        self.layout.addWidget(self.status)
        self.table = DataTableWidget()
        self.layout.addWidget(self.table, 1)

    def browse(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Choose folder to scan")
        if path:
            self.folder.setText(path)

    def scan(self) -> None:
        if not Path(self.folder.text()).is_dir():
            QMessageBox.warning(self, "Select a folder", "Choose a valid folder first.")
            return
        self.status.setText("Scanning folder…")
        self._cancel_event = threading.Event()
        self.cancel_button.setEnabled(True)
        worker = FunctionWorker(scan_folder, self.folder.text(), recursive=self.recursive.isChecked(), max_files=self.max_files.value(), cancel_event=self._cancel_event)
        worker.signals.result.connect(self._display)
        worker.signals.error.connect(lambda error: QMessageBox.critical(self, "Folder scan failed", error))
        worker.signals.finished.connect(lambda: self.cancel_button.setEnabled(False))
        QThreadPool.globalInstance().start(worker)

    def cancel_scan(self) -> None:
        if self._cancel_event is not None:
            self._cancel_event.set()
            self.status.setText("Canceling after the active file analyses finish…")
            self.cancel_button.setEnabled(False)

    def _display(self, rows: list[dict[str, Any]]) -> None:
        self.table.set_rows(rows, max_rows=250000)
        canceled = self._cancel_event is not None and self._cancel_event.is_set()
        self.status.setText(("Canceled" if canceled else "Completed") + f": {len(rows):,} file(s) analyzed.")


class ComparePage(PageShell):
    def __init__(self, current_path: Path) -> None:
        super().__init__("Compare", "Compare hashes, metadata, archive entries, permissions, indicators, and imports.")
        controls = QHBoxLayout()
        self.left = QLineEdit(str(current_path))
        self.right = QLineEdit()
        choose_left = QPushButton("Left…")
        choose_left.clicked.connect(lambda: self.choose(self.left))
        choose_right = QPushButton("Right…")
        choose_right.clicked.connect(lambda: self.choose(self.right))
        compare = QPushButton("Compare files")
        compare.setObjectName("accentButton")
        compare.clicked.connect(self.compare)
        controls.addWidget(QLabel("Left"))
        controls.addWidget(self.left, 1)
        controls.addWidget(choose_left)
        controls.addWidget(QLabel("Right"))
        controls.addWidget(self.right, 1)
        controls.addWidget(choose_right)
        controls.addWidget(compare)
        self.layout.addLayout(controls)
        self.status = QLabel("Ready")
        self.layout.addWidget(self.status)
        self.tree = JsonTreeWidget()
        self.layout.addWidget(self.tree, 1)

    def choose(self, field: QLineEdit) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Choose file")
        if path:
            field.setText(path)

    def compare(self) -> None:
        if not Path(self.left.text()).is_file() or not Path(self.right.text()).is_file():
            QMessageBox.warning(self, "Choose two files", "Both paths must point to existing files.")
            return
        self.status.setText("Analyzing and comparing both files…")
        worker = FunctionWorker(compare_files, self.left.text(), self.right.text())
        worker.signals.result.connect(self._display)
        worker.signals.error.connect(lambda error: QMessageBox.critical(self, "Comparison failed", error))
        QThreadPool.globalInstance().start(worker)

    def _display(self, value: dict[str, Any]) -> None:
        self.tree.set_data(value)
        self.status.setText("Comparison complete.")


class GlobalSearchPage(PageShell):
    def __init__(self, result: AnalysisResult) -> None:
        super().__init__("Global Search", "Search all parsed data for the current file.")
        self.result = result
        controls = QHBoxLayout()
        self.query = QLineEdit()
        self.query.setPlaceholderText("Search all parsed data…")
        search = QPushButton("Search")
        search.setObjectName("accentButton")
        search.clicked.connect(self.run_search)
        controls.addWidget(self.query, 1)
        controls.addWidget(search)
        self.layout.addLayout(controls)
        self.table = DataTableWidget()
        self.layout.addWidget(self.table, 1)
        self.query.returnPressed.connect(self.run_search)

    def run_search(self) -> None:
        self.table.set_rows(search_result(self.result, self.query.text()))


class ReportPage(PageShell):
    def __init__(self, result: AnalysisResult) -> None:
        super().__init__("Reports", "Export HTML, JSON, CSV, or text reports.")
        self.result = result
        buttons = QHBoxLayout()
        for label, suffix, filter_text in (
            ("Export HTML", ".html", "HTML report (*.html)"),
            ("Export JSON", ".json", "JSON report (*.json)"),
            ("Export CSV", ".csv", "CSV report (*.csv)"),
            ("Export Text", ".txt", "Text report (*.txt)"),
        ):
            button = QPushButton(label)
            button.clicked.connect(lambda checked=False, s=suffix, f=filter_text: self.export(s, f))
            buttons.addWidget(button)
        buttons.addStretch(1)
        self.layout.addLayout(buttons)
        preview = QPlainTextEdit()
        preview.setReadOnly(True)
        preview.setPlainText(json.dumps({
            "file": str(result.path),
            "type": result.detected_type,
            "risk_score": result.risk_score,
            "risk_level": result.risk_label,
            "findings": [item.title for item in result.findings],
            "metadata_sections": sorted(result.metadata),
            "analysis_sections": sorted(result.sections),
        }, indent=2))
        self.layout.addWidget(preview, 1)

    def export(self, suffix: str, filter_text: str) -> None:
        destination, _ = QFileDialog.getSaveFileName(self, "Export FileScope report", str(self.result.path.with_suffix(self.result.path.suffix + ".filescope" + suffix)), filter_text)
        if not destination:
            return
        if not destination.lower().endswith(suffix):
            destination += suffix
        try:
            export_report(self.result, destination)
            QMessageBox.information(self, "Report exported", f"Saved to:\n{destination}")
        except Exception as exc:
            QMessageBox.critical(self, "Export failed", str(exc))


class SettingsAboutPage(PageShell):
    theme_requested = Signal(str)

    def __init__(self, settings: QSettings) -> None:
        super().__init__("Settings & About", "Appearance, analysis limits, privacy behavior, and keyboard shortcuts.")
        self.settings = settings
        appearance = QGroupBox("Appearance")
        form = QFormLayout(appearance)
        self.theme = QComboBox()
        self.theme.addItems(["Dark", "Light"])
        current = str(settings.value("appearance/theme", "Dark"))
        self.theme.setCurrentText(current if current in {"Dark", "Light"} else "Dark")
        form.addRow("Theme", self.theme)
        self.layout.addWidget(appearance)

        analysis = QGroupBox("Analysis limits")
        analysis_form = QFormLayout(analysis)
        self.string_scan = QSpinBox()
        self.string_scan.setRange(1, 2048)
        self.string_scan.setSuffix(" MB")
        self.string_scan.setValue(int(settings.value("analysis/string_scan_mb", 64)))
        self.preview = QSpinBox()
        self.preview.setRange(1, 64)
        self.preview.setSuffix(" MB")
        self.preview.setValue(int(settings.value("analysis/preview_mb", 1)))
        analysis_form.addRow("String scan limit", self.string_scan)
        analysis_form.addRow("Hex/text preview", self.preview)
        self.layout.addWidget(analysis)

        privacy = QFrame()
        privacy.setObjectName("card")
        privacy_layout = QVBoxLayout(privacy)
        privacy_layout.addWidget(QLabel("Privacy"))
        privacy_text = QLabel("FileScope parses files locally. EXIF GPS coordinates are decoded and plotted against the bundled offline map database without contacting a geocoding service. Reputation buttons open a browser with the SHA-256 hash only; the application never uploads a file automatically.")
        privacy_text.setWordWrap(True)
        privacy_layout.addWidget(privacy_text)
        self.layout.addWidget(privacy)

        about = QFrame()
        about.setObjectName("card")
        about_layout = QFormLayout(about)
        about_layout.addRow("Application", QLabel("FileScope for Windows"))
        about_layout.addRow("Workspaces", QLabel("29 file-analysis workspaces"))
        about_layout.addRow("Security engine", QLabel("YARA-X with bundled and custom rules"))
        about_layout.addRow("GPS mapping", QLabel("Offline Natural Earth country map; no automatic network lookup"))
        about_layout.addRow("Shortcuts", QLabel("Ctrl+O open · Ctrl+Shift+O folder · Ctrl+E export · Ctrl+F global search · F5 rescan"))
        self.layout.addWidget(about)
        save = QPushButton("Save settings")
        save.setObjectName("accentButton")
        save.clicked.connect(self.save)
        self.layout.addWidget(save, alignment=Qt.AlignmentFlag.AlignLeft)
        self.layout.addStretch(1)

    def save(self) -> None:
        self.settings.setValue("appearance/theme", self.theme.currentText())
        self.settings.setValue("analysis/string_scan_mb", self.string_scan.value())
        self.settings.setValue("analysis/preview_mb", self.preview.value())
        self.settings.sync()
        self.theme_requested.emit(self.theme.currentText())
