from __future__ import annotations

from pathlib import Path
from typing import Any

from PySide6.QtCore import QSettings, Qt, Signal
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QListWidget, QListWidgetItem, QStackedWidget, QVBoxLayout, QWidget

from filescope.core.models import AnalysisResult
from filescope.core.paths import resource_path

from .hex_page import HexPage
from .metadata_page import MetadataPage
from .pages import (
    AndroidPage,
    ArchivePage,
    ComparePage,
    DashboardPage,
    EntropyPage,
    FolderScanPage,
    GlobalSearchPage,
    IOCPage,
    NetworkPage,
    OfficePage,
    ReportPage,
    ResourcePage,
    SecurityPage,
    SettingsAboutPage,
    SignaturePage,
    SQLitePage,
    StringsPage,
    YaraPage,
)
from .widgets import GenericDataPage


from filescope.core.constants import WORKSPACE_NAMES



class AnalysisWorkspace(QWidget):
    theme_requested = Signal(str)

    def __init__(self, result: AnalysisResult, settings: QSettings) -> None:
        super().__init__()
        self.result = result
        self.settings = settings
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        header = QFrame()
        header.setObjectName("headerPanel")
        header_layout = QVBoxLayout(header)
        header_layout.setContentsMargins(20, 14, 20, 14)
        title = QLabel(result.path.name)
        title.setStyleSheet("font-size:16pt;font-weight:700")
        subtitle = QLabel(f"{result.detected_type}  •  {result.risk_score}/100 {result.risk_label} risk  •  {result.summary.get('SHA-256','')}")
        subtitle.setObjectName("pageSubtitle")
        subtitle.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        header_layout.addWidget(title)
        header_layout.addWidget(subtitle)
        root.addWidget(header)

        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)
        self.navigation = QListWidget()
        self.navigation.setObjectName("navigation")
        self.navigation.setFixedWidth(218)
        self.stack = QStackedWidget()
        body.addWidget(self.navigation)
        body.addWidget(self.stack, 1)
        body_widget = QWidget()
        body_widget.setLayout(body)
        root.addWidget(body_widget, 1)

        starter_rules = resource_path("rules", "starter_rules.yar")
        settings_page = SettingsAboutPage(settings)
        settings_page.theme_requested.connect(self.theme_requested)

        structure_data = result.sections.get("Structure", {
            key: value for key, value in result.sections.items()
            if key not in {"Hex preview", "Text preview", "Strings", "IOCs", "Entropy", "Security"}
        })

        pages: list[QWidget] = [
            DashboardPage(result),
            self._generic("Structure", "Parsed hierarchy and format-specific structures.", structure_data),
            MetadataPage(result),
            StringsPage(result),
            HexPage(result, str(result.sections.get("Hex preview", ""))),
            SecurityPage(result),
            EntropyPage(result),
            IOCPage(result),
            NetworkPage(result),
            SignaturePage(result),
            self._generic("PE Imports", "Imported DLLs and functions, including sensitive Windows APIs.", result.sections.get("PE imports", []), True),
            self._generic("PE Exports", "Exported names, ordinals, RVAs, and forwarders.", result.sections.get("PE exports", []), True),
            self._generic("PE Sections", "Section addresses, sizes, permissions, and entropy.", result.sections.get("PE sections", []), True),
            ResourcePage(result),
            self._generic("Packers", "Compiler, runtime, installer, and packer markers.", result.sections.get("Packers and compilers", []), True),
            ArchivePage(result),
            AndroidPage(result),
            self._generic("DEX", "DEX headers, class descriptors, method signatures, API presets, and indicators.", result.sections.get("DEX", [])),
            self._generic("Android Components", "Activities, services, receivers, providers, intent filters, permissions, and exported state.", result.sections.get("Android components", []), True),
            self._generic("Unity", "Unity version, scripting backend, managed assemblies, IL2CPP metadata, and asset-bundle inventory.", result.sections.get("Unity", {})),
            self._generic("SDKs & Trackers", "Detected analytics, advertising, crash reporting, attribution, and engagement SDK markers.", result.sections.get("SDKs and trackers", []), True),
            OfficePage(result),
            SQLitePage(result),
            YaraPage(result, starter_rules),
            FolderScanPage(),
            ComparePage(result.path),
            GlobalSearchPage(result),
            ReportPage(result),
            settings_page,
        ]

        if len(pages) != len(WORKSPACE_NAMES):
            raise RuntimeError(f"Workspace page count mismatch: {len(pages)} pages for {len(WORKSPACE_NAMES)} names")
        for name, page in zip(WORKSPACE_NAMES, pages):
            self.navigation.addItem(QListWidgetItem(name))
            self.stack.addWidget(page)
        self.navigation.currentRowChanged.connect(self.stack.setCurrentIndex)
        self.navigation.setCurrentRow(0)

    def _generic(self, title: str, subtitle: str, data: Any, table: bool = False) -> GenericDataPage:
        page = GenericDataPage(title, subtitle, table_mode=table)
        page.set_data(data)
        return page

    def show_page(self, name: str) -> None:
        try:
            index = WORKSPACE_NAMES.index(name)
        except ValueError:
            return
        self.navigation.setCurrentRow(index)


class LoadingWorkspace(QWidget):
    def __init__(self, path: Path) -> None:
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title = QLabel("Analyzing file")
        title.setObjectName("pageTitle")
        subtitle = QLabel(str(path))
        subtitle.setObjectName("pageSubtitle")
        subtitle.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        status = QLabel("Reading metadata, calculating hashes, extracting indicators, and running format parsers…")
        status.setWordWrap(True)
        layout.addStretch(1)
        layout.addWidget(title, alignment=Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(subtitle, alignment=Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(status, alignment=Qt.AlignmentFlag.AlignCenter)
        layout.addStretch(1)
