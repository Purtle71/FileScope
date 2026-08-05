from __future__ import annotations

from pathlib import Path
from typing import Any

from PySide6.QtCore import QSettings, QThreadPool, Qt
from PySide6.QtGui import QAction, QCloseEvent, QDragEnterEvent, QDropEvent, QIcon, QKeySequence
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QLabel,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPushButton,
    QTabWidget,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from filescope.core.analyzer import FileAnalyzer
from filescope.core.paths import resource_path

from .theme import DARK_QSS, LIGHT_QSS
from .workers import FunctionWorker
from .workspace import AnalysisWorkspace, LoadingWorkspace
from .pages import FolderScanPage


class WelcomePage(QWidget):
    open_file_requested = None
    open_folder_requested = None

    def __init__(self, open_file_callback: Any, open_folder_callback: Any) -> None:
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(80, 60, 80, 60)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        logo = QLabel("◈")
        logo.setStyleSheet("font-size:64pt;color:#15bedb;font-weight:800")
        title = QLabel("FileScope")
        title.setObjectName("pageTitle")
        subtitle = QLabel("Inspect files locally without executing or uploading them")
        subtitle.setObjectName("pageSubtitle")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        details = QLabel(
            "Open a file or scan a folder. FileScope reads supported formats locally and does not execute the selected file.\n\n"
            "External reputation actions open a browser with the SHA-256 hash only."
        )
        details.setWordWrap(True)
        details.setAlignment(Qt.AlignmentFlag.AlignCenter)
        open_file = QPushButton("Open a file")
        open_file.setObjectName("accentButton")
        open_file.setMinimumWidth(220)
        open_file.clicked.connect(open_file_callback)
        open_folder = QPushButton("Open folder scan")
        open_folder.setMinimumWidth(220)
        open_folder.clicked.connect(open_folder_callback)
        layout.addStretch(1)
        layout.addWidget(logo, alignment=Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title, alignment=Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(subtitle, alignment=Qt.AlignmentFlag.AlignCenter)
        layout.addSpacing(18)
        layout.addWidget(details)
        layout.addSpacing(22)
        layout.addWidget(open_file, alignment=Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(open_folder, alignment=Qt.AlignmentFlag.AlignCenter)
        layout.addStretch(1)


class MainWindow(QMainWindow):
    def __init__(self, initial_path: str | None = None) -> None:
        super().__init__()
        self.settings = QSettings("FileScope", "FileScope")
        self.thread_pool = QThreadPool.globalInstance()
        self._workers: set[FunctionWorker] = set()
        self._closed_paths: list[Path] = []
        self.setWindowTitle("FileScope — Windows File Analysis")
        self.resize(1480, 920)
        self.setMinimumSize(1080, 700)
        saved_geometry = self.settings.value("window/geometry")
        if saved_geometry is not None:
            self.restoreGeometry(saved_geometry)
        self.setAcceptDrops(True)
        icon_path = resource_path("assets", "filescope.ico")
        if icon_path.exists():
            self.setWindowIcon(QIcon(str(icon_path)))
        self._build_actions()
        self._build_menu()
        self._build_toolbar()
        self.tabs = QTabWidget()
        self.tabs.setTabsClosable(True)
        self.tabs.setMovable(True)
        self.tabs.tabCloseRequested.connect(self.close_tab)
        self.setCentralWidget(self.tabs)
        self.statusBar().showMessage("Ready")
        self.apply_theme(str(self.settings.value("appearance/theme", "Dark")))
        self._show_welcome()
        if initial_path:
            self.open_path(Path(initial_path))

    def _build_actions(self) -> None:
        self.open_action = QAction("Open file…", self)
        self.open_action.setShortcut(QKeySequence.StandardKey.Open)
        self.open_action.triggered.connect(self.open_dialog)
        self.folder_action = QAction("Folder scan…", self)
        self.folder_action.setShortcut(QKeySequence("Ctrl+Shift+O"))
        self.folder_action.triggered.connect(self.open_folder_scan)
        self.export_action = QAction("Export report…", self)
        self.export_action.setShortcut(QKeySequence("Ctrl+E"))
        self.export_action.triggered.connect(lambda: self.show_current_page("Reports"))
        self.search_action = QAction("Global search", self)
        self.search_action.setShortcut(QKeySequence.StandardKey.Find)
        self.search_action.triggered.connect(lambda: self.show_current_page("Global Search"))
        self.refresh_action = QAction("Rescan", self)
        self.refresh_action.setShortcut(QKeySequence.Refresh)
        self.refresh_action.triggered.connect(self.refresh_current)
        self.close_action = QAction("Close tab", self)
        self.close_action.setShortcut(QKeySequence.StandardKey.Close)
        self.close_action.triggered.connect(lambda: self.close_tab(self.tabs.currentIndex()))
        self.reopen_action = QAction("Reopen last closed file", self)
        self.reopen_action.setShortcut(QKeySequence("Ctrl+Shift+T"))
        self.reopen_action.triggered.connect(self.reopen_last_closed)
        self.clear_workspace_action = QAction("Clear workspace", self)
        self.clear_workspace_action.triggered.connect(self.clear_workspace)
        self.exit_action = QAction("Exit", self)
        self.exit_action.triggered.connect(self.close)

    def _build_menu(self) -> None:
        file_menu = self.menuBar().addMenu("File")
        file_menu.addAction(self.open_action)
        file_menu.addAction(self.folder_action)
        self.recent_menu = QMenu("Recent files", self)
        file_menu.addMenu(self.recent_menu)
        file_menu.addSeparator()
        file_menu.addAction(self.export_action)
        file_menu.addAction(self.close_action)
        file_menu.addAction(self.reopen_action)
        file_menu.addAction(self.clear_workspace_action)
        file_menu.addSeparator()
        file_menu.addAction(self.exit_action)
        analysis_menu = self.menuBar().addMenu("Analysis")
        analysis_menu.addAction(self.refresh_action)
        analysis_menu.addAction(self.search_action)
        for page in ("Security", "Entropy", "Indicators", "Hex", "YARA", "Compare"):
            action = QAction(page, self)
            action.triggered.connect(lambda checked=False, p=page: self.show_current_page(p))
            analysis_menu.addAction(action)
        help_menu = self.menuBar().addMenu("Help")
        about = QAction("Settings & About", self)
        about.triggered.connect(lambda: self.show_current_page("Settings & About"))
        help_menu.addAction(about)
        self._update_recent_menu()

    def _build_toolbar(self) -> None:
        toolbar = QToolBar("Main")
        toolbar.setMovable(False)
        toolbar.addAction(self.open_action)
        toolbar.addAction(self.folder_action)
        toolbar.addSeparator()
        toolbar.addAction(self.refresh_action)
        toolbar.addAction(self.search_action)
        toolbar.addAction(self.export_action)
        self.addToolBar(toolbar)

    def _show_welcome(self) -> None:
        if self.tabs.count() == 0:
            self.tabs.addTab(WelcomePage(self.open_dialog, self.open_folder_scan), "Welcome")
            self.tabs.tabBar().setTabButton(0, self.tabs.tabBar().ButtonPosition.RightSide, None)

    def open_dialog(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Open file for analysis")
        if path:
            self.open_path(Path(path))

    def open_path(self, path: Path) -> None:
        path = path.expanduser().resolve()
        if not path.is_file():
            QMessageBox.warning(self, "File not found", f"The selected path is not a file:\n{path}")
            return
        for index in range(self.tabs.count()):
            workspace = self.tabs.widget(index)
            if isinstance(workspace, AnalysisWorkspace) and workspace.result.path == path:
                self.tabs.setCurrentIndex(index)
                return
        if self.tabs.count() == 1 and isinstance(self.tabs.widget(0), WelcomePage):
            self.tabs.removeTab(0)
        loading = LoadingWorkspace(path)
        tab_index = self.tabs.addTab(loading, f"{path.name} — scanning")
        self.tabs.setCurrentIndex(tab_index)
        self.statusBar().showMessage(f"Analyzing {path.name}…")
        preview_mb = int(self.settings.value("analysis/preview_mb", 1))
        string_mb = int(self.settings.value("analysis/string_scan_mb", 64))
        analyzer = FileAnalyzer(preview_bytes=preview_mb * 1024 * 1024, string_scan_bytes=string_mb * 1024 * 1024)
        worker = FunctionWorker(analyzer.analyze, path)
        self._workers.add(worker)
        worker.signals.result.connect(lambda result, index=tab_index, p=path: self._analysis_finished(index, p, result))
        worker.signals.error.connect(lambda error, index=tab_index, p=path: self._analysis_failed(index, p, error))
        worker.signals.finished.connect(lambda w=worker: self._workers.discard(w))
        self.thread_pool.start(worker)

    def _analysis_finished(self, index: int, path: Path, result: Any) -> None:
        if index >= self.tabs.count() or not isinstance(self.tabs.widget(index), LoadingWorkspace):
            for candidate in range(self.tabs.count()):
                if isinstance(self.tabs.widget(candidate), LoadingWorkspace):
                    index = candidate
                    break
            else:
                return
        workspace = AnalysisWorkspace(result, self.settings)
        workspace.theme_requested.connect(self.apply_theme)
        old = self.tabs.widget(index)
        self.tabs.removeTab(index)
        old.deleteLater()
        self.tabs.insertTab(index, workspace, path.name)
        self.tabs.setCurrentIndex(index)
        self.statusBar().showMessage(f"Analysis complete — {result.risk_score}/100 {result.risk_label} risk", 10000)
        self._add_recent(path)

    def _analysis_failed(self, index: int, path: Path, error: str) -> None:
        if 0 <= index < self.tabs.count():
            self.tabs.setTabText(index, f"{path.name} — failed")
        self.statusBar().showMessage("Analysis failed")
        QMessageBox.critical(self, "File analysis failed", error)

    def open_folder_scan(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Choose folder to scan")
        if not folder:
            return
        workspace = self.current_workspace()
        if workspace is not None:
            workspace.show_page("Folder Scan")
            page = workspace.stack.currentWidget()
            if hasattr(page, "folder"):
                page.folder.setText(folder)
            return
        if self.tabs.count() == 1 and isinstance(self.tabs.widget(0), WelcomePage):
            self.tabs.removeTab(0)
        page = FolderScanPage()
        page.folder.setText(folder)
        index = self.tabs.addTab(page, "Folder Scan")
        self.tabs.setCurrentIndex(index)

    def refresh_current(self) -> None:
        workspace = self.current_workspace()
        if workspace is None:
            return
        path = workspace.result.path
        index = self.tabs.currentIndex()
        old = self.tabs.widget(index)
        loading = LoadingWorkspace(path)
        self.tabs.removeTab(index)
        old.deleteLater()
        self.tabs.insertTab(index, loading, f"{path.name} — scanning")
        self.tabs.setCurrentIndex(index)
        preview_mb = int(self.settings.value("analysis/preview_mb", 1))
        string_mb = int(self.settings.value("analysis/string_scan_mb", 64))
        analyzer = FileAnalyzer(preview_bytes=preview_mb * 1024 * 1024, string_scan_bytes=string_mb * 1024 * 1024)
        worker = FunctionWorker(analyzer.analyze, path)
        self._workers.add(worker)
        worker.signals.result.connect(lambda result, i=index, p=path: self._analysis_finished(i, p, result))
        worker.signals.error.connect(lambda error, i=index, p=path: self._analysis_failed(i, p, error))
        worker.signals.finished.connect(lambda w=worker: self._workers.discard(w))
        self.thread_pool.start(worker)

    def current_workspace(self) -> AnalysisWorkspace | None:
        widget = self.tabs.currentWidget()
        return widget if isinstance(widget, AnalysisWorkspace) else None

    def show_current_page(self, name: str) -> None:
        workspace = self.current_workspace()
        if workspace:
            workspace.show_page(name)

    def close_tab(self, index: int) -> None:
        if index < 0 or index >= self.tabs.count():
            return
        widget = self.tabs.widget(index)
        if isinstance(widget, AnalysisWorkspace):
            self._closed_paths.append(widget.result.path)
            self._closed_paths = self._closed_paths[-20:]
        self.tabs.removeTab(index)
        widget.deleteLater()
        self._show_welcome()

    def reopen_last_closed(self) -> None:
        while self._closed_paths:
            path = self._closed_paths.pop()
            if path.is_file():
                self.open_path(path)
                return
        recent = self._recent_paths()
        if recent and Path(recent[0]).is_file():
            self.open_path(Path(recent[0]))

    def clear_workspace(self) -> None:
        for index in range(self.tabs.count() - 1, -1, -1):
            widget = self.tabs.widget(index)
            if isinstance(widget, AnalysisWorkspace):
                self._closed_paths.append(widget.result.path)
            self.tabs.removeTab(index)
            widget.deleteLater()
        self._show_welcome()

    def closeEvent(self, event: QCloseEvent) -> None:
        self.settings.setValue("window/geometry", self.saveGeometry())
        self.settings.sync()
        super().closeEvent(event)

    def apply_theme(self, theme: str) -> None:
        QApplication.instance().setStyleSheet(LIGHT_QSS if theme == "Light" else DARK_QSS)
        self.settings.setValue("appearance/theme", theme)

    def _recent_paths(self) -> list[str]:
        value = self.settings.value("recent/files", [])
        if isinstance(value, str):
            return [value]
        return [str(item) for item in value]

    def _add_recent(self, path: Path) -> None:
        paths = [str(path)] + [item for item in self._recent_paths() if item != str(path) and Path(item).exists()]
        self.settings.setValue("recent/files", paths[:12])
        self._update_recent_menu()

    def _update_recent_menu(self) -> None:
        if not hasattr(self, "recent_menu"):
            return
        self.recent_menu.clear()
        paths = self._recent_paths()
        if not paths:
            disabled = QAction("No recent files", self)
            disabled.setEnabled(False)
            self.recent_menu.addAction(disabled)
            return
        for path in paths:
            action = QAction(path, self)
            action.triggered.connect(lambda checked=False, p=path: self.open_path(Path(p)))
            self.recent_menu.addAction(action)
        self.recent_menu.addSeparator()
        clear = QAction("Clear recent files", self)
        clear.triggered.connect(self._clear_recent)
        self.recent_menu.addAction(clear)

    def _clear_recent(self) -> None:
        self.settings.remove("recent/files")
        self._update_recent_menu()

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        if event.mimeData().hasUrls() and any(url.isLocalFile() for url in event.mimeData().urls()):
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent) -> None:
        for url in event.mimeData().urls():
            if not url.isLocalFile():
                continue
            path = Path(url.toLocalFile())
            if path.is_file():
                self.open_path(path)
            elif path.is_dir():
                workspace = self.current_workspace()
                if workspace:
                    workspace.show_page("Folder Scan")
                    page = workspace.stack.currentWidget()
                    if hasattr(page, "folder"):
                        page.folder.setText(str(path))
        event.acceptProposedAction()
