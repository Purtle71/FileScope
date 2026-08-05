from __future__ import annotations

import binascii
import struct
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QTextCursor
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QProgressDialog,
    QPushButton,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from filescope.core.models import AnalysisResult
from filescope.core.utils import human_size, iter_hex_dump, make_hex_dump

from .widgets import PageShell


class HexPage(PageShell):
    PREVIEW_SIZE = 1024 * 1024
    WINDOW_SIZE = 256 * 1024

    def __init__(self, result: AnalysisResult, preview: str) -> None:
        super().__init__("Hex", "Offset navigation, search, bookmarks, data interpretation, full copy, and export.")
        self.result = result
        self.path = result.path
        self.current_offset = 0
        self._last_search_offset = 0
        self._bookmarks: list[int] = []
        self._landmarks = self._build_landmarks(result)

        first_row = QHBoxLayout()
        self.offset = QLineEdit("0")
        self.offset.setPlaceholderText("Offset, for example 0x1000")
        self.offset.setMaximumWidth(180)
        go = QPushButton("Go to offset")
        go.clicked.connect(self.go_to_offset)
        add_bookmark = QPushButton("Add bookmark")
        add_bookmark.clicked.connect(self.add_bookmark)
        self.bookmark_choice = QComboBox()
        self.bookmark_choice.setMinimumWidth(180)
        self.bookmark_choice.addItem("Bookmarks…", -1)
        self.bookmark_choice.currentIndexChanged.connect(self.jump_bookmark)
        self.landmark_choice = QComboBox()
        self.landmark_choice.setMinimumWidth(260)
        self.landmark_choice.addItem("Parsed structures…", -1)
        for label, offset, size in self._landmarks:
            self.landmark_choice.addItem(f"{label} — 0x{offset:X} ({human_size(size)})", offset)
        self.landmark_choice.currentIndexChanged.connect(self.jump_landmark)
        first_row.addWidget(QLabel("Offset"))
        first_row.addWidget(self.offset)
        first_row.addWidget(go)
        first_row.addWidget(add_bookmark)
        first_row.addWidget(self.bookmark_choice)
        first_row.addWidget(self.landmark_choice, 1)
        self.layout.addLayout(first_row)

        second_row = QHBoxLayout()
        self.search_mode = QComboBox()
        self.search_mode.addItems(["Text", "Hex bytes"])
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search value…")
        find = QPushButton("Find next")
        find.clicked.connect(self.find_next)
        copy_selection = QPushButton("Copy Selection")
        copy_selection.clicked.connect(self.copy_selection)
        copy_preview = QPushButton("Copy Preview")
        copy_preview.clicked.connect(lambda: QApplication.clipboard().setText(self.editor.toPlainText()))
        export_all = QPushButton("Export All Hex")
        export_all.clicked.connect(self.export_all_hex)
        copy_all = QPushButton("Copy All Hex")
        copy_all.setObjectName("accentButton")
        copy_all.clicked.connect(self.copy_all_hex)
        second_row.addWidget(self.search_mode)
        second_row.addWidget(self.search, 1)
        second_row.addWidget(find)
        second_row.addWidget(copy_selection)
        second_row.addWidget(copy_preview)
        second_row.addWidget(export_all)
        second_row.addWidget(copy_all)
        self.layout.addLayout(second_row)

        self.info = QLabel(f"Previewing the first {human_size(min(self.path.stat().st_size, self.PREVIEW_SIZE))} of {human_size(self.path.stat().st_size)}.")
        self.info.setObjectName("pageSubtitle")
        self.layout.addWidget(self.info)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        self.editor = QPlainTextEdit()
        self.editor.setReadOnly(True)
        self.editor.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.editor.setFont(QFont("Consolas", 9))
        self.editor.setPlainText(preview)
        splitter.addWidget(self.editor)

        interpretation_panel = QWidget()
        panel_layout = QVBoxLayout(interpretation_panel)
        panel_layout.setContentsMargins(10, 4, 0, 4)
        title = QLabel("Data interpretation")
        title.setStyleSheet("font-weight:700")
        panel_layout.addWidget(title)
        self.interpretation = QGridLayout()
        self.interpretation_labels: dict[str, QLabel] = {}
        names = ["Bytes", "ASCII", "UInt8", "Int8", "UInt16 LE", "UInt16 BE", "UInt32 LE", "UInt32 BE", "UInt64 LE", "UInt64 BE", "Float32 LE", "Float64 LE"]
        for row, name in enumerate(names):
            self.interpretation.addWidget(QLabel(name), row, 0)
            value = QLabel("—")
            value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            value.setWordWrap(True)
            self.interpretation.addWidget(value, row, 1)
            self.interpretation_labels[name] = value
        panel_layout.addLayout(self.interpretation)
        panel_layout.addStretch(1)
        splitter.addWidget(interpretation_panel)
        splitter.setSizes([1000, 320])
        self.layout.addWidget(splitter, 1)
        self._update_interpretation(0)

    def _build_landmarks(self, result: AnalysisResult) -> list[tuple[str, int, int]]:
        landmarks: list[tuple[str, int, int]] = []
        for row in result.sections.get("PE sections", []):
            if isinstance(row, dict):
                try:
                    landmarks.append((f"PE section {row.get('name', '')}", int(row.get("raw_offset", 0)), int(row.get("raw_size", 0))))
                except (TypeError, ValueError):
                    pass
        for row in result.sections.get("PE resources", []):
            if isinstance(row, dict):
                try:
                    offset = int(row.get("file_offset", -1))
                    if offset >= 0:
                        landmarks.append((f"PE resource {row.get('type', '')}/{row.get('id', '')}", offset, int(row.get("size", 0))))
                except (TypeError, ValueError):
                    pass
        overlay = result.sections.get("PE overlay")
        if isinstance(overlay, dict):
            try:
                landmarks.append(("PE overlay", int(overlay.get("file_offset", 0)), int(overlay.get("size", 0))))
            except (TypeError, ValueError):
                pass
        for row in result.sections.get("Archive entries", []):
            if isinstance(row, dict) and "local_header_offset" in row:
                try:
                    landmarks.append((f"Archive entry {row.get('name', '')}", int(row.get("local_header_offset", 0)), int(row.get("compressed", 0))))
                except (TypeError, ValueError):
                    pass
        unique: dict[tuple[str, int], tuple[str, int, int]] = {}
        for item in landmarks:
            if 0 <= item[1] < result.path.stat().st_size:
                unique[(item[0], item[1])] = item
        return sorted(unique.values(), key=lambda item: item[1])

    def go_to_offset(self) -> None:
        value = self.offset.text().strip()
        try:
            offset = int(value, 0)
        except ValueError:
            QMessageBox.warning(self, "Invalid offset", "Enter a decimal offset or a hexadecimal value beginning with 0x.")
            return
        size = self.path.stat().st_size
        if offset < 0 or offset >= max(1, size):
            QMessageBox.warning(self, "Offset outside file", f"The valid range is 0 through {max(0, size - 1):,}.")
            return
        with self.path.open("rb") as handle:
            handle.seek(offset)
            data = handle.read(self.WINDOW_SIZE)
        self.current_offset = offset
        self.editor.setPlainText(make_hex_dump(data, offset))
        self.info.setText(f"Showing {human_size(len(data))} beginning at offset 0x{offset:X} ({offset:,}).")
        self._last_search_offset = offset
        self._update_interpretation(offset)

    def _update_interpretation(self, offset: int) -> None:
        with self.path.open("rb") as handle:
            handle.seek(offset)
            data = handle.read(16)
        def unpack(fmt: str, length: int) -> str:
            if len(data) < length:
                return "—"
            try:
                return str(struct.unpack(fmt, data[:length])[0])
            except struct.error:
                return "—"
        self.interpretation_labels["Bytes"].setText(" ".join(f"{value:02X}" for value in data) or "—")
        self.interpretation_labels["ASCII"].setText("".join(chr(value) if 32 <= value <= 126 else "." for value in data) or "—")
        self.interpretation_labels["UInt8"].setText(unpack("<B", 1))
        self.interpretation_labels["Int8"].setText(unpack("<b", 1))
        self.interpretation_labels["UInt16 LE"].setText(unpack("<H", 2))
        self.interpretation_labels["UInt16 BE"].setText(unpack(">H", 2))
        self.interpretation_labels["UInt32 LE"].setText(unpack("<I", 4))
        self.interpretation_labels["UInt32 BE"].setText(unpack(">I", 4))
        self.interpretation_labels["UInt64 LE"].setText(unpack("<Q", 8))
        self.interpretation_labels["UInt64 BE"].setText(unpack(">Q", 8))
        self.interpretation_labels["Float32 LE"].setText(unpack("<f", 4))
        self.interpretation_labels["Float64 LE"].setText(unpack("<d", 8))

    def add_bookmark(self) -> None:
        if self.current_offset not in self._bookmarks:
            self._bookmarks.append(self.current_offset)
            self._bookmarks.sort()
            self.bookmark_choice.clear()
            self.bookmark_choice.addItem("Bookmarks…", -1)
            for offset in self._bookmarks:
                self.bookmark_choice.addItem(f"0x{offset:X} ({offset:,})", offset)

    def jump_bookmark(self, index: int) -> None:
        offset = self.bookmark_choice.itemData(index)
        if isinstance(offset, int) and offset >= 0:
            self.offset.setText(f"0x{offset:X}")
            self.go_to_offset()

    def jump_landmark(self, index: int) -> None:
        offset = self.landmark_choice.itemData(index)
        if isinstance(offset, int) and offset >= 0:
            self.offset.setText(f"0x{offset:X}")
            self.go_to_offset()

    def find_next(self) -> None:
        query = self.search.text()
        if not query:
            return
        try:
            needle = query.encode("utf-8") if self.search_mode.currentText() == "Text" else bytes.fromhex(query.replace("0x", "").replace(",", " "))
        except (ValueError, binascii.Error):
            QMessageBox.warning(self, "Invalid hex search", "Enter hexadecimal bytes such as: 4D 5A 90 00")
            return
        if not needle:
            return
        start = min(self.path.stat().st_size, self._last_search_offset + 1)
        found = self._find_bytes(needle, start)
        if found < 0 and start > 0:
            answer = QMessageBox.question(self, "Not found", "No later match was found. Search again from the beginning?")
            if answer == QMessageBox.StandardButton.Yes:
                found = self._find_bytes(needle, 0)
        if found < 0:
            QMessageBox.information(self, "Not found", "The pattern was not found in the file.")
            return
        self._last_search_offset = found
        self.offset.setText(f"0x{found:X}")
        self.go_to_offset()
        cursor = self.editor.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.Start)
        cursor.select(QTextCursor.SelectionType.LineUnderCursor)
        self.editor.setTextCursor(cursor)
        self.info.setText(self.info.text() + f" Match begins at 0x{found:X}.")

    def _find_bytes(self, needle: bytes, start: int) -> int:
        chunk_size = 4 * 1024 * 1024
        overlap = max(0, len(needle) - 1)
        with self.path.open("rb") as handle:
            handle.seek(start)
            absolute = start
            carry = b""
            while chunk := handle.read(chunk_size):
                data = carry + chunk
                index = data.find(needle)
                if index >= 0:
                    return absolute - len(carry) + index
                carry = data[-overlap:] if overlap else b""
                absolute += len(chunk)
        return -1

    def copy_selection(self) -> None:
        selected = self.editor.textCursor().selectedText().replace("\u2029", "\n")
        if selected:
            QApplication.clipboard().setText(selected)

    def export_all_hex(self) -> None:
        destination, _ = QFileDialog.getSaveFileName(self, "Export complete hex dump", str(self.path.with_suffix(self.path.suffix + ".hex.txt")), "Text files (*.txt);;All files (*)")
        if not destination:
            return
        size = self.path.stat().st_size
        progress = QProgressDialog("Writing the complete hex dump…", "Cancel", 0, max(1, size), self)
        progress.setWindowTitle("Export All Hex")
        progress.setWindowModality(Qt.WindowModality.WindowModal)
        progress.setMinimumDuration(0)
        processed = 0
        try:
            with Path(destination).open("w", encoding="utf-8", newline="\n") as output:
                first = True
                for text in iter_hex_dump(self.path):
                    if not first:
                        output.write("\n")
                    output.write(text)
                    first = False
                    processed = min(size, processed + 1024 * 1024)
                    progress.setValue(processed)
                    QApplication.processEvents()
                    if progress.wasCanceled():
                        output.close()
                        Path(destination).unlink(missing_ok=True)
                        self.info.setText("Hex export was canceled; the partial file was removed.")
                        return
            progress.setValue(size)
            self.info.setText(f"Exported the complete hex dump to {destination}.")
        except Exception as exc:
            QMessageBox.critical(self, "Export failed", str(exc))
        finally:
            progress.close()

    def copy_all_hex(self) -> None:
        size = self.path.stat().st_size
        estimated = size * 4.6
        message = (
            f"This will format and copy every byte in the file.\n\n"
            f"File size: {human_size(size)}\nEstimated clipboard text: {human_size(int(estimated))}\n\n"
            "Large clipboard operations can temporarily use substantial memory. Continue?"
        )
        if size > 16 * 1024 * 1024:
            if QMessageBox.warning(self, "Copy complete hex dump", message, QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
                return
        progress = QProgressDialog("Formatting the complete hex dump…", "Cancel", 0, max(1, size), self)
        progress.setWindowTitle("Copy All Hex")
        progress.setWindowModality(Qt.WindowModality.WindowModal)
        progress.setMinimumDuration(0)
        chunks: list[str] = []
        processed = 0
        try:
            for text in iter_hex_dump(self.path):
                chunks.append(text)
                processed = min(size, processed + 1024 * 1024)
                progress.setValue(processed)
                QApplication.processEvents()
                if progress.wasCanceled():
                    self.info.setText("Copy All Hex was canceled; the clipboard was not changed.")
                    return
            progress.setValue(size)
            QApplication.clipboard().setText("\n".join(chunks))
            self.info.setText(f"Copied the complete {human_size(size)} file as a formatted hex dump.")
        except MemoryError:
            QMessageBox.critical(self, "Not enough memory", "Windows could not allocate enough memory for the complete formatted hex dump. Use Export All Hex instead for very large files.")
        except Exception as exc:
            QMessageBox.critical(self, "Copy failed", str(exc))
        finally:
            progress.close()
