from __future__ import annotations

import json
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QHeaderView,
    QLabel,
    QLineEdit,
    QTableWidget,
    QTableWidgetItem,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)


class PageShell(QWidget):
    def __init__(self, title: str, subtitle: str = "") -> None:
        super().__init__()
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(22, 18, 22, 20)
        self.layout.setSpacing(12)
        title_label = QLabel(title)
        title_label.setObjectName("pageTitle")
        self.layout.addWidget(title_label)
        if subtitle:
            subtitle_label = QLabel(subtitle)
            subtitle_label.setObjectName("pageSubtitle")
            subtitle_label.setWordWrap(True)
            self.layout.addWidget(subtitle_label)


class MetricCard(QFrame):
    def __init__(self, label: str, value: str) -> None:
        super().__init__()
        self.setObjectName("card")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        self.value_label = QLabel(value)
        self.value_label.setObjectName("metricValue")
        self.value_label.setWordWrap(True)
        label_widget = QLabel(label)
        label_widget.setObjectName("metricLabel")
        layout.addWidget(self.value_label)
        layout.addWidget(label_widget)


class JsonTreeWidget(QTreeWidget):
    def __init__(self) -> None:
        super().__init__()
        self.setHeaderLabels(["Name", "Value"])
        self.header().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.header().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.setAlternatingRowColors(True)
        self.setUniformRowHeights(True)
        self.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)

    def set_data(self, value: Any, limit: int = 50_000) -> None:
        self.clear()
        count = [0]

        def add(parent: QTreeWidgetItem | None, key: str, item: Any) -> None:
            if count[0] >= limit:
                return
            count[0] += 1
            if isinstance(item, dict):
                node = QTreeWidgetItem([str(key), f"{{{len(item)} item(s)}}"])
                (parent.addChild(node) if parent else self.addTopLevelItem(node))
                for child_key, child_value in item.items():
                    add(node, str(child_key), child_value)
            elif isinstance(item, list):
                node = QTreeWidgetItem([str(key), f"[{len(item)} item(s)]"])
                (parent.addChild(node) if parent else self.addTopLevelItem(node))
                for index, child_value in enumerate(item):
                    add(node, f"[{index}]", child_value)
            else:
                node = QTreeWidgetItem([str(key), str(item)])
                (parent.addChild(node) if parent else self.addTopLevelItem(node))

        if isinstance(value, dict):
            for key, item in value.items():
                add(None, str(key), item)
        elif isinstance(value, list):
            for index, item in enumerate(value):
                add(None, f"[{index}]", item)
        else:
            add(None, "Value", value)
        if count[0] >= limit:
            self.addTopLevelItem(QTreeWidgetItem(["Display limit", f"Only the first {limit:,} nodes are shown."]))


class DataTableWidget(QTableWidget):
    def __init__(self) -> None:
        super().__init__()
        self.setAlternatingRowColors(True)
        self.setSortingEnabled(False)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.verticalHeader().setVisible(False)
        self.horizontalHeader().setStretchLastSection(True)

    def set_rows(self, rows: Any, max_rows: int = 50_000) -> None:
        self.clear()
        if isinstance(rows, dict):
            rows = [{"name": key, "value": value} for key, value in rows.items()]
        if not isinstance(rows, list):
            rows = [{"value": rows}]
        normalized = []
        columns: list[str] = []
        seen: set[str] = set()
        for row in rows[:max_rows]:
            if not isinstance(row, dict):
                row = {"value": row}
            normalized.append(row)
            for key in row:
                if key not in seen:
                    seen.add(key)
                    columns.append(str(key))
        self.setColumnCount(len(columns))
        self.setHorizontalHeaderLabels(columns)
        self.setRowCount(len(normalized))
        for row_index, row in enumerate(normalized):
            for column_index, column in enumerate(columns):
                value = row.get(column, "")
                if isinstance(value, (dict, list)):
                    value = json.dumps(value, ensure_ascii=False)
                item = QTableWidgetItem(str(value))
                if isinstance(value, (int, float)):
                    item.setData(Qt.ItemDataRole.UserRole, value)
                self.setItem(row_index, column_index, item)
        self.resizeColumnsToContents()
        for index in range(self.columnCount()):
            if self.columnWidth(index) > 420:
                self.setColumnWidth(index, 420)
        self.setSortingEnabled(True)

    def selected_row_dicts(self) -> list[dict[str, str]]:
        rows = sorted({index.row() for index in self.selectedIndexes()})
        headers = [self.horizontalHeaderItem(i).text() if self.horizontalHeaderItem(i) else str(i) for i in range(self.columnCount())]
        output = []
        for row in rows:
            output.append({headers[col]: self.item(row, col).text() if self.item(row, col) else "" for col in range(self.columnCount())})
        return output


class GenericDataPage(PageShell):
    def __init__(self, title: str, subtitle: str = "", table_mode: bool = False) -> None:
        super().__init__(title, subtitle)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Filter displayed data…")
        self.layout.addWidget(self.search)
        self.view = DataTableWidget() if table_mode else JsonTreeWidget()
        self.layout.addWidget(self.view, 1)
        self._original: Any = None
        self.search.textChanged.connect(self._apply_filter)

    def set_data(self, data: Any) -> None:
        self._original = data
        if isinstance(self.view, DataTableWidget):
            self.view.set_rows(data)
        else:
            self.view.set_data(data)

    def _apply_filter(self, query: str) -> None:
        needle = query.casefold().strip()
        if isinstance(self.view, DataTableWidget):
            for row in range(self.view.rowCount()):
                visible = not needle or any(
                    needle in (self.view.item(row, column).text().casefold() if self.view.item(row, column) else "")
                    for column in range(self.view.columnCount())
                )
                self.view.setRowHidden(row, not visible)
        else:
            def update(item: QTreeWidgetItem) -> bool:
                child_match = any(update(item.child(i)) for i in range(item.childCount()))
                own_match = not needle or needle in item.text(0).casefold() or needle in item.text(1).casefold()
                item.setHidden(not (own_match or child_match))
                return own_match or child_match
            for index in range(self.view.topLevelItemCount()):
                update(self.view.topLevelItem(index))
