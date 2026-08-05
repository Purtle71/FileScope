from __future__ import annotations

import math
from pathlib import Path
from typing import Any

from PySide6.QtCore import QPoint, QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QMouseEvent, QPainter, QPainterPath, QPen, QWheelEvent
from PySide6.QtWidgets import QApplication, QFrame, QHBoxLayout, QLabel, QPushButton, QSplitter, QVBoxLayout, QWidget

from filescope.core.geo import load_world_database
from filescope.core.models import AnalysisResult
from filescope.core.paths import resource_path

from .widgets import JsonTreeWidget, PageShell


class OfflineWorldMap(QWidget):
    def __init__(self, latitude: float | None, longitude: float | None, database_path: Path) -> None:
        super().__init__()
        self.latitude = latitude
        self.longitude = longitude
        self.database_path = database_path
        self.database = load_world_database(database_path)
        self.zoom = 1.0
        self.pan = QPointF(0.0, 0.0)
        self._drag_start: QPoint | None = None
        self._pan_start = QPointF(0.0, 0.0)
        self.setMinimumHeight(300)
        self.setMouseTracking(True)
        self.setToolTip("Mouse wheel: zoom • Drag: pan • Double-click: reset")

    def reset_view(self) -> None:
        self.zoom = 1.0
        self.pan = QPointF(0.0, 0.0)
        self.update()

    def _base_rect(self) -> QRectF:
        margin = 18.0
        return QRectF(margin, margin, max(1.0, self.width() - margin * 2), max(1.0, self.height() - margin * 2))

    def _project(self, longitude: float, latitude: float) -> QPointF:
        rect = self._base_rect()
        x = rect.left() + ((longitude + 180.0) / 360.0) * rect.width()
        y = rect.top() + ((90.0 - latitude) / 180.0) * rect.height()
        center = rect.center()
        x = center.x() + (x - center.x()) * self.zoom + self.pan.x()
        y = center.y() + (y - center.y()) * self.zoom + self.pan.y()
        return QPointF(x, y)

    def _iter_rings(self, geometry: dict[str, Any]):
        kind = geometry.get("type")
        coordinates = geometry.get("coordinates", [])
        if kind == "Polygon":
            for ring in coordinates:
                yield ring
        elif kind == "MultiPolygon":
            for polygon in coordinates:
                for ring in polygon:
                    yield ring

    def paintEvent(self, event) -> None:  # type: ignore[override]
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        palette = self.palette()
        background = palette.base().color()
        foreground = palette.text().color()
        muted = QColor(foreground)
        muted.setAlpha(80)
        land = QColor(foreground)
        land.setAlpha(26)
        border = QColor(foreground)
        border.setAlpha(125)
        accent = QColor("#16c3df") if background.lightness() < 128 else QColor("#0b8fa8")

        painter.fillRect(self.rect(), background)
        rect = self._base_rect()
        painter.setPen(QPen(muted, 1.0))
        for longitude in range(-180, 181, 30):
            top = self._project(float(longitude), 90.0)
            bottom = self._project(float(longitude), -90.0)
            painter.drawLine(top, bottom)
        for latitude in range(-60, 61, 30):
            left = self._project(-180.0, float(latitude))
            right = self._project(180.0, float(latitude))
            painter.drawLine(left, right)

        painter.setPen(QPen(border, 0.9))
        painter.setBrush(land)
        for feature in self.database.get("features", []):
            geometry = feature.get("geometry", {}) if isinstance(feature, dict) else {}
            if not isinstance(geometry, dict):
                continue
            for ring in self._iter_rings(geometry):
                if not isinstance(ring, list) or len(ring) < 3:
                    continue
                path = QPainterPath()
                started = False
                previous_lon: float | None = None
                for coordinate in ring:
                    try:
                        longitude, latitude = float(coordinate[0]), float(coordinate[1])
                    except (TypeError, ValueError, IndexError):
                        continue
                    point = self._project(longitude, latitude)
                    if not started or (previous_lon is not None and abs(longitude - previous_lon) > 180.0):
                        if started:
                            painter.drawPath(path)
                        path = QPainterPath(point)
                        started = True
                    else:
                        path.lineTo(point)
                    previous_lon = longitude
                if started:
                    path.closeSubpath()
                    painter.drawPath(path)

        painter.setPen(QPen(muted, 1.0))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawRoundedRect(rect, 7.0, 7.0)

        if self.latitude is not None and self.longitude is not None:
            point = self._project(self.longitude, self.latitude)
            painter.setPen(QPen(QColor("#ffffff"), 2.0))
            painter.setBrush(accent)
            painter.drawEllipse(point, 7.0, 7.0)
            painter.setPen(QPen(accent, 1.5))
            painter.drawEllipse(point, 13.0, 13.0)
            label = f"{self.latitude:.6f}, {self.longitude:.6f}"
            label_rect = QRectF(point.x() + 12.0, point.y() - 28.0, 220.0, 24.0)
            painter.fillRect(label_rect.adjusted(-5, -2, 5, 2), QColor(background).lighter(115))
            painter.setPen(foreground)
            painter.drawText(label_rect, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, label)
        else:
            painter.setPen(foreground)
            painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, "No GPS coordinates were found in this file.")

    def wheelEvent(self, event: QWheelEvent) -> None:  # type: ignore[override]
        steps = event.angleDelta().y() / 120.0
        if not steps:
            return
        old_zoom = self.zoom
        self.zoom = min(8.0, max(1.0, self.zoom * math.pow(1.18, steps)))
        if abs(self.zoom - old_zoom) < 0.001:
            return
        mouse = event.position()
        rect = self._base_rect()
        center = rect.center()
        base_x = (mouse.x() - self.pan.x() - center.x()) / old_zoom + center.x()
        base_y = (mouse.y() - self.pan.y() - center.y()) / old_zoom + center.y()
        self.pan = QPointF(mouse.x() - (center.x() + (base_x - center.x()) * self.zoom), mouse.y() - (center.y() + (base_y - center.y()) * self.zoom))
        self.update()

    def mousePressEvent(self, event: QMouseEvent) -> None:  # type: ignore[override]
        if event.button() == Qt.MouseButton.LeftButton:
            self._drag_start = event.position().toPoint()
            self._pan_start = QPointF(self.pan)
            self.setCursor(Qt.CursorShape.ClosedHandCursor)

    def mouseMoveEvent(self, event: QMouseEvent) -> None:  # type: ignore[override]
        if self._drag_start is not None:
            delta = event.position().toPoint() - self._drag_start
            self.pan = self._pan_start + QPointF(delta)
            self.update()

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:  # type: ignore[override]
        if event.button() == Qt.MouseButton.LeftButton:
            self._drag_start = None
            self.unsetCursor()

    def mouseDoubleClickEvent(self, event: QMouseEvent) -> None:  # type: ignore[override]
        self.reset_view()


class MetadataPage(PageShell):
    def __init__(self, result: AnalysisResult) -> None:
        super().__init__("Metadata", "Filesystem and format metadata, including EXIF GPS data when present.")
        self.result = result
        gps = result.sections.get("GPS", {})
        if not isinstance(gps, dict):
            gps = {}
        latitude = self._float_or_none(gps.get("Latitude"))
        longitude = self._float_or_none(gps.get("Longitude"))

        splitter = QSplitter(Qt.Orientation.Vertical)
        tree = JsonTreeWidget()
        tree.set_data(result.metadata)
        splitter.addWidget(tree)

        map_card = QFrame()
        map_card.setObjectName("card")
        map_layout = QVBoxLayout(map_card)
        map_layout.setContentsMargins(16, 14, 16, 14)
        top = QHBoxLayout()
        title = QLabel("Offline GPS map")
        title.setStyleSheet("font-weight:700;font-size:12pt")
        top.addWidget(title)
        top.addStretch(1)
        copy_button = QPushButton("Copy coordinates")
        copy_button.setEnabled(latitude is not None and longitude is not None)
        copy_button.clicked.connect(lambda: QApplication.clipboard().setText(str(gps.get("Coordinates", ""))))
        reset_button = QPushButton("Reset map")
        top.addWidget(copy_button)
        top.addWidget(reset_button)
        map_layout.addLayout(top)

        location_parts = [str(gps.get(key, "")) for key in ("Country", "Continent", "ISO A3") if gps.get(key)]
        if latitude is not None and longitude is not None:
            summary = f"Coordinates: {latitude:.8f}, {longitude:.8f}"
            if location_parts:
                summary += "  •  " + "  •  ".join(location_parts)
        else:
            summary = "No embedded GPS coordinates were found. FileScope does not contact any online geocoding service."
        summary_label = QLabel(summary)
        summary_label.setObjectName("pageSubtitle")
        summary_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        summary_label.setWordWrap(True)
        map_layout.addWidget(summary_label)

        self.map = OfflineWorldMap(latitude, longitude, resource_path("assets", "world_countries.json"))
        reset_button.clicked.connect(self.map.reset_view)
        map_layout.addWidget(self.map, 1)
        source = QLabel("Map database: Natural Earth 1:110m public-domain country boundaries. Coordinates remain local.")
        source.setObjectName("pageSubtitle")
        source.setWordWrap(True)
        map_layout.addWidget(source)
        splitter.addWidget(map_card)
        splitter.setSizes([430, 380])
        self.layout.addWidget(splitter, 1)

    @staticmethod
    def _float_or_none(value: Any) -> float | None:
        try:
            output = float(value)
        except (TypeError, ValueError):
            return None
        return output if math.isfinite(output) else None
