from __future__ import annotations

import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import tempfile
import time
import unittest
from pathlib import Path

try:
    from PySide6.QtCore import QSettings
    from PySide6.QtWidgets import QApplication
    from filescope.gui.main_window import MainWindow, WelcomePage
    from filescope.gui.workspace import AnalysisWorkspace, WORKSPACE_NAMES
    HAS_QT = True
except ImportError:
    HAS_QT = False


@unittest.skipUnless(HAS_QT, "PySide6 is not installed")
class FileScopeGuiSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])
        QSettings.setDefaultFormat(QSettings.Format.IniFormat)

    def test_main_window_loads_all_29_workspaces(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "smoke.json"
            path.write_text('{"hello":"world","url":"https://example.com"}', encoding="utf-8")
            window = MainWindow()
            self.assertIsInstance(window.tabs.widget(0), WelcomePage)
            window.open_path(path)
            deadline = time.time() + 15
            while time.time() < deadline:
                self.app.processEvents()
                if isinstance(window.tabs.currentWidget(), AnalysisWorkspace):
                    break
                time.sleep(0.02)
            workspace = window.tabs.currentWidget()
            self.assertIsInstance(workspace, AnalysisWorkspace)
            self.assertEqual(workspace.stack.count(), 29)
            self.assertEqual(workspace.navigation.count(), 29)
            for name in WORKSPACE_NAMES:
                workspace.show_page(name)
                self.app.processEvents()
                self.assertEqual(workspace.navigation.currentItem().text(), name)
            workspace.show_page("Hex")
            hex_page = workspace.stack.currentWidget()
            hex_page.copy_all_hex()
            self.assertIn("00000000", self.app.clipboard().text())
            window.close()
            self.app.processEvents()

    def test_metadata_workspace_loads_offline_gps_map(self) -> None:
        from PIL import Image
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "gps.jpg"
            image = Image.new("RGB", (20, 20), "white")
            exif = Image.Exif()
            exif[34853] = {1: "N", 2: (35.0, 17.0, 30.0), 3: "W", 4: (81.0, 32.0, 15.0)}
            image.save(path, exif=exif)
            window = MainWindow()
            window.open_path(path)
            deadline = time.time() + 15
            while time.time() < deadline:
                self.app.processEvents()
                if isinstance(window.tabs.currentWidget(), AnalysisWorkspace):
                    break
                time.sleep(0.02)
            workspace = window.tabs.currentWidget()
            self.assertIsInstance(workspace, AnalysisWorkspace)
            workspace.show_page("Metadata")
            metadata_page = workspace.stack.currentWidget()
            self.assertAlmostEqual(metadata_page.map.latitude, 35.29166667, places=6)
            self.assertAlmostEqual(metadata_page.map.longitude, -81.5375, places=6)
            self.assertGreaterEqual(len(metadata_page.map.database.get("features", [])), 170)
            window.close()
            self.app.processEvents()


if __name__ == "__main__":
    unittest.main()
