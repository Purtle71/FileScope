from __future__ import annotations

import ctypes
import os
import sys
import tempfile
from pathlib import Path


def _run_self_test(app) -> int:
    """Exercise bundled imports, resources, parsers, YARA-X, GPS, and all workspaces."""
    try:
        from PIL import Image
        from PySide6.QtCore import QSettings

        from filescope.core.analyzer import FileAnalyzer
        from filescope.core.constants import WORKSPACE_NAMES
        from filescope.core.geo import load_world_database
        from filescope.core.paths import resource_path
        from filescope.core.yara_engine import scan_with_yara, validate_yara_rule
        from filescope.gui.workspace import AnalysisWorkspace

        map_path = resource_path("assets", "world_countries.json")
        rules_path = resource_path("rules", "starter_rules.yar")
        if not map_path.is_file() or len(load_world_database(map_path).get("features", [])) < 150:
            raise RuntimeError("Offline map database is missing or incomplete.")
        ok, message = validate_yara_rule(rules_path)
        if not ok:
            raise RuntimeError(f"Bundled YARA-X rules failed validation: {message}")

        with tempfile.TemporaryDirectory(prefix="FileScopeSelfTest_") as temp:
            root = Path(temp)
            target = root / "gps_sample.jpg"
            image = Image.new("RGB", (24, 18), "white")
            exif = Image.Exif()
            exif[34853] = {
                1: "N",
                2: (35.0, 17.0, 30.0),
                3: "W",
                4: (81.0, 32.0, 15.0),
                5: 0,
                6: 250.0,
            }
            image.save(target, exif=exif)
            result = FileAnalyzer().analyze(target)
            gps = result.sections.get("GPS", {})
            if not isinstance(gps, dict) or "Coordinates" not in gps:
                raise RuntimeError("EXIF GPS parsing failed.")
            scan = scan_with_yara(target, rules_path)
            if not scan.get("available"):
                raise RuntimeError(f"YARA-X scan unavailable: {scan.get('error', '')}")

            settings = QSettings(str(root / "settings.ini"), QSettings.Format.IniFormat)
            workspace = AnalysisWorkspace(result, settings)
            if workspace.stack.count() != 29 or workspace.navigation.count() != 29 or len(WORKSPACE_NAMES) != 29:
                raise RuntimeError("The 29-workspace interface did not initialize correctly.")
            workspace.deleteLater()
            app.processEvents()
        return 0
    except Exception as exc:
        try:
            log_path = Path(tempfile.gettempdir()) / "FileScope_self_test.log"
            log_path.write_text(f"FileScope self-test failed: {exc!r}\n", encoding="utf-8")
        except Exception:
            pass
        return 1


def main() -> int:
    self_test = "--self-test" in sys.argv
    if self_test:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    try:
        from PySide6.QtWidgets import QApplication
    except ImportError:
        print("FileScope requires PySide6. Run BUILD_FILESCOPE.bat to create the standalone executable.", file=sys.stderr)
        return 2
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("FileScope.Windows")
    except Exception:
        pass
    from filescope.gui.main_window import MainWindow

    app = QApplication(sys.argv)
    app.setApplicationName("FileScope")
    app.setOrganizationName("FileScope")
    if self_test:
        return _run_self_test(app)
    initial_path = next((value for value in sys.argv[1:] if not value.startswith("--")), None)
    window = MainWindow(initial_path)
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
