from __future__ import annotations

import io
import json
import sqlite3
import struct
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path

from filescope.core.analyzer import FileAnalyzer
from filescope.core.compare import compare_files
from filescope.core.constants import WORKSPACE_NAMES
from filescope.core.folder_scan import scan_folder
from filescope.core.global_search import search_result
from filescope.core.geo import load_world_database, lookup_country
from filescope.core.models import AnalysisResult, StringArtifact
from filescope.core.reports import export_csv, export_html, export_json, export_text
from filescope.core.utils import (
    detect_type,
    entropy_profile,
    extract_iocs,
    extract_strings,
    file_hashes,
    flatten_mapping,
    human_size,
    iter_hex_dump,
    looks_text,
    make_hex_dump,
    shannon_entropy,
)
from filescope.core.yara_engine import scan_with_yara, validate_yara_rule
from filescope.plugins.archive import zip_entry_to_dict


class FileScopeCoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.analyzer = FileAnalyzer(preview_bytes=256 * 1024, string_scan_bytes=8 * 1024 * 1024)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write(self, name: str, data: bytes | str) -> Path:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data.encode("utf-8") if isinstance(data, str) else data)
        return path

    def make_minimal_pe(self, name: str = "sample.exe") -> Path:
        data = bytearray(0x600)
        data[0:2] = b"MZ"
        struct.pack_into("<I", data, 0x3C, 0x80)
        data[0x80:0x84] = b"PE\0\0"
        # machine, sections, timestamp, symbol table, symbols, optional size, characteristics
        struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 1, 1_700_000_000, 0, 0, 0xF0, 0x0022)
        optional = 0x98
        struct.pack_into("<H", data, optional, 0x20B)
        struct.pack_into("<I", data, optional + 4, 0x200)
        struct.pack_into("<I", data, optional + 16, 0x1000)
        struct.pack_into("<I", data, optional + 20, 0x1000)
        struct.pack_into("<Q", data, optional + 24, 0x140000000)
        struct.pack_into("<I", data, optional + 32, 0x1000)
        struct.pack_into("<I", data, optional + 36, 0x200)
        struct.pack_into("<I", data, optional + 56, 0x2000)
        struct.pack_into("<I", data, optional + 60, 0x200)
        struct.pack_into("<H", data, optional + 68, 3)
        struct.pack_into("<I", data, optional + 108, 16)
        section = optional + 0xF0
        data[section:section + 8] = b".text\0\0\0"
        struct.pack_into("<IIIIIIHHI", data, section + 8, 0x180, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
        data[0x200:0x240] = b"VirtualAllocEx\0WriteProcessMemory\0CreateRemoteThread\0"
        return self.write(name, bytes(data))

    def make_fake_dex(self) -> bytes:
        data = bytearray(112)
        data[0:8] = b"dex\n035\x00"
        struct.pack_into("<I", data, 32, 112)
        struct.pack_into("<I", data, 36, 112)
        struct.pack_into("<I", data, 40, 0x12345678)
        data.extend(b"Landroid/media/AudioRecord;\x00Ldalvik/system/DexClassLoader;\x00https://api.example.com/v1\x00com/google/firebase\x00")
        return bytes(data)

    def make_apk_bytes(self) -> bytes:
        manifest = """<?xml version='1.0' encoding='utf-8'?>
<manifest xmlns:android='http://schemas.android.com/apk/res/android' package='com.example.demo' android:versionCode='12' android:versionName='1.2'>
  <uses-sdk android:minSdkVersion='24' android:targetSdkVersion='35'/>
  <uses-permission android:name='android.permission.INTERNET'/>
  <uses-permission android:name='android.permission.RECORD_AUDIO'/>
  <application android:label='Demo' android:debuggable='true' android:usesCleartextTraffic='true'>
    <activity android:name='.MainActivity' android:exported='true'>
      <intent-filter><action android:name='android.intent.action.MAIN'/><category android:name='android.intent.category.LAUNCHER'/></intent-filter>
    </activity>
    <service android:name='.SyncService' android:exported='true'/>
  </application>
</manifest>"""
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("AndroidManifest.xml", manifest)
            archive.writestr("classes.dex", self.make_fake_dex())
            archive.writestr("lib/arm64-v8a/libil2cpp.so", b"ELF Unity IL2CPP")
            archive.writestr("assets/bin/Data/Managed/Metadata/global-metadata.dat", b"metadata")
            archive.writestr("assets/bin/Data/globalgamemanagers", b"Unity 2022.3.10f1")
            archive.writestr("assets/firebase_analytics.txt", b"firebase_analytics")
            archive.writestr("META-INF/CERT.RSA", b"signature")
        return stream.getvalue()

    def make_ooxml(self) -> Path:
        path = self.root / "book.xlsm"
        core = """<cp:coreProperties xmlns:cp='http://schemas.openxmlformats.org/package/2006/metadata/core-properties' xmlns:dc='http://purl.org/dc/elements/1.1/'><dc:title>Quarterly Report</dc:title><dc:creator>RJ</dc:creator></cp:coreProperties>"""
        rels = """<Relationships xmlns='http://schemas.openxmlformats.org/package/2006/relationships'><Relationship Id='rId1' Type='http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate' Target='https://example.com/template.dotm' TargetMode='External'/></Relationships>"""
        workbook = """<workbook xmlns='http://schemas.openxmlformats.org/spreadsheetml/2006/main'><sheets><sheet name='Visible' sheetId='1'/><sheet name='Hidden' sheetId='2' state='veryHidden'/></sheets></workbook>"""
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("docProps/core.xml", core)
            archive.writestr("_rels/.rels", rels)
            archive.writestr("xl/workbook.xml", workbook)
            archive.writestr("xl/vbaProject.bin", b"macro")
            archive.writestr("xl/embeddings/oleObject1.bin", b"embedded")
            archive.writestr("xl/comments1.xml", b"<comments/>")
        return path

    def test_workspace_count_is_exactly_29(self) -> None:
        self.assertEqual(len(WORKSPACE_NAMES), 29)
        self.assertEqual(len(set(WORKSPACE_NAMES)), 29)

    def test_human_size(self) -> None:
        self.assertEqual(human_size(0), "0 B")
        self.assertEqual(human_size(1024), "1.00 KB")

    def test_entropy_known_values(self) -> None:
        self.assertEqual(shannon_entropy(b""), 0.0)
        self.assertEqual(shannon_entropy(b"A" * 100), 0.0)
        self.assertAlmostEqual(shannon_entropy(bytes(range(256))), 8.0, places=6)

    def test_text_detection(self) -> None:
        self.assertTrue(looks_text(b"hello\nworld"))
        self.assertFalse(looks_text(b"\x00\x01\x02\x03"))

    def test_magic_detection_and_mismatch(self) -> None:
        path = self.write("picture.jpg", b"MZ" + b"\0" * 100)
        detected, _, mismatch = detect_type(path, path.read_bytes())
        self.assertEqual(detected, "Windows PE executable")
        self.assertTrue(mismatch)

    def test_hashes(self) -> None:
        path = self.write("hash.txt", "abc")
        hashes = file_hashes(path)
        self.assertEqual(hashes["MD5"], "900150983cd24fb0d6963f7d28e17f72")
        self.assertEqual(hashes["SHA-256"], "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

    def test_hex_preview_and_iterator(self) -> None:
        path = self.write("hex.bin", bytes(range(33)))
        preview = make_hex_dump(path.read_bytes())
        full = "\n".join(iter_hex_dump(path, chunk_size=7))
        self.assertIn("00000000", preview)
        self.assertIn("00000020", full)
        self.assertIn("20", full)

    def test_string_offsets_and_categories(self) -> None:
        path = self.write("strings.bin", b"\x00http://example.com\x00\x00P\x00o\x00w\x00e\x00r\x00S\x00h\x00e\x00l\x00l\x00")
        strings, truncated = extract_strings(path, min_length=4)
        self.assertFalse(truncated)
        self.assertTrue(any(item.category == "URL" for item in strings))
        self.assertTrue(any(item.encoding == "UTF-16 LE" for item in strings))

    def test_ioc_extraction(self) -> None:
        artifacts = [StringArtifact(0, "ASCII", "https://example.com/a 10.2.3.4 admin@example.com HKEY_LOCAL_MACHINE\\Software\\Demo", "General")]
        iocs = extract_iocs(artifacts)
        self.assertIn("https://example.com/a", iocs["URLs"])
        self.assertIn("10.2.3.4", iocs["IPv4"])
        self.assertIn("admin@example.com", iocs["Emails"])

    def test_json_analysis(self) -> None:
        path = self.write("sample.json", json.dumps({"name": "demo", "url": "https://example.com"}))
        result = self.analyzer.analyze(path)
        self.assertEqual(result.detected_type, "JSON document")
        self.assertEqual(result.sections["Structure"]["name"], "demo")
        self.assertIn("URLs", result.iocs)
        self.assertIn("Text encoding", result.metadata)

    def test_xml_analysis(self) -> None:
        path = self.write("sample.xml", "<root><child key='1'>value</child></root>")
        result = self.analyzer.analyze(path)
        self.assertEqual(result.sections["Structure"]["tag"], "root")

    def test_csv_analysis(self) -> None:
        path = self.write("sample.csv", "a,b\n1,2\n")
        result = self.analyzer.analyze(path)
        self.assertEqual(result.metadata["Rows (preview)"], 2)
        self.assertEqual(result.metadata["Maximum columns"], 2)

    def test_ini_analysis(self) -> None:
        path = self.write("sample.ini", "[main]\nname=demo\n")
        result = self.analyzer.analyze(path)
        self.assertEqual(result.sections["Structure"]["main"]["name"], "demo")

    def test_png_metadata(self) -> None:
        from PIL import Image
        path = self.root / "image.png"
        Image.new("RGB", (13, 17), "white").save(path)
        result = self.analyzer.analyze(path)
        self.assertEqual(result.metadata["Image"]["Width"], 13)
        self.assertEqual(result.metadata["Image"]["Height"], 17)

    def test_exif_gps_metadata_and_offline_country_lookup(self) -> None:
        from PIL import Image
        path = self.root / "gps.jpg"
        image = Image.new("RGB", (20, 20), "white")
        exif = Image.Exif()
        exif[34853] = {
            1: "N",
            2: (35.0, 17.0, 30.0),
            3: "W",
            4: (81.0, 32.0, 15.0),
            5: 0,
            6: 250.5,
        }
        image.save(path, exif=exif)
        result = self.analyzer.analyze(path)
        gps = result.sections["GPS"]
        self.assertAlmostEqual(gps["Latitude"], 35.29166667, places=6)
        self.assertAlmostEqual(gps["Longitude"], -81.5375, places=6)
        self.assertEqual(gps["ISO A3"], "USA")
        self.assertEqual(gps["Altitude (meters)"], 250.5)
        self.assertIn("Natural Earth", gps["Map database"])

    def test_invalid_exif_gps_is_rejected(self) -> None:
        from PIL import Image
        path = self.root / "invalid_gps.jpg"
        image = Image.new("RGB", (20, 20), "white")
        exif = Image.Exif()
        exif[34853] = {1: "N", 2: (95.0, 0.0, 0.0), 3: "E", 4: (10.0, 0.0, 0.0)}
        image.save(path, exif=exif)
        result = self.analyzer.analyze(path)
        gps = result.sections["GPS"]
        self.assertNotIn("Coordinates", gps)
        self.assertIn("outside the valid", gps["GPS decode error"])

    def test_offline_map_database_integrity(self) -> None:
        database_path = Path(__file__).resolve().parents[1] / "assets" / "world_countries.json"
        database = load_world_database(database_path)
        self.assertGreaterEqual(len(database.get("features", [])), 170)
        country = lookup_country(-81.5375, 35.29166667, database_path)
        self.assertIsNotNone(country)
        self.assertEqual(country["ISO A3"], "USA")

    def test_sqlite_schema_and_preview(self) -> None:
        path = self.root / "data.sqlite"
        connection = sqlite3.connect(path)
        connection.execute("CREATE TABLE demo(id INTEGER PRIMARY KEY, name TEXT)")
        connection.execute("INSERT INTO demo(name) VALUES ('alpha'), ('beta')")
        connection.commit()
        connection.close()
        result = self.analyzer.analyze(path)
        self.assertIn("SQLite schema", result.sections)
        self.assertEqual(len(result.sections["SQLite tables"]["demo"]["rows"]), 2)

    def test_zip_safety_findings(self) -> None:
        path = self.root / "unsafe.zip"
        nested = io.BytesIO()
        with zipfile.ZipFile(nested, "w", zipfile.ZIP_DEFLATED) as inner:
            inner.writestr("inside.txt", "hello")
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("../escape.txt", "bad")
            archive.writestr("photo.jpg.exe", b"MZ")
            archive.writestr("nested.zip", nested.getvalue())
            archive.writestr("repeat.txt", "A" * 2_000_000)
        result = self.analyzer.analyze(path)
        titles = {item.title for item in result.findings}
        self.assertIn("Archive path traversal entries", titles)
        self.assertIn("Double-extension executable in archive", titles)
        self.assertIn("Nested archives", result.sections)

    def test_zip_entry_metadata(self) -> None:
        info = zipfile.ZipInfo("../bad.exe")
        info.file_size = 100
        info.compress_size = 1
        row = zip_entry_to_dict(info)
        self.assertTrue(row["path_traversal"])

    def test_pe_headers_and_sensitive_strings(self) -> None:
        path = self.make_minimal_pe()
        result = self.analyzer.analyze(path)
        self.assertIn("PE headers", result.metadata)
        self.assertEqual(result.metadata["PE headers"]["Machine"], "x64")
        self.assertTrue(any("VirtualAllocEx" in item.value for item in result.strings))

    def test_apk_manifest_permissions_dex_unity_and_trackers(self) -> None:
        path = self.write("demo.apk", self.make_apk_bytes())
        result = self.analyzer.analyze(path)
        self.assertEqual(result.metadata["Android manifest"]["Package"], "com.example.demo")
        permissions = {row["name"] for row in result.sections["Android permissions"]}
        self.assertIn("android.permission.RECORD_AUDIO", permissions)
        self.assertTrue(result.sections["Unity"]["detected"])
        self.assertEqual(result.sections["Unity"]["summary"]["Scripting backend"], "IL2CPP")
        self.assertTrue(any(row["sdk"] == "Firebase" for row in result.sections["SDKs and trackers"]))
        self.assertTrue(result.sections["DEX"][0]["api_presets"])

    def test_apks_base_and_split_classification(self) -> None:
        base = self.make_apk_bytes()
        path = self.root / "demo.apks"
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as bundle:
            bundle.writestr("base-master.apk", base)
            bundle.writestr("split_config.arm64_v8a.apk", base)
            bundle.writestr("split_config.xxhdpi.apk", base)
            bundle.writestr("split_config.en.apk", base)
        result = self.analyzer.analyze(path)
        self.assertEqual(result.metadata["Android bundle"]["Base APK"], "base-master.apk")
        dimensions = {row["dimension"] for row in result.sections["Android split packages"]}
        self.assertTrue({"base", "abi", "density", "language"}.issubset(dimensions))

    def test_office_metadata_macros_links_and_hidden_sheet(self) -> None:
        result = self.analyzer.analyze(self.make_ooxml())
        self.assertEqual(result.metadata["Document properties"]["title"], "Quarterly Report")
        self.assertEqual(len(result.sections["Office macros"]), 1)
        self.assertEqual(len(result.sections["Office external links"]), 1)
        self.assertEqual(result.sections["Office hidden sheets"][0]["name"], "Hidden")
        self.assertTrue(any(item.title == "Office macro project present" for item in result.findings))

    def test_pdf_metadata(self) -> None:
        from pypdf import PdfWriter
        path = self.root / "sample.pdf"
        writer = PdfWriter()
        writer.add_blank_page(width=100, height=100)
        writer.add_metadata({"/Title": "Demo PDF", "/Author": "RJ"})
        with path.open("wb") as handle:
            writer.write(handle)
        result = self.analyzer.analyze(path)
        self.assertEqual(result.metadata["PDF"]["Pages"], 1)
        self.assertEqual(result.metadata["PDF"]["Title"], "Demo PDF")

    def test_reports_export(self) -> None:
        result = self.analyzer.analyze(self.write("report.json", '{"key":"value"}'))
        targets = [
            export_json(result, self.root / "report.json.out.json"),
            export_text(result, self.root / "report.txt"),
            export_csv(result, self.root / "report.csv"),
            export_html(result, self.root / "report.html"),
        ]
        for target in targets:
            self.assertTrue(target.is_file())
            self.assertGreater(target.stat().st_size, 20)
        html = (self.root / "report.html").read_text(encoding="utf-8")
        self.assertIn("FileScope analysis report", html)

    def test_compare_files(self) -> None:
        left = self.root / "left.zip"
        right = self.root / "right.zip"
        with zipfile.ZipFile(left, "w") as archive:
            archive.writestr("a.txt", "one")
        with zipfile.ZipFile(right, "w") as archive:
            archive.writestr("a.txt", "two")
            archive.writestr("b.txt", "new")
        comparison = compare_files(left, right, self.analyzer)
        self.assertIn("b.txt", comparison["added_archive_entries"])
        self.assertTrue(any(item["name"] == "a.txt" for item in comparison["changed_archive_entries"]))

    def test_global_search(self) -> None:
        result = self.analyzer.analyze(self.write("search.json", '{"secret_name":"needle_value"}'))
        rows = search_result(result, "needle_value")
        self.assertTrue(rows)
        self.assertTrue(any("needle_value" in row["value"] for row in rows))

    def test_folder_scan(self) -> None:
        self.write("folder/a.txt", "alpha")
        self.write("folder/b.json", '{"b":2}')
        rows = scan_folder(self.root / "folder", max_files=10, workers=2, analyzer=self.analyzer)
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(row["parse_status"] in {"OK", "Partial"} for row in rows))

    def test_yara_unavailable_or_scans(self) -> None:
        target = self.write("yara.txt", "powershell -encodedcommand QUFBQUFBQUFBQUFBQUFBQUFBQUFB")
        rule = self.root / "test.yar"
        rule.write_text('rule demo { strings: $a = "powershell" nocase condition: $a }', encoding="utf-8")
        result = scan_with_yara(target, rule)
        self.assertIn("available", result)
        self.assertIn("matches", result)
        ok, message = validate_yara_rule(rule)
        self.assertIsInstance(ok, bool)
        self.assertIsInstance(message, str)

    def test_entropy_profile(self) -> None:
        path = self.write("entropy.bin", bytes(range(256)) * 300)
        profile = entropy_profile(path, block_size=4096)
        self.assertGreater(profile["overall"], 7.9)
        self.assertGreater(len(profile["blocks"]), 1)

    def test_flatten_mapping(self) -> None:
        rows = flatten_mapping({"a": {"b": [1, 2]}})
        self.assertIn(("a.b[0]", "1"), rows)
        self.assertIn(("a.b[1]", "2"), rows)

    def test_analysis_result_risk_clamps_to_100(self) -> None:
        path = self.write("risk.bin", b"x")
        result = AnalysisResult(path)
        result.add_finding("High", "A", "a", 80)
        result.add_finding("High", "B", "b", 80)
        self.assertEqual(result.risk_score, 100)
        self.assertEqual(result.risk_label, "High")


    def test_extended_ioc_categories(self) -> None:
        text = r"IPv6 2001:db8::1 Global\DemoMutex \\.\pipe\demo Mozilla/5.0 TestAgent"
        iocs = extract_iocs([StringArtifact(0, "ASCII", text, "General")])
        self.assertIn("2001:db8::1", iocs.get("IPv6", []))
        self.assertIn(r"Global\DemoMutex", iocs.get("Mutex names", []))
        self.assertIn(r"\\.\pipe\demo", iocs.get("Named pipes", []))
        self.assertTrue(iocs.get("User agents"))

    def test_folder_scan_can_be_canceled(self) -> None:
        folder = self.root / "cancel"
        folder.mkdir()
        for index in range(20):
            (folder / f"{index}.txt").write_text("x", encoding="utf-8")
        event = threading.Event()
        event.set()
        rows = scan_folder(folder, max_files=100, workers=2, analyzer=self.analyzer, cancel_event=event)
        self.assertEqual(rows, [])

    def test_sqlite_deleted_data_indicators(self) -> None:
        path = self.root / "freelist.sqlite"
        connection = sqlite3.connect(path)
        connection.execute("PRAGMA secure_delete=OFF")
        connection.execute("CREATE TABLE messages(id INTEGER PRIMARY KEY, body TEXT)")
        connection.executemany("INSERT INTO messages(body) VALUES (?)", [("x" * 1000,) for _ in range(100)])
        connection.commit()
        connection.execute("DELETE FROM messages")
        connection.commit()
        connection.close()
        result = self.analyzer.analyze(path)
        self.assertIn("Freelist pages", result.metadata["SQLite"])
        self.assertTrue(result.sections.get("Android database indicators"))

    def test_bundled_yara_rules_compile_when_available(self) -> None:
        rule_path = Path(__file__).resolve().parents[1] / "rules" / "starter_rules.yar"
        ok, message = validate_yara_rule(rule_path)
        try:
            import yara_x  # noqa: F401
        except ImportError:
            self.assertFalse(ok)
        else:
            self.assertTrue(ok, message)

    def test_parser_failures_are_contained(self) -> None:
        # A malformed SQLite extension should not crash the generic analyzer.
        path = self.write("bad.db", b"not sqlite\x00binary")
        result = self.analyzer.analyze(path)
        self.assertIsInstance(result, AnalysisResult)
        self.assertIn("SHA-256", result.summary)


if __name__ == "__main__":
    unittest.main()
