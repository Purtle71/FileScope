from __future__ import annotations

import re
import zipfile
from pathlib import Path
import xml.etree.ElementTree as ET

from filescope.core.models import AnalysisResult

from .base import AnalysisPlugin

OOXML_EXTENSIONS = {".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm", ".dotx", ".dotm", ".xltx", ".xltm", ".potx", ".potm"}
OFFICE_EXTENSIONS = OOXML_EXTENSIONS | {".pdf", ".rtf", ".doc", ".xls", ".ppt"}
NS = {
    "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
    "dc": "http://purl.org/dc/elements/1.1/",
    "dcterms": "http://purl.org/dc/terms/",
    "ep": "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties",
    "r": "http://schemas.openxmlformats.org/package/2006/relationships",
    "s": "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
}


class OfficePlugin(AnalysisPlugin):
    name = "Office and PDF metadata parser"

    def supports(self, path: Path, header: bytes, detected_type: str) -> bool:
        return path.suffix.lower() in OFFICE_EXTENSIONS or detected_type == "PDF document" or detected_type == "OLE compound document"

    def analyze(self, result: AnalysisResult, header: bytes) -> None:
        ext = result.path.suffix.lower()
        if ext == ".pdf" or header.startswith(b"%PDF-"):
            self._parse_pdf(result)
        elif ext in OOXML_EXTENSIONS and zipfile.is_zipfile(result.path):
            self._parse_ooxml(result)
        elif ext == ".rtf" or header.startswith(b"{\\rtf"):
            self._parse_rtf(result)
        elif header.startswith(b"\xd0\xcf\x11\xe0"):
            result.metadata["Legacy Office/OLE"] = {
                "Container": "Compound File Binary Format",
                "Note": "Install oletools for macro and stream-level inspection of legacy Office documents.",
            }
            result.add_finding("Info", "Legacy OLE document", "The file uses the older compound-document format. Advanced macro analysis requires oletools.", 3, result.path.suffix)

    def _parse_ooxml(self, result: AnalysisResult) -> None:
        metadata = {}
        relationships = []
        external = []
        embedded = []
        comments = []
        hidden_sheets = []
        macros = []
        with zipfile.ZipFile(result.path) as archive:
            names = archive.namelist()
            for name in names:
                lower = name.lower()
                if lower.endswith("vbaproject.bin"):
                    macros.append(name)
                if "/embeddings/" in lower:
                    try:
                        info = archive.getinfo(name)
                        embedded.append({"name": name, "size": info.file_size, "compressed": info.compress_size})
                    except KeyError:
                        pass
                if "comments" in lower and lower.endswith(".xml"):
                    comments.append(name)
            for property_name in ("docProps/core.xml", "docProps/app.xml", "docProps/custom.xml"):
                if property_name not in names:
                    continue
                try:
                    root = ET.fromstring(archive.read(property_name))
                except ET.ParseError:
                    continue
                for child in list(root):
                    key = child.tag.rsplit("}", 1)[-1]
                    text = (child.text or "").strip()
                    if text:
                        metadata[key] = text
            for name in names:
                if not name.endswith(".rels"):
                    continue
                try:
                    root = ET.fromstring(archive.read(name))
                except ET.ParseError:
                    continue
                for rel in root:
                    item = {
                        "source": name,
                        "id": rel.attrib.get("Id", ""),
                        "type": rel.attrib.get("Type", "").rsplit("/", 1)[-1],
                        "target": rel.attrib.get("Target", ""),
                        "target_mode": rel.attrib.get("TargetMode", "Internal"),
                    }
                    relationships.append(item)
                    if item["target_mode"].lower() == "external" or re.match(r"^[a-z]+://", item["target"], re.I):
                        external.append(item)
            if "xl/workbook.xml" in names:
                try:
                    root = ET.fromstring(archive.read("xl/workbook.xml"))
                    for sheet in root.findall(".//s:sheet", NS):
                        state = sheet.attrib.get("state", "visible")
                        if state != "visible":
                            hidden_sheets.append({"name": sheet.attrib.get("name", ""), "state": state})
                except ET.ParseError:
                    pass
        result.metadata["Document properties"] = metadata
        result.metadata["OOXML"] = {
            "Relationships": len(relationships),
            "External relationships": len(external),
            "Embedded objects": len(embedded),
            "Comment parts": len(comments),
            "Hidden worksheets": len(hidden_sheets),
            "Macro projects": len(macros),
        }
        result.sections["Office metadata"] = metadata
        result.sections["Office relationships"] = relationships
        result.sections["Office external links"] = external
        result.sections["Office embedded objects"] = embedded
        result.sections["Office comments"] = comments
        result.sections["Office hidden sheets"] = hidden_sheets
        result.sections["Office macros"] = macros
        if macros:
            result.add_finding("High", "Office macro project present", "The document contains a VBA project. Macros can be legitimate but should be reviewed before enabling.", 22, ", ".join(macros))
        if external:
            result.add_finding("Medium", "External Office relationships", "The document references content outside the package, which may cause network access or template loading.", min(18, 5 + len(external)), f"{len(external)} relationship(s)")
        if embedded:
            result.add_finding("Info", "Embedded Office objects", "The document contains embedded files or OLE objects.", 3, f"{len(embedded)} object(s)")
        if hidden_sheets:
            result.add_finding("Info", "Hidden worksheets", "The workbook contains hidden or very-hidden worksheets.", 2, ", ".join(item["name"] for item in hidden_sheets))

    def _parse_pdf(self, result: AnalysisResult) -> None:
        try:
            from pypdf import PdfReader
        except ImportError:
            result.warnings.append("pypdf is not installed; PDF metadata is unavailable.")
            return
        reader = PdfReader(str(result.path), strict=False)
        info = {
            "Encrypted": bool(reader.is_encrypted),
            "Pages": len(reader.pages) if not reader.is_encrypted else "Unavailable until decrypted",
        }
        metadata = reader.metadata or {}
        for key, value in metadata.items():
            info[str(key).lstrip("/")] = str(value)
        result.metadata["PDF"] = info
        result.sections["PDF metadata"] = info
        attachments = []
        try:
            for name, content_list in (reader.attachments or {}).items():
                sizes = [len(content) for content in content_list]
                attachments.append({"name": name, "items": len(content_list), "sizes": sizes})
        except Exception as exc:
            result.warnings.append(f"PDF attachment inspection warning: {exc}")
        result.sections["PDF attachments"] = attachments
        if attachments:
            result.add_finding("Medium", "Embedded PDF attachments", "The PDF contains attached files.", 10, f"{len(attachments)} attachment name(s)")
        raw = result.path.read_bytes()[:64 * 1024 * 1024]
        js_markers = sum(raw.count(marker) for marker in (b"/JavaScript", b"/JS", b"/OpenAction", b"/AA"))
        launch_markers = raw.count(b"/Launch")
        if js_markers:
            result.add_finding("High", "PDF active-content markers", "JavaScript, automatic actions, or additional actions were found in the PDF structure.", min(25, 12 + js_markers), f"{js_markers} marker(s)")
        if launch_markers:
            result.add_finding("High", "PDF launch action", "A /Launch action marker was found.", 25, f"{launch_markers} marker(s)")

    def _parse_rtf(self, result: AnalysisResult) -> None:
        raw = result.path.read_bytes()[:32 * 1024 * 1024]
        text = raw.decode("latin-1", errors="ignore")
        controls = re.findall(r"\\([a-zA-Z]+)-?\d* ?", text)
        result.metadata["RTF"] = {
            "Control words": len(controls),
            "Unique control words": len(set(controls)),
            "Embedded object markers": text.count("\\object"),
            "OLE object data markers": text.count("\\objdata"),
        }
        result.sections["RTF controls"] = sorted(set(controls))
        if "\\objdata" in text or "\\object" in text:
            result.add_finding("Medium", "RTF embedded object", "The RTF contains embedded object data.", 14, "\\object or \\objdata")
