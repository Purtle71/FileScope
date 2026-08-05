from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

from filescope.core.models import AnalysisResult
from filescope.core.utils import human_size

from .base import AnalysisPlugin

ARCHIVE_EXTENSIONS = {".zip", ".jar", ".war", ".ear", ".tar", ".tgz", ".gz", ".bz2", ".xz", ".7z", ".rar"}
NESTED_SUFFIXES = {".zip", ".jar", ".apk", ".apks", ".xapk", ".apkm", ".docx", ".xlsx", ".pptx"}
EXECUTABLE_SUFFIXES = {".exe", ".dll", ".sys", ".scr", ".com", ".msi", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta"}


def zip_entry_to_dict(info: zipfile.ZipInfo) -> dict[str, Any]:
    ratio = (info.file_size / info.compress_size) if info.compress_size else (float("inf") if info.file_size else 1.0)
    name_path = PurePosixPath(info.filename.replace("\\", "/"))
    traversal = name_path.is_absolute() or ".." in name_path.parts
    double_extension = False
    suffixes = [suffix.lower() for suffix in name_path.suffixes]
    if len(suffixes) >= 2 and suffixes[-1] in EXECUTABLE_SUFFIXES:
        double_extension = True
    return {
        "name": info.filename,
        "size": info.file_size,
        "compressed": info.compress_size,
        "local_header_offset": int(getattr(info, "header_offset", 0)),
        "compression_ratio": round(ratio, 2) if ratio != float("inf") else "infinite",
        "method": info.compress_type,
        "encrypted": bool(info.flag_bits & 0x1),
        "crc32": f"{getattr(info, 'CRC', 0):08X}",
        "directory": info.is_dir(),
        "path_traversal": traversal,
        "double_extension_executable": double_extension,
    }


def inspect_nested_zip(data: bytes, name: str, depth: int, max_depth: int, max_entries: int) -> dict[str, Any]:
    node: dict[str, Any] = {"name": name, "depth": depth, "entries": []}
    if depth >= max_depth:
        node["limited"] = "Maximum recursion depth reached"
        return node
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as nested:
            for info in nested.infolist()[:max_entries]:
                item = zip_entry_to_dict(info)
                node["entries"].append(item)
                suffix = Path(info.filename).suffix.lower()
                if not info.is_dir() and suffix in NESTED_SUFFIXES and info.file_size <= 64 * 1024 * 1024:
                    try:
                        item["nested"] = inspect_nested_zip(nested.read(info), info.filename, depth + 1, max_depth, max_entries)
                    except (RuntimeError, OSError, zipfile.BadZipFile) as exc:
                        item["nested_error"] = str(exc)
    except zipfile.BadZipFile as exc:
        node["error"] = str(exc)
    return node


class ArchivePlugin(AnalysisPlugin):
    name = "Archive and nested-content parser"

    def supports(self, path: Path, header: bytes, detected_type: str) -> bool:
        return path.suffix.lower() in ARCHIVE_EXTENSIONS or header.startswith((b"PK\x03\x04", b"PK\x05\x06", b"\x1f\x8b")) or tarfile.is_tarfile(path)

    def analyze(self, result: AnalysisResult, header: bytes) -> None:
        if zipfile.is_zipfile(result.path):
            self._analyze_zip(result)
        elif tarfile.is_tarfile(result.path):
            self._analyze_tar(result)
        else:
            result.warnings.append("This archive format was detected but is not natively readable without an external library.")

    def _analyze_zip(self, result: AnalysisResult) -> None:
        entries: list[dict[str, Any]] = []
        duplicate_counts: dict[str, int] = {}
        total_uncompressed = 0
        total_compressed = 0
        unsafe_paths = 0
        encrypted = 0
        hidden_executables = 0
        huge_ratios = 0
        with zipfile.ZipFile(result.path) as archive:
            infos = archive.infolist()
            for info in infos[:100_000]:
                item = zip_entry_to_dict(info)
                entries.append(item)
                duplicate_counts[info.filename] = duplicate_counts.get(info.filename, 0) + 1
                total_uncompressed += info.file_size
                total_compressed += info.compress_size
                unsafe_paths += int(bool(item["path_traversal"]))
                encrypted += int(bool(item["encrypted"]))
                hidden_executables += int(bool(item["double_extension_executable"]))
                ratio = item["compression_ratio"]
                if ratio == "infinite" or (isinstance(ratio, float) and ratio >= 1000):
                    huge_ratios += 1
            if len(infos) > 100_000:
                result.warnings.append("Archive listing limited to 100,000 entries.")
            root = {"name": result.path.name, "depth": 0, "entries": []}
            nested_budget = 100
            for info, item in zip(infos, entries):
                root["entries"].append(item)
                if nested_budget <= 0:
                    continue
                suffix = Path(info.filename).suffix.lower()
                if not info.is_dir() and suffix in NESTED_SUFFIXES and info.file_size <= 64 * 1024 * 1024:
                    try:
                        item["nested"] = inspect_nested_zip(archive.read(info), info.filename, 1, 4, 5000)
                        nested_budget -= 1
                    except (RuntimeError, OSError, zipfile.BadZipFile) as exc:
                        item["nested_error"] = str(exc)
        duplicates = [name for name, count in duplicate_counts.items() if count > 1]
        result.sections["Archive entries"] = entries
        result.sections["Nested archives"] = root
        result.metadata["Archive"] = {
            "Entry count": len(entries),
            "Total uncompressed": total_uncompressed,
            "Total uncompressed (display)": human_size(total_uncompressed),
            "Total compressed": total_compressed,
            "Total compressed (display)": human_size(total_compressed),
            "Overall compression ratio": round(total_uncompressed / max(1, total_compressed), 2),
            "Encrypted entries": encrypted,
            "Duplicate names": len(duplicates),
            "Unsafe paths": unsafe_paths,
        }
        if unsafe_paths:
            result.add_finding("High", "Archive path traversal entries", "One or more entries could write outside the extraction directory if extracted unsafely.", 30, f"{unsafe_paths} entry(s)")
        if huge_ratios or (total_uncompressed > 2 * 1024**3 and total_uncompressed / max(1, total_compressed) > 100):
            result.add_finding("High", "Possible archive bomb", "The archive contains extreme compression ratios or a very large expanded size.", 28, f"{huge_ratios} extreme entry ratio(s)")
        if duplicates:
            result.add_finding("Medium", "Duplicate archive filenames", "Duplicate names can cause inconsistent extraction or parser behavior.", 8, ", ".join(duplicates[:10]))
        if hidden_executables:
            result.add_finding("Medium", "Double-extension executable in archive", "An executable or script uses multiple filename extensions.", 12, f"{hidden_executables} entry(s)")
        if encrypted:
            result.add_finding("Info", "Password-protected archive content", "Encrypted entries cannot be inspected without a password.", 2, f"{encrypted} entry(s)")

    def _analyze_tar(self, result: AnalysisResult) -> None:
        entries = []
        unsafe = 0
        with tarfile.open(result.path, "r:*") as archive:
            members = archive.getmembers()
            for member in members[:100_000]:
                posix = PurePosixPath(member.name.replace("\\", "/"))
                traversal = posix.is_absolute() or ".." in posix.parts
                unsafe += int(traversal)
                entries.append({
                    "name": member.name,
                    "size": member.size,
                    "type": "directory" if member.isdir() else "file" if member.isfile() else "link" if member.issym() else "other",
                    "mode": oct(member.mode),
                    "user": member.uname,
                    "group": member.gname,
                    "link": member.linkname,
                    "path_traversal": traversal,
                })
        result.sections["Archive entries"] = entries
        result.metadata["Archive"] = {"Entry count": len(entries), "Unsafe paths": unsafe}
        if unsafe:
            result.add_finding("High", "Archive path traversal entries", "One or more TAR members contain absolute paths or parent traversal components.", 30, f"{unsafe} entry(s)")
