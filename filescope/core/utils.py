from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import mimetypes
import os
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

from .models import StringArtifact

ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")
UTF16LE_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
URL_RE = re.compile(r"\bhttps?://[^\s\"'<>]{4,}", re.I)
DOMAIN_RE = re.compile(r"(?<![@\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|co|gov|edu|mil|app|dev|cloud|online|site|info|biz|xyz|ru|cn|uk|de|jp|fr|au|ca)(?![\w.-])", re.I)
IPV4_RE = re.compile(r"(?<!\d)(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\d)")
IPV6_CANDIDATE_RE = re.compile(r"(?<![A-F0-9:])([A-F0-9]*:[A-F0-9:]+)(?![A-F0-9:])", re.I)
MUTEX_RE = re.compile(r"\b(?:Global|Local)\\[A-Za-z0-9_.{}()\-]{3,}\b", re.I)
NAMED_PIPE_RE = re.compile(r"\\\\\.\\pipe\\[A-Za-z0-9_.$\-\\/]{2,}", re.I)
USER_AGENT_RE = re.compile(r"(?:Mozilla/5\.0[^\r\n\x00]{0,300}|(?:curl|Wget|python-requests|okhttp|Dalvik)/[^\s\r\n\x00]{1,120})", re.I)
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
REGISTRY_RE = re.compile(r"\b(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS)|HKLM|HKCU|HKCR)\\[^\r\n\x00]+", re.I)
WIN_PATH_RE = re.compile(r"\b[A-Z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*", re.I)
HASH_RE = re.compile(r"\b(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b", re.I)
CRYPTO_RE = re.compile(r"\b(?:bc1[a-z0-9]{20,70}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40})\b")

SUSPICIOUS_COMMANDS = (
    "powershell", "cmd.exe", "wscript", "cscript", "rundll32", "regsvr32",
    "mshta", "certutil", "bitsadmin", "curl ", "wget ", "schtasks", "wmic",
)

MAGIC_SIGNATURES: list[tuple[bytes, str, str]] = [
    (b"MZ", "Windows PE executable", "application/vnd.microsoft.portable-executable"),
    (b"\x7fELF", "ELF executable", "application/x-elf"),
    (b"PK\x03\x04", "ZIP-based archive", "application/zip"),
    (b"PK\x05\x06", "Empty ZIP archive", "application/zip"),
    (b"\x89PNG\r\n\x1a\n", "PNG image", "image/png"),
    (b"\xff\xd8\xff", "JPEG image", "image/jpeg"),
    (b"GIF87a", "GIF image", "image/gif"),
    (b"GIF89a", "GIF image", "image/gif"),
    (b"BM", "BMP image", "image/bmp"),
    (b"RIFF", "RIFF container", "application/octet-stream"),
    (b"%PDF-", "PDF document", "application/pdf"),
    (b"SQLite format 3\x00", "SQLite database", "application/vnd.sqlite3"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE compound document", "application/x-ole-storage"),
    (b"\x1f\x8b", "GZIP archive", "application/gzip"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive", "application/x-7z-compressed"),
    (b"Rar!\x1a\x07", "RAR archive", "application/vnd.rar"),
]

EXTENSION_TYPES = {
    ".apk": ("Android APK package", "application/vnd.android.package-archive"),
    ".apks": ("Android split package set", "application/zip"),
    ".xapk": ("Android XAPK package", "application/zip"),
    ".apkm": ("Android APKM package", "application/zip"),
    ".docx": ("Microsoft Word document", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
    ".xlsx": ("Microsoft Excel workbook", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
    ".pptx": ("Microsoft PowerPoint presentation", "application/vnd.openxmlformats-officedocument.presentationml.presentation"),
    ".jar": ("Java archive", "application/java-archive"),
    ".dex": ("Android DEX bytecode", "application/octet-stream"),
    ".xml": ("XML document", "application/xml"),
    ".json": ("JSON document", "application/json"),
    ".csv": ("CSV document", "text/csv"),
    ".tsv": ("TSV document", "text/tab-separated-values"),
    ".ini": ("INI configuration", "text/plain"),
    ".log": ("Log file", "text/plain"),
    ".txt": ("Text document", "text/plain"),
    ".db": ("Database file", "application/octet-stream"),
    ".sqlite": ("SQLite database", "application/vnd.sqlite3"),
    ".sqlite3": ("SQLite database", "application/vnd.sqlite3"),
    ".exe": ("Windows PE executable", "application/vnd.microsoft.portable-executable"),
    ".dll": ("Windows PE library", "application/vnd.microsoft.portable-executable"),
    ".sys": ("Windows PE driver", "application/vnd.microsoft.portable-executable"),
}


def human_size(size: int) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.2f} {unit}"
        value /= 1024
    return f"{size} B"


def iso_time(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).astimezone().isoformat(timespec="seconds")


def file_hashes(path: Path, chunk_size: int = 1024 * 1024) -> dict[str, str]:
    digests = {name: hashlib.new(name) for name in ("md5", "sha1", "sha256")}
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            for digest in digests.values():
                digest.update(chunk)
    return {name.upper().replace("SHA", "SHA-"): digest.hexdigest() for name, digest in digests.items()}


def read_prefix(path: Path, limit: int = 1024 * 1024) -> bytes:
    with path.open("rb") as handle:
        return handle.read(limit)


def detect_type(path: Path, header: bytes) -> tuple[str, str, bool]:
    ext = path.suffix.lower()
    ext_type = EXTENSION_TYPES.get(ext)
    magic_type: tuple[str, str] | None = None
    for signature, label, mime in MAGIC_SIGNATURES:
        if header.startswith(signature):
            magic_type = (label, mime)
            break
    if header.startswith(b"dex\n"):
        magic_type = ("Android DEX bytecode", "application/octet-stream")
    if header.startswith(b"RIFF") and header[8:12] == b"WEBP":
        magic_type = ("WebP image", "image/webp")
    if magic_type and magic_type[0].startswith("ZIP") and ext_type:
        return ext_type[0], ext_type[1], False
    if magic_type:
        mismatch = bool(ext_type and ext_type[0] != magic_type[0] and not magic_type[0].startswith("ZIP"))
        if not ext_type and ext:
            guessed_mime, _ = mimetypes.guess_type(path.name)
            if guessed_mime:
                expected_family = guessed_mime.split("/", 1)[0]
                actual_family = magic_type[1].split("/", 1)[0]
                mismatch = expected_family != actual_family or (expected_family == "application" and guessed_mime != magic_type[1])
        return magic_type[0], magic_type[1], mismatch
    if ext_type:
        return ext_type[0], ext_type[1], False
    guessed, _ = mimetypes.guess_type(path.name)
    return "Unknown binary", guessed or "application/octet-stream", False


def looks_text(data: bytes) -> bool:
    if not data:
        return True
    if data.startswith((b"\xff\xfe", b"\xfe\xff", b"\xef\xbb\xbf")):
        return True
    sample = data[:8192]
    if b"\x00" in sample:
        return False
    printable = sum(1 for byte in sample if byte in b"\t\r\n" or 32 <= byte <= 126 or byte >= 128)
    return printable / max(1, len(sample)) >= 0.85


def decode_text(data: bytes) -> tuple[str, str]:
    if data.startswith(b"\xef\xbb\xbf"):
        return data.decode("utf-8-sig", errors="replace"), "UTF-8 BOM"
    if data.startswith(b"\xff\xfe"):
        return data.decode("utf-16-le", errors="replace"), "UTF-16 LE"
    if data.startswith(b"\xfe\xff"):
        return data.decode("utf-16-be", errors="replace"), "UTF-16 BE"
    for encoding in ("utf-8", "cp1252", "latin-1"):
        try:
            return data.decode(encoding), encoding.upper()
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace"), "UTF-8 (replacement)"


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def entropy_profile(path: Path, block_size: int = 64 * 1024, max_blocks: int = 4096) -> dict[str, Any]:
    blocks: list[dict[str, Any]] = []
    total_counts = Counter()
    total_size = 0
    with path.open("rb") as handle:
        index = 0
        while index < max_blocks and (chunk := handle.read(block_size)):
            entropy = shannon_entropy(chunk)
            blocks.append({"offset": index * block_size, "size": len(chunk), "entropy": round(entropy, 4)})
            total_counts.update(chunk)
            total_size += len(chunk)
            index += 1
    overall = 0.0
    if total_size:
        overall = -sum((count / total_size) * math.log2(count / total_size) for count in total_counts.values())
    return {
        "overall": round(overall, 4),
        "block_size": block_size,
        "blocks": blocks,
        "truncated": path.stat().st_size > block_size * max_blocks,
    }


def categorize_string(value: str) -> str:
    low = value.lower()
    if URL_RE.search(value):
        return "URL"
    if EMAIL_RE.search(value):
        return "Email"
    if IPV4_RE.search(value):
        return "IP address"
    if REGISTRY_RE.search(value):
        return "Registry path"
    if WIN_PATH_RE.search(value):
        return "Windows path"
    if any(command in low for command in SUSPICIOUS_COMMANDS):
        return "Command"
    if "api_key" in low or "apikey" in low or "secret" in low or "token=" in low or "password" in low:
        return "Possible credential"
    if DOMAIN_RE.search(value):
        return "Domain"
    return "General"


def extract_strings(path: Path, min_length: int = 4, max_bytes: int = 64 * 1024 * 1024, max_strings: int = 100_000) -> tuple[list[StringArtifact], bool]:
    size = path.stat().st_size
    with path.open("rb") as handle:
        data = handle.read(max_bytes)
    ascii_re = re.compile(rb"[\x20-\x7e]{%d,}" % min_length)
    utf16_re = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_length)
    items: list[StringArtifact] = []
    seen: set[tuple[int, str]] = set()
    for match in ascii_re.finditer(data):
        value = match.group().decode("ascii", errors="ignore")
        key = (match.start(), value)
        if key not in seen:
            seen.add(key)
            items.append(StringArtifact(match.start(), "ASCII", value, categorize_string(value)))
            if len(items) >= max_strings:
                return items, True
    for match in utf16_re.finditer(data):
        value = match.group().decode("utf-16-le", errors="ignore")
        key = (match.start(), value)
        if key not in seen:
            seen.add(key)
            items.append(StringArtifact(match.start(), "UTF-16 LE", value, categorize_string(value)))
            if len(items) >= max_strings:
                return sorted(items, key=lambda item: item.offset), True
    return sorted(items, key=lambda item: item.offset), size > max_bytes


def extract_iocs(strings: Iterable[StringArtifact | str]) -> dict[str, list[str]]:
    buckets: dict[str, set[str]] = {
        "URLs": set(), "Domains": set(), "IPv4": set(), "IPv6": set(), "Emails": set(),
        "Hashes": set(), "Registry paths": set(), "Windows paths": set(),
        "Mutex names": set(), "Named pipes": set(), "User agents": set(),
        "Cryptocurrency addresses": set(), "Commands": set(),
    }
    for item in strings:
        value = item.value if isinstance(item, StringArtifact) else item
        buckets["URLs"].update(URL_RE.findall(value))
        buckets["Domains"].update(match.group(0) for match in DOMAIN_RE.finditer(value))
        buckets["IPv4"].update(IPV4_RE.findall(value))
        for candidate in IPV6_CANDIDATE_RE.findall(value):
            try:
                if ipaddress.ip_address(candidate).version == 6:
                    buckets["IPv6"].add(candidate)
            except ValueError:
                pass
        buckets["Emails"].update(EMAIL_RE.findall(value))
        buckets["Hashes"].update(HASH_RE.findall(value))
        buckets["Registry paths"].update(REGISTRY_RE.findall(value))
        buckets["Windows paths"].update(WIN_PATH_RE.findall(value))
        buckets["Mutex names"].update(MUTEX_RE.findall(value))
        buckets["Named pipes"].update(NAMED_PIPE_RE.findall(value))
        buckets["User agents"].update(USER_AGENT_RE.findall(value))
        buckets["Cryptocurrency addresses"].update(CRYPTO_RE.findall(value))
        if any(command in value.lower() for command in SUSPICIOUS_COMMANDS):
            buckets["Commands"].add(value[:500])
    urls = buckets["URLs"]
    for url in urls:
        host_match = re.match(r"https?://([^/:?#]+)", url, re.I)
        if host_match:
            buckets["Domains"].add(host_match.group(1).lower())
    return {key: sorted(values, key=str.lower) for key, values in buckets.items() if values}


def make_hex_dump(data: bytes, base_offset: int = 0, width: int = 16) -> str:
    output: list[str] = []
    for offset in range(0, len(data), width):
        chunk = data[offset: offset + width]
        hex_part = " ".join(f"{byte:02X}" for byte in chunk)
        ascii_part = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in chunk)
        output.append(f"{base_offset + offset:08X}  {hex_part:<{width * 3 - 1}}  |{ascii_part}|")
    return "\n".join(output)


def iter_hex_dump(path: Path, chunk_size: int = 1024 * 1024, width: int = 16) -> Iterator[str]:
    offset = 0
    carry = b""
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            data = carry + chunk
            usable = len(data) - (len(data) % width)
            if usable:
                yield make_hex_dump(data[:usable], offset, width)
                offset += usable
            carry = data[usable:]
        if carry:
            yield make_hex_dump(carry, offset, width)


def common_metadata(path: Path) -> dict[str, Any]:
    stat = path.stat()
    return {
        "File name": path.name,
        "Full path": str(path.resolve()),
        "Extension": path.suffix.lower() or "(none)",
        "Size": human_size(stat.st_size),
        "Size (bytes)": stat.st_size,
        "Created": iso_time(stat.st_ctime),
        "Modified": iso_time(stat.st_mtime),
        "Accessed": iso_time(stat.st_atime),
        "Read only": not os.access(path, os.W_OK),
        "Hidden": path.name.startswith(".") or (os.name == "nt" and bool(getattr(stat, "st_file_attributes", 0) & 2)),
    }


def json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, dict):
        return {str(key): json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [json_safe(item) for item in value]
    try:
        json.dumps(value)
        return value
    except (TypeError, ValueError):
        return str(value)


def flatten_mapping(value: Any, prefix: str = "") -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            rows.extend(flatten_mapping(item, path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            path = f"{prefix}[{index}]"
            rows.extend(flatten_mapping(item, path))
    else:
        rows.append((prefix, str(value)))
    return rows
