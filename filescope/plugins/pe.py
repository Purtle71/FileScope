from __future__ import annotations

import datetime as dt
import json
import os
import struct
import subprocess
from pathlib import Path
from typing import Any

from filescope.core.models import AnalysisResult
from filescope.core.utils import human_size, shannon_entropy

from .base import AnalysisPlugin

SUSPICIOUS_APIS = {
    "VirtualAlloc": ("Memory allocation", 3),
    "VirtualAllocEx": ("Remote-process memory allocation", 7),
    "WriteProcessMemory": ("Remote-process memory write", 9),
    "CreateRemoteThread": ("Remote-thread creation", 10),
    "NtCreateThreadEx": ("Native remote-thread creation", 10),
    "WinExec": ("Command execution", 6),
    "ShellExecuteA": ("Shell execution", 4),
    "ShellExecuteW": ("Shell execution", 4),
    "URLDownloadToFileA": ("File download", 7),
    "URLDownloadToFileW": ("File download", 7),
    "InternetOpenA": ("WinINet networking", 3),
    "InternetOpenW": ("WinINet networking", 3),
    "InternetReadFile": ("WinINet data read", 4),
    "RegSetValueExA": ("Registry modification", 4),
    "RegSetValueExW": ("Registry modification", 4),
    "CreateServiceA": ("Service creation", 8),
    "CreateServiceW": ("Service creation", 8),
    "AdjustTokenPrivileges": ("Token privilege adjustment", 7),
    "IsDebuggerPresent": ("Debugger detection", 3),
    "CheckRemoteDebuggerPresent": ("Debugger detection", 3),
}

PACKER_MARKERS = {
    "UPX": ["UPX0", "UPX1", "UPX2", "UPX!"],
    "ASPack": [".aspack", ".adata"],
    "Themida/WinLicense": [".themida", "WinLicense", "Themida"],
    "VMProtect": [".vmp0", ".vmp1", "VMProtect"],
    "PyInstaller": ["pyi-windows-manifest-filename", "PYZ-00.pyz", "pyiboot01_bootstrap"],
    "NSIS": ["Nullsoft.NSIS", "$PLUGINSDIR"],
    "Inno Setup": ["Inno Setup Setup Data", "Inno Setup"],
    "AutoIt": ["AU3!EA06", "AutoIt v3"],
    "Electron": ["electron.asar", "app.asar", "Electron Framework"],
    "Go": ["Go build ID:", "runtime.main", "go.buildid"],
    "Rust": ["rust_begin_unwind", "rust_eh_personality"],
    "Delphi": ["Embarcadero Delphi", "Borland Delphi"],
}

MACHINE_TYPES = {
    0x014C: "x86",
    0x8664: "x64",
    0x01C0: "ARM",
    0x01C4: "ARMv7",
    0xAA64: "ARM64",
    0x0200: "IA-64",
}

SUBSYSTEMS = {
    1: "Native",
    2: "Windows GUI",
    3: "Windows Console",
    5: "OS/2 Console",
    7: "POSIX Console",
    9: "Windows CE GUI",
    10: "EFI Application",
    11: "EFI Boot Service Driver",
    12: "EFI Runtime Driver",
    14: "Xbox",
    16: "Windows Boot Application",
}


class PEPlugin(AnalysisPlugin):
    name = "Windows PE analyzer"

    def supports(self, path: Path, header: bytes, detected_type: str) -> bool:
        return header.startswith(b"MZ") or path.suffix.lower() in {".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl"}

    def analyze(self, result: AnalysisResult, header: bytes) -> None:
        if not header.startswith(b"MZ"):
            result.warnings.append("The extension suggests a PE file, but the MZ signature is missing.")
            return
        self._fallback_headers(result)
        try:
            import pefile
        except ImportError:
            result.warnings.append("pefile is not installed; imports, exports, resources, and advanced PE metadata are unavailable.")
            self._scan_markers(result)
            self._authenticode(result)
            return
        pe = pefile.PE(str(result.path), fast_load=False)
        try:
            self._full_analysis(result, pe)
        finally:
            pe.close()
        self._scan_markers(result)
        self._authenticode(result)

    def _fallback_headers(self, result: AnalysisResult) -> None:
        with result.path.open("rb") as handle:
            dos = handle.read(64)
            if len(dos) < 64:
                raise ValueError("Truncated DOS header")
            pe_offset = struct.unpack_from("<I", dos, 0x3C)[0]
            handle.seek(pe_offset)
            signature = handle.read(4)
            if signature != b"PE\0\0":
                raise ValueError("Invalid PE signature")
            coff = handle.read(20)
            machine, section_count, timestamp, _, _, optional_size, characteristics = struct.unpack("<HHIIIHH", coff)
            optional = handle.read(optional_size)
        magic = struct.unpack_from("<H", optional, 0)[0] if len(optional) >= 2 else 0
        is_64 = magic == 0x20B
        entry_offset = 16
        image_base_offset = 24 if is_64 else 28
        subsystem_offset = 68
        entry_point = struct.unpack_from("<I", optional, entry_offset)[0] if len(optional) >= entry_offset + 4 else 0
        image_base = struct.unpack_from("<Q" if is_64 else "<I", optional, image_base_offset)[0] if len(optional) >= image_base_offset + (8 if is_64 else 4) else 0
        subsystem = struct.unpack_from("<H", optional, subsystem_offset)[0] if len(optional) >= subsystem_offset + 2 else 0
        compile_time = dt.datetime.fromtimestamp(timestamp, dt.timezone.utc).isoformat() if timestamp else "Not set"
        headers = {
            "PE offset": pe_offset,
            "Machine": MACHINE_TYPES.get(machine, f"0x{machine:04X}"),
            "Sections": section_count,
            "Compilation timestamp (UTC)": compile_time,
            "Optional header": "PE32+" if is_64 else "PE32" if magic == 0x10B else f"Unknown 0x{magic:04X}",
            "Entry point RVA": f"0x{entry_point:X}",
            "Image base": f"0x{image_base:X}",
            "Subsystem": SUBSYSTEMS.get(subsystem, str(subsystem)),
            "Characteristics": f"0x{characteristics:04X}",
        }
        result.metadata["PE headers"] = headers
        result.sections["PE headers"] = headers

    def _full_analysis(self, result: AnalysisResult, pe: Any) -> None:
        sections = []
        for section in pe.sections:
            name = section.Name.rstrip(b"\x00").decode("ascii", errors="replace")
            data = section.get_data()
            characteristics = int(section.Characteristics)
            sections.append({
                "name": name,
                "virtual_address": f"0x{int(section.VirtualAddress):X}",
                "virtual_size": int(section.Misc_VirtualSize),
                "raw_offset": int(section.PointerToRawData),
                "raw_size": int(section.SizeOfRawData),
                "entropy": round(shannon_entropy(data), 4),
                "readable": bool(characteristics & 0x40000000),
                "writable": bool(characteristics & 0x80000000),
                "executable": bool(characteristics & 0x20000000),
                "characteristics": f"0x{characteristics:08X}",
            })
            if (characteristics & 0x80000000) and (characteristics & 0x20000000):
                result.add_finding("Medium", "Writable and executable PE section", "A section is both writable and executable, which is unusual and can support runtime code modification.", 12, name)
            if sections[-1]["entropy"] >= 7.5 and len(data) >= 1024:
                result.add_finding("Medium", "High-entropy PE section", "A PE section may be packed, compressed, or encrypted.", 8, f"{name}: {sections[-1]['entropy']}")
        result.sections["PE sections"] = sections

        imports = []
        suspicious_hits = []
        for descriptor in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            dll = descriptor.dll.decode("ascii", errors="replace") if descriptor.dll else ""
            for imported in descriptor.imports:
                name = imported.name.decode("ascii", errors="replace") if imported.name else f"Ordinal {imported.ordinal}"
                imports.append({"dll": dll, "name": name, "address": f"0x{int(imported.address):X}"})
                base_name = name.split("@")[0]
                if base_name in SUSPICIOUS_APIS:
                    suspicious_hits.append((base_name, dll))
        result.sections["PE imports"] = imports
        result.metadata["Imported functions"] = len(imports)
        for api, dll in sorted(set(suspicious_hits)):
            description, points = SUSPICIOUS_APIS[api]
            result.add_finding("Medium", f"Sensitive API import: {api}", description + ". This can be legitimate; review surrounding behavior.", points, dll)

        exports = []
        directory = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
        if directory:
            for symbol in directory.symbols:
                exports.append({
                    "name": symbol.name.decode("ascii", errors="replace") if symbol.name else "",
                    "ordinal": int(symbol.ordinal),
                    "address_rva": f"0x{int(symbol.address):X}",
                    "forwarder": symbol.forwarder.decode("ascii", errors="replace") if symbol.forwarder else "",
                })
        result.sections["PE exports"] = exports

        resources = []
        manifests = []
        resource_type_names = {1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU", 5: "DIALOG", 6: "STRING", 9: "ACCELERATOR", 10: "RCDATA", 12: "GROUP_CURSOR", 14: "GROUP_ICON", 16: "VERSION", 24: "MANIFEST"}
        root = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
        if root:
            for type_entry in root.entries:
                type_id = int(type_entry.struct.Id) if not type_entry.name else -1
                type_name = str(type_entry.name) if type_entry.name else resource_type_names.get(type_id, str(type_id))
                if not hasattr(type_entry, "directory"):
                    continue
                for id_entry in type_entry.directory.entries:
                    id_name = str(id_entry.name) if id_entry.name else str(id_entry.struct.Id)
                    if not hasattr(id_entry, "directory"):
                        continue
                    for lang_entry in id_entry.directory.entries:
                        data_entry = lang_entry.data.struct
                        rva = int(data_entry.OffsetToData)
                        size = int(data_entry.Size)
                        try:
                            file_offset = int(pe.get_offset_from_rva(rva))
                        except Exception:
                            file_offset = -1
                        resource_row = {
                            "type": type_name,
                            "id": id_name,
                            "language": int(lang_entry.struct.Id),
                            "rva": rva,
                            "file_offset": file_offset,
                            "size": size,
                            "codepage": int(data_entry.CodePage),
                        }
                        resources.append(resource_row)
                        if type_id == 24 or str(type_name).upper() == "MANIFEST":
                            raw_manifest = pe.get_data(rva, size)
                            manifest_text = ""
                            for encoding in ("utf-8", "utf-16-le", "cp1252"):
                                try:
                                    manifest_text = raw_manifest.decode(encoding).strip("\x00")
                                    if "<" in manifest_text:
                                        break
                                except UnicodeDecodeError:
                                    continue
                            manifests.append({**resource_row, "xml": manifest_text[:2_000_000]})
        result.sections["PE resources"] = resources
        result.sections["PE manifests"] = manifests
        result.metadata["PE resources"] = len(resources)
        result.metadata["PE manifests"] = len(manifests)

        tls = []
        tls_dir = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
        if tls_dir:
            callbacks_va = int(getattr(tls_dir.struct, "AddressOfCallBacks", 0))
            callback_values = []
            if callbacks_va:
                try:
                    callback_rva = callbacks_va - int(pe.OPTIONAL_HEADER.ImageBase)
                    callback_offset = int(pe.get_offset_from_rva(callback_rva))
                    pointer_size = 8 if int(pe.OPTIONAL_HEADER.Magic) == 0x20B else 4
                    raw = pe.__data__
                    for index in range(256):
                        start = callback_offset + index * pointer_size
                        if start + pointer_size > len(raw):
                            break
                        value = struct.unpack_from("<Q" if pointer_size == 8 else "<I", raw, start)[0]
                        if value == 0:
                            break
                        callback_values.append(f"0x{value:X}")
                except Exception:
                    pass
            tls.append({"AddressOfCallbacks": f"0x{callbacks_va:X}", "Callbacks": callback_values})
            result.add_finding("Medium", "TLS directory present", "TLS callbacks can execute before the normal program entry point.", 5, tls[0]["AddressOfCallbacks"])
        result.sections["PE TLS"] = tls

        debug_rows = []
        for entry in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []):
            debug_rows.append({
                "type": int(entry.struct.Type),
                "size": int(entry.struct.SizeOfData),
                "timestamp": int(entry.struct.TimeDateStamp),
                "raw_offset": int(entry.struct.PointerToRawData),
            })
        result.sections["PE debug"] = debug_rows

        version_info = {}
        for file_info in getattr(pe, "FileInfo", []) or []:
            for item in file_info:
                if getattr(item, "Key", b"") == b"StringFileInfo":
                    for table in item.StringTable:
                        for key, value in table.entries.items():
                            version_info[key.decode(errors="replace")] = value.decode(errors="replace")
        if version_info:
            result.metadata["PE version information"] = version_info
            result.sections["PE version information"] = version_info

        optional = pe.OPTIONAL_HEADER
        security_dir = optional.DATA_DIRECTORY[4]
        signed = bool(int(security_dir.VirtualAddress) and int(security_dir.Size))
        result.metadata["PE certificate table"] = {
            "Present": signed,
            "File offset": int(security_dir.VirtualAddress),
            "Size": int(security_dir.Size),
        }
        if not signed:
            result.add_finding("Low", "Unsigned PE file", "No Authenticode certificate table is present. Many legitimate files are unsigned.", 5, result.path.name)

        overlay_offset = pe.get_overlay_data_start_offset()
        if overlay_offset is not None:
            overlay_size = result.path.stat().st_size - int(overlay_offset)
            result.sections["PE overlay"] = {"file_offset": int(overlay_offset), "size": overlay_size, "size_display": human_size(overlay_size)}
            if overlay_size > 0:
                result.add_finding("Info", "PE overlay data", "Data exists after the final mapped PE section.", 2, human_size(overlay_size))

        com_descriptor = optional.DATA_DIRECTORY[14]
        result.metadata[".NET assembly"] = bool(int(com_descriptor.VirtualAddress) and int(com_descriptor.Size))

    def _scan_markers(self, result: AnalysisResult) -> None:
        with result.path.open("rb") as handle:
            data = handle.read(min(result.path.stat().st_size, 64 * 1024 * 1024))
        text = data.decode("latin-1", errors="ignore")
        hits = []
        for product, markers in PACKER_MARKERS.items():
            matched = [marker for marker in markers if marker in text]
            if matched:
                hits.append({"product": product, "markers": matched})
        section_names = [str(row.get("name", "")) for row in result.sections.get("PE sections", [])]
        for product, markers in PACKER_MARKERS.items():
            matched_sections = [marker for marker in markers if marker in section_names]
            if matched_sections and not any(hit["product"] == product for hit in hits):
                hits.append({"product": product, "markers": matched_sections})
        result.sections["Packers and compilers"] = hits
        for hit in hits:
            result.add_finding("Info", f"Possible {hit['product']} build or packaging", "Signature markers associated with this compiler, runtime, installer, or packer were found.", 2 if hit["product"] not in {"UPX", "Themida/WinLicense", "VMProtect", "ASPack"} else 7, ", ".join(hit["markers"]))

    def _authenticode(self, result: AnalysisResult) -> None:
        if os.name != "nt":
            result.metadata["Authenticode"] = {"Status": "Requires Windows for trust-chain verification"}
            return
        escaped = str(result.path).replace("'", "''")
        command = [
            "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
            f"$s=Get-AuthenticodeSignature -LiteralPath '{escaped}'; [pscustomobject]@{{Status=$s.Status.ToString();StatusMessage=$s.StatusMessage;SignerSubject=$s.SignerCertificate.Subject;SignerIssuer=$s.SignerCertificate.Issuer;Thumbprint=$s.SignerCertificate.Thumbprint;NotBefore=$s.SignerCertificate.NotBefore;NotAfter=$s.SignerCertificate.NotAfter}} | ConvertTo-Json -Compress",
        ]
        try:
            completed = subprocess.run(command, capture_output=True, text=True, timeout=20, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            if completed.returncode == 0 and completed.stdout.strip():
                value = json.loads(completed.stdout)
                result.metadata["Authenticode"] = value
                result.sections["Digital signature"] = value
                if value.get("Status") not in {"Valid", "NotSigned"}:
                    result.add_finding("Medium", "Authenticode validation issue", "Windows did not report a valid signature.", 12, str(value.get("StatusMessage", value.get("Status", "Unknown"))))
            else:
                result.warnings.append("Authenticode check failed: " + (completed.stderr.strip() or "unknown PowerShell error"))
        except Exception as exc:
            result.warnings.append(f"Authenticode check failed: {exc}")
