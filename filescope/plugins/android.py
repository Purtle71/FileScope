from __future__ import annotations

import io
import json
import re
import struct
import zipfile
from pathlib import Path
from typing import Any
import xml.etree.ElementTree as ET

from filescope.core.models import AnalysisResult, StringArtifact
from filescope.core.utils import categorize_string, extract_iocs, shannon_entropy

from .base import AnalysisPlugin

ANDROID_EXTENSIONS = {".apk", ".apks", ".xapk", ".apkm"}
ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

PERMISSION_RISK: dict[str, tuple[str, int, str]] = {
    "android.permission.INTERNET": ("Low", 0, "Allows network connections."),
    "android.permission.ACCESS_NETWORK_STATE": ("Low", 0, "Reads network connection state."),
    "android.permission.RECORD_AUDIO": ("High", 12, "Allows microphone recording."),
    "android.permission.CAMERA": ("High", 8, "Allows camera access."),
    "android.permission.ACCESS_FINE_LOCATION": ("High", 10, "Allows precise location access."),
    "android.permission.ACCESS_COARSE_LOCATION": ("Medium", 6, "Allows approximate location access."),
    "android.permission.READ_CONTACTS": ("High", 10, "Allows reading contacts."),
    "android.permission.WRITE_CONTACTS": ("High", 10, "Allows modifying contacts."),
    "android.permission.READ_SMS": ("Critical", 18, "Allows reading SMS messages."),
    "android.permission.SEND_SMS": ("Critical", 18, "Allows sending SMS messages."),
    "android.permission.RECEIVE_SMS": ("High", 12, "Allows receiving SMS messages."),
    "android.permission.READ_CALL_LOG": ("Critical", 18, "Allows reading call history."),
    "android.permission.WRITE_CALL_LOG": ("Critical", 18, "Allows changing call history."),
    "android.permission.READ_PHONE_STATE": ("High", 8, "Allows reading phone and cellular state."),
    "android.permission.CALL_PHONE": ("High", 10, "Allows placing phone calls."),
    "android.permission.READ_EXTERNAL_STORAGE": ("Medium", 4, "Allows reading shared storage on older Android versions."),
    "android.permission.WRITE_EXTERNAL_STORAGE": ("Medium", 5, "Allows writing shared storage on older Android versions."),
    "android.permission.MANAGE_EXTERNAL_STORAGE": ("Critical", 18, "Allows broad shared-storage access."),
    "android.permission.REQUEST_INSTALL_PACKAGES": ("Critical", 18, "Allows requesting installation of other packages."),
    "android.permission.SYSTEM_ALERT_WINDOW": ("Critical", 18, "Allows drawing over other applications."),
    "android.permission.QUERY_ALL_PACKAGES": ("High", 8, "Allows broad discovery of installed applications."),
    "android.permission.PACKAGE_USAGE_STATS": ("Critical", 15, "Allows access to app usage history after user approval."),
    "android.permission.BIND_ACCESSIBILITY_SERVICE": ("Critical", 20, "Accessibility services can observe and control device interactions after user approval."),
    "android.permission.BIND_DEVICE_ADMIN": ("Critical", 20, "Device administrator capabilities require user activation."),
    "android.permission.FOREGROUND_SERVICE": ("Low", 1, "Allows long-running foreground services."),
    "android.permission.POST_NOTIFICATIONS": ("Low", 0, "Allows notifications after user approval."),
    "android.permission.BLUETOOTH_CONNECT": ("Medium", 4, "Allows connecting to nearby Bluetooth devices."),
    "android.permission.BLUETOOTH_SCAN": ("Medium", 5, "Allows scanning for nearby Bluetooth devices."),
}

API_PRESETS: dict[str, list[bytes]] = {
    "Microphone access": [b"Landroid/media/AudioRecord;", b"Landroid/media/MediaRecorder;", b"startRecording", b"RECORD_AUDIO"],
    "Camera access": [b"Landroid/hardware/Camera;", b"Landroid/hardware/camera2/", b"android.permission.CAMERA"],
    "Location tracking": [b"Landroid/location/LocationManager;", b"FusedLocationProviderClient", b"ACCESS_FINE_LOCATION"],
    "Network requests": [b"Lokhttp3/", b"Lretrofit2/", b"Ljava/net/HttpURLConnection;", b"Lorg/apache/http/"],
    "WebView": [b"Landroid/webkit/WebView;", b"addJavascriptInterface", b"setJavaScriptEnabled"],
    "Dynamic code loading": [b"Ldalvik/system/DexClassLoader;", b"Ldalvik/system/PathClassLoader;", b"loadDex", b"System.loadLibrary"],
    "Reflection": [b"Ljava/lang/reflect/", b"Class.forName", b"getDeclaredMethod"],
    "Root detection": [b"/system/xbin/su", b"/system/bin/su", b"test-keys", b"magisk"],
    "Emulator detection": [b"goldfish", b"ranchu", b"generic_x86", b"qemu"],
    "Native methods": [b" native ", b"RegisterNatives", b"JNI_OnLoad"],
    "Encryption libraries": [b"Ljavax/crypto/", b"Cipher.getInstance", b"SecretKeySpec"],
}

SDK_MARKERS: dict[str, list[str]] = {
    "Firebase": ["com/google/firebase", "firebase_analytics", "google-services.json"],
    "Google Mobile Ads": ["com/google/android/gms/ads", "admob"],
    "Unity Ads": ["com/unity3d/ads", "unityads"],
    "Unity Analytics": ["com/unity3d/services/analytics", "UnityAnalytics"],
    "Facebook SDK": ["com/facebook/", "facebook_app_id"],
    "AppsFlyer": ["com/appsflyer", "AppsFlyerLib"],
    "Adjust": ["com/adjust/sdk", "AdjustConfig"],
    "Crashlytics": ["com/google/firebase/crashlytics", "crashlytics"],
    "OneSignal": ["com/onesignal", "OneSignal"],
    "GameAnalytics": ["com/gameanalytics", "GameAnalytics"],
    "Amplitude": ["com/amplitude", "AmplitudeClient"],
    "Sentry": ["io/sentry", "sentry.properties"],
    "Branch": ["io/branch", "Branch.getInstance"],
    "Flurry": ["com/flurry", "FlurryAgent"],
    "AppLovin": ["com/applovin", "applovin.sdk.key"],
    "IronSource": ["com/ironsource", "IronSource"],
}


class AndroidPlugin(AnalysisPlugin):
    name = "Android, DEX, split-package, and Unity analyzer"

    def supports(self, path: Path, header: bytes, detected_type: str) -> bool:
        return path.suffix.lower() in ANDROID_EXTENSIONS or header.startswith(b"dex\n")

    def analyze(self, result: AnalysisResult, header: bytes) -> None:
        if header.startswith(b"dex\n"):
            raw = result.path.read_bytes()
            result.sections["DEX"] = self._inspect_dex(raw, result.path.name, result)
            return
        if not zipfile.is_zipfile(result.path):
            result.warnings.append("Android package extension detected, but the file is not a readable ZIP container.")
            return
        ext = result.path.suffix.lower()
        if ext == ".apk":
            with zipfile.ZipFile(result.path) as archive:
                self._inspect_apk_archive(archive, result, result.path.name)
        else:
            self._inspect_bundle(result)

    def _inspect_bundle(self, result: AnalysisResult) -> None:
        bundle_rows = []
        base_name = ""
        with zipfile.ZipFile(result.path) as bundle:
            names = bundle.namelist()
            manifest_json = {}
            for candidate in ("toc.pb", "manifest.json", "info.json"):
                if candidate in names and candidate.endswith(".json"):
                    try:
                        manifest_json[candidate] = json.loads(bundle.read(candidate).decode("utf-8", errors="replace"))
                    except Exception:
                        pass
            apk_infos = [info for info in bundle.infolist() if info.filename.lower().endswith(".apk")]
            for info in apk_infos:
                kind, dimension, value = self._classify_split(info.filename)
                row = {
                    "name": info.filename,
                    "size": info.file_size,
                    "compressed": info.compress_size,
                    "kind": kind,
                    "dimension": dimension,
                    "value": value,
                    "selected_for_universal": kind == "base" or dimension not in {"abi", "density", "language"},
                }
                bundle_rows.append(row)
                if kind == "base" and not base_name:
                    base_name = info.filename
            if not base_name and apk_infos:
                base_name = min(apk_infos, key=lambda info: ("base" not in info.filename.lower(), len(info.filename))).filename
            result.sections["Android split packages"] = bundle_rows
            result.sections["Android bundle manifests"] = manifest_json
            result.metadata["Android bundle"] = {
                "APK count": len(apk_infos),
                "Base APK": base_name or "Not identified",
                "ABI splits": sorted({row["value"] for row in bundle_rows if row["dimension"] == "abi"}),
                "Density splits": sorted({row["value"] for row in bundle_rows if row["dimension"] == "density"}),
                "Language splits": sorted({row["value"] for row in bundle_rows if row["dimension"] == "language"}),
            }
            if base_name:
                try:
                    data = bundle.read(base_name)
                    with zipfile.ZipFile(io.BytesIO(data)) as base_apk:
                        self._inspect_apk_archive(base_apk, result, base_name)
                except Exception as exc:
                    result.warnings.append(f"Could not inspect base APK {base_name}: {exc}")
            split_manifests = []
            for info in apk_infos[:100]:
                if info.filename == base_name or info.file_size > 512 * 1024 * 1024:
                    continue
                try:
                    with zipfile.ZipFile(io.BytesIO(bundle.read(info))) as split_apk:
                        if "AndroidManifest.xml" not in split_apk.namelist():
                            continue
                        xml_bytes = split_apk.read("AndroidManifest.xml")
                        xml_text, root = self._decode_manifest(xml_bytes)
                        split_manifests.append({
                            "split": info.filename,
                            "manifest_decoded": bool(root is not None),
                            "package": root.attrib.get("package", "") if root is not None else "",
                            "split_name": root.attrib.get("split", "") if root is not None else "",
                            "preview": xml_text[:2000],
                        })
                except Exception:
                    continue
            result.sections["Android split manifests"] = split_manifests

    def _classify_split(self, name: str) -> tuple[str, str, str]:
        low = Path(name).name.lower()
        stem = Path(low).stem
        if low in {"base.apk", "base-master.apk"} or stem == "base" or "base-master" in stem:
            return "base", "base", "base"
        abi_map = {
            "arm64_v8a": "arm64-v8a", "arm64-v8a": "arm64-v8a", "armeabi_v7a": "armeabi-v7a",
            "armeabi-v7a": "armeabi-v7a", "x86_64": "x86_64", "x86-64": "x86_64", "x86": "x86",
        }
        for marker, value in abi_map.items():
            if marker in stem:
                return "configuration", "abi", value
        density_markers = ("ldpi", "mdpi", "hdpi", "xhdpi", "xxhdpi", "xxxhdpi", "tvdpi")
        for marker in density_markers:
            if marker in stem:
                return "configuration", "density", marker
        language_match = re.search(r"(?:config[._-])([a-z]{2,3}(?:[-_][a-z]{2})?)$", stem)
        if language_match:
            return "configuration", "language", language_match.group(1)
        return "split", "feature", stem

    def _inspect_apk_archive(self, archive: zipfile.ZipFile, result: AnalysisResult, label: str) -> None:
        names = archive.namelist()
        native_libs = []
        architectures = set()
        dex_rows = []
        assets = []
        signing = []
        for info in archive.infolist():
            name = info.filename
            lower = name.lower()
            if lower.startswith("lib/") and lower.endswith(".so"):
                parts = name.split("/")
                architecture = parts[1] if len(parts) > 2 else "unknown"
                architectures.add(architecture)
                native_libs.append({"name": name, "architecture": architecture, "size": info.file_size, "compressed": info.compress_size})
            elif re.fullmatch(r"classes\d*\.dex", Path(lower).name):
                try:
                    dex_data = archive.read(info)
                    dex_rows.append(self._inspect_dex(dex_data, name, result))
                except Exception as exc:
                    dex_rows.append({"name": name, "error": str(exc)})
            elif lower.startswith("assets/"):
                assets.append({"name": name, "size": info.file_size, "compressed": info.compress_size})
            elif lower.startswith("meta-inf/") and lower.endswith((".rsa", ".dsa", ".ec", ".sf", "manifest.mf")):
                signing.append({"name": name, "size": info.file_size})
        result.sections["Android native libraries"] = native_libs
        result.sections["DEX"] = dex_rows
        result.sections["Android assets"] = assets[:100_000]
        result.sections["Android signing files"] = signing
        result.metadata["Android package"] = {
            "Inspected package": label,
            "Entry count": len(names),
            "DEX files": len(dex_rows),
            "Native libraries": len(native_libs),
            "Architectures": sorted(architectures),
            "Assets": len(assets),
            "Signing files": len(signing),
        }
        if "AndroidManifest.xml" in names:
            xml_bytes = archive.read("AndroidManifest.xml")
            xml_text, root = self._decode_manifest(xml_bytes)
            result.sections["Android manifest XML"] = xml_text
            if root is not None:
                self._parse_manifest_root(result, root)
            else:
                result.warnings.append("AndroidManifest.xml could not be decoded. Install androguard for binary Android XML support.")
        unity = self._detect_unity(names, archive)
        result.sections["Unity"] = unity
        result.metadata["Unity"] = unity.get("summary", {})
        if unity.get("detected"):
            result.add_finding("Info", "Unity application detected", "Unity engine files were found. The analysis path depends on whether the build uses Mono or IL2CPP.", 0, unity.get("analysis_path", ""))
        trackers = self._detect_sdks(names, dex_rows)
        result.sections["SDKs and trackers"] = trackers
        result.metadata["Detected SDKs and trackers"] = len(trackers)

    def _decode_manifest(self, data: bytes) -> tuple[str, ET.Element | None]:
        if data.lstrip().startswith(b"<"):
            text = data.decode("utf-8", errors="replace")
            try:
                return text, ET.fromstring(text)
            except ET.ParseError:
                return text, None
        try:
            from androguard.core.axml import AXMLPrinter
            printer = AXMLPrinter(data)
            try:
                root = printer.get_xml_obj()
                text = ET.tostring(root, encoding="unicode")
                return text, root
            except Exception:
                xml = printer.get_xml()
                if isinstance(xml, bytes):
                    text = xml.decode("utf-8", errors="replace")
                else:
                    text = str(xml)
                return text, ET.fromstring(text)
        except Exception:
            return "Binary Android XML. Install androguard to decode this manifest.", None

    def _parse_manifest_root(self, result: AnalysisResult, root: ET.Element) -> None:
        app = root.find("application")
        manifest_info = {
            "Package": root.attrib.get("package", ""),
            "Version code": root.attrib.get(ANDROID_NS + "versionCode", ""),
            "Version name": root.attrib.get(ANDROID_NS + "versionName", ""),
            "Split": root.attrib.get("split", ""),
            "Compile SDK": root.attrib.get(ANDROID_NS + "compileSdkVersion", ""),
        }
        uses_sdk = root.find("uses-sdk")
        if uses_sdk is not None:
            manifest_info["Minimum SDK"] = uses_sdk.attrib.get(ANDROID_NS + "minSdkVersion", "")
            manifest_info["Target SDK"] = uses_sdk.attrib.get(ANDROID_NS + "targetSdkVersion", "")
            manifest_info["Maximum SDK"] = uses_sdk.attrib.get(ANDROID_NS + "maxSdkVersion", "")
        if app is not None:
            manifest_info["Application name"] = app.attrib.get(ANDROID_NS + "name", "")
            manifest_info["Application label"] = app.attrib.get(ANDROID_NS + "label", "")
            manifest_info["Debuggable"] = app.attrib.get(ANDROID_NS + "debuggable", "false")
            manifest_info["Backup allowed"] = app.attrib.get(ANDROID_NS + "allowBackup", "")
            manifest_info["Cleartext traffic"] = app.attrib.get(ANDROID_NS + "usesCleartextTraffic", "")
            manifest_info["Network security config"] = app.attrib.get(ANDROID_NS + "networkSecurityConfig", "")
        result.metadata["Android manifest"] = manifest_info
        result.sections["Android manifest"] = manifest_info

        permission_rows = []
        for tag in ("uses-permission", "uses-permission-sdk-23", "permission"):
            for node in root.findall(tag):
                name = node.attrib.get(ANDROID_NS + "name", "")
                if not name:
                    continue
                severity, points, explanation = PERMISSION_RISK.get(name, ("Info", 0, "Permission not classified by the built-in rules."))
                permission_rows.append({
                    "name": name,
                    "severity": severity,
                    "score": points,
                    "explanation": explanation,
                    "max_sdk": node.attrib.get(ANDROID_NS + "maxSdkVersion", ""),
                })
                if points:
                    result.add_finding(severity, f"Android permission: {name.rsplit('.', 1)[-1]}", explanation, points, name)
        result.sections["Android permissions"] = permission_rows
        result.metadata["Android permission count"] = len(permission_rows)

        components = []
        if app is not None:
            for component_tag in ("activity", "activity-alias", "service", "receiver", "provider"):
                for node in app.findall(component_tag):
                    name = node.attrib.get(ANDROID_NS + "name", "")
                    explicit = node.attrib.get(ANDROID_NS + "exported")
                    has_filter = node.find("intent-filter") is not None
                    exported = explicit == "true" or (explicit is None and has_filter)
                    item = {
                        "type": component_tag,
                        "name": name,
                        "exported": exported,
                        "exported_explicit": explicit if explicit is not None else "inferred",
                        "permission": node.attrib.get(ANDROID_NS + "permission", ""),
                        "process": node.attrib.get(ANDROID_NS + "process", ""),
                        "authorities": node.attrib.get(ANDROID_NS + "authorities", ""),
                        "intent_filters": [],
                    }
                    for intent_filter in node.findall("intent-filter"):
                        filters = {
                            "actions": [child.attrib.get(ANDROID_NS + "name", "") for child in intent_filter.findall("action")],
                            "categories": [child.attrib.get(ANDROID_NS + "name", "") for child in intent_filter.findall("category")],
                            "data": [dict(child.attrib) for child in intent_filter.findall("data")],
                        }
                        item["intent_filters"].append(filters)
                    components.append(item)
                    if exported and not item["permission"] and component_tag in {"service", "receiver", "provider"}:
                        result.add_finding("Medium", f"Unprotected exported Android {component_tag}", "The component is reachable by other applications and does not declare a component-level permission.", 9, name)
        result.sections["Android components"] = components
        result.metadata["Android component count"] = len(components)

        launcher = ""
        for component in components:
            for intent_filter in component["intent_filters"]:
                if "android.intent.action.MAIN" in intent_filter["actions"] and "android.intent.category.LAUNCHER" in intent_filter["categories"]:
                    launcher = component["name"]
                    break
        if launcher:
            result.metadata["Android manifest"]["Launcher activity"] = launcher

        if str(manifest_info.get("Debuggable", "")).lower() == "true":
            result.add_finding("High", "Debuggable Android application", "The application manifest enables debugging.", 18, "android:debuggable=true")
        if str(manifest_info.get("Cleartext traffic", "")).lower() == "true":
            result.add_finding("Medium", "Cleartext Android network traffic allowed", "The application explicitly permits unencrypted HTTP traffic.", 10, "android:usesCleartextTraffic=true")
        if str(manifest_info.get("Backup allowed", "")).lower() == "true":
            result.add_finding("Low", "Android backup allowed", "Application data may be eligible for backup depending on Android version and backup rules.", 3, "android:allowBackup=true")

    def _inspect_dex(self, data: bytes, name: str, result: AnalysisResult) -> dict[str, Any]:
        row: dict[str, Any] = {"name": name, "size": len(data), "entropy": round(shannon_entropy(data), 4)}
        if len(data) >= 112 and data.startswith(b"dex\n"):
            row.update({
                "version": data[4:7].decode("ascii", errors="replace"),
                "checksum": f"0x{struct.unpack_from('<I', data, 8)[0]:08X}",
                "file_size_header": struct.unpack_from("<I", data, 32)[0],
                "header_size": struct.unpack_from("<I", data, 36)[0],
                "endian_tag": f"0x{struct.unpack_from('<I', data, 40)[0]:08X}",
                "string_ids": struct.unpack_from("<I", data, 56)[0],
                "type_ids": struct.unpack_from("<I", data, 64)[0],
                "proto_ids": struct.unpack_from("<I", data, 72)[0],
                "field_ids": struct.unpack_from("<I", data, 80)[0],
                "method_ids": struct.unpack_from("<I", data, 88)[0],
                "class_defs": struct.unpack_from("<I", data, 96)[0],
            })
        text = data.decode("latin-1", errors="ignore")
        classes = sorted(set(re.findall(r"L(?:[A-Za-z0-9_$-]+/)+[A-Za-z0-9_$-]+;", text)))
        methods = sorted(set(re.findall(r"(?:[A-Za-z_$][A-Za-z0-9_$]{2,})\([^\x00\r\n]{0,120}\)[VZBSCIJFDL\[]", text)))
        androguard_used = False
        try:
            from androguard.core.dex import DEX
            dex_vm = DEX(data)
            classes = sorted(set(str(item) for item in dex_vm.get_classes_names()))
            parsed_methods = []
            for method in dex_vm.get_methods():
                try:
                    parsed_methods.append(f"{method.get_class_name()}->{method.get_name()}{method.get_descriptor()}")
                except Exception:
                    parsed_methods.append(str(method))
            methods = sorted(set(parsed_methods))
            dex_strings = [str(item) for item in dex_vm.get_strings()]
            text += "\n" + "\n".join(dex_strings[:200000])
            androguard_used = True
        except Exception:
            pass
        packages = sorted({value[1:-1].rsplit("/", 1)[0].replace("/", ".") for value in classes if value.startswith("L") and "/" in value})
        preset_hits = []
        for preset, markers in API_PRESETS.items():
            hits = [marker.decode("latin-1", errors="replace") for marker in markers if marker in data]
            if hits:
                preset_hits.append({"preset": preset, "markers": hits})
                if preset == "Dynamic code loading":
                    result.add_finding("Medium", "Android dynamic code loading indicators", "DEX class loading or native loading APIs were found.", 8, ", ".join(hits))
                elif preset in {"Root detection", "Emulator detection"}:
                    result.add_finding("Info", f"Android {preset.lower()} indicators", "Markers commonly used for environment detection were found.", 2, ", ".join(hits))
        row["androguard_parser_used"] = androguard_used
        row["package_count"] = len(packages)
        row["packages"] = packages[:50_000]
        row["class_count_preview"] = len(classes)
        row["classes"] = classes[:50_000]
        row["method_signature_preview_count"] = len(methods)
        row["method_signatures"] = methods[:20_000]
        row["api_presets"] = preset_hits
        local_strings = []
        for match in re.finditer(rb"[\x20-\x7e]{5,}", data[:64 * 1024 * 1024]):
            value = match.group().decode("ascii", errors="ignore")
            local_strings.append(StringArtifact(match.start(), "ASCII", value, categorize_string(value)))
            if len(local_strings) >= 100_000:
                break
        row["iocs"] = extract_iocs(local_strings)
        return row

    def _detect_unity(self, names: list[str], archive: zipfile.ZipFile) -> dict[str, Any]:
        lower_names = {name.lower(): name for name in names}
        mono_markers = [name for name in names if name.lower().endswith("assembly-csharp.dll") or "/managed/" in name.lower()]
        il2cpp_markers = [name for name in names if name.lower().endswith("libil2cpp.so") or name.lower().endswith("global-metadata.dat")]
        asset_bundles = [name for name in names if any(marker in name.lower() for marker in (".unity3d", "assetbundle", "sharedassets", "resources.assets"))]
        detected = bool(mono_markers or il2cpp_markers or any("unity" in name.lower() for name in names))
        mode = "IL2CPP" if il2cpp_markers else "Mono" if mono_markers else "Unknown"
        version = ""
        version_candidates = [
            "assets/bin/data/resources/unity_builtin_extra",
            "assets/bin/data/globalgamemanagers",
            "assets/bin/data/data.unity3d",
        ]
        for candidate in version_candidates:
            actual = lower_names.get(candidate)
            if not actual:
                continue
            try:
                data = archive.read(actual)[:2 * 1024 * 1024]
                match = re.search(rb"20\d{2}\.\d+\.\d+[a-z]\d+", data)
                if match:
                    version = match.group().decode("ascii", errors="replace")
                    break
            except Exception:
                continue
        analysis_path = "Analyze global-metadata.dat together with libil2cpp.so." if mode == "IL2CPP" else "Extract and inspect Assembly-CSharp.dll and other managed assemblies." if mode == "Mono" else "Inspect Unity assets and native libraries to determine the scripting backend."
        return {
            "detected": detected,
            "summary": {
                "Detected": detected,
                "Scripting backend": mode,
                "Unity version": version or "Not identified",
                "Managed assembly markers": len(mono_markers),
                "IL2CPP markers": len(il2cpp_markers),
                "Asset bundle markers": len(asset_bundles),
            },
            "managed": mono_markers[:10_000],
            "il2cpp": il2cpp_markers[:10_000],
            "assets": asset_bundles[:20_000],
            "analysis_path": analysis_path,
        }

    def _detect_sdks(self, names: list[str], dex_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        searchable = "\n".join(names).lower()
        for dex in dex_rows:
            searchable += "\n" + "\n".join(dex.get("classes", [])[:50_000]).lower()
        hits = []
        for sdk, markers in SDK_MARKERS.items():
            matched = [marker for marker in markers if marker.lower() in searchable]
            if matched:
                hits.append({"sdk": sdk, "markers": matched, "confidence": "High" if len(matched) >= 2 else "Medium"})
        return hits
