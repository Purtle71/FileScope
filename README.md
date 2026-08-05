# FileScope

FileScope is a Windows desktop application for inspecting files locally without executing them. The interface contains 29 workspaces covering file identity, metadata, strings, hex, security indicators, Windows executables, Android packages, Unity games, archives, documents, databases, YARA rules, folder scans, comparison, search, and reports.

## Highlights

* Complete **Copy All Hex** and streamed full-hex export
* EXIF GPS metadata with an offline country map
* PE imports, exports, sections, resources, signatures, overlays, and packer markers
* APK/APKS/XAPK/APKM manifests, permissions, DEX indicators, components, splits, trackers, and Unity detection
* ZIP/TAR inspection, nested archives, safety checks, and controlled extraction
* Office, PDF, image, JSON, XML, CSV, INI, text, and SQLite parsing
* Local YARA-X scanning
* Recursive folder scans, comparison, global search, and HTML/JSON/CSV/text reports

## Build on Windows

Requirements:

* 64-bit Windows 10 or Windows 11
* 64-bit Python 3.14
* Internet access for the first dependency installation

Run:

```text
BUILD\_FILESCOPE.bat
```

The builder accepts only precompiled wheels, verifies exact package versions and imports, compiles the source, runs the complete test suite, runs a source self-test, builds with PyInstaller, validates the Windows PE output, and runs the self-test against the completed executable.

Output:

```text
dist\\FileScope.exe
```

## Run from source

```powershell
py -3.14 -m venv .venv
.\\.venv\\Scripts\\python.exe -m pip install --only-binary=:all: --no-deps -r requirements.txt -r requirements-build.txt
.\\.venv\\Scripts\\python.exe app.py
```

## Tests

```powershell
$env:QT\_QPA\_PLATFORM = "offscreen"
.\\.venv\\Scripts\\python.exe -m unittest discover -s tests -v
.\\.venv\\Scripts\\python.exe app.py --self-test
```

## GPS behavior

When an image contains supported EXIF GPS tags, FileScope can display coordinates, altitude, GPS time, direction, speed, datum, processing method, and area information. Coordinates can be plotted against the bundled Natural Earth country database. Mapping and country lookup remain local; no street-address lookup is performed.

## Security behavior

* Selected files are not executed.
* Files are not uploaded automatically.
* Reputation actions open a browser with the SHA-256 hash only.
* Archive extraction blocks path traversal.
* SQLite custom queries use read-only mode.
* YARA-X scans locally.
* Risk scores are static-analysis indicators, not malware verdicts.

## License

The project is licensed under the MIT License. Third-party components and map data are described in `THIRD\_PARTY\_NOTICES.txt`.

