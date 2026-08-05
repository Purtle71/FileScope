# Feature matrix

| Capability | Implementation |
|---|---|
| Application output | One PyInstaller single-file Windows executable containing the GUI, parsers, rules, and map database |
| Dependency setup | Pinned Python 3.14 Windows wheels, offline installation, SHA-256 validation, no source compilation |
| YARA | YARA-X with bundled starter rules and custom-rule support |
| GPS metadata | EXIF coordinates, decimal/DMS, altitude, timestamps, direction, speed, datum, and related tags |
| Offline map | Pan, zoom, coordinate marker, country/ISO/continent lookup, no automatic network request |
| Folder scanning | Recursive, background, sortable, and cancelable |
| Type detection | Magic-byte detection with misleading-extension findings |
| Entropy | Whole-file and block entropy with graph and findings |
| Strings and indicators | ASCII/UTF-16 offsets, filtering, URLs, domains, IPs, emails, hashes, registry, pipes, commands, agents, and wallets |
| Hex | Preview, search, navigation, landmarks, bookmarks, interpretation, Copy All Hex, and streamed export |
| PE | Headers, imports, exports, sections, resources, signatures, TLS, debug, overlay, .NET, manifests, compilers, and packers |
| Android | Manifest, permissions, components, DEX, signing, native libraries, splits, trackers, and Unity Mono/IL2CPP |
| Archives | Nested inspection, traversal/bomb/encryption/duplicate/double-extension checks, ZIP/TAR extraction |
| Office and PDF | Metadata, macros, links, relationships, templates, hidden content, objects, attachments, and active content |
| SQLite | Schema, previews, read-only SQL, CSV, Android hints, freelist, WAL, and journal metadata |
| Reports and comparison | HTML/JSON/CSV/text reports, global search, and two-file comparison |
| Interface | 29 workspaces, file tabs, drag-and-drop, recent files, dark/light themes, high-DPI layout |
| Validation | Automated tests, source self-test, packaged self-test, import checks, and PE validation |
