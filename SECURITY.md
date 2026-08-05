# Security notes

FileScope performs static inspection of untrusted files. Parsing libraries can still contain defects, so highly suspicious material is best analyzed in a disposable Windows virtual machine.

The application does not execute inspected files and does not upload them automatically. External reputation actions expose only the selected SHA-256 hash through the browser. EXIF GPS decoding, country lookup, and map rendering remain local.

Archive extraction validates resolved output paths before writing. SQLite custom SQL uses read-only mode and accepts only query-like statements. YARA-X scans locally.

The bundled country map is low-resolution geographic context, not a reverse-geocoding, street-address, navigation, cadastral, or legal-boundary database.

Do not treat a low score as proof that a file is safe or a high score as proof that it is malicious. The score is a transparent triage aid built from static indicators.
