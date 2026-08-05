from __future__ import annotations

import sqlite3
from pathlib import Path

from filescope.core.models import AnalysisResult

from .base import AnalysisPlugin


class SQLitePlugin(AnalysisPlugin):
    name = "SQLite database parser"

    def supports(self, path: Path, header: bytes, detected_type: str) -> bool:
        return header.startswith(b"SQLite format 3\x00") or path.suffix.lower() in {".sqlite", ".sqlite3", ".db"}

    def analyze(self, result: AnalysisResult, header: bytes) -> None:
        if not header.startswith(b"SQLite format 3\x00"):
            return
        uri = f"file:{result.path.as_posix()}?mode=ro"
        connection = sqlite3.connect(uri, uri=True)
        try:
            connection.row_factory = sqlite3.Row
            tables = []
            for row in connection.execute("SELECT name, type, sql FROM sqlite_master WHERE type IN ('table','view','index','trigger') ORDER BY type, name"):
                tables.append({"name": row["name"], "type": row["type"], "sql": row["sql"] or ""})
            result.sections["SQLite schema"] = tables
            result.metadata["SQLite objects"] = len(tables)
            page_size = connection.execute("PRAGMA page_size").fetchone()[0]
            page_count = connection.execute("PRAGMA page_count").fetchone()[0]
            user_version = connection.execute("PRAGMA user_version").fetchone()[0]
            application_id = connection.execute("PRAGMA application_id").fetchone()[0]
            freelist_count = connection.execute("PRAGMA freelist_count").fetchone()[0]
            journal_mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
            secure_delete = connection.execute("PRAGMA secure_delete").fetchone()[0]
            encoding = connection.execute("PRAGMA encoding").fetchone()[0]
            result.metadata["SQLite"] = {
                "Page size": page_size,
                "Page count": page_count,
                "User version": user_version,
                "Application ID": application_id,
                "Encoding": encoding,
                "Journal mode": journal_mode,
                "Secure delete": bool(secure_delete),
                "Freelist pages": freelist_count,
                "Possible deleted-data pages": freelist_count > 0 and not bool(secure_delete),
                "WAL file present": result.path.with_name(result.path.name + "-wal").exists(),
                "Rollback journal present": result.path.with_name(result.path.name + "-journal").exists(),
                "Calculated database bytes": page_size * page_count,
            }
            if freelist_count > 0 and not secure_delete:
                result.add_finding("Info", "SQLite freelist pages present", "Freelist pages may retain remnants of deleted records until reused or vacuumed. FileScope does not recover deleted rows automatically.", 2, f"{freelist_count} page(s)")
            previews = {}
            for row in tables:
                if row["type"] != "table" or row["name"].startswith("sqlite_"):
                    continue
                safe_name = row["name"].replace('"', '""')
                columns = [dict(item) for item in connection.execute(f'PRAGMA table_info("{safe_name}")')]
                try:
                    sample_rows = [dict(item) for item in connection.execute(f'SELECT * FROM "{safe_name}" LIMIT 200')]
                except sqlite3.DatabaseError as exc:
                    sample_rows = [{"error": str(exc)}]
                previews[row["name"]] = {"columns": columns, "rows": sample_rows}
            result.sections["SQLite tables"] = previews
            common_android_names = {"sms", "mms", "threads", "contacts", "raw_contacts", "data", "calls", "messages", "cookies", "history", "accounts", "notifications", "downloads"}
            indicators = []
            for table_name, preview in previews.items():
                columns = [str(column.get("name", "")) for column in preview.get("columns", [])]
                lowered = table_name.lower()
                matched = sorted({name for name in common_android_names if name in lowered})
                if matched:
                    indicators.append({"table": table_name, "matched_presets": matched, "columns": columns})
            result.sections["Android database indicators"] = indicators
        finally:
            connection.close()
