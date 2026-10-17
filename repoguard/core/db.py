"""
RepoGuard Database Layer
SQLite storage for scan history and offline PyPI license cache.
"""

import sqlite3
import json
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime


DEFAULT_DB_PATH = Path.home() / ".repoguard" / "repoguard.db"


class Database:
    def __init__(self, db_path: Optional[Path] = None):
        if db_path is None:
            db_path = DEFAULT_DB_PATH
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    repo_name TEXT NOT NULL,
                    repo_path TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    health_score INTEGER NOT NULL,
                    grade TEXT NOT NULL,
                    total_issues INTEGER NOT NULL,
                    critical_count INTEGER NOT NULL,
                    warning_count INTEGER NOT NULL,
                    files_scanned INTEGER NOT NULL,
                    report_json TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS pypi_license_cache (
                    package_name TEXT PRIMARY KEY,
                    license_name TEXT,
                    spdx_id TEXT,
                    category TEXT,
                    is_copyleft INTEGER,
                    cached_at TEXT
                )
            """)
            conn.commit()

    def save_scan(self, report_dict: Dict[str, Any]) -> int:
        summary = report_dict.get("summary", {})
        repo_name = report_dict.get("repo_name", "Unknown")
        repo_path = report_dict.get("repo_path", "")
        timestamp = summary.get("timestamp", datetime.now().isoformat())
        health_score = summary.get("health_score", 100)
        grade = summary.get("grade", "A+")
        total_issues = summary.get("total_issues", 0)
        critical_count = summary.get("critical_count", 0)
        warning_count = summary.get("warning_count", 0)
        files_scanned = summary.get("files_scanned", 0)
        report_json = json.dumps(report_dict)

        with self._get_connection() as conn:
            cursor = conn.execute("""
                INSERT INTO scan_history (
                    repo_name, repo_path, timestamp, health_score, grade,
                    total_issues, critical_count, warning_count, files_scanned, report_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                repo_name, repo_path, timestamp, health_score, grade,
                total_issues, critical_count, warning_count, files_scanned, report_json
            ))
            conn.commit()
            return cursor.lastrowid

    def get_recent_scans(self, limit: int = 15) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.execute("""
                SELECT id, repo_name, repo_path, timestamp, health_score, grade,
                       total_issues, critical_count, warning_count, files_scanned
                FROM scan_history
                ORDER BY id DESC
                LIMIT ?
            """, (limit,))
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    def get_scan_by_id(self, scan_id: int) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.execute("""
                SELECT report_json FROM scan_history WHERE id = ?
            """, (scan_id,))
            row = cursor.fetchone()
            if row:
                return json.loads(row["report_json"])
            return None

    def get_cached_license(self, package_name: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.execute("""
                SELECT license_name, spdx_id, category, is_copyleft
                FROM pypi_license_cache
                WHERE package_name = ?
            """, (package_name.lower(),))
            row = cursor.fetchone()
            if row:
                return {
                    "license_name": row["license_name"],
                    "spdx_id": row["spdx_id"],
                    "category": row["category"],
                    "is_copyleft": bool(row["is_copyleft"]),
                }
            return None

    def cache_license(self, package_name: str, license_name: str, spdx_id: str, category: str, is_copyleft: bool):
        with self._get_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO pypi_license_cache (
                    package_name, license_name, spdx_id, category, is_copyleft, cached_at
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, (
                package_name.lower(),
                license_name,
                spdx_id,
                category,
                1 if is_copyleft else 0,
                datetime.now().isoformat()
            ))
            conn.commit()


# Singleton instance
db = Database()
