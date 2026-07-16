from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from analyzer import AnalysisResult


DB_PATH = Path(os.environ.get("THZ_HISTORY_DB", Path.home() / ".local" / "share" / "thzcodespair-inspector" / "history.db"))


class HistoryStore:
    def __init__(self, path: Path = DB_PATH):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.execute("""
            CREATE TABLE IF NOT EXISTS analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scanned_at TEXT NOT NULL,
                name TEXT NOT NULL,
                path TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                size INTEGER NOT NULL,
                mime TEXT NOT NULL,
                score INTEGER NOT NULL,
                verdict TEXT NOT NULL,
                report_json TEXT NOT NULL
            )
        """)
        self.connection.commit()

    def add(self, result: AnalysisResult) -> None:
        payload = asdict(result)
        self.connection.execute(
            "INSERT INTO analyses (scanned_at,name,path,sha256,size,mime,score,verdict,report_json) VALUES (?,?,?,?,?,?,?,?,?)",
            (datetime.now().astimezone().isoformat(timespec="seconds"), result.name, result.path,
             result.hashes["SHA256"], result.size, result.mime, result.score, result.verdict,
             json.dumps(payload, ensure_ascii=False)),
        )
        self.connection.commit()

    def list(self, limit: int = 100) -> list[tuple]:
        return self.connection.execute(
            "SELECT scanned_at,name,mime,score,verdict,sha256,path FROM analyses ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()

    def clear(self) -> None:
        self.connection.execute("DELETE FROM analyses")
        self.connection.commit()
