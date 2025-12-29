from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from typing import Any, Dict, Optional


class AuditLog:
    """
    Optional SQLite audit log.

    This is OFF by default. Enable by setting `AUDIT_DB_PATH` (or `READYTRADER_AUDIT_DB_PATH`).
    The log is intended for operators to debug and review tool activity.

    IMPORTANT:
    - This does NOT persist risk-consent state (consent remains in-memory only by design).
    - Avoid storing secrets. We store only a summarized view of tool outputs.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._conn: Optional[sqlite3.Connection] = None

    def enabled(self) -> bool:
        return bool(self._db_path())

    def append(
        self,
        *,
        ts_ms: int,
        request_id: str,
        tool: str,
        ok: bool,
        error_code: str | None = None,
        mode: str | None = None,
        venue: str | None = None,
        exchange: str | None = None,
        market_type: str | None = None,
        summary: Dict[str, Any] | None = None,
    ) -> None:
        conn = self._get_conn()
        if conn is None:
            return
        payload = json.dumps(summary or {}, sort_keys=True)
        with self._lock:
            conn.execute(
                """
                INSERT INTO audit_events(
                    ts_ms, request_id, tool, ok, error_code, mode, venue, exchange, market_type, summary_json
                )
                VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    int(ts_ms),
                    str(request_id),
                    str(tool),
                    1 if ok else 0,
                    error_code,
                    mode,
                    venue,
                    exchange,
                    market_type,
                    payload,
                ),
            )
            conn.commit()

    def _db_path(self) -> str:
        return (os.getenv("READYTRADER_AUDIT_DB_PATH") or os.getenv("AUDIT_DB_PATH") or "").strip()

    def _get_conn(self) -> Optional[sqlite3.Connection]:
        path = self._db_path()
        if not path:
            return None
        with self._lock:
            if self._conn is None:
                self._conn = sqlite3.connect(path, check_same_thread=False)
                self._conn.execute("PRAGMA journal_mode=WAL;")
                self._conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS audit_events(
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ts_ms INTEGER NOT NULL,
                        request_id TEXT NOT NULL,
                        tool TEXT NOT NULL,
                        ok INTEGER NOT NULL,
                        error_code TEXT,
                        mode TEXT,
                        venue TEXT,
                        exchange TEXT,
                        market_type TEXT,
                        summary_json TEXT NOT NULL
                    )
                    """
                )
                self._conn.commit()
            return self._conn


def now_ms() -> int:
    return int(time.time() * 1000)

