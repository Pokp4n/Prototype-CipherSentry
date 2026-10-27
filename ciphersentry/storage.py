"""Local SQLite audit trail and portable evidence exports for CipherSentry."""

from __future__ import annotations

import csv
import json
import sqlite3
import time
from pathlib import Path

from .engine import Assessment, FileEvent


class EventStore:
    """A single-threaded store: call from the UI/controller thread.

    Exports contain observed local file paths and process names. No file contents
    or sampled bytes are stored. Existing audit rows are retained across launches.
    """

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(str(self.path))
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                path TEXT NOT NULL,
                operation TEXT NOT NULL,
                pid INTEGER,
                process_name TEXT NOT NULL,
                entropy_before REAL,
                entropy_after REAL,
                source TEXT NOT NULL,
                score INTEGER NOT NULL,
                level TEXT NOT NULL,
                assessment_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS events_time ON events(timestamp DESC, id DESC);
            CREATE TABLE IF NOT EXISTS actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                action TEXT NOT NULL,
                detail TEXT NOT NULL,
                pid INTEGER
            );
            CREATE INDEX IF NOT EXISTS actions_time ON actions(timestamp DESC, id DESC);
            """
        )
        self._connection.commit()

    def record_event(self, event: FileEvent, assessment: Assessment) -> None:
        with self._connection:
            self._connection.execute(
                """INSERT INTO events
                (timestamp, path, operation, pid, process_name, entropy_before,
                 entropy_after, source, score, level, assessment_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    event.timestamp, event.path, event.operation, event.pid,
                    event.process_name, event.entropy_before, event.entropy_after,
                    event.source, assessment.score, assessment.level,
                    json.dumps(assessment.to_dict(), ensure_ascii=False, allow_nan=False),
                ),
            )

    def record_action(self, action: str, detail: str, pid: int | None = None) -> None:
        with self._connection:
            self._connection.execute(
                "INSERT INTO actions (timestamp, action, detail, pid) VALUES (?, ?, ?, ?)",
                (time.time(), action, detail, pid),
            )

    @staticmethod
    def _event_dict(row: sqlite3.Row) -> dict:
        result = dict(row)
        result["assessment"] = json.loads(result.pop("assessment_json"))
        return result

    def recent_events(self, limit: int = 200) -> list[dict]:
        rows = self._connection.execute(
            "SELECT * FROM events ORDER BY timestamp DESC, id DESC LIMIT ?", (max(0, int(limit)),)
        )
        return [self._event_dict(row) for row in rows]

    def recent_actions(self, limit: int = 100) -> list[dict]:
        rows = self._connection.execute(
            "SELECT * FROM actions ORDER BY timestamp DESC, id DESC LIMIT ?", (max(0, int(limit)),)
        )
        return [dict(row) for row in rows]

    def counts(self) -> dict[str, int]:
        return {
            "events": self._connection.execute("SELECT COUNT(*) FROM events").fetchone()[0],
            "actions": self._connection.execute("SELECT COUNT(*) FROM actions").fetchone()[0],
        }

    def export_json(self, path: Path | str) -> int:
        """Export all event evidence and actions; return the number of event rows."""
        events = [self._event_dict(row) for row in self._connection.execute("SELECT * FROM events ORDER BY timestamp, id")]
        actions = [dict(row) for row in self._connection.execute("SELECT * FROM actions ORDER BY timestamp, id")]
        payload = {"format_version": 1, "exported_at": time.time(), "events": events, "actions": actions}
        Path(path).write_text(json.dumps(payload, ensure_ascii=False, indent=2, allow_nan=False), encoding="utf-8")
        return len(events)

    def export_csv(self, path: Path | str) -> int:
        """Export all event rows, including JSON explanations; return their count."""
        columns = [
            "id", "timestamp", "path", "operation", "pid", "process_name",
            "entropy_before", "entropy_after", "source", "score", "level", "assessment_json",
        ]
        count = 0
        with Path(path).open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=columns)
            writer.writeheader()
            for row in self._connection.execute("SELECT * FROM events ORDER BY timestamp, id"):
                writer.writerow(dict(row))
                count += 1
        return count

    def close(self) -> None:
        self._connection.close()
