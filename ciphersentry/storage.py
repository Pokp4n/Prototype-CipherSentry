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
                assessment_json TEXT NOT NULL,
                event_json TEXT,
                response_json TEXT
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
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                key TEXT NOT NULL,
                pid INTEGER,
                process_name TEXT NOT NULL,
                level TEXT NOT NULL,
                score INTEGER NOT NULL,
                reason TEXT NOT NULL,
                response_action TEXT NOT NULL,
                response_reason TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open',
                assessment_json TEXT NOT NULL,
                response_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS alerts_time ON alerts(timestamp DESC, id DESC);
            """
        )
        # Add columns to the original prototype's database without rebuilding or
        # relabelling any historical event, assessment, or response action.
        event_columns = {row["name"] for row in self._connection.execute("PRAGMA table_info(events)")}
        for name in ("event_json", "response_json"):
            if name not in event_columns:
                self._connection.execute(f"ALTER TABLE events ADD COLUMN {name} TEXT")
        self._connection.execute("PRAGMA user_version=2")
        self._connection.commit()
        self._closed = False

    def record_event(self, event: FileEvent, assessment: Assessment, response: dict | None = None) -> None:
        """Keep original event metadata and the separate policy decision together.

        Response permission is not an action-success result. Actual process
        outcomes belong in the action audit after the OS operation completes.
        """
        event_json = json.dumps(event.to_dict(), ensure_ascii=False, allow_nan=False)
        assessment_json = json.dumps(assessment.to_dict(), ensure_ascii=False, allow_nan=False)
        response_json = json.dumps(response, ensure_ascii=False, allow_nan=False) if response is not None else None
        with self._connection:
            self._connection.execute(
                """INSERT INTO events
                (timestamp, path, operation, pid, process_name, entropy_before,
                 entropy_after, source, score, level, assessment_json, event_json, response_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    event.timestamp, event.path, event.operation, event.pid,
                    event.process_name, event.entropy_before, event.entropy_after,
                    event.source, assessment.score, assessment.level,
                    assessment_json, event_json, response_json,
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
        event_json = result.pop("event_json", None)
        if event_json:
            # Preserve identity/score/database columns; append event-only fields.
            for name, value in json.loads(event_json).items():
                if name not in result:
                    result[name] = value
        result.setdefault("process_context", None)
        result.setdefault("attribution", "unavailable")
        result.setdefault("observed_at", None)
        response_json = result.pop("response_json", None)
        result["response"] = json.loads(response_json) if response_json else None
        return result

    @staticmethod
    def _alert_dict(row: sqlite3.Row) -> dict:
        result = dict(row)
        result["assessment"] = json.loads(result.pop("assessment_json"))
        result["response"] = json.loads(result.pop("response_json"))
        return result

    def record_alert(self, assessment: Assessment, response: dict) -> int:
        """Persist an alert episode; the controller owns risk-transition deduping."""
        contributions = [f"{signal.name}: {signal.value} (+{signal.points})"
                         for signal in assessment.signals if signal.points > 0]
        if assessment.level == "High":
            reason = "High-risk ransomware-like file activity detected."
        elif assessment.level in {"Uncertain", "Elevated"}:
            reason = "Uncertain behavioural risk; gather more evidence and reassess."
        else:
            reason = "Behavioural assessment recorded for review."
        if contributions:
            reason += " Supporting indicators: " + "; ".join(contributions) + "."
        assessment_json = json.dumps(assessment.to_dict(), ensure_ascii=False, allow_nan=False)
        response_json = json.dumps(response, ensure_ascii=False, allow_nan=False)
        with self._connection:
            cursor = self._connection.execute(
                """INSERT INTO alerts
                (timestamp, key, pid, process_name, level, score, reason,
                 response_action, response_reason, status, assessment_json, response_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?)""",
                (time.time(), assessment.key, assessment.pid, assessment.process_name,
                 assessment.level, assessment.score, reason,
                 str(response.get("action", "alert_only")),
                 str(response.get("reason", "No response decision was supplied.")),
                 assessment_json, response_json),
            )
        return int(cursor.lastrowid)

    def recent_alerts(self, limit: int = 100) -> list[dict]:
        rows = self._connection.execute(
            "SELECT * FROM alerts ORDER BY timestamp DESC, id DESC LIMIT ?", (max(0, int(limit)),)
        )
        return [self._alert_dict(row) for row in rows]

    def acknowledge_alert(self, alert_id: int) -> bool:
        """Acknowledge review without changing risk evidence or process state."""
        with self._connection:
            cursor = self._connection.execute(
                "UPDATE alerts SET status='acknowledged' WHERE id=? AND status='open'", (alert_id,)
            )
            changed = cursor.rowcount == 1
            if changed:
                self._connection.execute(
                    "INSERT INTO actions (timestamp, action, detail, pid) VALUES (?, ?, ?, NULL)",
                    (time.time(), "alert_acknowledged", f"Alert {alert_id} reviewed; no process action performed"),
                )
        return changed

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
            "alerts": self._connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0],
            "open_alerts": self._connection.execute("SELECT COUNT(*) FROM alerts WHERE status='open'").fetchone()[0],
            "suspicious_events": self._connection.execute("SELECT COUNT(*) FROM events WHERE level IN ('High', 'Uncertain', 'Elevated')").fetchone()[0],
        }

    def export_json(self, path: Path | str) -> int:
        """Export events, explanations, alerts and actions; return event-row count."""
        events = [self._event_dict(row) for row in self._connection.execute("SELECT * FROM events ORDER BY timestamp, id")]
        actions = [dict(row) for row in self._connection.execute("SELECT * FROM actions ORDER BY timestamp, id")]
        alerts = [self._alert_dict(row) for row in self._connection.execute("SELECT * FROM alerts ORDER BY timestamp, id")]
        payload = {"format_version": 2, "exported_at": time.time(), "events": events, "actions": actions, "alerts": alerts}
        Path(path).write_text(json.dumps(payload, ensure_ascii=False, indent=2, allow_nan=False), encoding="utf-8")
        return len(events)

    def export_csv(self, path: Path | str) -> int:
        """Export all event rows, including JSON explanations; return their count."""
        columns = [
            "id", "timestamp", "path", "operation", "pid", "process_name",
            "entropy_before", "entropy_after", "source", "score", "level", "assessment_json", "event_json", "response_json",
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
        if not self._closed:
            self._connection.close()
            self._closed = True
