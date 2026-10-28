import csv
import json
import sqlite3
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from ciphersentry.engine import FileEvent, RiskEngine
from ciphersentry.storage import EventStore


class EventStoreTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.store = EventStore(self.root / "audit.sqlite3")
        self.event = FileEvent(1000, "C:\\Example\\résumé, one.txt", "modified", entropy_before=2, entropy_after=7.9)
        self.assessment = RiskEngine().ingest(self.event)

    def tearDown(self):
        self.store.close()
        self.directory.cleanup()

    def test_round_trip_keeps_evidence_and_actions(self):
        self.store.record_event(self.event, self.assessment)
        self.store.record_action("suspend", "Paused the verified lab worker", 321)
        self.assertEqual(self.store.counts()["events"], 1)
        self.assertEqual(self.store.counts()["actions"], 1)
        self.assertEqual(self.store.counts()["alerts"], 0)
        saved = self.store.recent_events()[0]
        self.assertEqual(saved["path"], self.event.path)
        self.assertEqual(saved["assessment"], self.assessment.to_dict())
        self.assertEqual(saved["score"], self.assessment.score)
        self.assertEqual(self.store.recent_actions()[0]["pid"], 321)

    def test_reopening_preserves_audit(self):
        self.store.record_event(self.event, self.assessment)
        self.store.close()
        self.store = EventStore(self.root / "audit.sqlite3")
        self.assertEqual(self.store.counts()["events"], 1)

    def test_json_and_csv_exports_are_parseable_and_include_explanations(self):
        self.store.record_event(self.event, self.assessment)
        self.store.record_action("monitor_start", "Watching user-selected folder")
        json_path, csv_path = self.root / "evidence.json", self.root / "evidence.csv"
        self.assertEqual(self.store.export_json(json_path), 1)
        payload = json.loads(json_path.read_text(encoding="utf-8"))
        self.assertEqual(payload["events"][0]["assessment"]["signals"], self.assessment.to_dict()["signals"])
        self.assertEqual(payload["actions"][0]["action"], "monitor_start")
        self.assertEqual(self.store.export_csv(csv_path), 1)
        with csv_path.open(newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["path"], self.event.path)
        self.assertEqual(json.loads(rows[0]["assessment_json"])["key"], self.assessment.key)

    def test_limit_and_order(self):
        self.store.record_event(self.event, self.assessment)
        newer = FileEvent(1002, "/tmp/new.txt", "created")
        self.store.record_event(newer, RiskEngine().ingest(newer))
        self.assertEqual(self.store.recent_events(limit=1)[0]["path"], newer.path)
        self.assertEqual(self.store.recent_events(limit=0), [])
        self.assertEqual(self.store.recent_actions(limit=-1), [])

    def test_new_event_metadata_and_response_round_trip(self):
        event = replace(self.event, pid=43210, source="lab", attribution="cooperative_lab",
                        observed_at=1000.1, process_context={"pid": 43210, "create_time": 999,
                        "executable": "C:\\Python312\\python.exe", "signature_status": "not_checked"})
        assessment = RiskEngine().ingest(event)
        response = {"action": "alert_only", "allowed": False, "reason": "Alert-only mode", "checks": {"simulation_mode": False}}
        self.store.record_event(event, assessment, response)
        saved = self.store.recent_events()[0]
        self.assertEqual(saved["process_context"], event.process_context)
        self.assertEqual(saved["attribution"], "cooperative_lab")
        self.assertEqual(saved["observed_at"], 1000.1)
        self.assertEqual(saved["response"], response)

    def test_alert_review_and_exports_preserve_decision_not_claim_action(self):
        assessment = replace(self.assessment, level="High", score=90)
        response = {"action": "alert_only", "allowed": False, "reason": "Attribution is unavailable", "checks": {"attribution": False}}
        self.store.record_event(self.event, assessment, response)
        alert_id = self.store.record_alert(assessment, response)
        alert = self.store.recent_alerts()[0]
        self.assertEqual(alert["id"], alert_id)
        self.assertEqual(alert["status"], "open")
        self.assertIn("ransomware-like", alert["reason"])
        self.assertEqual(alert["response_reason"], response["reason"])
        self.assertEqual(alert["assessment"], assessment.to_dict())
        self.assertEqual(self.store.counts()["open_alerts"], 1)
        self.assertEqual(self.store.counts()["suspicious_events"], 1)
        self.assertTrue(self.store.acknowledge_alert(alert_id))
        self.assertFalse(self.store.acknowledge_alert(alert_id))
        self.assertFalse(self.store.acknowledge_alert(99999))
        self.assertEqual(self.store.counts()["open_alerts"], 0)
        self.assertEqual(self.store.recent_actions()[0]["action"], "alert_acknowledged")
        target = self.root / "alerts.json"
        self.store.export_json(target)
        exported = json.loads(target.read_text(encoding="utf-8"))
        self.assertEqual(exported["format_version"], 2)
        self.assertEqual(exported["alerts"][0]["status"], "acknowledged")
        self.assertEqual(exported["alerts"][0]["response"], response)
        self.assertEqual(self.store.recent_alerts(0), [])

    def test_original_database_is_migrated_without_losing_or_relabelling_evidence(self):
        legacy_path = self.root / "legacy.sqlite3"
        legacy_assessment = {"key": "folder:unattributed", "score": 45, "level": "Elevated", "signals": []}
        with sqlite3.connect(legacy_path) as connection:
            connection.executescript("""
                CREATE TABLE events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp REAL NOT NULL,
                    path TEXT NOT NULL, operation TEXT NOT NULL, pid INTEGER,
                    process_name TEXT NOT NULL, entropy_before REAL, entropy_after REAL,
                    source TEXT NOT NULL, score INTEGER NOT NULL, level TEXT NOT NULL,
                    assessment_json TEXT NOT NULL);
                CREATE TABLE actions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp REAL NOT NULL,
                    action TEXT NOT NULL, detail TEXT NOT NULL, pid INTEGER);
            """)
            connection.execute("INSERT INTO events VALUES (1,1000,'old.txt','modified',NULL,'Unknown',NULL,NULL,'folder',45,'Elevated',?)", (json.dumps(legacy_assessment),))
            connection.execute("INSERT INTO actions VALUES (1,1000,'old_action','Original audit detail',NULL)")
        legacy = EventStore(legacy_path)
        try:
            saved = legacy.recent_events()[0]
            self.assertEqual(saved["assessment"], legacy_assessment)
            self.assertEqual(saved["level"], "Elevated")
            self.assertEqual(saved["attribution"], "unavailable")
            self.assertIsNone(saved["process_context"])
            self.assertIsNone(saved["response"])
            self.assertEqual(legacy.recent_actions()[0]["detail"], "Original audit detail")
            self.assertEqual(legacy.counts()["suspicious_events"], 1)
            legacy.record_event(self.event, self.assessment)
            legacy.export_csv(self.root / "legacy.csv")
            with (self.root / "legacy.csv").open(newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0]["event_json"], "")
            self.assertEqual(json.loads(rows[1]["event_json"])["path"], self.event.path)
        finally:
            legacy.close()
        reopened = EventStore(legacy_path)
        try:
            self.assertEqual(reopened.counts()["events"], 2)
            self.assertEqual(reopened.counts()["actions"], 1)
        finally:
            reopened.close()


if __name__ == "__main__":
    unittest.main()
