import csv
import json
import tempfile
import unittest
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
        self.assertEqual(self.store.counts(), {"events": 1, "actions": 1})
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


if __name__ == "__main__":
    unittest.main()
