"""Read-only candidate-correlation regressions; no process control."""
import unittest
from datetime import datetime, timezone

from ciphersentry.engine import FileEvent
from ciphersentry.etw_evidence import parse_write
from ciphersentry.etw_correlation import RecentEtwEvidence

ROOT = r"C:\Demo\protected"
PATH = r"C:\Demo\protected\folder\file.txt"
SECONDS = datetime.fromisoformat("2026-11-17T04:00:00+00:00").timestamp()


def etw(pid=22208, *, path=PATH, offset=0.0, prior=True):
    from datetime import datetime, timezone
    stamp = datetime.fromtimestamp(SECONDS + offset, tz=timezone.utc).isoformat()
    row = {
        "kind": "Write", "event_time_utc": stamp,
        "callback_time_utc": stamp, "reported_pid": str(pid),
        "file_key": "0x0000000000000001", "file_object": "0x0000000000000002",
        "io_size": "25", "filename": path,
        "details": "reader-prior-key-candidate" if prior else "no-reader-prior-key-candidate",
    }
    return parse_write(row)


def folder(*, path=PATH, op="modified", timestamp=SECONDS, pid=None):
    return FileEvent(timestamp=timestamp, path=path, operation=op,
                     pid=pid, source="folder", attribution="unavailable")


class CorrelationTests(unittest.TestCase):
    def test_one_pid_and_system_event_remain_unverified(self):
        bridge = RecentEtwEvidence(ROOT)
        self.assertTrue(bridge.add(etw(22208), received_at=100.0))
        self.assertTrue(bridge.add(etw(4), received_at=100.1))
        evidence = bridge.correlate(folder(pid=999), received_at=100.2)
        self.assertEqual(evidence.matched_write_count, 2)
        self.assertEqual(evidence.unverified_event_pids, (22208,))
        self.assertEqual(evidence.system_pid4_writes, 1)
        self.assertEqual(evidence.reader_prior_key_candidates, 2)
        self.assertEqual(evidence.status, "single_unverified_pid")
        self.assertIsNone(evidence.verified_writer_pid)
        self.assertFalse(evidence.containment_authorized)

    def test_two_pids_same_file_are_ambiguous(self):
        bridge = RecentEtwEvidence(ROOT)
        bridge.add(etw(22208), received_at=10)
        bridge.add(etw(34988, offset=0.2), received_at=10)
        found = bridge.correlate(folder(), received_at=10)
        self.assertEqual(found.status, "multiple_unverified_pids")
        self.assertEqual(found.unverified_event_pids, (22208, 34988))
        self.assertFalse(found.containment_authorized)

    def test_scope_boundary_and_case_insensitive_paths(self):
        bridge = RecentEtwEvidence(ROOT)
        self.assertFalse(bridge.add(etw(path=r"C:\Demo\protected-extra\file.txt"), received_at=10))
        self.assertFalse(bridge.add(etw(path=r"D:\Demo\protected\file.txt"), received_at=10))
        bridge.add(etw(path=PATH.upper()), received_at=10)
        found = bridge.correlate(folder(), received_at=10)
        self.assertEqual(found.matched_write_count, 1)

    def test_timestamp_distance_and_operation_not_assumed(self):
        bridge = RecentEtwEvidence(ROOT)
        bridge.add(etw(), received_at=10)
        self.assertEqual(bridge.correlate(folder(timestamp=SECONDS + 5), received_at=10).matched_write_count, 0)
        self.assertEqual(bridge.correlate(folder(op="deleted"), received_at=10).matched_write_count, 0)
        self.assertEqual(bridge.correlate(folder(op="moved"), received_at=10).matched_write_count, 0)

    def test_no_pid4_attribution_and_outside_folder(self):
        bridge = RecentEtwEvidence(ROOT)
        bridge.add(etw(4), received_at=10)
        found = bridge.correlate(folder(), received_at=10)
        self.assertEqual(found.status, "no_usable_pid")
        self.assertEqual(found.unverified_event_pids, ())
        self.assertIsNone(found.verified_writer_pid)
        self.assertEqual(bridge.correlate(folder(path=r"C:\Demo\other\file.txt"), received_at=10).matched_write_count, 0)

    def test_bounded_retention_and_rejection(self):
        bridge = RecentEtwEvidence(ROOT, max_events=1, retention_seconds=3)
        bridge.add(etw(1111), received_at=10)
        bridge.add(etw(2222), received_at=10.1)
        self.assertEqual(bridge.stored_records, 1)
        self.assertEqual(bridge.evicted, 1)
        self.assertEqual(bridge.correlate(folder(), received_at=10.2).unverified_event_pids, (2222,))
        self.assertEqual(bridge.correlate(folder(), received_at=20).matched_write_count, 0)
        self.assertEqual(bridge.stored_records, 0)
        self.assertEqual(bridge.evicted, 2)
        with self.assertRaises(ValueError):
            bridge.correlate(FileEvent(SECONDS, PATH, "modified", source="lab"), received_at=20)
        with self.assertRaises(ValueError):
            bridge.correlate(folder(timestamp=float("nan")), received_at=20)


if __name__ == "__main__":
    unittest.main()
