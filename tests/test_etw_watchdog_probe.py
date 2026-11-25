"""Stage 5.5F.2 read-only live correlation harness unit tests."""
import unittest
from datetime import datetime, timezone

from ciphersentry.engine import FileEvent
from ciphersentry.etw_evidence import parse_write
from ciphersentry.etw_watchdog_probe import EtwWatchdogProbe

ROOT = r"C:\dev\CipherSentry\Experiments\CipherSentry-ETW"
TARGET = ROOT + r"\writer-run-20261117-123000-22208\etw-writer-test.txt"
T = datetime(2026, 11, 17, 4, 30, tzinfo=timezone.utc)


def create_etw(pid=22208, path=TARGET, *, offset=0):
    stamp = datetime.fromtimestamp(T.timestamp() + offset, tz=timezone.utc).isoformat()
    return parse_write({
        "kind": "Write", "event_time_utc": stamp, "callback_time_utc": stamp,
        "reported_pid": str(pid), "file_key": "0x0000000000000001",
        "file_object": "0x0000000000000002", "io_size": "21",
        "filename": path, "details": "reader-prior-key-candidate",
    })


def create_folder(path=TARGET, *, offset=0, operation="modified", source="folder"):
    return FileEvent(T.timestamp() + offset, path, operation, source=source, attribution="unavailable")


class LiveJoinTests(unittest.TestCase):
    def test_folder_first_etw_later(self):
        matches = []
        probe = EtwWatchdogProbe(ROOT, on_match=matches.append)
        probe.on_folder(create_folder(), received_at=10)
        self.assertEqual(probe.matched, 0)
        probe.on_etw(create_etw(), received_at=10.3)
        self.assertEqual(probe.matched, 0)  # Early matching does not finalize.
        probe.tick(received_at=13.5)
        self.assertEqual(probe.matched, 1)
        self.assertEqual(matches[0].evidence.unverified_event_pids, (22208,))
        self.assertIsNone(matches[0].evidence.verified_writer_pid)
        self.assertFalse(matches[0].evidence.containment_authorized)

    def test_etw_first_folder_later(self):
        probe = EtwWatchdogProbe(ROOT)
        probe.on_etw(create_etw(), received_at=10)
        probe.on_folder(create_folder(), received_at=10.1)
        self.assertEqual(probe.matched, 0)
        probe.tick(received_at=13.6)
        self.assertEqual(probe.matched, 1)

    def test_system_pid_does_not_create_writer_identity(self):
        matches = []
        probe = EtwWatchdogProbe(ROOT, on_match=matches.append)
        probe.on_etw(create_etw(4), received_at=10)
        probe.on_folder(create_folder(), received_at=10.2)
        probe.tick(received_at=13.7)
        self.assertEqual(matches[0].evidence.status, "no_usable_pid")
        self.assertEqual(matches[0].evidence.unverified_event_pids, ())
        self.assertEqual(probe.system_pid_writes, 1)

    def test_multiple_candidate_pids_remain_ambiguous(self):
        matches = []
        probe = EtwWatchdogProbe(ROOT, on_match=matches.append)
        probe.on_etw(create_etw(22208), received_at=10)
        probe.on_etw(create_etw(34988, offset=0.1), received_at=10.1)
        probe.on_folder(create_folder(), received_at=10.2)
        probe.tick(received_at=13.7)
        self.assertEqual(matches[0].evidence.status, "multiple_unverified_pids")
        self.assertFalse(matches[0].evidence.containment_authorized)

    def test_late_second_pid_is_included_before_maturity(self):
        matches = []
        probe = EtwWatchdogProbe(ROOT, on_match=matches.append)
        probe.on_folder(create_folder(), received_at=10.0)
        probe.on_etw(create_etw(39964), received_at=10.1)
        self.assertEqual(len(matches), 0)  # No irreversible early decision.
        probe.on_etw(create_etw(13160, offset=0.1), received_at=10.2)
        probe.tick(received_at=13.49)
        self.assertEqual(len(matches), 0)
        probe.tick(received_at=13.5)
        self.assertEqual(len(matches), 1)
        evidence = matches[0].evidence
        self.assertEqual(evidence.unverified_event_pids, (13160, 39964))
        self.assertEqual(evidence.status, "multiple_unverified_pids")
        self.assertIsNone(evidence.verified_writer_pid)
        self.assertFalse(evidence.containment_authorized)

    def test_late_system_pid4_is_counted_without_assigning_writer(self):
        matches = []
        probe = EtwWatchdogProbe(ROOT, on_match=matches.append)
        probe.on_folder(create_folder(), received_at=10.0)
        probe.on_etw(create_etw(39964), received_at=10.1)
        probe.on_etw(create_etw(4, offset=0.1), received_at=11.0)
        probe.tick(received_at=13.5)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].evidence.unverified_event_pids, (39964,))
        self.assertEqual(matches[0].evidence.system_pid4_writes, 1)
        self.assertIsNone(matches[0].evidence.verified_writer_pid)

    def test_no_match_expires_without_more_events(self):
        probe = EtwWatchdogProbe(ROOT)
        probe.on_folder(create_folder(), received_at=10.0)
        probe.tick(received_at=13.49)
        self.assertEqual(probe.not_matched, 0)
        probe.tick(received_at=13.5)
        self.assertEqual(probe.not_matched, 1)
        self.assertEqual(probe.matched, 0)
        probe.tick(received_at=15.0)
        self.assertEqual(probe.not_matched, 1)  # No duplicate resolution.

    def test_excludes_unrelated_and_untrusted_folder_source(self):
        probe = EtwWatchdogProbe(ROOT)
        probe.on_etw(create_etw(path=ROOT + r"\other.txt"), received_at=10)
        probe.on_etw(create_etw(path=ROOT + r"-outside\writer-run-4\etw-writer-test.txt"), received_at=10)
        probe.on_folder(create_folder(source="lab"), received_at=10)
        self.assertEqual(probe.etw_events, 0)
        self.assertEqual(probe.folder_events, 0)

    def test_unmatched_is_reported_without_guessing(self):
        probe = EtwWatchdogProbe(ROOT)
        probe.on_folder(create_folder(), received_at=10)
        probe.on_folder(create_folder(operation="deleted"), received_at=10)
        probe.finish()
        self.assertEqual(probe.matched, 0)
        self.assertEqual(probe.not_matched, 1)
        self.assertEqual(probe.folder_events, 1)


if __name__ == "__main__":
    unittest.main()
