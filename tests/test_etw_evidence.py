"""Regression tests for the read-only experimental ETW CSV adapter."""
import csv
import tempfile
import unittest
from pathlib import Path

from ciphersentry.etw_evidence import is_within_root, iter_writes, parse_write, summarize_scope


ROOT = r"C:\Demo\protected"
FIRST = r"C:\Demo\protected\writer-run-1\etw-writer-test.txt"
OUTSIDE = r"C:\Demo\protected-extra\other.txt"


def row(kind="Write", pid="1234", filename=FIRST, details="reader-prior-key-candidate"):
    return {
        "kind": kind,
        "event_time_utc": "2026-11-16T09:49:50.8653013Z",
        "callback_time_utc": "2026-11-16T09:49:51.7989653Z",
        "reported_pid": pid,
        "file_key": "0xFFFFCD8AD974B180",
        "file_object": "0xFFFFDF8323966BF0",
        "io_size": "25",
        "filename": filename,
        "details": details,
    }


class EtwEvidenceTests(unittest.TestCase):
    def test_read_priors_are_not_verified_attribution(self):
        evidence = parse_write(row())
        self.assertEqual(evidence.reported_pid, 1234)
        self.assertEqual(evidence.process_attribution, "unverified_event_pid")
        self.assertTrue(evidence.reader_prior_key_candidate)
        self.assertAlmostEqual(evidence.callback_delay_ms, 933.664, places=2)

    def test_system_pid_and_unknown_are_not_attributed(self):
        self.assertEqual(parse_write(row(pid="4")).process_attribution, "unknown")
        self.assertEqual(parse_write(row(pid="-1")).process_attribution, "unknown")

    def test_root_boundary_excludes_sibling_and_missing_path(self):
        self.assertTrue(is_within_root(FIRST, ROOT.lower()))
        self.assertFalse(is_within_root(OUTSIDE, ROOT.lower()))
        self.assertFalse(is_within_root(None, ROOT.lower()))
        self.assertFalse(is_within_root(r"D:\Demo\protected\x.txt", ROOT.lower()))

    def test_summary_counts_only_named_in_scope_and_no_hidden_attribution(self):
        rows = [row(), row(pid="4"), row(filename="", details="no-reader-prior-key-candidate"),
                row(filename=OUTSIDE), row(kind="ProcessStart")]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.csv"
            with path.open("w", encoding="utf-8", newline="") as fp:
                writer = csv.DictWriter(fp, fieldnames=list(rows[0].keys()))
                writer.writeheader()
                writer.writerows(rows)
            items = list(iter_writes(path))
            self.assertEqual(len(items), 4)
            summary = summarize_scope(path, ROOT)
            self.assertEqual(summary.total_write_callbacks, 4)
            self.assertEqual(summary.filename_present, 3)
            self.assertEqual(summary.named_writes_in_scope, 2)
            self.assertEqual(summary.reader_prior_candidates_in_scope, 2)
            self.assertEqual(summary.system_pid_writes_in_scope, 1)
            self.assertEqual(summary.unverified_pid_writes_in_scope, 1)

    def test_malformed_rows_fail_closed(self):
        with self.assertRaises(ValueError):
            parse_write(row(pid="not-a-pid"))
        with self.assertRaises(ValueError):
            parse_write(row(details="verified-original-writer"))
        invalid = row()
        invalid["event_time_utc"] = "not-a-time"
        with self.assertRaises(ValueError):
            parse_write(invalid)


if __name__ == "__main__":
    unittest.main()
