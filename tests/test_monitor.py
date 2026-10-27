"""Real filesystem notifications and entropy-baseline tests."""

import os
import tempfile
import threading
import time
import unittest
from pathlib import Path

from ciphersentry.monitor import FolderMonitor


class FolderMonitorTests(unittest.TestCase):
    def test_real_write_reports_entropy_change_without_pid(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            document = root / "document.txt"
            document.write_bytes(b"A" * 8192)
            events = []
            received = threading.Event()

            def callback(event):
                events.append(event)
                if event.entropy_before is not None and event.entropy_after is not None and event.entropy_after > 7:
                    received.set()

            monitor = FolderMonitor(root, callback)
            try:
                monitor.start()
                self.assertEqual(monitor.baseline_count, 1)
                document.write_bytes(bytes(range(256)) * 32)
                self.assertTrue(received.wait(5), "Watchdog did not deliver the modified file")
                changed = next(event for event in events if event.entropy_after and event.entropy_after > 7)
                self.assertIsNone(changed.pid)
                self.assertEqual(changed.source, "folder")
                self.assertEqual(changed.entropy_before, 0.0)
            finally:
                monitor.stop()
            self.assertFalse(monitor.running)

    def test_symlink_target_is_never_sampled(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            watched = root / "watched"
            watched.mkdir()
            outside = root / "private.txt"
            outside.write_bytes(b"secret contents")
            link = watched / "linked.txt"
            try:
                link.symlink_to(outside)
            except OSError:
                self.skipTest("Symlink creation is unavailable")
            monitor = FolderMonitor(watched, lambda event: None)
            try:
                monitor.start()
                self.assertEqual(monitor.baseline_count, 0)
                self.assertIsNone(monitor._sample(link))
                self.assertIsNone(monitor._safe_path(outside))
            finally:
                monitor.stop()

    def test_bounded_baseline_and_unknown_initial_entropy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            for index in range(4):
                (root / f"file-{index}.txt").write_bytes(b"initial")
            warnings = []
            monitor = FolderMonitor(root, lambda event: None, warnings.append)
            monitor.MAX_BASELINE_FILES = 2
            try:
                monitor.start()
                self.assertEqual(monitor.baseline_count, 2)
                self.assertTrue(any("limit" in warning.lower() for warning in warnings))
            finally:
                monitor.stop()

    @unittest.skipUnless(hasattr(os, "mkfifo"), "Named pipes are POSIX-only")
    def test_special_files_are_skipped_without_blocking(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            pipe = root / "pipe"
            os.mkfifo(pipe)
            monitor = FolderMonitor(root, lambda event: None)
            self.assertIsNone(monitor._sample(pipe))

    def test_stop_during_baseline_cancels_observer_start(self):
        with tempfile.TemporaryDirectory() as directory:
            monitor = FolderMonitor(Path(directory).resolve(), lambda event: None)
            entered = threading.Event()
            release = threading.Event()

            def delayed_baseline():
                entered.set()
                release.wait(2)

            monitor._build_baseline = delayed_baseline
            starter = threading.Thread(target=monitor.start)
            starter.start()
            self.assertTrue(entered.wait(2))
            monitor.stop()
            release.set()
            starter.join(timeout=2)
            self.assertFalse(starter.is_alive())
            self.assertFalse(monitor.running)
            self.assertIsNone(monitor._observer)


if __name__ == "__main__":
    unittest.main()
