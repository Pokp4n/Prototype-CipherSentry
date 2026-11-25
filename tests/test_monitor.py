"""Real filesystem notifications and entropy-baseline tests."""

import os
import tempfile
import threading
import time
import unittest
from pathlib import Path

from ciphersentry.monitor import FolderMonitor


class RecordingStopEvent(threading.Event):
    """Records debounce waits so tests assert behaviour, not wall-clock speed."""

    def __init__(self):
        super().__init__()
        self.waits = []

    def wait(self, timeout=None):
        self.waits.append(timeout)
        return super().wait(timeout)


def wait_for(predicate, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


class FolderMonitorTests(unittest.TestCase):
    def test_backlog_older_than_debounce_is_not_delayed_per_event(self):
        """Regression: the old consumer slept 60 ms before every queued event."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            paths = []
            for index in range(25):
                path = root / f"queued-{index}.txt"
                path.write_bytes(bytes(range(256)) * 16)
                paths.append(path)
            events = []
            monitor = FolderMonitor(root, events.append)
            stop = RecordingStopEvent()
            monitor._stop = stop
            observed_at = time.time() - 5.0  # notifications already 5 s old
            for path in paths:
                monitor._pending.put_nowait(("modified", str(path), "", observed_at))
            consumer = threading.Thread(target=monitor._consume)
            consumer.start()
            try:
                self.assertTrue(wait_for(lambda: len(events) == len(paths)), "Backlog was not delivered")
            finally:
                stop.set()
                consumer.join(timeout=2)
            self.assertFalse(consumer.is_alive())
            self.assertEqual(stop.waits, [], "A stale backlog must not wait again for each event")
            self.assertEqual({event.path for event in events}, {str(path) for path in paths})
            self.assertTrue(all(event.timestamp == observed_at for event in events),
                            "Events keep their notification time as the time origin")
            # Lag is measured from the notification, so it is at least the 5 s age.
            self.assertGreaterEqual(monitor.max_lag_seconds, 5.0)
            self.assertGreaterEqual(monitor.last_lag_seconds, 5.0)
            self.assertEqual(monitor.pending_count, 0)

    def test_fresh_notification_waits_and_stop_interrupts_the_wait(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            path = root / "fresh.txt"
            path.write_bytes(b"fresh write")
            events = []
            monitor = FolderMonitor(root, events.append)
            monitor.DEBOUNCE_SECONDS = 30.0  # long enough that the wait is certain
            stop = RecordingStopEvent()
            monitor._stop = stop
            monitor._pending.put_nowait(("modified", str(path), "", time.time()))
            consumer = threading.Thread(target=monitor._consume)
            consumer.start()
            try:
                self.assertTrue(wait_for(lambda: stop.waits, 5), "Fresh event was not debounced")
            finally:
                stop.set()
                consumer.join(timeout=2)
            self.assertFalse(consumer.is_alive(), "Stop must interrupt the debounce wait")
            self.assertEqual(len(stop.waits), 1)
            self.assertTrue(0 < stop.waits[0] <= 30.0)
            self.assertEqual(events, [], "An event interrupted by stop is not emitted")

    def test_real_burst_is_fully_observed_without_queue_drops(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            folders = [root / f"dept-{index}" for index in range(4)]
            for folder in folders:
                folder.mkdir()
            paths = [folders[index % 4] / f"doc-{index:03d}.txt" for index in range(120)]
            for path in paths:
                path.write_bytes(b"plain document\n" * 64)
            seen = set()
            lock = threading.Lock()

            def callback(event):
                with lock:
                    seen.add(os.path.normcase(event.path))

            monitor = FolderMonitor(root, callback)
            try:
                monitor.start()
                self.assertEqual(monitor.baseline_count, len(paths))
                for path in paths:
                    path.write_bytes(os.urandom(4096))
                expected = {os.path.normcase(str(path)) for path in paths}

                def all_observed():
                    with lock:
                        return expected <= seen

                self.assertTrue(wait_for(all_observed, 30), "Some rewritten files were never observed")
            finally:
                monitor.stop()
            self.assertEqual(monitor.dropped_events, 0)

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
