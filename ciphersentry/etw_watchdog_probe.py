"""Stage 5.5F.2: read-only live ETW + watchdog candidate-correlation probe.

Usage (Windows, from project root, with the existing C# streamer on stdin):
    dotnet <LiveEtwStreamer.dll> | python -u -m ciphersentry.etw_watchdog_probe --root <experiment-root>

This is an *observability experiment*, NOT trusted process attribution,
not an input to RiskEngine, and never a process-control authorization.
The ETW event-header PID and lexical path/time matches remain unverified.
"""
from __future__ import annotations

import argparse
import ntpath
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, TextIO

from .engine import FileEvent
from .etw_correlation import RecentEtwEvidence, FolderWriteCorrelation
from .etw_evidence import EtwWriteEvidence, is_within_root
from .etw_stream import parse_stream_line


@dataclass(frozen=True)
class CandidateMatch:
    """One folder notification with nearby ETW evidence; NEVER PID verification."""

    path: str
    operation: str
    evidence: FolderWriteCorrelation


class EtwWatchdogProbe:
    """Join notification and ETW observations in either arrival order.

    Supports callbacks from the FolderMonitor worker and stdin on another
    thread. Pending folder events are retained briefly to allow ETW buffering.
    Only the two-writer fixture file is shown, so unrelated paths stay private.
    """

    def __init__(self, root: str, *, on_match: Callable[[CandidateMatch], None] | None = None,
                 max_pending: int = 1024, pending_seconds: float = 3.5):
        if not isinstance(root, str) or not ntpath.isabs(root):
            raise ValueError("root must be an absolute Windows path")
        if type(max_pending) is not int or not 1 <= max_pending <= 100_000:
            raise ValueError("invalid max_pending")
        if isinstance(pending_seconds, bool) or not isinstance(pending_seconds, (int, float)) or not 1 <= pending_seconds <= 10:
            raise ValueError("invalid pending_seconds")
        self.root = ntpath.normcase(ntpath.normpath(root))
        self._recent = RecentEtwEvidence(root, retention_seconds=10.0,
                                         match_window_seconds=2.0)
        self._pending: deque[tuple[float, FileEvent]] = deque()
        self._lock = threading.RLock()
        self._on_match = on_match or (lambda match: None)
        self.max_pending = max_pending
        self.pending_seconds = float(pending_seconds)
        self.folder_events = 0
        self.etw_events = 0
        self.matched = 0
        self.not_matched = 0
        self.pending_evicted = 0
        self.unique_reported_pids: set[int] = set()
        self.system_pid_writes = 0
        self.arrival_delay_ms: list[float] = []

    def _is_target(self, path: str | None) -> bool:
        if not is_within_root(path, self.root):
            return False
        assert path is not None
        if ntpath.normcase(ntpath.basename(path)) != "etw-writer-test.txt":
            return False
        return ntpath.normcase(ntpath.basename(ntpath.dirname(path))).startswith("writer-run-")

    def on_folder(self, event: FileEvent, *, received_at: float | None = None) -> None:
        if (not isinstance(event, FileEvent) or event.source != "folder" or
                event.operation not in {"created", "modified"} or not self._is_target(event.path)):
            return
        now = time.monotonic() if received_at is None else float(received_at)
        with self._lock:
            self.folder_events += 1
            if len(self._pending) >= self.max_pending:
                self._pending.popleft()
                self.pending_evicted += 1
            self._pending.append((now, event))
            self._resolve(now, final=False)

    def on_etw(self, event: EtwWriteEvidence, *, received_at: float | None = None,
               wall_time: datetime | None = None) -> None:
        if not isinstance(event, EtwWriteEvidence):
            raise TypeError("event must be parsed ETW write evidence")
        now = time.monotonic() if received_at is None else float(received_at)
        if not self._is_target(event.filename):
            return
        with self._lock:
            if self._recent.add(event, received_at=now):
                self.etw_events += 1
                if event.reported_pid == 4:
                    self.system_pid_writes += 1
                elif event.reported_pid > 4:
                    self.unique_reported_pids.add(event.reported_pid)
                if wall_time is None:
                    wall_time = datetime.now(timezone.utc)
                self.arrival_delay_ms.append((wall_time - event.event_time_utc).total_seconds() * 1000)
                self._resolve(now, final=False)

    def _resolve(self, now: float, *, final: bool) -> None:
        """Finalize only mature notifications, allowing delayed ETW candidates.

        An early ETW match is NOT complete evidence: later records for the same
        file can report different PIDs. `pending_seconds` is a bounded *test*
        window, not proof that all relevant kernel events were delivered.
        Must be called with the lock held.
        """
        remaining: deque[tuple[float, FileEvent]] = deque()
        notifications: list[CandidateMatch] = []
        for queued_at, folder in self._pending:
            if not final and now - queued_at < self.pending_seconds:
                remaining.append((queued_at, folder))
                continue
            result = self._recent.correlate(folder, received_at=now)
            if result.matched_write_count:
                self.matched += 1
                notifications.append(CandidateMatch(folder.path, folder.operation, result))
            else:
                self.not_matched += 1
        self._pending = remaining
        for notification in notifications:
            self._on_match(notification)

    def tick(self, *, received_at: float | None = None) -> None:
        """Expire matured notifications even when no new ETW events arrive."""
        now = time.monotonic() if received_at is None else float(received_at)
        with self._lock:
            self._resolve(now, final=False)

    def finish(self) -> None:
        with self._lock:
            self._resolve(time.monotonic(), final=True)


def consume_and_join(source: TextIO, probe: EtwWatchdogProbe) -> int:
    """Validated JSONL intake; each record is observed exactly once."""
    count = 0
    for number, line in enumerate(source, 1):
        try:
            event = parse_stream_line(line)
        except ValueError as exc:
            raise ValueError(f"Invalid JSONL line {number}: {exc}") from exc
        probe.on_etw(event)
        count += 1
    return count


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only ETW + watchdog live correlation experiment")
    parser.add_argument("--root", required=True, help="Existing experiment directory (Windows absolute path)")
    parser.add_argument("--show-first", type=int, default=12)
    args = parser.parse_args()
    if not 0 <= args.show_first <= 50:
        parser.error("--show-first must be 0..50")
    root_path = Path(args.root)
    if not root_path.is_dir() or root_path.is_symlink():
        print("Experiment root must be an existing, real directory.", file=sys.stderr)
        return 2

    # Import only in live CLI mode; pure join logic is unit-testable without Qt.
    try:
        from .monitor import FolderMonitor
    except ImportError as exc:
        print(f"Watchdog monitor unavailable: {exc}", file=sys.stderr)
        return 2

    shown = 0
    def report_match(match: CandidateMatch) -> None:
        nonlocal shown
        if shown >= args.show_first:
            return
        shown += 1
        evidence = match.evidence
        print(f"[CANDIDATE {shown}] {ntpath.basename(match.path)!r} "
              f"folder={match.operation} nearby_ETW={evidence.matched_write_count} "
              f"unverified_pids={evidence.unverified_event_pids} "
              f"pid4_writes={evidence.system_pid4_writes} "
              f"status={evidence.status}; verified_writer_pid=None", flush=True)

    probe = EtwWatchdogProbe(args.root, on_match=report_match)
    monitor = FolderMonitor(root_path, probe.on_folder,
                            lambda msg: print(f"[Watchdog warning] {msg}", file=sys.stderr, flush=True))
    print("=== Stage 5.5F.2: Live ETW + watchdog correlation (READ ONLY) ===", flush=True)
    print("No risk scoring. No process containment. PID claims remain UNVERIFIED.", flush=True)
    try:
        monitor.start()  # Start filesystem observer BEFORE reading ETW stdin.
    except Exception as exc:
        print(f"Could not start folder monitor: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print("Watchdog ready. Once C# reports 'Listening for events', run two-writer-probe.ps1.", flush=True)
    # The ETW reader may block awaiting a record. A small clock thread ensures
    # candidate windows still close when there is no subsequent I/O activity.
    ticker_stop = threading.Event()
    def close_mature_windows() -> None:
        while not ticker_stop.wait(0.10):
            probe.tick()
    ticker = threading.Thread(target=close_mature_windows, name="etw-join-expiry", daemon=True)
    ticker.start()
    exit_code = 0
    consumed = 0
    try:
        consumed = consume_and_join(sys.stdin, probe)
    except (UnicodeError, ValueError, OSError) as exc:
        print(f"ETW input rejected: {exc}", file=sys.stderr)
        exit_code = 2
    finally:
        ticker_stop.set()
        ticker.join(timeout=1)
        monitor.stop()
        probe.finish()
    print("\n=== Stage 5.5F.2 Live Correlation Summary ===")
    print(f"ETW JSONL records received: {consumed}")
    print(f"In-scope target-file ETW writes: {probe.etw_events}")
    print(f"Target-file watchdog notifications: {probe.folder_events}")
    print(f"Folder notifications with nearby ETW evidence: {probe.matched}")
    print(f"Folder notifications without nearby ETW evidence: {probe.not_matched}")
    print(f"Pending notifications evicted: {probe.pending_evicted}")
    print(f"Observed non-system event PIDs (UNVERIFIED): {sorted(probe.unique_reported_pids)}")
    print(f"System PID 4 target-file writes: {probe.system_pid_writes}")
    if probe.arrival_delay_ms:
        durations = sorted(probe.arrival_delay_ms)
        percentile = durations[(len(durations) - 1) // 2]
        print(f"Approximate ETW event-to-Python arrival P50: {percentile:.2f} ms")
    print("Correlation is candidate evidence only. No risk scoring or containment.")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
