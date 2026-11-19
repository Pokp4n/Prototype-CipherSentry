"""Stage 5.5F: bounded, read-only correlation of ETW writes with watchdog events.

Matches ETW event time and a normalized Windows path to a folder notification.
The result is observational evidence ONLY: matching a PID never verifies the
original writer, and this module cannot authorize process containment.

This is a prototype research aid. Path equality is lexical, not a proof of
underlying file identity (reparse points, renames, and races remain possible).
"""
from __future__ import annotations

import math
import ntpath
import time
from collections import deque
from dataclasses import dataclass

from .engine import FileEvent
from .etw_evidence import EtwWriteEvidence, is_within_root


@dataclass(frozen=True)
class FolderWriteCorrelation:
    """Non-authoritative evidence associated with one watchdog notification."""

    path: str
    operation: str
    matched_write_count: int
    unverified_event_pids: tuple[int, ...]
    system_pid4_writes: int
    reader_prior_key_candidates: int
    status: str
    # No code in this experimental bridge is allowed to verify a writer or
    # to turn a match into a process-control authorization.
    verified_writer_pid: None = None
    containment_authorized: bool = False


class RecentEtwEvidence:
    """A bounded, in-memory set of named Write events under a monitored root.

    ``add`` is called by the receiver on valid, already-parsed ETW writes.
    ``correlate`` is called after the watchdog notification is available.
    Both may be called on one thread; add external synchronization if used on
    multiple threads. Do not send ETW records directly to RiskEngine.ingest.
    """

    def __init__(self, root: str, *, max_events: int = 4096,
                 retention_seconds: float = 10.0,
                 match_window_seconds: float = 2.0):
        if not isinstance(root, str) or not ntpath.isabs(root):
            raise ValueError("Root must be an absolute Windows path")
        if type(max_events) is not int or not 1 <= max_events <= 100_000:
            raise ValueError("max_events must be between 1 and 100000")
        for value, name, minimum, maximum in (
            (retention_seconds, "retention_seconds", 1.0, 120.0),
            (match_window_seconds, "match_window_seconds", 0.01, 10.0),
        ):
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not minimum <= value <= maximum:
                raise ValueError(f"{name} out of range")
        self.root = ntpath.normcase(ntpath.normpath(root))
        self.max_events = max_events
        self.retention_seconds = float(retention_seconds)
        self.match_window_seconds = float(match_window_seconds)
        self._recent: deque[tuple[float, str, EtwWriteEvidence]] = deque()
        self.evicted = 0

    @property
    def stored_records(self) -> int:
        return len(self._recent)

    def _prune(self, received_at: float) -> None:
        cutoff = received_at - self.retention_seconds
        while self._recent and self._recent[0][0] < cutoff:
            self._recent.popleft()
            self.evicted += 1

    def add(self, event: EtwWriteEvidence, *, received_at: float | None = None) -> bool:
        """Retain an in-scope named Write; never try to infer missing filenames."""
        if not isinstance(event, EtwWriteEvidence):
            raise TypeError("Expected parsed EtwWriteEvidence")
        now = time.monotonic() if received_at is None else float(received_at)
        if not math.isfinite(now):
            raise ValueError("received_at must be finite")
        self._prune(now)
        if not is_within_root(event.filename, self.root):
            return False
        path = ntpath.normcase(ntpath.normpath(event.filename))
        while len(self._recent) >= self.max_events:
            self._recent.popleft()
            self.evicted += 1
        self._recent.append((now, path, event))
        return True

    def correlate(self, folder_event: FileEvent, *, received_at: float | None = None) -> FolderWriteCorrelation:
        """Return candidate evidence, never verified writer identity.

        The watcher timestamp is notification time, not necessarily exact write
        time; the fixed window is a *candidate* filter, not an attribution proof.
        A deleted/moved notification is not matched to a Write operation.
        """
        if not isinstance(folder_event, FileEvent) or folder_event.source != "folder":
            raise ValueError("Expected a genuine folder-source FileEvent")
        if isinstance(folder_event.timestamp, bool) or not isinstance(folder_event.timestamp, (int, float)) or not math.isfinite(folder_event.timestamp):
            raise ValueError("Folder timestamp must be finite")
        now = time.monotonic() if received_at is None else float(received_at)
        if not math.isfinite(now):
            raise ValueError("received_at must be finite")
        self._prune(now)
        result = dict(path=folder_event.path, operation=folder_event.operation,
                      matched_write_count=0, unverified_event_pids=(),
                      system_pid4_writes=0, reader_prior_key_candidates=0,
                      status="no_write_evidence")
        if (folder_event.operation not in {"created", "modified"}
                or not is_within_root(folder_event.path, self.root)):
            return FolderWriteCorrelation(**result)
        normalized = ntpath.normcase(ntpath.normpath(folder_event.path))
        matches = [etw for _, path, etw in self._recent
                   if path == normalized and
                   abs(etw.event_time_utc.timestamp() - folder_event.timestamp)
                   <= self.match_window_seconds]
        if not matches:
            return FolderWriteCorrelation(**result)
        pids = tuple(sorted({e.reported_pid for e in matches if e.reported_pid > 4}))
        result.update(
            matched_write_count=len(matches),
            unverified_event_pids=pids,
            system_pid4_writes=sum(e.reported_pid == 4 for e in matches),
            reader_prior_key_candidates=sum(e.reader_prior_key_candidate for e in matches),
            status=("multiple_unverified_pids" if len(pids) > 1
                    else "single_unverified_pid" if pids else "no_usable_pid"),
        )
        return FolderWriteCorrelation(**result)
