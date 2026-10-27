"""Explainable, rolling-window behavioural scoring for the CipherSentry prototype.

The weights are transparent demonstration rules, not a trained or validated malware
classifier. Folder notifications do not establish process attribution. Only events
from the application's lab worker can be eligible for its containment controller.
"""

from __future__ import annotations

import math
import time
from collections import Counter, deque
from dataclasses import asdict, dataclass
from pathlib import PurePosixPath, PureWindowsPath


def shannon_entropy(data: bytes) -> float:
    """Return byte-wise Shannon entropy (0–8 bits/byte); empty data has entropy 0."""
    if not data:
        return 0.0
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in Counter(data).values())


@dataclass(frozen=True)
class FileEvent:
    timestamp: float
    path: str
    operation: str
    pid: int | None = None
    process_name: str = "Unattributed activity"
    entropy_before: float | None = None
    entropy_after: float | None = None
    source: str = "folder"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class Signal:
    name: str
    value: str
    points: int
    explanation: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class Assessment:
    key: str
    score: int
    level: str
    signals: list[Signal]
    event_count: int
    files_count: int
    directories_count: int
    process_name: str
    pid: int | None
    first_seen: float
    last_seen: float
    eligible_for_containment: bool

    def to_dict(self) -> dict:
        return asdict(self)


def _path_parts(path: str) -> tuple[str, str, str]:
    # Windows event logs must remain meaningful when evaluated on Linux in CI.
    cls = PureWindowsPath if "\\" in path or (len(path) > 1 and path[1] == ":") else PurePosixPath
    parsed = cls(path)
    normalized = str(parsed).casefold() if cls is PureWindowsPath else str(parsed)
    directory = str(parsed.parent).casefold() if cls is PureWindowsPath else str(parsed.parent)
    return normalized, directory, parsed.suffix.casefold()


class RiskEngine:
    """Aggregate evidence per verified lab PID, or one unattributed folder stream.

    The engine does not verify PIDs or suspend processes. That is the responsibility
    of the separate lab controller, which must verify process creation time and
    ownership before acting. All evidence expires after ``window_seconds``.
    """

    MAX_EVENTS_PER_GROUP = 10_000
    MAX_GROUPS = 128
    SUSPICIOUS_SUFFIXES = frozenset({".locked-demo", ".locked", ".encrypted", ".cipher", ".crypt", ".enc"})

    def __init__(self, window_seconds: float = 10.0, containment_threshold: int = 75):
        if not math.isfinite(window_seconds) or window_seconds <= 0:
            raise ValueError("window_seconds must be positive and finite")
        self.window_seconds = float(window_seconds)
        self.containment_threshold = containment_threshold
        self._history: dict[str, deque[FileEvent]] = {}

    @property
    def containment_threshold(self) -> int:
        return self._containment_threshold

    @containment_threshold.setter
    def containment_threshold(self, value: int) -> None:
        if isinstance(value, bool) or not isinstance(value, int) or not 40 <= value <= 100:
            raise ValueError("containment_threshold must be an integer from 40 to 100")
        self._containment_threshold = value

    @staticmethod
    def _key(event: FileEvent) -> str:
        if event.source == "lab" and event.pid is not None and event.pid > 0:
            return f"lab:{event.pid}"
        return "folder:unattributed"

    def reset(self) -> None:
        self._history.clear()

    def forget_process(self, pid: int) -> None:
        """Clear a lab PID's evidence after a newly launched worker is verified.

        Operating systems reuse PIDs. The controller must call this when it
        registers a new worker, so a previous incarnation cannot contribute to
        the new run. The containment controller separately verifies creation time.
        Unattributed folder evidence and other lab groups remain intact.
        """
        self._history.pop(f"lab:{pid}", None)

    def ingest(self, event: FileEvent) -> Assessment:
        if not math.isfinite(event.timestamp):
            raise ValueError("event timestamp must be finite")
        key = self._key(event)
        if key not in self._history and len(self._history) >= self.MAX_GROUPS:
            oldest = min(self._history, key=lambda k: max(e.timestamp for e in self._history[k]))
            del self._history[oldest]
        history = self._history.setdefault(key, deque(maxlen=self.MAX_EVENTS_PER_GROUP))
        history.append(event)
        newest = max(e.timestamp for e in history)
        # Filtering, instead of popleft alone, also handles delayed/out-of-order events.
        history = deque(
            (e for e in history if e.timestamp >= newest - self.window_seconds),
            maxlen=self.MAX_EVENTS_PER_GROUP,
        )
        self._history[key] = history
        return self._assess(key, list(history))

    def latest(self, now: float | None = None) -> list[Assessment]:
        """Return current assessments, removing expired evidence and empty groups."""
        current = time.time() if now is None else now
        if not math.isfinite(current):
            raise ValueError("now must be finite")
        results = []
        for key in list(self._history):
            history = deque(
                (e for e in self._history[key] if e.timestamp >= current - self.window_seconds),
                maxlen=self.MAX_EVENTS_PER_GROUP,
            )
            if not history:
                del self._history[key]
                continue
            self._history[key] = history
            results.append(self._assess(key, list(history)))
        return sorted(results, key=lambda a: (a.score, a.last_seen), reverse=True)

    def _assess(self, key: str, events: list[FileEvent]) -> Assessment:
        events.sort(key=lambda e: e.timestamp)
        paths = [_path_parts(e.path) for e in events]
        file_count = len({p[0] for p in paths})
        directory_count = len({p[1] for p in paths})
        count = len(events)

        activity_points = 25 if file_count >= 16 else 18 if file_count >= 8 else 8 if file_count >= 4 else 0
        activity = Signal(
            "File activity",
            f"{file_count} files / {self.window_seconds:g}s",
            activity_points,
            f"{count} observed operations touched {file_count} distinct files in the rolling "
            f"{self.window_seconds:g}-second window. High I/O alone is insufficient for containment.",
        )

        comparable = [
            e for e in events
            if e.entropy_before is not None and e.entropy_after is not None
            and math.isfinite(e.entropy_before) and math.isfinite(e.entropy_after)
            and 0 <= e.entropy_before <= 8 and 0 <= e.entropy_after <= 8
        ]
        rises = {
            _path_parts(e.path)[0] for e in comparable
            if e.entropy_after >= 7.0 and e.entropy_after - e.entropy_before >= 1.0
        }
        rise_count = len(rises)
        entropy_points = 30 if rise_count >= 3 else 20 if rise_count >= 2 else 8 if rise_count else 0
        entropy = Signal(
            "Entropy change",
            f"{rise_count} significant rises",
            entropy_points,
            f"{rise_count} distinct files rose by at least 1.0 bit/byte to at least 7.0 bits/byte. "
            f"{len(comparable)} operations had before/after samples. Existing compressed or encrypted "
            "files do not score merely for already having high entropy.",
        )

        spread_points = 15 if directory_count >= 3 else 8 if directory_count >= 2 else 0
        spread = Signal(
            "Directory spread",
            f"{directory_count} directories",
            spread_points,
            f"Observed changes span {directory_count} parent directories. This contextual signal "
            "also occurs in legitimate backups and bulk edits.",
        )

        operation_counts = Counter(e.operation.casefold() for e in events)
        destructive_counts = {k: v for k, v in operation_counts.items() if k in {"modified", "moved", "renamed", "deleted"}}
        repeated_operation, repeats = max(destructive_counts.items(), key=lambda kv: kv[1], default=("changes", 0))
        repeat_points = 15 if repeats >= 6 else 8 if repeats >= 3 else 0
        pattern = Signal(
            "Repeated operations",
            f"{repeats} {repeated_operation}",
            repeat_points,
            f"The window contains {repeats} repeated {repeated_operation} operations. This is "
            "supporting evidence, not proof that a process is malicious.",
        )

        renamed = {
            part[0] for event, part in zip(events, paths)
            if event.operation.casefold() in {"moved", "renamed"} and part[2] in self.SUSPICIOUS_SUFFIXES
        }
        rename_count = len(renamed)
        rename_points = 15 if rename_count >= 3 else 6 if rename_count else 0
        extension = Signal(
            "Rename pattern",
            f"{rename_count} flagged extensions",
            rename_points,
            f"{rename_count} distinct files were renamed to demonstration watch-list extensions "
            "such as .locked-demo, .locked or .encrypted. Extensions alone do not identify ransomware.",
        )

        signals = [activity, entropy, spread, pattern, extension]
        score = min(100, sum(signal.points for signal in signals))
        contributing = sum(signal.points > 0 for signal in signals)
        level = "High" if score >= self.containment_threshold else "Elevated" if score >= 40 else "Low"
        attributed = key.startswith("lab:")
        newest = events[-1]
        return Assessment(
            key=key,
            score=score,
            level=level,
            signals=signals,
            event_count=count,
            files_count=file_count,
            directories_count=directory_count,
            process_name=newest.process_name if attributed else "Unattributed folder activity",
            pid=newest.pid if attributed else None,
            first_seen=events[0].timestamp,
            last_seen=newest.timestamp,
            eligible_for_containment=attributed and score >= self.containment_threshold and contributing >= 3,
        )
