"""Configurable behavioural scoring. Numerical rules are development placeholders.

Scores are not malware probabilities. This module never controls a process: a
separate response policy must revalidate identity, provenance and permissions.
"""
from __future__ import annotations

import math
import time
from collections import Counter, deque
from dataclasses import asdict, dataclass, field, replace
from pathlib import PurePosixPath, PureWindowsPath
from types import MappingProxyType
from typing import Mapping

INDICATORS = ("frequency", "entropy", "operations", "spread", "context")
DEFAULT_WEIGHTS = {"frequency": 30, "entropy": 35, "operations": 25, "spread": 10, "context": 0}
INDICATOR_NAMES = {"frequency": "File modification frequency", "entropy": "Entropy change",
                   "operations": "Repeated operations", "spread": "Directory spread", "context": "Process context"}


@dataclass(frozen=True)
class RiskConfig:
    """Immutable development policy; disabled indicators are not renormalized."""
    window_seconds: float = 10.0
    uncertain_threshold: int = 40
    high_threshold: int = 75
    weights: Mapping[str, int] = field(default_factory=lambda: DEFAULT_WEIGHTS.copy())
    enabled_indicators: tuple[str, ...] = INDICATORS

    def __post_init__(self):
        if (isinstance(self.window_seconds, bool) or not isinstance(self.window_seconds, (int, float))
                or not math.isfinite(self.window_seconds) or not .1 <= self.window_seconds <= 300):
            raise ValueError("window_seconds must be finite and between 0.1 and 300")
        for name in ("uncertain_threshold", "high_threshold"):
            if type(getattr(self, name)) is not int or not 1 <= getattr(self, name) <= 100:
                raise ValueError(f"{name} must be an integer from 1 to 100")
        if self.uncertain_threshold >= self.high_threshold:
            raise ValueError("uncertain_threshold must be lower than high_threshold")
        if not isinstance(self.weights, Mapping) or set(self.weights) != set(INDICATORS):
            raise ValueError("weights must contain exactly frequency, entropy, operations, spread and context")
        if any(type(value) is not int or not 0 <= value <= 100 for value in self.weights.values()):
            raise ValueError("Each weight must be an integer from 0 to 100")
        if sum(self.weights.values()) > 100:
            raise ValueError("The sum of indicator weights must not exceed 100")
        if (not isinstance(self.enabled_indicators, (tuple, list))
                or any(not isinstance(item, str) or item not in INDICATORS for item in self.enabled_indicators)
                or len(set(self.enabled_indicators)) != len(self.enabled_indicators)):
            raise ValueError("enabled_indicators must contain unique known indicator names")
        object.__setattr__(self, "window_seconds", float(self.window_seconds))
        object.__setattr__(self, "weights", MappingProxyType(dict(self.weights)))
        object.__setattr__(self, "enabled_indicators", tuple(self.enabled_indicators))

    def to_dict(self) -> dict:
        return {"window_seconds": self.window_seconds, "uncertain_threshold": self.uncertain_threshold,
                "high_threshold": self.high_threshold, "weights": dict(self.weights),
                "enabled_indicators": list(self.enabled_indicators)}

    @classmethod
    def from_dict(cls, value: dict) -> "RiskConfig":
        if not isinstance(value, dict):
            raise ValueError("Risk configuration must be a JSON object")
        allowed = {"window_seconds", "uncertain_threshold", "high_threshold", "weights", "enabled_indicators"}
        if set(value) - allowed:
            raise ValueError("Unknown risk configuration fields")
        return cls(**value)


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    return -sum((count / len(data)) * math.log2(count / len(data)) for count in Counter(data).values())


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
    process_context: dict | None = None
    attribution: str = "unavailable"
    observed_at: float | None = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class Signal:
    name: str
    value: str
    points: int
    explanation: str
    maximum: int = 0
    available: bool = True

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
    features: dict = field(default_factory=dict)
    missing_evidence: list[str] = field(default_factory=list)
    attribution: str = "unavailable"
    response_reason: str = "No response safety decision has been made."
    config: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def _path_parts(path: str) -> tuple[str, str, str]:
    windows = "\\" in path or (len(path) > 1 and path[1] == ":")
    parsed = (PureWindowsPath if windows else PurePosixPath)(path)
    return (str(parsed).casefold() if windows else str(parsed),
            str(parsed.parent).casefold() if windows else str(parsed.parent), parsed.suffix.casefold())


def _stable_lab_identity(event: FileEvent) -> float | None:
    """Check supplied cooperative provenance; this is not OS identity validation."""
    context = event.process_context or {}
    if (event.source != "lab" or event.attribution != "cooperative_lab" or type(event.pid) is not int
            or event.pid <= 0 or type(context.get("pid")) is not int or context.get("pid") != event.pid
            or context.get("identity_verified") is False):
        return None
    started = context.get("create_time", context.get("start_time"))
    if isinstance(started, bool) or not isinstance(started, (int, float)) or not math.isfinite(started) or started <= 0:
        return None
    return float(started)


class RiskEngine:
    """Five-indicator research baseline with bounded, expiring event history."""
    MAX_EVENTS_PER_GROUP = 10_000
    MAX_GROUPS = 128
    SUSPICIOUS_SUFFIXES = frozenset({".locked-demo", ".locked", ".encrypted", ".cipher", ".crypt", ".enc"})

    def __init__(self, window_seconds: float = 10.0, containment_threshold: int = 75, config: RiskConfig | None = None):
        self.config = config if config is not None else RiskConfig(window_seconds=window_seconds, high_threshold=containment_threshold)
        if not isinstance(self.config, RiskConfig):
            raise ValueError("config must be a RiskConfig")
        self._history: dict[str, deque[FileEvent]] = {}
        self._watermark: float | None = None

    @property
    def window_seconds(self) -> float:
        return self.config.window_seconds

    @property
    def containment_threshold(self) -> int:
        """Compatibility alias for the high-risk threshold, not action permission."""
        return self.config.high_threshold

    @containment_threshold.setter
    def containment_threshold(self, value: int):
        self.config = replace(self.config, high_threshold=value)

    def configure(self, config: RiskConfig):
        if not isinstance(config, RiskConfig):
            raise ValueError("config must be a RiskConfig")
        self.config = config
        self.reset()

    @staticmethod
    def _key(event: FileEvent) -> str:
        identity = _stable_lab_identity(event)
        if identity is not None:
            return f"lab:{event.pid}:{identity:.6f}"
        return "folder:unattributed" if event.source == "folder" else "lab:unattributed"

    def reset(self):
        self._history.clear()
        self._watermark = None

    def forget_process(self, pid: int):
        for key in list(self._history):
            if key == f"lab:{pid}" or key.startswith(f"lab:{pid}:"):
                del self._history[key]

    def ingest(self, event: FileEvent) -> Assessment:
        if isinstance(event.timestamp, bool) or not isinstance(event.timestamp, (float, int)) or not math.isfinite(event.timestamp):
            raise ValueError("event timestamp must be finite")
        if event.process_context is not None and not isinstance(event.process_context, dict):
            raise ValueError("process_context must be an object when present")
        if not isinstance(event.path, str) or not event.path.strip():
            raise ValueError("event path must be a nonempty string")
        if not isinstance(event.operation, str) or not event.operation.strip():
            raise ValueError("event operation must be a nonempty string")
        self._watermark = max(event.timestamp, self._watermark if self._watermark is not None else event.timestamp)
        key = self._key(event)
        if event.timestamp < self._watermark - self.window_seconds:
            # An already-expired delayed observation must not resurrect evidence.
            remaining = [e for e in self._history.get(key, ()) if e.timestamp >= self._watermark - self.window_seconds]
            if remaining:
                self._history[key] = deque(remaining, maxlen=self.MAX_EVENTS_PER_GROUP)
                return self._assess(key, remaining)
            self._history.pop(key, None)
            return self._expired_assessment(key, event)
        if key not in self._history and len(self._history) >= self.MAX_GROUPS:
            oldest = min(self._history, key=lambda k: max(e.timestamp for e in self._history[k]))
            del self._history[oldest]
        history = self._history.setdefault(key, deque(maxlen=self.MAX_EVENTS_PER_GROUP))
        history.append(event)
        history = deque((e for e in history if e.timestamp >= self._watermark - self.window_seconds), maxlen=self.MAX_EVENTS_PER_GROUP)
        self._history[key] = history
        return self._assess(key, list(history))

    def latest(self, now: float | None = None) -> list[Assessment]:
        current = time.time() if now is None else now
        if isinstance(current, bool) or not isinstance(current, (float, int)) or not math.isfinite(current):
            raise ValueError("now must be finite")
        self._watermark = max(current, self._watermark if self._watermark is not None else current)
        current = self._watermark
        results = []
        for key in list(self._history):
            history = deque((e for e in self._history[key] if e.timestamp >= current - self.window_seconds), maxlen=self.MAX_EVENTS_PER_GROUP)
            if not history:
                del self._history[key]
                continue
            self._history[key] = history
            results.append(self._assess(key, list(history)))
        return sorted(results, key=lambda a: (a.score, a.last_seen), reverse=True)

    def _expired_assessment(self, key: str, event: FileEvent) -> Assessment:
        reason = "The observation predates the active evidence window; it cannot revive an expired risk assessment."
        signals = [Signal(INDICATOR_NAMES[name], "No current evidence", 0, reason,
                          self.config.weights[name], False) for name in INDICATORS]
        features = {"window_seconds": self.window_seconds, "modification_count": 0,
                    "modification_rate": 0.0, "unique_modified_files": 0, "unique_modified_rate": 0.0,
                    "combined_lab_rewrites": 0, "operation_counts": {}, "operation_transitions": {},
                    "entropy_comparable_count": 0, "entropy_rise_files": 0, "modified_directories": 0,
                    "rename_suffix_files": 0, "process_context": {}, "contributing_families": 0}
        return Assessment(key, 0, "Low", signals, 0, 0, 0, "Expired observation", None,
                          event.timestamp, event.timestamp, False, features, [reason],
                          "unavailable", reason, self.config.to_dict())

    def _signal(self, key, name, value, fraction, explanation, available=True) -> Signal:
        enabled = key in self.config.enabled_indicators
        maximum = self.config.weights[key]
        points = round(maximum * fraction) if enabled and available else 0
        if not enabled:
            explanation += " Disabled by the selected ablation policy; points are excluded without renormalizing other indicators."
        return Signal(name, value, points, explanation, maximum, available)

    def _assess(self, key: str, events: list[FileEvent]) -> Assessment:
        events.sort(key=lambda e: e.timestamp)
        newest = events[-1]
        attributed = _stable_lab_identity(newest) is not None
        paths = [_path_parts(event.path) for event in events]
        changes = []
        combined = 0
        for event, path in zip(events, paths):
            # The lab reports a measured rewrite+rename; an ordinary move alone
            # does not establish a write operation.
            lab_rewrite = (_stable_lab_identity(event) is not None
                           and event.operation.casefold() in {"moved", "renamed"}
                           and event.entropy_before is not None and event.entropy_after is not None)
            if event.operation.casefold() in {"modified", "write", "written"} or lab_rewrite:
                changes.append((event, path))
                combined += int(lab_rewrite)
        unique_modified = len({path[0] for _, path in changes})
        modified_dirs = len({path[1] for _, path in changes})
        modification_rate, unique_rate = len(changes) / self.window_seconds, unique_modified / self.window_seconds
        frequency_fraction = 1.0 if unique_rate >= 1.6 else .72 if unique_rate >= .8 else .32 if unique_rate >= .4 else 0
        if unique_modified < 4:
            frequency_fraction = 0
        frequency = self._signal("frequency", "File modification frequency",
            f"{modification_rate:.2f} changes/s; {unique_rate:.2f} unique files/s", frequency_fraction,
            f"{len(changes)} modification observations affected {unique_modified} distinct paths in {self.window_seconds:g}s. "
            "Repeated writes to one file are counted separately from distinct files. Notifications are not exact OS write-call counts. "
            f"{combined} cooperative lab observations combine a measured rewrite and rename. Activity alone cannot establish maliciousness.")

        def valid_entropy(value):
            return not isinstance(value, bool) and isinstance(value, (float, int)) and math.isfinite(value) and 0 <= value <= 8
        comparable = [event for event in events if valid_entropy(event.entropy_before) and valid_entropy(event.entropy_after)]
        rises = {_path_parts(event.path)[0] for event in comparable if event.entropy_after >= 7.0 and event.entropy_after - event.entropy_before >= 1.0}
        rise_count = len(rises)
        entropy = self._signal("entropy", "Entropy change", f"{rise_count} rises / {len(comparable)} sampled observations",
            1.0 if rise_count >= 3 else .67 if rise_count == 2 else .25 if rise_count else 0,
            f"{rise_count} distinct paths rose by at least 1 bit/byte to at least 7 bits/byte. "
            f"{len(events) - len(comparable)} observations lack comparable samples. Missing samples are unknown evidence. "
            "Compression and legitimate encryption can produce similar changes; partial modifications may be missed.", bool(comparable))
        operation_counts = Counter(event.operation.casefold() for event in events)
        transitions = Counter(f"{a.operation.casefold()} → {b.operation.casefold()}" for a, b in zip(events, events[1:]))
        changing = {name: count for name, count in operation_counts.items() if name in {"modified", "write", "written", "moved", "renamed", "deleted"}}
        repeated_operation, repeats = max(changing.items(), key=lambda item: item[1], default=("changes", 0))
        rename_count = len({part[0] for event, part in zip(events, paths) if event.operation.casefold() in {"moved", "renamed"} and part[2] in self.SUSPICIOUS_SUFFIXES})
        pattern = self._signal("operations", "Repeated operations", f"{repeats} repeated {repeated_operation}",
            1.0 if repeats >= 6 else .5 if repeats >= 3 else 0,
            f"Observed operation counts: {dict(operation_counts)}. {len(transitions)} adjacent transition types were measured; "
            "no fixed Read → Write → Rename sequence is required. "
            f"{rename_count} paths ended in demonstration watch-list suffixes; this adds no separate points. "
            "Adjacency in a collected stream is not proof of a causal sequence.")
        spread = self._signal("spread", "Directory spread", f"{modified_dirs} modified-file directories",
            1.0 if modified_dirs >= 3 else .5 if modified_dirs == 2 else 0,
            f"Modification observations span {modified_dirs} distinct immediate parent directories. "
            "Nested parents each count once; ancestors are not added. Backups can spread widely. "
            "Directory spread is supporting evidence and is not required for high risk.")
        context = dict(newest.process_context or {})
        if "create_time" not in context and "start_time" in context:
            context["create_time"] = context["start_time"]
        signature = context.get("signature_status", "not_checked")
        process_signal = self._signal("context", "Process context",
            f"PID {newest.pid}; signature {signature}" if attributed else "Writer identity unavailable", 0,
            "Attribution identifies the writer; metadata only describes that process. "
            + (f"Cooperative lab PID {newest.pid}, start time {context.get('create_time')}, executable {context.get('executable', 'unavailable')}. " if attributed else "The collector has not established a stable writer identity. ")
            + "Signature validation is not implemented. Names, familiarity, signatures and missing metadata do not establish safety or maliciousness. "
            "No contextual risk rule has been validated, so this indicator currently contributes zero points regardless of its configured weight.", attributed)
        missing = []
        if len(comparable) < len(events):
            missing.append(f"Comparable before/after entropy is unavailable for {len(events) - len(comparable)} of {len(events)} observations.")
        if not attributed:
            missing.append("Stable process attribution is unavailable; activity may combine multiple writers.")
        if attributed:
            metadata_missing = context.get("missing", [])
            metadata_errors = context.get("errors", [])
            if isinstance(metadata_missing, list):
                missing.extend(f"Process metadata unavailable: {name}." for name in metadata_missing if isinstance(name, str))
            if isinstance(metadata_errors, list):
                missing.extend(f"Process metadata collection: {message}" for message in metadata_errors if isinstance(message, str))
        missing.append("Digital signature validation is not implemented.")
        missing.append("The folder collector does not observe read calls or exact per-process writes; notification completeness is not guaranteed." if newest.source == "folder" else "Lab telemetry is cooperative simulation instrumentation, not an independent Windows process-attribution collector.")
        signals = [frequency, entropy, pattern, spread, process_signal]
        score = sum(signal.points for signal in signals)
        contributing = sum(signal.points > 0 for signal in signals)
        level = "High" if score >= self.config.high_threshold else "Uncertain" if score >= self.config.uncertain_threshold else "Low"
        eligible = attributed and level == "High" and contributing >= 3
        if not attributed:
            reason = "Alert-only: reliable writer attribution is unavailable. No process action is authorized."
        elif level != "High":
            reason = ("Continue monitoring" if level == "Low" else "Gather more evidence and reassess") + "; the high-risk threshold has not been met."
        elif contributing < 3:
            reason = "Alert only: fewer than three indicator families contribute; a high score alone cannot authorize containment."
        else:
            reason = "Candidate for a separate safety review only; response mode and live registered-child identity must be checked before any action."
        features = {"window_seconds": self.window_seconds, "modification_count": len(changes),
                    "modification_rate": modification_rate, "unique_modified_files": unique_modified,
                    "unique_modified_rate": unique_rate, "combined_lab_rewrites": combined,
                    "operation_counts": dict(operation_counts), "operation_transitions": dict(transitions),
                    "entropy_comparable_count": len(comparable), "entropy_rise_files": rise_count,
                    "modified_directories": modified_dirs, "rename_suffix_files": rename_count,
                    "process_context": context if attributed else {}, "contributing_families": contributing}
        return Assessment(key, score, level, signals, len(events), len({path[0] for path in paths}), modified_dirs,
            newest.process_name if attributed else "Unattributed file activity", newest.pid if attributed else None,
            events[0].timestamp, newest.timestamp, eligible, features, missing,
            "cooperative_lab" if attributed else "unavailable", reason, self.config.to_dict())
