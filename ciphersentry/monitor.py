"""Bounded, read-only folder observation with explicitly unknown process identity.

Watchdog filesystem notifications do not identify the writer. This adapter never
invents a PID and cannot authorize process containment. Entropy is estimated from
the first 64 KiB of each file, rather than reading entire user documents.
"""

from __future__ import annotations

import os
import queue
import stat
import threading
import time
from pathlib import Path
from typing import Callable, NamedTuple

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from .block_entropy import BlockSample, block_evidence, measure_sample
from .engine import FileEvent, shannon_entropy
from .telemetry import WATCHDOG_CAPABILITIES


class _Sample(NamedTuple):
    """One read of a file. ``blocks`` is evidence only and is not scored.

    ``blocks_missing`` says why ``blocks`` is None for a sample that was read:
    "not_measured" (collection switched off) or "deferred_under_load".
    """
    entropy: float
    size: int
    mtime_ns: int
    blocks: BlockSample | None = None
    blocks_missing: str | None = None


def _same_state(before: _Sample | None, after: _Sample | None) -> bool:
    """The pre-Step-1 duplicate test: whole-sample entropy, size and mtime only.

    Block measurements are deliberately excluded so that collecting them cannot
    change which notifications become events.
    """
    if before is None or after is None:
        return before is after
    return before[:3] == after[:3]


class _Notifications(FileSystemEventHandler):
    def __init__(self, monitor: "FolderMonitor") -> None:
        self.monitor = monitor

    def on_any_event(self, event) -> None:
        if not event.is_directory and event.event_type in {"created", "modified", "deleted", "moved"}:
            self.monitor._enqueue(event.event_type, event.src_path, getattr(event, "dest_path", ""))


class FolderMonitor:
    """Observe a selected real directory; callbacks execute on a background thread.

    ``start`` takes an initial bounded baseline synchronously. Call it on a
    background thread for very large directories. The monitor only reads files;
    symlinks and paths escaping the selected root are excluded. A missed baseline
    means entropy_before=None, never an assumed zero-entropy original file.
    """

    MAX_BASELINE_FILES = 5000
    MAX_SAMPLE_BYTES = 64 * 1024
    MAX_PENDING_EVENTS = 2048
    DEBOUNCE_SECONDS = 0.06
    # Record 4 KiB block entropy from the same sample (M3B Step 1, evidence only).
    COLLECT_BLOCK_ENTROPY = True
    # Overload criterion for block evidence. When the notification being sampled
    # is older than this, the monitor is backlogged: the sample keeps the original
    # whole-sample entropy calculation, block measurement is skipped, and the
    # event records "deferred_under_load". Healthy delivery is about 0.1 s and
    # observations become Unscored after the 10 s window, so 2 s means "seriously
    # behind" while leaving most of the window. Collection resumes automatically
    # as soon as queued notifications are younger again.
    BLOCK_DEFER_AGE_SECONDS = 2.0
    capabilities = WATCHDOG_CAPABILITIES

    def __init__(
        self,
        path: Path,
        callback: Callable[[FileEvent], None],
        on_error: Callable[[str], None] | None = None,
    ) -> None:
        self.path = Path(path).absolute()
        self.callback = callback
        self.on_error = on_error or (lambda message: None)
        self._baseline: dict[str, _Sample] = {}
        self._pending: queue.Queue[tuple[str, str, str, float]] = queue.Queue(self.MAX_PENDING_EVENTS)
        self._stop = threading.Event()
        self._observer = None
        self._worker: threading.Thread | None = None
        self._running = False
        self._dropped = 0
        self._block_deferred = 0
        self._last_lag = 0.0
        self._max_lag = 0.0
        self._baseline_warning_sent = False
        self._lock = threading.RLock()
        self._lifecycle_lock = threading.RLock()

    @property
    def running(self) -> bool:
        return self._running

    @property
    def baseline_count(self) -> int:
        with self._lock:
            return len(self._baseline)

    @property
    def dropped_events(self) -> int:
        return self._dropped

    @property
    def block_deferred_count(self) -> int:
        """Emitted observations whose block evidence was deferred under load (either side)."""
        return self._block_deferred

    @property
    def pending_count(self) -> int:
        """Notifications queued but not yet sampled (approximate, thread-safe)."""
        return self._pending.qsize()

    @property
    def last_lag_seconds(self) -> float:
        """Delay between notification and delivery for the latest emitted event."""
        return self._last_lag

    @property
    def max_lag_seconds(self) -> float:
        """Largest notification-to-delivery delay seen by this monitor."""
        return self._max_lag

    def _report(self, message: str) -> None:
        try:
            self.on_error(message)
        except Exception:
            # An observer must survive a GUI callback that has already closed.
            pass

    def _safe_path(self, value: str | Path) -> Path | None:
        candidate = Path(value).absolute()
        try:
            candidate.relative_to(self.path)
            candidate.resolve(strict=False).relative_to(self.path)
        except (ValueError, OSError, RuntimeError):
            return None
        current = candidate
        while current != self.path:
            if current.is_symlink():
                return None
            current = current.parent
        return candidate

    def _sample(self, path: Path, *, defer_blocks: bool = False) -> _Sample | None:
        if self._safe_path(path) is None:
            return None
        descriptor = None
        try:
            # Inspect the type before opening: a FIFO can block an ordinary open.
            # O_NONBLOCK also closes the race if a special file replaces it.
            if not stat.S_ISREG(path.lstat().st_mode):
                return None
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
            descriptor = os.open(path, flags)
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                return None
            data = os.read(descriptor, self.MAX_SAMPLE_BYTES)
            if not self.COLLECT_BLOCK_ENTROPY:
                return _Sample(shannon_entropy(data), metadata.st_size, metadata.st_mtime_ns, None, "not_measured")
            if defer_blocks:
                # Same 64 KiB sample and original whole-sample calculation; only
                # the extra block measurement is skipped, and that is recorded.
                return _Sample(shannon_entropy(data), metadata.st_size, metadata.st_mtime_ns, None,
                               "deferred_under_load")
            # One pass over the bytes already read (the file is not reread). The
            # whole-sample value is bit-identical to shannon_entropy(data).
            whole, blocks = measure_sample(data, metadata.st_size)
            return _Sample(whole, metadata.st_size, metadata.st_mtime_ns, blocks)
        except (FileNotFoundError, IsADirectoryError):
            return None
        except OSError as error:
            self._report(f"Could not sample {path.name}: {error.strerror or type(error).__name__}")
            return None
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def _block_evidence(self, before: _Sample | None, after: _Sample | None, operation: str):
        """Block evidence for one event, or None when collection is switched off."""
        if not self.COLLECT_BLOCK_ENTROPY:
            return None
        return block_evidence(
            before.blocks if before is not None else None,
            after.blocks if after is not None else None,
            operation,
            before_unmeasured=before.blocks_missing if before is not None and before.blocks is None else None,
            after_unmeasured=after.blocks_missing if after is not None and after.blocks is None else None,
        )

    def _remember(self, path: str, sample: _Sample | None) -> None:
        if sample is None:
            return
        warning = False
        with self._lock:
            if path in self._baseline or len(self._baseline) < self.MAX_BASELINE_FILES:
                self._baseline[path] = sample
            elif not self._baseline_warning_sent:
                self._baseline_warning_sent = True
                warning = True
        if warning:
            self._report(f"Baseline limit of {self.MAX_BASELINE_FILES:,} files reached; additional files have no before-entropy baseline.")

    def _build_baseline(self) -> None:
        def walk_error(error: OSError) -> None:
            self._report(f"Baseline directory inaccessible: {error.filename}: {error.strerror}. Coverage is incomplete.")

        for directory, dirs, files in os.walk(self.path, followlinks=False, onerror=walk_error):
            if self._stop.is_set():
                return
            dirs[:] = sorted(d for d in dirs if not (Path(directory) / d).is_symlink())
            for name in sorted(files):
                if self._stop.is_set():
                    return
                path = Path(directory) / name
                self._remember(str(path), self._sample(path))
                if self.baseline_count >= self.MAX_BASELINE_FILES:
                    self._report(f"Baseline limited to {self.MAX_BASELINE_FILES:,} files. Additional activity is still observed with unknown initial entropy.")
                    self._baseline_warning_sent = True
                    return

    def start(self) -> None:
        with self._lifecycle_lock:
            if self._running:
                return
            if not self.path.is_dir():
                raise ValueError("Choose an existing folder to monitor.")
            if self.path.resolve() != self.path or self.path.is_symlink():
                raise ValueError("Choose a real folder, rather than a symbolic link.")
            self._stop.clear()
        with self._lock:
            self._baseline.clear()
        self._baseline_warning_sent = False
        self._dropped = 0
        self._block_deferred = 0
        while not self._pending.empty():
            try:
                self._pending.get_nowait()
            except queue.Empty:
                break
        self._build_baseline()
        with self._lifecycle_lock:
            if self._stop.is_set():
                return
            observer = Observer()
            observer.schedule(_Notifications(self), str(self.path), recursive=True)
            self._observer = observer
            self._worker = threading.Thread(target=self._consume, name="CipherSentry-folder-monitor", daemon=True)
            self._running = True
            try:
                observer.start()
                self._worker.start()
            except Exception:
                self._running = False
                self._stop.set()
                observer.stop()
                if observer.is_alive():
                    observer.join(timeout=2)
                raise

    def stop(self) -> None:
        with self._lifecycle_lock:
            self._stop.set()
            self._running = False
            observer = self._observer
            if observer is not None:
                observer.stop()
                if observer.is_alive() and observer is not threading.current_thread():
                    observer.join(timeout=2)
            worker = self._worker
            if worker is not None and worker.is_alive() and worker is not threading.current_thread():
                worker.join(timeout=2)
            self._observer = None
            self._worker = None

    def _enqueue(self, operation: str, source: str, destination: str = "") -> None:
        if self._stop.is_set():
            return
        try:
            self._pending.put_nowait((operation, source, destination, time.time()))
        except queue.Full:
            self._dropped += 1
            if self._dropped == 1 or self._dropped % 100 == 0:
                self._report(f"Monitor backlog is full; {self._dropped:,} notifications dropped. Coverage is incomplete.")

    def _consume(self) -> None:
        recent: dict[tuple[str, str], float] = {}
        while not self._stop.is_set():
            try:
                operation, source, destination, observed_at = self._pending.get(timeout=0.1)
            except queue.Empty:
                continue
            if operation in {"modified", "created"}:
                # Let a short write finish before sampling its contents. The
                # delay is measured from the notification, not applied per item:
                # a backlog that is already older than the debounce is sampled
                # immediately instead of accumulating 60 ms per queued event.
                remaining = observed_at + self.DEBOUNCE_SECONDS - time.time()
                if remaining > 0 and self._stop.wait(remaining):
                    break
            path = self._safe_path(destination if operation == "moved" else source)
            old_path = self._safe_path(source)
            if path is None or old_path is None:
                continue
            now = time.time()
            key = (str(path), operation)
            with self._lock:
                before = self._baseline.get(str(old_path))
            # Overload criterion (see BLOCK_DEFER_AGE_SECONDS): the age of this
            # notification. Only the extra block measurement is deferred.
            defer_blocks = self.COLLECT_BLOCK_ENTROPY and now - observed_at > self.BLOCK_DEFER_AGE_SECONDS
            after = None if operation == "deleted" else self._sample(path, defer_blocks=defer_blocks)
            if operation == "modified" and _same_state(before, after):
                continue
            if operation == "created" and _same_state(before, after) and key in recent:
                continue
            if operation in {"deleted", "moved"}:
                with self._lock:
                    self._baseline.pop(str(old_path), None)
            self._remember(str(path), after)
            recent[key] = now
            if len(recent) > self.MAX_PENDING_EVENTS:
                recent = {k: t for k, t in recent.items() if now - t < 1.0}
            evidence = self._block_evidence(before, after, operation)
            if evidence is not None and "deferred_under_load" in (evidence.before_missing, evidence.after_missing):
                self._block_deferred += 1
            event = FileEvent(
                timestamp=observed_at,
                path=str(path),
                operation=operation,
                pid=None,
                process_name="Unattributed folder activity",
                entropy_before=before[0] if before is not None else None,
                entropy_after=after[0] if after is not None else None,
                source="folder",
                attribution="unavailable",
                observed_at=observed_at,
                process_context=None,
                block_entropy=evidence,
            )
            lag = max(0.0, time.time() - observed_at)
            self._last_lag = lag
            if lag > self._max_lag:
                self._max_lag = lag
            try:
                self.callback(event)
            except Exception as error:
                self._report(f"Event consumer failed: {type(error).__name__}: {error}")
