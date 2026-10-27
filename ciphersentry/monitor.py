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
from typing import Callable

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from .engine import FileEvent, shannon_entropy


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

    def __init__(
        self,
        path: Path,
        callback: Callable[[FileEvent], None],
        on_error: Callable[[str], None] | None = None,
    ) -> None:
        self.path = Path(path).absolute()
        self.callback = callback
        self.on_error = on_error or (lambda message: None)
        self._baseline: dict[str, tuple[float, int, int]] = {}
        self._pending: queue.Queue[tuple[str, str, str]] = queue.Queue(self.MAX_PENDING_EVENTS)
        self._stop = threading.Event()
        self._observer = None
        self._worker: threading.Thread | None = None
        self._running = False
        self._dropped = 0
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

    def _sample(self, path: Path) -> tuple[float, int, int] | None:
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
            return shannon_entropy(data), metadata.st_size, metadata.st_mtime_ns
        except (FileNotFoundError, IsADirectoryError):
            return None
        except OSError as error:
            self._report(f"Could not sample {path.name}: {error.strerror or type(error).__name__}")
            return None
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def _remember(self, path: str, sample: tuple[float, int, int] | None) -> None:
        if sample is None:
            return
        with self._lock:
            if path in self._baseline or len(self._baseline) < self.MAX_BASELINE_FILES:
                self._baseline[path] = sample
            elif not self._baseline_warning_sent:
                self._baseline_warning_sent = True
                self._report(f"Baseline limit of {self.MAX_BASELINE_FILES:,} files reached; additional files have no before-entropy baseline.")

    def _build_baseline(self) -> None:
        for directory, dirs, files in os.walk(self.path, followlinks=False):
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
            self._pending.put_nowait((operation, source, destination))
        except queue.Full:
            self._dropped += 1
            if self._dropped == 1 or self._dropped % 100 == 0:
                self._report(f"Monitor backlog is full; {self._dropped:,} notifications dropped. Coverage is incomplete.")

    def _consume(self) -> None:
        recent: dict[tuple[str, str], float] = {}
        while not self._stop.is_set():
            try:
                operation, source, destination = self._pending.get(timeout=0.1)
            except queue.Empty:
                continue
            if operation in {"modified", "created"}:
                # Let a short write finish before sampling its contents.
                if self._stop.wait(self.DEBOUNCE_SECONDS):
                    break
            path = self._safe_path(destination if operation == "moved" else source)
            old_path = self._safe_path(source)
            if path is None or old_path is None:
                continue
            now = time.time()
            key = (str(path), operation)
            with self._lock:
                before = self._baseline.get(str(old_path))
            after = None if operation == "deleted" else self._sample(path)
            if operation == "modified" and before == after:
                continue
            if operation == "created" and before == after and key in recent:
                continue
            if operation in {"deleted", "moved"}:
                with self._lock:
                    self._baseline.pop(str(old_path), None)
            self._remember(str(path), after)
            recent[key] = now
            if len(recent) > self.MAX_PENDING_EVENTS:
                recent = {k: t for k, t in recent.items() if now - t < 1.0}
            event = FileEvent(
                timestamp=now,
                path=str(path),
                operation=operation,
                pid=None,
                process_name="Unattributed folder activity",
                entropy_before=before[0] if before is not None else None,
                entropy_after=after[0] if after is not None else None,
                source="folder",
            )
            try:
                self.callback(event)
            except Exception as error:
                self._report(f"Event consumer failed: {type(error).__name__}: {error}")
