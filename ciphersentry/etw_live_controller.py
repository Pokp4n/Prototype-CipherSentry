"""Stage 5.5G.5: live ETW -> existing CipherSentry Controller audit smoke.

This is a *headless integration harness*, not a GUI feature or production service.
The actual FolderMonitor feeds the Controller's existing risk engine once per
folder notification, while the same FileEvent also reaches the separate ETW
candidate correlator. ETW records never enter RiskEngine, and candidate PIDs
never authorize process control. Use a fresh dedicated audit data directory.

Windows invocation (from the integration worktree, using cmd.exe for the pipe):
    dotnet LiveEtwStreamer.dll | python -u -m ciphersentry.etw_live_controller \
         --root C:\\...\\CipherSentry-ETW --data-dir C:\\...\\.ciphersentry\\etw-live-unique
"""
from __future__ import annotations

import argparse
import sys
import threading
import time
from pathlib import Path
from typing import TextIO

from .controller import Controller
from .etw_stream import parse_stream_line
from .etw_watchdog_probe import CandidateMatch, EtwWatchdogProbe
from .monitor import FolderMonitor


class LiveControllerHarness:
    """Use a single real folder watcher for scoring AND candidate correlation."""

    def __init__(self, root: Path, data_dir: Path, *, show_first: int = 12):
        if type(show_first) is not int or not 0 <= show_first <= 50:
            raise ValueError("show_first must be 0..50")
        self.root = Path(root).resolve(strict=True)
        self.data_dir = Path(data_dir).resolve(strict=False)
        if not self.root.is_dir() or self.root.is_symlink():
            raise ValueError("Monitored root must be an existing nonsymlink directory")
        if self.data_dir.exists():
            raise ValueError("A fresh audit data directory is required")
        if self.root == self.data_dir or self.root in self.data_dir.parents or self.data_dir in self.root.parents:
            raise ValueError("Audit data directory must not overlap the monitored root")
        self.show_first = show_first
        self.errors: list[str] = []
        self.stream_error: str | None = None
        self.stream_count = 0
        self._stream_finished = threading.Event()
        self.probe = EtwWatchdogProbe(str(self.root), on_match=self._send_candidate)
        self.controller = Controller(self.data_dir, monitor_factory=self._make_monitor)
        # Fresh directory guarantees alert_only; never auto-control real processes.
        if self.controller.settings["response_mode"] != "alert_only":
            self.controller.close()
            raise RuntimeError("Refusing non-alert-only mode")
        self.controller.etw_candidate_recorded.connect(self._recorded)
        self.controller.error.connect(self.errors.append)
        self.controller.choose_folder(self.root)

    def _make_monitor(self, path, callback, on_error):
        def forward(event):
            callback(event)  # existing Qt controller scoring path; exactly once
            self.probe.on_folder(event)  # independent evidence, no score increment
        return FolderMonitor(path, forward, on_error)

    def _send_candidate(self, candidate: CandidateMatch) -> None:
        self.controller.submit_etw_candidate(candidate)

    def _recorded(self, payload: dict) -> None:
        n = self.controller.etw_candidate_count
        if n <= self.show_first:
            print(f"[CONTROLLER ETW AUDIT {n}] "
                  f"file={Path(payload['path']).name!r} "
                  f"status={payload['status']} "
                  f"pids={payload['unverified_event_pids']} "
                  f"pid4={payload['system_pid4_writes']} "
                  "containment_authorized=False", flush=True)

    def await_ready(self, app, *, timeout: float = 15.0) -> None:
        self.controller.start_monitor()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            app.processEvents()
            if self.controller.monitoring:
                print("Controller watchdog READY; run two-writer-probe.ps1 after C# prints Listening for events ...",
                      flush=True)
                return
            if not self.controller.monitor_starting:
                break
            time.sleep(0.015)
        raise RuntimeError("Controller watchdog did not start: " + "; ".join(self.errors[-3:]))

    def _receive(self, source: TextIO) -> None:
        try:
            for number, line in enumerate(source, 1):
                if not line.strip():
                    raise ValueError(f"Blank ETW record at line {number}")
                try:
                    event = parse_stream_line(line)
                except ValueError as exc:
                    raise ValueError(f"Invalid ETW JSONL line {number}: {exc}") from exc
                self.probe.on_etw(event)
                self.stream_count += 1
        except (UnicodeError, OSError, ValueError) as exc:
            self.stream_error = f"{type(exc).__name__}: {exc}"
        finally:
            self._stream_finished.set()

    def run(self, app, source: TextIO) -> int:
        self.await_ready(app)
        print("Live controller audit enabled (read-only ETW; alert-only mode).", flush=True)
        reader = threading.Thread(target=self._receive, args=(source,), daemon=True,
                                  name="etw-controller-jsonl-reader")
        reader.start()
        try:
            while not self._stream_finished.is_set():
                app.processEvents()
                self.probe.tick()
                time.sleep(0.015)
            reader.join(timeout=2)
            # Let any last watchdog callbacks reach the probe, then finalize
            # pending candidates WHILE controller.monitoring is still True.
            for _ in range(15):
                app.processEvents()
                self.probe.tick()
                time.sleep(0.01)
            self.probe.finish()
            # Qt must persist queued candidates before monitor shutdown; the
            # controller's audit hook intentionally rejects stopped monitors.
            for _ in range(30):
                app.processEvents()
                time.sleep(0.005)
            self.controller.stop_monitor()
            print("\n=== CipherSentry LIVE Controller Evidence Summary ===", flush=True)
            print(f"ETW JSONL records received: {self.stream_count}", flush=True)
            print(f"Target ETW file writes: {self.probe.etw_events}", flush=True)
            print(f"Target watchdog notifications: {self.probe.folder_events}", flush=True)
            print(f"Candidate matches: {self.probe.matched}; unmatched: {self.probe.not_matched}", flush=True)
            print(f"Controller audit records: {self.controller.etw_candidate_count}", flush=True)
            print(f"Watchdog risk-engine events: {self.controller.session_events}", flush=True)
            print(f"Evidence database: {self.controller.store.path}", flush=True)
            print("ETW PIDs UNVERIFIED. ETW risk-scoring: OFF. Process containment: NOT AUTHORIZED.", flush=True)
            if self.stream_error:
                print(f"ETW input FAILED: {self.stream_error}", file=sys.stderr, flush=True)
                return 2
            if not self.stream_count or not self.controller.etw_candidate_count:
                print("No live ETW-to-controller audit observations; experiment incomplete.", file=sys.stderr, flush=True)
                return 3
            return 0
        finally:
            self.controller.close()
            app.processEvents()


def main() -> int:
    parser = argparse.ArgumentParser(description="ETW -> real CipherSentry Controller audit smoke (headless)")
    parser.add_argument("--root", required=True)
    parser.add_argument("--data-dir", required=True, help="Fresh dedicated audit directory outside watched root")
    parser.add_argument("--show-first", type=int, default=12)
    args = parser.parse_args()
    try:
        from PySide6.QtCore import QCoreApplication
        app = QCoreApplication.instance() or QCoreApplication([])
        harness = LiveControllerHarness(Path(args.root), Path(args.data_dir), show_first=args.show_first)
    except (OSError, ImportError, RuntimeError, ValueError) as exc:
        print(f"Live controller preflight FAILED: {exc}", file=sys.stderr, flush=True)
        return 2
    try:
        return harness.run(app, sys.stdin)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"Live controller FAILED: {exc}", file=sys.stderr, flush=True)
        return 2
    finally:
        harness.controller.close()


if __name__ == "__main__":
    raise SystemExit(main())
