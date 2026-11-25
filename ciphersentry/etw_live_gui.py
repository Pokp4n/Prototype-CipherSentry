"""Stage 5.5H.3: opt-in lab-only LIVE ETW -> CipherSentry desktop UI.

This is NOT the normal CipherSentry launcher, a privileged background
service, or production protection. It reuses the existing single-watchdog
controller harness. ETW candidate IDs remain UNVERIFIED, do not enter the
RiskEngine, and do not authorize process containment.

Windows (Administrator PowerShell):
  cmd.exe /d /c "dotnet <streamer.dll> | <venv-python.exe> -u -m ciphersentry.etw_live_gui --root <root> --data-dir <new-dir>"

The end-of-stream leaves the GUI open for inspection; close the window to exit.
Do not close the GUI before the ETW streamer completes unless aborting the test.
"""
from __future__ import annotations

import argparse
import sys
import threading
import time
from pathlib import Path
from typing import TextIO

from PySide6.QtCore import QTimer
from PySide6.QtGui import QFont
from PySide6.QtWidgets import QApplication

from .etw_live_controller import LiveControllerHarness
from .ui.theme import STYLESHEET
from .ui.window import MainWindow


class LiveGuiSession:
    """Qt-loop-driven live evidence viewer backed by one real FolderMonitor.

    Read ETW JSONL on a daemon reader thread; run correlation expiry, controller
    updates, and SQLite/GUI refresh on the Qt thread. Only a *fresh* audit data
    directory may be used, enforced by LiveControllerHarness.
    """

    def __init__(self, app: QApplication, root: Path, data_dir: Path,
                 source: TextIO, *, show_first: int = 12):
        if not isinstance(app, QApplication):
            raise TypeError("A QApplication is required for the desktop viewer")
        self.app = app
        self.source = source
        self.harness = LiveControllerHarness(root, data_dir, show_first=show_first)
        try:
            self.window = MainWindow(self.harness.controller)
        except BaseException:
            self.harness.controller.close()
            raise
        self.window.navigate(1)  # Event explorer, including the ETW evidence table
        self._timer = QTimer(self.window)
        self._timer.setInterval(100)
        self._timer.timeout.connect(self._poll)
        self._reader: threading.Thread | None = None
        self._started = False
        self._finished = False
        self._first_etw_focused = False
        self._eof_seen_at: float | None = None
        self.result: int | None = None
        self.harness.controller.etw_candidate_recorded.connect(self._show_first_evidence)
        self.app.aboutToQuit.connect(self.shutdown)

    def start(self) -> None:
        """Run on the Qt thread after event loop starts; outputs readiness."""
        if self._started:
            raise RuntimeError("Live GUI already started")
        self.window.show()
        self.harness.await_ready(self.app)
        self._started = True
        self._reader = threading.Thread(
            target=self.harness._receive, args=(self.source,), daemon=True,
            name="etw-live-gui-jsonl-reader",
        )
        self._reader.start()
        self._timer.start()
        self.window.show_message("LIVE ETW lab audit running · candidate PIDs unverified · containment disabled for ETW")
        print("LIVE CipherSentry GUI READY; run two-writer-probe.ps1 after C# reports Listening for events ...", flush=True)
        print("View Event explorer -> ETW candidate evidence; do not close GUI until streamer ends.", flush=True)

    def _show_first_evidence(self, _payload: dict) -> None:
        if self._first_etw_focused or not self._started or self._finished:
            return
        self._first_etw_focused = True
        # Show the first candidate without continuously stealing scroll focus.
        def reveal() -> None:
            if not self._finished and not self.harness.controller._closed:
                self.window.navigate(1)
                self.window.stack.widget(1).ensureWidgetVisible(self.window.etw_candidate_table)
        QTimer.singleShot(400, reveal)

    def _poll(self) -> None:
        if self._finished or not self._started:
            return
        self.harness.probe.tick()
        if self.harness._stream_finished.is_set():
            if self._eof_seen_at is None:
                self._eof_seen_at = time.monotonic()
            # Give the last watchdog callbacks a short chance to enter Qt before
            # closing the candidate windows; it is not a coverage guarantee.
            if time.monotonic() - self._eof_seen_at >= 0.25:
                self.complete()

    def complete(self) -> int:
        """Finish read-only audit, leave window open for historical inspection."""
        if self._finished:
            assert self.result is not None
            return self.result
        if not self._started or not self.harness._stream_finished.is_set():
            raise RuntimeError("Cannot finalize before ETW input reaches EOF")
        self._timer.stop()
        self.harness.probe.finish()
        # A CandidateMatch may have been queued from the watchdog worker.
        self.app.processEvents()
        self.harness.controller.stop_monitor()
        self.app.processEvents()
        controller = self.harness.controller
        probe = self.harness.probe
        print("\n=== CipherSentry LIVE GUI Evidence Summary ===", flush=True)
        print(f"ETW JSONL records received: {self.harness.stream_count}", flush=True)
        print(f"Target ETW file writes: {probe.etw_events}", flush=True)
        print(f"Target watchdog notifications: {probe.folder_events}", flush=True)
        print(f"Candidate matches: {probe.matched}; unmatched: {probe.not_matched}", flush=True)
        print(f"Controller audit records: {controller.etw_candidate_count}", flush=True)
        print(f"Watchdog risk-engine events: {controller.session_events}", flush=True)
        print(f"Evidence database: {controller.store.path}", flush=True)
        print("ETW process IDs UNVERIFIED. ETW risk scoring OFF. No ETW containment authorization.", flush=True)
        if self.harness.stream_error:
            self.result = 2
            msg = "ETW input FAILED: " + self.harness.stream_error
            print(msg, file=sys.stderr, flush=True)
            self.window.show_message(msg, error=True)
        elif not self.harness.stream_count or not controller.etw_candidate_count:
            self.result = 3
            msg = "Live GUI experiment incomplete: no ETW evidence and/or candidate audits."
            print(msg, file=sys.stderr, flush=True)
            self.window.show_message(msg, error=True)
        else:
            self.result = 0
            self.window.show_message(
                f"ETW capture finished. {controller.etw_candidate_count} unverified candidate records saved. "
                "Review Event explorer; close window when done."
            )
            print("Capture finished. GUI remains open for inspection; close the window to exit.", flush=True)
        self.window.refresh_tables()
        self._finished = True
        return self.result

    def shutdown(self) -> None:
        """Idempotent cleanup; never takes a process-control action."""
        self._timer.stop()
        self.harness.controller.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Lab-only live ETW -> CipherSentry desktop GUI")
    parser.add_argument("--root", required=True, type=Path, help="Existing Windows ETW experiment root")
    parser.add_argument("--data-dir", required=True, type=Path, help="NEW isolated audit data directory")
    parser.add_argument("--show-first", type=int, default=12)
    args = parser.parse_args()
    app = QApplication.instance() or QApplication(sys.argv[:1])
    app.setApplicationName("CipherSentry Live ETW Lab")
    app.setOrganizationName("CipherSentry FYP")
    app.setFont(QFont("Segoe UI" if sys.platform == "win32" else "DejaVu Sans", 10))
    app.setStyle("Fusion")
    app.setStyleSheet(STYLESHEET)
    try:
        session = LiveGuiSession(app, args.root, args.data_dir, sys.stdin,
                                 show_first=args.show_first)
    except (OSError, TypeError, ValueError, RuntimeError, ImportError) as exc:
        print(f"LIVE GUI preflight FAILED: {exc}", file=sys.stderr, flush=True)
        return 2

    def start() -> None:
        try:
            session.start()
        except (OSError, ValueError, RuntimeError) as exc:
            print(f"LIVE GUI start FAILED: {exc}", file=sys.stderr, flush=True)
            session.shutdown()
            app.exit(2)

    QTimer.singleShot(0, start)
    try:
        qt_exit = app.exec()
        if qt_exit:
            return qt_exit
        return session.result if session.result is not None else 4
    finally:
        session.shutdown()


if __name__ == "__main__":
    raise SystemExit(main())
