"""Stage 5.5H.3B: real Qt-controller/GUI glue checks with synthetic JSONL.

No elevated ETW session or process control is started by these tests.
"""
from __future__ import annotations

from datetime import datetime, timezone
import io
import json
import os
import time

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from PySide6.QtWidgets import QApplication

from ciphersentry.engine import FileEvent
from ciphersentry.etw_live_gui import LiveGuiSession

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows ETW test fixture paths")


def _setup(tmp_path, source):
    app = QApplication.instance() or QApplication([])
    root = tmp_path / "watch"
    fixture = root / "writer-run-20261117-123000-12345"
    fixture.mkdir(parents=True)
    target = fixture / "etw-writer-test.txt"
    target.write_bytes(b"test only")
    session = LiveGuiSession(app, root, tmp_path / "new-audit", source, show_first=0)
    return app, target, session


def _pump_until(app, predicate, *, timeout=3.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        app.processEvents()
        if predicate():
            return
        time.sleep(0.01)
    assert predicate(), "Expected event not delivered through Qt"


def test_live_gui_shows_real_controller_audits_without_extra_risk_event(tmp_path):
    now = datetime.now(timezone.utc)
    # Compose stream after target creation? Fixture name is known, but use an
    # in-memory stream object populated before session.start().
    root = tmp_path / "watch"
    target = root / "writer-run-20261117-123000-12345" / "etw-writer-test.txt"
    payload = {
        "schema": 1, "kind": "Write", "event_time_utc": now.isoformat(),
        "callback_time_utc": now.isoformat(), "reported_pid": 12345,
        "file_key": "0x0000000000000001", "file_object": "0x0000000000000002",
        "io_size": 64, "filename": str(target), "details": "reader-prior-key-candidate",
    }
    app, target, session = _setup(tmp_path, io.StringIO(json.dumps(payload) + "\n"))
    try:
        session.start()
        session.harness.controller.monitor.callback(FileEvent(
            timestamp=now.timestamp(), path=str(target), operation="modified",
            source="folder", attribution="unavailable"))
        _pump_until(app, lambda: session.harness.controller.session_events == 1)
        assert session.harness._stream_finished.wait(timeout=1.5)
        assert session.complete() == 0
        controller = session.harness.controller
        assert controller.etw_candidate_count == 1
        assert controller.session_events == 1  # no additional ETW risk-engine event
        assert controller.store.counts()["events"] == 1
        assert controller.store.recent_etw_candidates()[0]["unverified_event_pids"] == [12345]
        assert controller.settings["response_mode"] == "alert_only"
        session.window.navigate(1)
        assert session.window.etw_candidate_table.rowCount() == 1
        assert "unverified" in session.window.etw_candidate_table.item(0, 3).text()
        assert session.window.monitor_button.text() == "Start monitoring"
    finally:
        session.shutdown()
        session.window.close()
        app.processEvents()


def test_live_gui_rejects_invalid_etw_stream_and_keeps_risk_separate(tmp_path):
    app, _target, session = _setup(tmp_path, io.StringIO("{malformed JSON}\n"))
    try:
        session.start()
        assert session.harness._stream_finished.wait(timeout=1.5)
        assert session.complete() == 2
        assert session.harness.controller.etw_candidate_count == 0
        assert session.harness.controller.session_events == 0
        assert session.harness.controller.settings["response_mode"] == "alert_only"
        assert not session.harness.controller.monitoring
    finally:
        session.shutdown()
        session.window.close()
        app.processEvents()
