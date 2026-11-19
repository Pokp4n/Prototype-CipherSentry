"""Stage 5.5G.5: isolated real-controller/FolderMonitor wiring tests, no ETW session."""
from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from PySide6.QtCore import QCoreApplication

from ciphersentry.engine import FileEvent
from ciphersentry.etw_live_controller import LiveControllerHarness

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows ETW filesystem harness")


def _pump(app, condition, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        app.processEvents()
        if condition():
            return
        time.sleep(0.015)
    app.processEvents()
    assert condition(), "Controller did not complete the expected event delivery"


def test_rejects_existing_or_overlapping_audit_dir(tmp_path):
    root = tmp_path / "watched"
    root.mkdir()
    data_dir = tmp_path / "existing"
    data_dir.mkdir()
    with pytest.raises(ValueError, match="fresh"):
        LiveControllerHarness(root, data_dir)
    with pytest.raises(ValueError, match="overlap"):
        LiveControllerHarness(root, root / "new-audit")


def test_single_folder_observation_enters_controller_without_etw_containment(tmp_path):
    app = QCoreApplication.instance() or QCoreApplication([])
    root = tmp_path / "monitored"
    fixture_dir = root / "writer-run-20261117-123000-12345"
    fixture_dir.mkdir(parents=True)
    target = fixture_dir / "etw-writer-test.txt"
    target.write_bytes(b"A" * 8192)

    harness = LiveControllerHarness(root, tmp_path / "audit", show_first=0)
    try:
        harness.await_ready(app)
        # Drive the same callback that the real FolderMonitor uses; test for
        # exactly one scoring event and a second independent correlation path.
        folder_event = FileEvent(timestamp=time.time(), path=str(target),
                                 operation="modified", source="folder", attribution="unavailable")
        harness.controller.monitor.callback(folder_event)
        _pump(app, lambda: harness.controller.session_events == 1)
        assert harness.probe.folder_events == 1
        assert harness.controller.etw_candidate_count == 0
        assert harness.controller.settings["response_mode"] == "alert_only"
        assert harness.controller.current_response["allowed"] is False
        assert harness.controller.store.counts()["events"] == 1
    finally:
        harness.controller.close()
        app.processEvents()


def test_jsonl_to_real_controller_audit_without_extra_risk_event(tmp_path):
    """Synthetic JSONL exercises the real adapter, Qt controller and SQLite."""
    import io
    import json
    from datetime import datetime, timezone

    app = QCoreApplication.instance() or QCoreApplication([])
    root = tmp_path / "monitored"
    fixture_dir = root / "writer-run-20261117-123000-12345"
    fixture_dir.mkdir(parents=True)
    target = fixture_dir / "etw-writer-test.txt"
    target.write_bytes(b"test only")
    harness = LiveControllerHarness(root, tmp_path / "audit", show_first=0)
    try:
        harness.await_ready(app)
        now = datetime.now(timezone.utc)
        harness.controller.monitor.callback(
            FileEvent(timestamp=now.timestamp(), path=str(target),
                      operation="modified", source="folder", attribution="unavailable")
        )
        _pump(app, lambda: harness.controller.session_events == 1)
        payload = {
            "schema": 1, "kind": "Write", "event_time_utc": now.isoformat(),
            "callback_time_utc": now.isoformat(), "reported_pid": 12345,
            "file_key": "0x0000000000000001", "file_object": "0x0000000000000002",
            "io_size": 64, "filename": str(target),
            "details": "reader-prior-key-candidate",
        }
        harness._receive(io.StringIO(json.dumps(payload) + "\n"))
        assert harness.stream_error is None
        assert harness.stream_count == 1
        harness.probe.finish()
        _pump(app, lambda: harness.controller.etw_candidate_count == 1)
        candidate = harness.controller.etw_latest_candidate
        assert candidate["unverified_event_pids"] == [12345]
        assert candidate["verified_writer_pid"] is None
        assert candidate["risk_scored"] is False
        assert candidate["containment_authorized"] is False
        assert harness.controller.session_events == 1
        assert harness.controller.store.counts()["events"] == 1
    finally:
        harness.controller.close()
        app.processEvents()
