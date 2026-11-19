"""Stage 5.5G.4: in-process evidence handoff smoke test.

Synthetic ETW and folder notifications cross the real probe -> Qt controller ->
SQLite action boundary. This test cannot authorize process control and does not
start an ETW session. It is an integration boundary test, NOT live GUI transport.
"""
from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime, timedelta, timezone

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import QEventLoop
from PySide6.QtWidgets import QApplication

from ciphersentry.controller import Controller
from ciphersentry.engine import FileEvent
from ciphersentry.etw_evidence import parse_write
from ciphersentry.etw_watchdog_probe import EtwWatchdogProbe

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Uses Windows paths and Windows folder observer")


def _pump_until(app, predicate, *, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        app.processEvents(QEventLoop.ProcessEventsFlag.AllEvents, 50)
        if predicate():
            return
        time.sleep(0.01)
    app.processEvents(QEventLoop.ProcessEventsFlag.AllEvents, 50)
    assert predicate(), "Timed out waiting for controller evidence signal"


def _write(path: str, pid: int, occurred: datetime):
    stamp = occurred.isoformat()
    return parse_write({
        "kind": "Write", "event_time_utc": stamp, "callback_time_utc": stamp,
        "reported_pid": str(pid),
        "file_key": "0x0000000000000001", "file_object": "0x0000000000000002",
        "io_size": "64", "filename": path,
        "details": "reader-prior-key-candidate",
    })


def test_probe_to_controller_persists_ambiguous_evidence_without_risk_or_containment(tmp_path):
    app = QApplication.instance() or QApplication([])
    root = tmp_path / "monitored"
    root.mkdir()
    target = root / "writer-run-20261117-120000-22208" / "etw-writer-test.txt"
    target.parent.mkdir()
    controller = Controller(tmp_path / "app-data")
    try:
        controller.choose_folder(root)
        controller.start_monitor()
        _pump_until(app, lambda: controller.monitoring)
        baseline_session_events = controller.session_events
        baseline_response = dict(controller.current_response)
        baseline_assessment = controller.assessment

        # The application receives a candidate from the existing probe callback.
        # The producer runs on another thread, just like real incoming ETW data.
        probe = EtwWatchdogProbe(str(root), on_match=controller.submit_etw_candidate)
        occurred = datetime.now(timezone.utc)
        folder_event = FileEvent(
            timestamp=occurred.timestamp(), path=str(target), operation="modified",
            source="folder", attribution="unavailable",
        )
        errors = []

        def producer():
            try:
                probe.on_folder(folder_event, received_at=10.0)
                probe.on_etw(_write(str(target), 22208, occurred), received_at=10.1, wall_time=occurred)
                probe.on_etw(_write(str(target), 42764, occurred + timedelta(milliseconds=100)),
                             received_at=10.2, wall_time=occurred + timedelta(milliseconds=100))
                probe.on_etw(_write(str(target), 4, occurred + timedelta(milliseconds=150)),
                             received_at=10.3, wall_time=occurred + timedelta(milliseconds=150))
                assert controller.etw_candidate_count == 0  # Evidence must mature first.
                probe.tick(received_at=13.5)
            except BaseException as exc:
                errors.append(exc)

        worker = threading.Thread(target=producer, name="synthetic-etw-writer")
        worker.start()
        worker.join(timeout=3)
        assert not worker.is_alive(), "Synthetic producer did not finish"
        assert not errors, f"Synthetic producer failed: {errors!r}"

        _pump_until(app, lambda: controller.etw_candidate_count == 1)
        evidence = controller.etw_latest_candidate
        assert evidence is not None
        assert evidence["matched_write_count"] == 3
        assert evidence["unverified_event_pids"] == [22208, 42764]
        assert evidence["system_pid4_writes"] == 1
        assert evidence["status"] == "multiple_unverified_pids"
        assert evidence["verified_writer_pid"] is None
        assert evidence["containment_authorized"] is False
        assert evidence["risk_scored"] is False

        audit = [record for record in controller.store.recent_actions()
                 if record["action"] == "etw_candidate_observation"]
        assert len(audit) == 1
        assert audit[0]["pid"] is None
        assert json.loads(audit[0]["detail"]) == evidence
        assert controller.session_events == baseline_session_events
        assert controller.assessment is baseline_assessment
        assert controller.current_response == baseline_response
        assert controller.store.counts()["events"] == 0
    finally:
        controller.close()
        app.processEvents()
