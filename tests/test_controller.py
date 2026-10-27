"""Real Qt integration: lab child control, audit persistence, and folder callbacks.

These tests pump a real Qt event loop and launch the actual worker through
QProcess. They do not replace the process or filesystem monitor with mocks.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import psutil
import pytest
from PySide6.QtCore import QEventLoop, QProcess
from PySide6.QtWidgets import QApplication

from ciphersentry.controller import Controller


@pytest.fixture(scope="module")
def qt_application():
    application = QApplication.instance() or QApplication([])
    yield application


def pump_until(application, predicate, timeout=10.0, description="expected state"):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        application.processEvents(QEventLoop.ProcessEventsFlag.AllEvents, 50)
        if predicate():
            return
        time.sleep(0.01)
    application.processEvents(QEventLoop.ProcessEventsFlag.AllEvents, 50)
    assert predicate(), f"Timed out waiting for {description}"


def pump_for(application, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        application.processEvents(QEventLoop.ProcessEventsFlag.AllEvents, 50)
        time.sleep(0.01)


@pytest.fixture
def live_controller(tmp_path, qt_application):
    controller = Controller(tmp_path / "app-data")
    errors = []
    controller.error.connect(errors.append)
    yield controller, errors
    controller.close()
    qt_application.processEvents()
    assert not controller.lab_active
    assert not controller.monitoring


def test_suspicious_lab_is_contained_then_resumes_to_completion(live_controller, qt_application):
    controller, errors = live_controller
    controller.start_lab("suspicious")
    pump_until(qt_application, lambda: controller.lab["status"] in {"Contained", "Failed"}, 6, "automatic containment")
    assert controller.lab["status"] == "Contained", errors
    paused_count = controller.lab["completed"]
    assert 0 < paused_count < 60
    assert controller.lab["files_at_containment"] == paused_count
    assert controller.lab["peak_score"] >= controller.settings["threshold"]
    assert controller.containment.is_suspended(controller.lab["pid"])
    root = Path(controller.lab["root"])
    before = {str(path): path.stat().st_mtime_ns for path in root.rglob("sample-*")}
    pump_for(qt_application, 0.25)
    after = {str(path): path.stat().st_mtime_ns for path in root.rglob("sample-*")}
    assert before == after
    assert controller.lab["completed"] == paused_count

    controller.resume_lab()
    pump_until(qt_application, lambda: not controller.lab_active, 9, "resumed worker to finish")
    assert controller.lab["status"] == "Completed", errors
    assert controller.lab["completed"] == 60
    assert controller.lab["released"] is True
    assert controller.lab["files_at_containment"] == paused_count
    assert controller.store.counts()["events"] == 60
    action_names = [row["action"] for row in controller.store.recent_actions()]
    assert "worker_suspended" in action_names
    assert "worker_resumed" in action_names
    results = [json.loads(line) for line in (controller.data_dir / "lab-results.jsonl").read_text(encoding="utf-8").splitlines()]
    assert results[-1]["status"] == "Completed"
    assert results[-1]["files_at_containment"] == paused_count
    assert errors == []


def test_benign_lab_completes_without_automatic_intervention(live_controller, qt_application):
    controller, errors = live_controller
    controller.start_lab("benign")
    pump_until(qt_application, lambda: controller.lab["status"] in {"Completed", "Failed", "Contained"} and not controller.lab_active, 10, "benign workload completion")
    assert controller.lab["status"] == "Completed", errors
    assert controller.lab["completed"] == 60
    assert controller.lab["peak_score"] < controller.settings["threshold"]
    assert controller.lab["contained_at"] is None
    assert controller.lab["first_high_at"] is None
    assert controller.store.counts()["events"] == 60
    assert "worker_suspended" not in [row["action"] for row in controller.store.recent_actions()]
    assert errors == []


def test_folder_events_reach_ui_thread_and_persist_without_attribution(live_controller, qt_application, tmp_path):
    controller, errors = live_controller
    folder = tmp_path / "watched-documents"
    folder.mkdir()
    document = folder / "document.txt"
    document.write_bytes(b"A" * 8192)
    controller.choose_folder(folder)
    controller.start_monitor()
    pump_until(qt_application, lambda: controller.monitoring, 5, "folder monitor readiness")
    assert controller.monitor.baseline_count == 1
    document.write_bytes(bytes(range(256)) * 32)
    pump_until(qt_application, lambda: controller.session_events > 0, 5, "persisted folder event")
    rows = controller.store.recent_events()
    changed = next(row for row in rows if row["path"] == str(document))
    assert changed["pid"] is None
    assert changed["source"] == "folder"
    assert changed["entropy_before"] == 0.0
    assert changed["entropy_after"] == 8.0
    assert changed["assessment"]["eligible_for_containment"] is False
    controller.stop_monitor()
    assert not controller.monitoring
    pump_for(qt_application, 0.1)
    stopped_count = controller.session_events
    document.write_text("Changed after stopping monitor", encoding="utf-8")
    pump_for(qt_application, 0.15)
    assert controller.session_events == stopped_count
    assert errors == []


def test_close_stops_suspended_child_and_closes_audit_store(live_controller, qt_application):
    controller, errors = live_controller
    controller.start_lab("suspicious")
    pump_until(qt_application, lambda: controller.lab["status"] in {"Contained", "Failed"}, 6, "suspended worker before close")
    assert controller.lab["status"] == "Contained", errors
    pid = controller.lab["pid"]
    controller.close()
    qt_application.processEvents()
    assert controller.process.state() == QProcess.ProcessState.NotRunning
    assert not psutil.pid_exists(pid)
    assert controller.lab["status"] == "Stopped"
    assert controller._closed is True
    controller.close()  # Idempotent close must not touch the closed SQLite handle.
    assert errors == []
