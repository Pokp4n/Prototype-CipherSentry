"""Milestone 1: monitor freshness, unscored late observations, and session isolation.

A fake monitor delivers events synchronously from the test thread, so these
tests control ordering exactly and do not depend on filesystem timing. No
process is controlled and no ETW session is started.
"""
from __future__ import annotations

import os
import threading
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import QEventLoop
from PySide6.QtWidgets import QApplication

from ciphersentry.controller import Controller
from ciphersentry.engine import UNSCORED_LEVEL, FileEvent
from ciphersentry.ui.window import MainWindow

FOLDER_KEY = "folder:unattributed"


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


class FakeMonitor:
    """Implements the controller's monitor lifecycle without watchdog threads."""

    def __init__(self, path, callback, on_error, gate=None):
        self.path = path
        self.callback = callback
        self.on_error = on_error
        self.gate = gate
        self._running = False
        self.baseline_count = 0
        self.dropped_events = 0
        self.pending_count = 0
        self.max_lag_seconds = 0.0

    @property
    def running(self):
        return self._running

    def start(self):
        if self.gate is not None:
            assert self.gate.wait(5), "test gate was never released"
        self._running = True

    def stop(self):
        self._running = False


def make_factory(created, gate=None):
    def factory(path, callback, on_error):
        monitor = FakeMonitor(path, callback, on_error, gate)
        created.append(monitor)
        return monitor
    return factory


def pump_until(app, predicate, seconds=5):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        app.processEvents(QEventLoop.ProcessEventsFlag.AllEvents, 30)
        if predicate():
            return
        time.sleep(0.01)
    assert predicate(), "expected state was not reached"


def folder_event(index, timestamp, root="C:\\Watched"):
    return FileEvent(timestamp=timestamp, path=f"{root}\\dept-{index % 3}\\file-{index}.txt",
                     operation="modified", process_name="Unattributed folder activity",
                     entropy_before=3.0, entropy_after=7.9, source="folder",
                     attribution="unavailable", observed_at=timestamp)


@pytest.fixture
def controller(tmp_path, app):
    instance = Controller(tmp_path / "app-data")
    yield instance
    instance.close()
    app.processEvents()


@pytest.fixture
def monitored(tmp_path, app):
    created = []
    instance = Controller(tmp_path / "app-data", monitor_factory=make_factory(created))
    watched = tmp_path / "watched"
    watched.mkdir()
    instance.choose_folder(watched)
    yield instance, created
    instance.close()
    app.processEvents()


def start(app, controller):
    controller.start_monitor()
    pump_until(app, lambda: controller.monitoring)


def raise_to_high(controller, now):
    for index in range(10):
        controller._ingest(folder_event(index, now + index * 0.01))
    assert controller._alert_levels[FOLDER_KEY] == "High"


# --- unscored late observations --------------------------------------------

def test_late_observation_is_stored_unscored_without_alert_or_response_change(controller):
    now = time.time()
    raise_to_high(controller, now)
    alerts_before = len(controller.store.recent_alerts())
    response_before = dict(controller.current_response)
    assessment_before = controller.assessment

    late = folder_event(99, now - 60)
    controller._ingest(late)

    row = next(r for r in controller.store.recent_events(500) if r["path"] == late.path)
    assert row["level"] == UNSCORED_LEVEL
    assert row["level"] != "Low"
    assert row["score"] == 0
    assert row["assessment"]["features"]["unscored"] is True
    assert row["response"]["action"] == "none"
    assert row["response"]["allowed"] is False
    assert "Late observation" in row["response"]["reason"]
    assert len(controller.store.recent_alerts()) == alerts_before
    assert controller._alert_levels[FOLDER_KEY] == "High", "Unscored evidence must not reset alert state"
    assert controller.current_response == response_before
    assert controller.assessment is assessment_before
    assert controller.late_observations == 1
    assert controller.monitor_health["late_observations"] == 1
    assert controller.store.counts()["suspicious_events"] == len(
        [r for r in controller.store.recent_events(500) if r["level"] in {"High", "Uncertain"}])


def test_late_observation_does_not_cause_duplicate_high_alert(controller):
    """Guard: unscored late evidence must never reset alert de-duplication for a live episode."""
    now = time.time()
    raise_to_high(controller, now)
    alerts_before = len(controller.store.recent_alerts())
    controller._ingest(folder_event(98, now - 60))
    controller._ingest(folder_event(10, now + 0.2))
    assert controller._alert_levels[FOLDER_KEY] == "High"
    assert len(controller.store.recent_alerts()) == alerts_before


def test_late_observation_never_reaches_response_policy_or_containment(controller, monkeypatch):
    from ciphersentry import controller as controller_module

    now = time.time()
    controller._ingest(folder_event(0, now))  # fresh evidence takes the normal path

    def forbidden(*args, **kwargs):
        raise AssertionError("an unscored late observation reached the response path")

    monkeypatch.setattr(controller_module, "evaluate_response", forbidden)
    monkeypatch.setattr(controller.containment, "validate", forbidden)
    monkeypatch.setattr(controller, "pause_lab", forbidden)
    controller.settings["response_mode"] = "simulation"
    context = {"pid": 4242, "create_time": 900.0, "executable": "C:\\Python\\python.exe",
               "parent_pid": 1, "identity_verified": True}
    late_lab = FileEvent(timestamp=now - 60, path="C:\\Lab\\dept-0\\sample.txt", operation="modified",
                         pid=4242, process_name="CipherSentry lab", entropy_before=3.0, entropy_after=7.9,
                         source="lab", attribution="cooperative_lab", process_context=context,
                         observed_at=now - 60)
    controller._ingest(late_lab)
    controller._ingest(folder_event(1, now - 61))
    assert controller.late_observations == 2
    rows = [r for r in controller.store.recent_events(500) if r["level"] == UNSCORED_LEVEL]
    assert len(rows) == 2
    assert all(r["response"]["allowed"] is False and r["response"]["outcome"] == "not_attempted" for r in rows)
    assert all(r["assessment"]["eligible_for_containment"] is False for r in rows)
    assert controller.lab["peak_score"] == 0, "Unscored lab evidence must not feed lab statistics"
    assert controller.store.recent_alerts() == []


def test_exports_label_late_observations_consistently(controller, tmp_path):
    import csv
    import json

    now = time.time()
    controller._ingest(folder_event(0, now))
    late = folder_event(1, now - 60)
    controller._ingest(late)
    controller.export(tmp_path / "evidence.json")
    controller.export(tmp_path / "evidence.csv")
    exported = json.loads((tmp_path / "evidence.json").read_text(encoding="utf-8"))
    row = next(e for e in exported["events"] if e["path"] == late.path)
    assert row["level"] == UNSCORED_LEVEL
    assert row["assessment"]["features"]["unscored"] is True
    assert row["response"]["action"] == "none"
    with (tmp_path / "evidence.csv").open(encoding="utf-8", newline="") as handle:
        csv_row = next(r for r in csv.DictReader(handle) if r["path"] == late.path)
    assert csv_row["level"] == UNSCORED_LEVEL
    assert json.loads(csv_row["assessment_json"])["features"]["unscored"] is True
    assert any(a["action"] == "late_observation" for a in exported["actions"])


def test_late_observation_audit_is_rate_limited(controller):
    now = time.time()
    controller._ingest(folder_event(0, now))
    for index in range(101):
        controller._ingest(folder_event(1000 + index, now - 60))
    late_actions = [a for a in controller.store.recent_actions(500) if a["action"] == "late_observation"]
    assert len(late_actions) == 2, "Audited on the 1st and 100th late observation only"
    assert "100 observation(s)" in late_actions[0]["detail"]
    assert controller.late_observations == 101
    assert controller.store.counts()["events"] == 102, "Every late observation is still preserved"


# --- monitoring-session isolation ------------------------------------------

def test_events_from_a_stopped_session_are_ignored_even_after_restart(monitored, app):
    controller, created = monitored
    start(app, controller)
    old = created[-1]
    old.callback(folder_event(1, time.time()))
    assert controller.session_events == 1

    controller.stop_monitor()
    old.callback(folder_event(2, time.time()))
    assert controller.session_events == 1
    assert controller.stale_events_ignored == 1

    start(app, controller)
    new = created[-1]
    assert new is not old
    old.callback(folder_event(3, time.time()))
    assert controller.session_events == 1, "Old-session events must not enter the new session"
    assert controller.stale_events_ignored == 2
    new.callback(folder_event(4, time.time()))
    assert controller.session_events == 2
    assert controller.monitor_health["stale_events_ignored"] == 2
    paths = {r["path"] for r in controller.store.recent_events()}
    assert folder_event(1, 0).path in paths and folder_event(4, 0).path in paths
    assert folder_event(2, 0).path not in paths and folder_event(3, 0).path not in paths


def test_queued_events_from_stopped_session_are_dropped_on_delivery(monitored, app):
    """Events emitted from a worker thread are queued; Stop must win if it runs first."""
    controller, created = monitored
    start(app, controller)
    monitor = created[-1]
    worker = threading.Thread(target=monitor.callback, args=(folder_event(5, time.time()),))
    worker.start()
    worker.join()
    controller.stop_monitor()  # before the queued signal is delivered
    for _ in range(10):
        app.processEvents(QEventLoop.ProcessEventsFlag.AllEvents, 30)
    assert controller.session_events == 0
    assert controller.stale_events_ignored == 1


def test_old_session_events_queued_across_restart_are_rejected_but_new_ones_kept(monitored, app):
    """Stop → Restart while old events are still queued on the Qt loop."""
    controller, created = monitored
    start(app, controller)
    old = created[-1]
    for index in (10, 11):
        worker = threading.Thread(target=old.callback, args=(folder_event(index, time.time()),))
        worker.start()
        worker.join()
    controller.stop_monitor()
    start(app, controller)  # pumping here delivers the two queued old-session events
    new = created[-1]
    worker = threading.Thread(target=new.callback, args=(folder_event(12, time.time()),))
    worker.start()
    worker.join()
    pump_until(app, lambda: controller.session_events == 1)
    assert controller.stale_events_ignored == 2
    paths = {r["path"] for r in controller.store.recent_events()}
    assert paths == {folder_event(12, 0).path}


def test_events_during_baseline_are_still_scored(tmp_path, app):
    created = []
    gate = threading.Event()
    controller = Controller(tmp_path / "app-data", monitor_factory=make_factory(created, gate))
    try:
        watched = tmp_path / "watched"
        watched.mkdir()
        controller.choose_folder(watched)
        controller.start_monitor()
        assert controller.monitor_starting and controller.monitor is None
        created[-1].callback(folder_event(1, time.time()))
        assert controller.session_events == 1
        assert controller.stale_events_ignored == 0
        gate.set()
        pump_until(app, lambda: controller.monitoring)
    finally:
        gate.set()
        controller.close()
        app.processEvents()


# --- honest health display --------------------------------------------------

def test_health_text_reports_delay_and_late_observations():
    clean = MainWindow.collector_health_text({"baseline_count": 3, "dropped_events": 0, "pending": 0,
                                              "max_lag_seconds": 0.08, "late_observations": 0})
    assert "max delay 0.1s" in clean
    assert "0 late observations not scored" in clean
    assert "does not prove complete coverage" in clean
    late = MainWindow.collector_health_text({"baseline_count": 3, "dropped_events": 0, "pending": 12,
                                             "max_lag_seconds": 14.2, "late_observations": 7})
    assert "backlog 12" in late and "max delay 14.2s" in late
    assert "7 late observations not scored" in late
    assert late.endswith("coverage incomplete")


def test_details_heading_never_shows_a_score_for_unscored_evidence():
    assert MainWindow.evidence_heading({"level": UNSCORED_LEVEL, "score": 0}) == \
        "Unscored · late observation, no risk score"
    assert MainWindow.evidence_heading({"level": "High", "score": 92}) == "High risk · 92 / 100"
    assert MainWindow.evidence_heading({"level": "Low", "score": 0}) == "Low risk · 0 / 100"


def test_unscored_rows_show_no_score_and_have_their_own_filter(controller, app):
    window = MainWindow(controller)
    try:
        now = time.time()
        controller._ingest(folder_event(0, now))
        late = folder_event(1, now - 60)
        controller._ingest(late)
        window.navigate(1)
        window.risk_filter.setCurrentText("Unscored (late)")
        window.refresh_tables()
        assert window.events_table.rowCount() == 1
        assert window.events_table.item(0, 2).text() == "file-1.txt"
        assert window.events_table.item(0, 4).text() == "—  Unscored"
        assert "not scored" in window.events_table.item(0, 4).toolTip()
        window.risk_filter.setCurrentText("Low")
        window.refresh_tables()
        assert all(window.events_table.item(row, 2).text() != "file-1.txt"
                   for row in range(window.events_table.rowCount())), "Unscored is not a Low result"
    finally:
        window.close()
        app.processEvents()
