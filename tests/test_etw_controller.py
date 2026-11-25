"""Stage 5.5G.2: real Qt controller audit-only integration tests.

These tests do not start ETW or suspend arbitrary Windows processes.
"""
import json
import os
import time
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import QEventLoop
from PySide6.QtWidgets import QApplication

from ciphersentry.controller import Controller
from ciphersentry.etw_correlation import FolderWriteCorrelation
from ciphersentry.etw_watchdog_probe import CandidateMatch


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def controller(tmp_path, app):
    instance = Controller(tmp_path / "app-data")
    root = tmp_path / "monitored"
    root.mkdir()
    instance.choose_folder(root)
    instance.start_monitor()
    deadline = time.monotonic() + 5
    while not instance.monitoring and time.monotonic() < deadline:
        app.processEvents(QEventLoop.ProcessEventsFlag.AllEvents, 30)
        time.sleep(0.01)
    assert instance.monitoring
    yield instance, root
    instance.close()
    app.processEvents()


def pump_until(app, predicate, seconds=2):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        app.processEvents(QEventLoop.ProcessEventsFlag.AllEvents, 30)
        if predicate():
            return
        time.sleep(0.01)
    assert predicate(), "Qt signal not delivered"


def candidate(path, pids=(22208,), *, verified=None, allowed=False):
    result = FolderWriteCorrelation(
        path=str(path), operation="modified", matched_write_count=3,
        unverified_event_pids=tuple(pids), system_pid4_writes=1,
        reader_prior_key_candidates=2,
        status="multiple_unverified_pids" if len(pids) > 1 else "single_unverified_pid",
        verified_writer_pid=verified, containment_authorized=allowed,
    )
    return CandidateMatch(str(path), "modified", result)


def test_audits_unverified_candidate_without_scoring_or_containment(controller, app):
    c, root = controller
    recorded = []
    c.etw_candidate_recorded.connect(recorded.append)
    initial_response = dict(c.current_response)
    initial_events = c.session_events
    c.submit_etw_candidate(candidate(root / "test.txt"))
    pump_until(app, lambda: c.etw_candidate_count == 1)
    assert len(recorded) == 1
    assert recorded[0]["unverified_event_pids"] == [22208]
    assert recorded[0]["verified_writer_pid"] is None
    assert recorded[0]["containment_authorized"] is False
    assert recorded[0]["risk_scored"] is False
    assert c.assessment is None
    assert c.session_events == initial_events
    assert c.current_response == initial_response
    rows = [r for r in c.store.recent_actions() if r["action"] == "etw_candidate_observation"]
    assert len(rows) == 1
    assert json.loads(rows[0]["detail"])["unverified_event_pids"] == [22208]
    assert rows[0]["pid"] is None


def test_rejects_outside_folder_and_claims_of_verified_identity(controller, app):
    c, root = controller
    c.submit_etw_candidate(candidate(root.parent / "other.txt"))
    c.submit_etw_candidate(candidate(root / "test.txt", verified=22208))
    c.submit_etw_candidate(candidate(root / "test.txt", allowed=True))
    # Queued signals drain on the Qt event loop.
    for _ in range(10):
        app.processEvents(QEventLoop.ProcessEventsFlag.AllEvents, 30)
    assert c.etw_candidate_count == 0
    assert not [r for r in c.store.recent_actions() if r["action"] == "etw_candidate_observation"]


def test_multiple_pids_remain_ambiguous_and_stopped_monitor_ignores_stale_data(controller, app):
    c, root = controller
    c.submit_etw_candidate(candidate(root / "test.txt", pids=(22208, 42764)))
    pump_until(app, lambda: c.etw_candidate_count == 1)
    assert c.etw_latest_candidate["status"] == "multiple_unverified_pids"
    assert c.etw_latest_candidate["verified_writer_pid"] is None
    c.stop_monitor()
    c.submit_etw_candidate(candidate(root / "test.txt"))
    for _ in range(10):
        app.processEvents(QEventLoop.ProcessEventsFlag.AllEvents, 30)
    assert c.etw_candidate_count == 1
