"""Milestone 2: read-only ETW collector readiness in the normal application.

Readiness is a file-metadata check only. These tests use dummy files in
pytest temporary directories; nothing is executed, no ETW session is started,
and no elevation is requested.
"""
from __future__ import annotations

import os
import sys
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import QEventLoop, QProcess
from PySide6.QtWidgets import QApplication

from ciphersentry import etw_sidecar
from ciphersentry.controller import Controller
from ciphersentry.engine import DEFAULT_WEIGHTS
from ciphersentry.etw_correlation import FolderWriteCorrelation
from ciphersentry.etw_sidecar import (
    FILE_FOUND, FILE_NOT_CHECKED, FILE_UNAVAILABLE, CollectorReadiness, collector_readiness,
)
from ciphersentry.etw_watchdog_probe import CandidateMatch
from ciphersentry.ui.window import MainWindow

# Process-launch, shell and foreign-call audit events (PEP 578). Any of these
# while readiness is evaluated or displayed means something was started.
LAUNCH_EVENTS = ("subprocess.Popen", "os.system", "os.startfile", "os.spawn", "os.exec",
                 "os.posix_spawn", "os.fork", "ctypes.call_function", "ctypes.dlopen")
_audit = {"active": False, "events": []}


def _audit_hook(event, args):
    if _audit["active"] and (event.startswith(LAUNCH_EVENTS) or event == "open"):
        _audit["events"].append((event, args))


sys.addaudithook(_audit_hook)  # cannot be removed; inert unless "active"


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


def make_package(root):
    application = root / "CipherSentry.exe"
    application.write_bytes(b"dummy gui, never executed")
    (root / "etw").mkdir()
    collector = root / "etw" / "LiveEtwStreamer.exe"
    collector.write_bytes(b"dummy collector, never executed")
    return application, collector


class FakeMonitor:
    def __init__(self, path, callback, on_error):
        self._running = False
        self.baseline_count = 0
        self.dropped_events = 0

    @property
    def running(self):
        return self._running

    def start(self):
        self._running = True

    def stop(self):
        self._running = False


def pump_until(app, predicate, seconds=5):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        app.processEvents(QEventLoop.ProcessEventsFlag.AllEvents, 30)
        if predicate():
            return
        time.sleep(0.01)
    assert predicate(), "expected state was not reached"


def candidate(path):
    evidence = FolderWriteCorrelation(
        path=str(path), operation="modified", matched_write_count=2,
        unverified_event_pids=(22208,), system_pid4_writes=0, reader_prior_key_candidates=0,
        status="single_unverified_pid", verified_writer_pid=None, containment_authorized=False)
    return CandidateMatch(str(path), "modified", evidence)


# --- readiness model -------------------------------------------------------

def test_found_collector_is_reported_as_present_but_unverified(tmp_path):
    application, collector = make_package(tmp_path)
    readiness = collector_readiness(application)
    assert readiness.file_state == FILE_FOUND and readiness.file_found
    assert readiness.collector_path == collector
    assert readiness.collection_started is False
    assert readiness.attribution_verified is False
    assert "not been verified, trusted, or run" in readiness.detail
    assert str(tmp_path) not in readiness.detail  # relative location only


def test_missing_collector_is_unavailable(tmp_path):
    application, collector = make_package(tmp_path)
    collector.unlink()
    readiness = collector_readiness(application)
    assert readiness.file_state == FILE_UNAVAILABLE and not readiness.file_found
    assert readiness.collector_path is None
    assert "was not found" in readiness.detail


def test_wrong_application_name_is_unavailable(tmp_path):
    application, _ = make_package(tmp_path)
    other = application.with_name("OtherApp.exe")
    application.rename(other)
    assert collector_readiness(other).file_state == FILE_UNAVAILABLE


def test_relative_application_path_is_unavailable_not_an_exception():
    readiness = collector_readiness("CipherSentry.exe")
    assert readiness.file_state == FILE_UNAVAILABLE
    assert "could not be checked" in readiness.detail


def test_collector_directory_symlink_is_unavailable(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (real / "LiveEtwStreamer.exe").write_bytes(b"dummy")
    package = tmp_path / "package"
    package.mkdir()
    application = package / "CipherSentry.exe"
    application.write_bytes(b"dummy")
    try:
        (package / "etw").symlink_to(real, target_is_directory=True)
    except OSError:
        pytest.skip("Creating symlinks needs Developer Mode or elevation on this host")
    assert collector_readiness(application).file_state == FILE_UNAVAILABLE


def test_source_mode_reports_not_checked_without_discovery(monkeypatch):
    monkeypatch.setattr(sys, "frozen", False, raising=False)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("source mode must not run packaged discovery")
    monkeypatch.setattr(etw_sidecar, "find_packaged_collector", forbidden)
    readiness = collector_readiness()
    assert readiness.file_state == FILE_NOT_CHECKED
    assert "Python source" in readiness.detail


def test_packaged_mode_uses_frozen_executable_location(tmp_path, monkeypatch):
    application, collector = make_package(tmp_path)
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(application))
    assert collector_readiness() == CollectorReadiness(
        FILE_FOUND, collector_readiness(application).detail, collector)


def test_packaged_mode_without_collector_is_unavailable(tmp_path, monkeypatch):
    application, collector = make_package(tmp_path)
    collector.unlink()
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(application))
    assert collector_readiness().file_state == FILE_UNAVAILABLE


# --- no execution, no elevation --------------------------------------------

def test_audit_hook_detects_a_launch_attempt(tmp_path):
    """Control: the hook used below really sees process launches.

    The target does not exist, so Popen fails before anything can run.
    """
    import subprocess
    _audit["events"].clear()
    _audit["active"] = True
    try:
        with pytest.raises(OSError):
            subprocess.Popen([str(tmp_path / "does-not-exist.exe")])
    finally:
        _audit["active"] = False
    assert any(event == "subprocess.Popen" for event, _ in _audit["events"])


def test_readiness_controller_and_gui_never_launch_or_open_the_collector(tmp_path, app, monkeypatch):
    package = tmp_path / "pkg"
    package.mkdir()
    application, collector = make_package(package)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("no process may be started")
    for name in ("start", "startDetached", "startCommand"):
        if hasattr(QProcess, name):
            monkeypatch.setattr(QProcess, name, forbidden)

    _audit["events"].clear()
    _audit["active"] = True
    try:
        controller = Controller(tmp_path / "app-data",
                                etw_readiness_provider=lambda: collector_readiness(application))
        window = MainWindow(controller)
        window.refresh()
        app.processEvents()
        status = controller.etw_status
    finally:
        _audit["active"] = False
    try:
        launches = [e for e, _ in _audit["events"] if e != "open"]
        collector_opens = [a for e, a in _audit["events"]
                           if e == "open" and "LiveEtwStreamer" in str(a[0] if a else "")]
        assert launches == []
        assert collector_opens == []
        assert status["file_state"] == FILE_FOUND
        assert status["collection_started_by_app"] is False
        assert controller.etw_readiness.collector_path == collector
        assert not controller.lab_active
        # The dummy file is untouched: still the exact bytes written above.
        assert collector.read_bytes() == b"dummy collector, never executed"
    finally:
        window.close()
        controller.close()
        app.processEvents()


# --- controller and GUI status ---------------------------------------------

def test_default_source_run_controller_reports_not_checked(tmp_path, app):
    controller = Controller(tmp_path / "app-data")
    try:
        assert controller.etw_status == {
            "file_state": FILE_NOT_CHECKED,
            "detail": controller.etw_readiness.detail,
            "collection_started_by_app": False,
            "attribution_verified": False,
            "candidate_records": 0,
        }
    finally:
        controller.close()
        app.processEvents()


def test_found_collector_does_not_change_scoring_response_or_folder_health(tmp_path, app):
    application, _ = make_package(tmp_path)
    found = Controller(tmp_path / "found", etw_readiness_provider=lambda: collector_readiness(application))
    plain = Controller(tmp_path / "plain")
    try:
        assert found.engine.config.to_dict() == plain.engine.config.to_dict()
        assert dict(found.engine.config.weights) == DEFAULT_WEIGHTS
        assert found.settings == plain.settings
        assert found.settings["response_mode"] == "alert_only"
        assert found.current_response == plain.current_response
        assert found.monitor_health == plain.monitor_health
        assert not any("etw" in key for key in found.monitor_health)
        assert not [a for a in found.store.recent_actions() if "etw" in a["action"]]
    finally:
        found.close()
        plain.close()
        app.processEvents()


@pytest.mark.parametrize("state, headline", [
    (FILE_FOUND, "Collector file found"),
    (FILE_UNAVAILABLE, "Collector file unavailable"),
    (FILE_NOT_CHECKED, "Collector file not checked"),
])
def test_readiness_text_never_claims_live_or_verified_etw(state, headline):
    text = MainWindow.etw_readiness_text({"file_state": state, "detail": "detail", "candidate_records": 0})
    lines = text.splitlines()
    assert lines[0] == f"{headline} · detail"
    assert lines[1] == "ETW collection not started by CipherSentry · folder monitoring does not use ETW"
    assert lines[2].startswith("ETW attribution is experimental and unverified")
    lowered = text.lower()
    for claim in ("active", "running", "live monitoring", "trusted", "protected", "verified writer"):
        assert claim not in lowered


def test_candidate_records_text_is_external_and_unverified():
    one = MainWindow.etw_readiness_text({"file_state": FILE_FOUND, "detail": "d", "candidate_records": 1})
    many = MainWindow.etw_readiness_text({"file_state": FILE_FOUND, "detail": "d", "candidate_records": 1200})
    assert ("ETW collection not started by CipherSentry · 1 unverified candidate record "
            "received from an external lab pipeline") in one
    assert "1,200 unverified candidate records received" in many


def test_gui_status_transitions_keep_folder_and_etw_status_independent(tmp_path, app):
    application, _ = make_package(tmp_path)
    controller = Controller(tmp_path / "app-data", monitor_factory=FakeMonitor,
                            etw_readiness_provider=lambda: collector_readiness(application))
    window = MainWindow(controller)
    try:
        etw_idle = window.etw_readiness_label.text()
        assert etw_idle.startswith("Collector file found · ")
        assert "not started by CipherSentry · folder monitoring does not use ETW" in etw_idle
        assert window.status_badge.text() == "●  Folder monitor idle"

        watched = tmp_path / "watched"
        watched.mkdir()
        controller.choose_folder(watched)
        controller.start_monitor()
        pump_until(app, lambda: controller.monitoring)
        window.refresh()
        assert window.status_badge.text() == "●  Folder monitor active"
        assert window.etw_readiness_label.text() == etw_idle  # folder state does not change ETW state

        controller.submit_etw_candidate(candidate(watched / "a.txt"))
        pump_until(app, lambda: controller.etw_candidate_count == 1)
        etw_text = window.etw_readiness_label.text()
        assert "not started by CipherSentry · 1 unverified candidate record received" in etw_text
        assert "experimental and unverified" in etw_text
        assert controller.assessment is None and controller.session_events == 0
        assert window.status_badge.text() == "●  Folder monitor active"

        controller.stop_monitor()
        window.refresh()
        assert window.status_badge.text() == "●  Folder monitor idle"
        assert "1 unverified candidate record received" in window.etw_readiness_label.text()
    finally:
        window.close()
        controller.close()
        app.processEvents()


def test_unavailable_collector_is_shown_in_gui(tmp_path, app):
    application, collector = make_package(tmp_path)
    collector.unlink()
    controller = Controller(tmp_path / "app-data",
                            etw_readiness_provider=lambda: collector_readiness(application))
    window = MainWindow(controller)
    try:
        text = window.etw_readiness_label.text()
        assert text.startswith("Collector file unavailable · etw\\LiveEtwStreamer.exe was not found")
    finally:
        window.close()
        controller.close()
        app.processEvents()
