"""Stage 5.5H.1: display persisted ETW candidate evidence safely in the GUI."""
from __future__ import annotations

import json
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from ciphersentry.controller import Controller
from ciphersentry.ui.window import MainWindow


def _payload():
    return {
        "schema": 1,
        "kind": "etw_watchdog_candidate",
        "path": r"C:\lab\writer-run-1\etw-writer-test.txt",
        "operation": "modified",
        "matched_write_count": 5,
        "unverified_event_pids": [3444, 6056],
        "system_pid4_writes": 1,
        "reader_prior_key_candidates": 5,
        "status": "multiple_unverified_pids",
        "verified_writer_pid": None,
        "containment_authorized": False,
        "risk_scored": False,
    }


def test_storage_queries_only_independent_etw_audit(tmp_path):
    app = QApplication.instance() or QApplication([])
    controller = Controller(tmp_path / "data")
    try:
        controller.store.record_action("response_decision", "unrelated")
        controller.store.record_action("etw_candidate_observation", json.dumps(_payload()))
        controller.store.record_action("etw_candidate_observation", "{not valid JSON")
        records = controller.store.recent_etw_candidates()
        assert len(records) == 1
        assert records[0]["unverified_event_pids"] == [3444, 6056]
        assert records[0]["containment_authorized"] is False
        assert controller.total_events == 0
    finally:
        controller.close()


def test_event_explorer_displays_unverified_etw_evidence_separately(tmp_path):
    app = QApplication.instance() or QApplication([])
    controller = Controller(tmp_path / "gui-data")
    window = MainWindow(controller)
    try:
        controller.store.record_action("etw_candidate_observation", json.dumps(_payload()))
        window.navigate(1)
        assert window.etw_candidate_table.rowCount() == 1
        assert window.etw_candidate_table.item(0, 2).text() == "modified"
        assert "3444, 6056" in window.etw_candidate_table.item(0, 3).text()
        assert "unverified" in window.etw_candidate_table.item(0, 3).text()
        assert "pid 4: 1" in window.etw_candidate_table.item(0, 4).text().lower()
        assert "latest 1" in window.etw_count_label.text().lower()
        assert controller.total_events == 0
        assert controller.session_events == 0
    finally:
        window.close()
        app.processEvents()
