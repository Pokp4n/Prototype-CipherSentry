"""Event Explorer preserves persisted evidence while avoiding idle table work."""
from __future__ import annotations

import csv
from dataclasses import replace
import json
import os
from pathlib import Path
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QDialog, QFileDialog, QTextEdit

from ciphersentry.controller import Controller
from ciphersentry.engine import FileEvent, RiskEngine
from ciphersentry.ui.theme import STYLESHEET
from ciphersentry.ui.window import MainWindow


@pytest.fixture
def explorer_factory(tmp_path):
    application = QApplication.instance() or QApplication([])
    application.setStyleSheet(STYLESHEET)
    windows = []

    def create(count=80):
        controller = Controller(tmp_path / f"data-{len(windows)}")
        controller.timer.stop()
        engine = RiskEngine()
        levels = [("High", 90), ("Uncertain", 50), ("Low", 10), ("Elevated", 55)]
        for index in range(count):
            # Deliberately include tied and out-of-order timestamps. These are
            # stored UI fixtures, never claims about an executing process.
            event = FileEvent(
                timestamp=1000 + (index * 7) % 23,
                path=str(tmp_path / ("invoices" if index % 2 else "notes") / f"fixture-{index:04d}.txt"),
                operation="modified" if index % 2 else "created",
                process_name="WriterAlpha" if index % 2 else "WriterBeta",
                entropy_before=2.0,
                entropy_after=7.9,
                source="lab" if index % 3 == 0 else "folder",
            )
            level, score = levels[index % len(levels)]
            assessment = replace(engine.ingest(event), level=level, score=score,
                                 response_reason=f"Original historical assessment {index}")
            controller.store.record_event(event, assessment, {
                "action": "alert_only", "allowed": False,
                "reason": "Synthetic display fixture; no process action.",
            })
        controller.total_events = count
        window = MainWindow(controller)
        windows.append(window)
        window.refresh_timer.stop()
        window.show()
        window.navigate(1)
        application.processEvents()
        assert controller.settings["response_mode"] == "alert_only"
        return application, controller, window

    yield create
    for window in windows:
        window.close()
        application.processEvents()


def displayed_records(table):
    return [table.item(row, 0).data(Qt.ItemDataRole.UserRole) for row in range(table.rowCount())]


def append_live_observation(controller, name="new-observation.txt"):
    event = FileEvent(time.time(), str(controller.data_dir / name), "modified",
                      entropy_before=3.0, entropy_after=3.2)
    controller._ingest(event)
    return event


def test_idle_updates_do_not_query_or_replace_event_rows(explorer_factory, monkeypatch):
    app, controller, window = explorer_factory()
    table = window.events_table
    table.selectRow(12)
    table.verticalScrollBar().setValue(table.verticalScrollBar().maximum() // 2)
    app.processEvents()
    item = table.item(0, 0)
    selected_id = table.item(table.currentRow(), 0).data(Qt.ItemDataRole.UserRole)["id"]
    scroll = table.verticalScrollBar().value()
    queries = []
    recent_events = controller.store.recent_events

    def counted(*args, **kwargs):
        queries.append(True)
        return recent_events(*args, **kwargs)

    monkeypatch.setattr(controller.store, "recent_events", counted)
    for _ in range(4):
        controller._tick()
        window.refresh_lab()
        window.refresh_tables()
        app.processEvents()
    assert queries == []
    assert table.item(0, 0) is item
    assert table.item(table.currentRow(), 0).data(Qt.ItemDataRole.UserRole)["id"] == selected_id
    assert table.verticalScrollBar().value() == scroll


def test_search_and_risk_filters_use_cached_original_records(explorer_factory, monkeypatch):
    app, controller, window = explorer_factory()
    original = controller.store.recent_events(500)
    queries = []
    recent_events = controller.store.recent_events

    def counted(*args, **kwargs):
        queries.append(True)
        return recent_events(*args, **kwargs)

    monkeypatch.setattr(controller.store, "recent_events", counted)
    for search in ["", "  INVOICES  ", "WriterALPHA", "modified", "folder", "not-in-evidence"]:
        window.search.setText(search)
        for risk_label in ["All risk levels", "High", "Uncertain", "Low", "Elevated (legacy)"]:
            window.risk_filter.setCurrentText(risk_label)
            window.refresh_tables()
            query = search.casefold().strip()
            risk = "Elevated" if risk_label == "Elevated (legacy)" else risk_label
            expected = [record for record in original
                        if (risk == "All risk levels" or record["level"] == risk)
                        and (not query or query in " ".join(str(record[key]) for key in
                             ("path", "process_name", "operation", "source")).casefold())]
            assert displayed_records(window.events_table) == expected
            assert f"{len(expected)} shown" in window.event_count_label.text()
    assert queries == []
    assert recent_events(500) == original


def test_new_evidence_defers_hidden_explorer_until_navigation(explorer_factory):
    app, controller, window = explorer_factory()
    first = window.events_table.item(0, 0)
    count = window.events_table.rowCount()
    window.navigate(3)
    event = append_live_observation(controller)
    window.refresh_tables()
    app.processEvents()
    assert window.events_table.item(0, 0) is first
    assert window.events_table.rowCount() == count
    window.navigate(1)
    app.processEvents()
    records = displayed_records(window.events_table)
    assert len(records) == count + 1
    assert records[0]["path"] == event.path
    assert records == controller.store.recent_events(500)


def test_new_evidence_preserves_selected_event_and_scrolled_anchor(explorer_factory):
    app, controller, window = explorer_factory()
    table = window.events_table
    table.selectRow(20)
    table.verticalScrollBar().setValue(table.verticalScrollBar().maximum() // 2)
    app.processEvents()
    selected_id = table.item(table.currentRow(), 0).data(Qt.ItemDataRole.UserRole)["id"]
    top = table.rowAt(0)
    assert top > 0
    anchor = table.item(top, 0)
    anchor_id = anchor.data(Qt.ItemDataRole.UserRole)["id"]
    offset = table.visualItemRect(anchor).top()
    append_live_observation(controller)
    window.refresh_tables()
    app.processEvents()
    assert table.item(table.currentRow(), 0).data(Qt.ItemDataRole.UserRole)["id"] == selected_id
    new_top = table.item(table.rowAt(0), 0)
    assert new_top.data(Qt.ItemDataRole.UserRole)["id"] == anchor_id
    assert abs(table.visualItemRect(new_top).top() - offset) <= 1
    table.verticalScrollBar().setValue(0)
    newest = append_live_observation(controller, "newest-observation.txt")
    window.refresh_tables()
    app.processEvents()
    assert table.verticalScrollBar().value() == 0
    assert table.item(0, 0).data(Qt.ItemDataRole.UserRole)["path"] == newest.path


def test_double_click_opens_original_historical_details(explorer_factory, monkeypatch):
    app, controller, window = explorer_factory()
    window.risk_filter.setCurrentText("Elevated (legacy)")
    window.refresh_tables()
    app.processEvents()
    table = window.events_table
    record = table.item(0, 0).data(Qt.ItemDataRole.UserRole)
    original = next(row for row in controller.store.recent_events(500) if row["id"] == record["id"])
    dialogs = []

    def inspect_dialog(dialog):
        dialogs.append(dialog.findChild(QTextEdit).toPlainText())
        return QDialog.DialogCode.Accepted

    monkeypatch.setattr(QDialog, "exec", inspect_dialog)
    point = table.visualItemRect(table.item(0, 2)).center()
    QTest.mouseClick(table.viewport(), Qt.MouseButton.LeftButton, pos=point)
    QTest.mouseDClick(table.viewport(), Qt.MouseButton.LeftButton, pos=point)
    app.processEvents()
    assert len(dialogs) == 1
    assert original["path"] in dialogs[0]
    assert original["assessment"]["response_reason"] in dialogs[0]
    for signal in original["assessment"]["signals"]:
        assert signal["explanation"] in dialogs[0]
    assert record == original


def test_display_limit_and_filters_do_not_change_full_exports(explorer_factory, monkeypatch, tmp_path):
    app, controller, window = explorer_factory(count=510)
    original = controller.store.recent_events(1000)
    raw_before = [tuple(row) for row in controller.store._connection.execute("SELECT * FROM events ORDER BY id")]
    assert len(original) == 510
    assert displayed_records(window.events_table) == original[:500]
    assert [(record["timestamp"], record["id"]) for record in original] == sorted(
        [(record["timestamp"], record["id"]) for record in original], reverse=True)
    window.search.setText("invoices")
    window.risk_filter.setCurrentText("High")
    window.refresh_tables()
    json_path, csv_path = tmp_path / "all-evidence.json", tmp_path / "all-evidence.csv"
    targets = iter([(str(json_path), "JSON evidence (*.json)"), (str(csv_path), "CSV events (*.csv)")])
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *args, **kwargs: next(targets))
    window.export_evidence()
    window.export_evidence()
    exported = json.loads(json_path.read_text(encoding="utf-8"))["events"]
    assert exported == list(reversed(original))
    with csv_path.open(encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream))
    assert len(rows) == 510
    by_id = {record["id"]: record for record in original}
    for row in rows:
        expected = by_id[int(row["id"])]
        assert json.loads(row["assessment_json"]) == expected["assessment"]
        assert json.loads(row["response_json"]) == expected["response"]
        assert json.loads(row["event_json"])["path"] == expected["path"]
    assert [tuple(row) for row in controller.store._connection.execute("SELECT * FROM events ORDER BY id")] == raw_before


def test_alert_review_and_audit_update_without_event_table_rebuild(explorer_factory):
    app, controller, window = explorer_factory()
    first = window.events_table.item(0, 0)
    event = FileEvent(time.time(), str(controller.data_dir / "alert-fixture.txt"), "modified")
    assessment = replace(RiskEngine().ingest(event), score=90, level="High")
    alert_id = controller.store.record_alert(assessment, {
        "action": "alert_only", "allowed": False, "reason": "Review this fixture only.",
    })
    controller.changed.emit()
    window.navigate(4)
    window.refresh_tables()
    window.alerts_table.selectRow(0)
    assert window.alerts_table.item(0, 0).data(Qt.ItemDataRole.UserRole)["id"] == alert_id
    window.acknowledge_selected_alert()
    assert window.alerts_table.item(0, 0).data(Qt.ItemDataRole.UserRole)["status"] == "acknowledged"
    window.navigate(1)
    window.refresh_tables()
    app.processEvents()
    assert window.events_table.item(0, 0) is first
    assert "alert acknowledged" in window.actions_label.text()
    assert controller.store.counts()["events"] == 80
    assert controller.settings["response_mode"] == "alert_only"
