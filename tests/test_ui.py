"""Real desktop journeys: alert-only review and explicit simulation opt-in."""
import json
import os
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QEventLoop, QPoint, Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QFileDialog

from ciphersentry.controller import Controller
from ciphersentry.ui.theme import STYLESHEET
from ciphersentry.ui.window import MainWindow


def pump_until(app, predicate, timeout=9):
    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        app.processEvents(QEventLoop.ProcessEventsFlag.AllEvents, 50)
        time.sleep(.01)
    assert predicate(), "Desktop workflow did not reach the expected state"


def create_window(tmp_path):
    app = QApplication.instance() or QApplication([])
    app.setStyleSheet(STYLESHEET)
    controller = Controller(tmp_path / "data")
    window = MainWindow(controller)
    errors = []
    controller.error.connect(errors.append)
    window.show()
    return app, controller, window, errors


def test_default_alert_only_review_acknowledgement_export_and_rule_settings(tmp_path, monkeypatch):
    app, controller, window, errors = create_window(tmp_path)
    try:
        assert controller.settings["response_mode"] == "alert_only"
        assert not window.auto_contain.isChecked()
        QTest.mouseClick(window.nav_buttons[2], Qt.MouseButton.LeftButton)
        QTest.mouseClick(window.suspicious_button, Qt.MouseButton.LeftButton)
        pump_until(app, lambda: controller.lab["first_high_at"] is not None)
        assert controller.lab["status"] == "Running"
        assert controller.lab["contained_at"] is None
        assert "Alert-only" in window.lab_mode_label.text()
        assert not window.resume_button.isEnabled()

        QTest.mouseClick(window.nav_buttons[4], Qt.MouseButton.LeftButton)
        assert window.alerts_table.rowCount() > 0
        window.alerts_table.selectRow(0)
        selected = window.alerts_table.item(0, 0).data(Qt.ItemDataRole.UserRole)
        assert selected["level"] == "High"
        assert selected["response_action"] == "alert_only"
        assert "MISSING / UNCERTAIN EVIDENCE" in window.alert_details.toPlainText()
        alert_id = selected["id"]
        QTest.mouseClick(window.acknowledge_button, Qt.MouseButton.LeftButton)
        acknowledged = next(a for a in controller.store.recent_alerts() if a["id"] == alert_id)
        assert acknowledged["status"] == "acknowledged"
        assert controller.lab["status"] == "Running", "Acknowledgement must not alter a process"

        QTest.mouseClick(window.nav_buttons[1], Qt.MouseButton.LeftButton)
        window.risk_filter.setCurrentText("High")
        window.refresh_tables()
        assert window.events_table.rowCount() > 0
        evidence = window.events_table.item(0, 0).data(Qt.ItemDataRole.UserRole)
        assert len(evidence["assessment"]["signals"]) == 5
        assert evidence["assessment"]["attribution"] == "cooperative_lab"
        assert evidence["response"]["allowed"] is False
        window.search.setText("file-that-is-not-in-the-evidence")
        window.refresh_tables()
        assert window.events_table.rowCount() == 0

        pump_until(app, lambda: not controller.lab_active)
        assert controller.lab["status"] == "Completed", errors
        assert controller.lab["completed"] == 60
        assert controller.lab["contained_at"] is None
        assert not any(a["action"] == "worker_suspended" for a in controller.store.recent_actions())

        target = tmp_path / "export.json"
        monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *a, **k: (str(target), "JSON evidence (*.json)"))
        window.export_evidence()
        exported = json.loads(target.read_text(encoding="utf-8"))
        assert len(exported["events"]) == 60
        assert any(a["id"] == alert_id and a["status"] == "acknowledged" for a in exported["alerts"])

        QTest.mouseClick(window.nav_buttons[3], Qt.MouseButton.LeftButton)
        window.threshold.setValue(90)
        window.window_seconds.setValue(15)
        window.weight_controls["frequency"].setValue(20)
        window.indicator_enabled["spread"].setChecked(False)
        window.stack.currentWidget().ensureWidgetVisible(window.save_policy_button)
        QTest.mouseClick(window.save_policy_button, Qt.MouseButton.LeftButton)
        saved = json.loads((controller.data_dir / "settings.json").read_text(encoding="utf-8"))
        assert saved["response_mode"] == "alert_only"
        assert saved["risk_config"]["high_threshold"] == 90
        assert saved["risk_config"]["window_seconds"] == 15
        assert saved["risk_config"]["weights"]["frequency"] == 20
        assert "spread" not in saved["risk_config"]["enabled_indicators"]
        assert window.lab_gauge.high_threshold == 90
        assert errors == []
    finally:
        window.close()
        app.processEvents()
    assert not controller.lab_active


def test_settings_explicitly_opt_in_to_managed_simulation_containment(tmp_path):
    app, controller, window, errors = create_window(tmp_path)
    try:
        QTest.mouseClick(window.nav_buttons[3], Qt.MouseButton.LeftButton)
        window.stack.currentWidget().ensureWidgetVisible(window.auto_contain)
        QTest.mouseClick(window.auto_contain, Qt.MouseButton.LeftButton,
                         pos=QPoint(8, window.auto_contain.height() // 2))
        window.stack.currentWidget().ensureWidgetVisible(window.save_policy_button)
        QTest.mouseClick(window.save_policy_button, Qt.MouseButton.LeftButton)
        assert controller.settings["response_mode"] == "simulation"
        QTest.mouseClick(window.nav_buttons[2], Qt.MouseButton.LeftButton)
        QTest.mouseClick(window.suspicious_button, Qt.MouseButton.LeftButton)
        pump_until(app, lambda: controller.lab["status"] in {"Contained", "Failed"})
        assert controller.lab["status"] == "Contained", errors
        assert controller.containment.is_suspended(controller.lab["pid"])
        assert window.resume_button.isEnabled()
        assert not window.pause_button.isEnabled()
        assert any(a["action"] == "worker_suspended" for a in controller.store.recent_actions())
        assert errors == []
    finally:
        window.close()
        app.processEvents()
    assert not controller.lab_active


def test_compression_control_launches_real_zip_workload(tmp_path):
    app, controller, window, errors = create_window(tmp_path)
    try:
        QTest.mouseClick(window.nav_buttons[2], Qt.MouseButton.LeftButton)
        window.stack.currentWidget().ensureWidgetVisible(window.compression_button)
        QTest.mouseClick(window.compression_button, Qt.MouseButton.LeftButton)
        pump_until(app, lambda: controller.lab["completed"] > 0)
        assert controller.lab["scenario"] == "compression"
        assert not window.compression_button.isEnabled()
        assert "Legitimate ZIP creation" in window.lab_description.text()
        assert "ZIP archives created" in window.lab_progress_label.text()
        event = controller.store.recent_events(1)[0]
        assert event["operation"] == "created"
        assert event["path"].endswith(".zip")
        assert event["entropy_before"] is None
        assert errors == []
    finally:
        window.close()
        app.processEvents()
    assert not controller.lab_active
