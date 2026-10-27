"""Exercise a desktop user journey with the actual worker, evidence and export."""
import json
import os
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QEventLoop, Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QFileDialog

from ciphersentry.controller import Controller
from ciphersentry.ui.theme import STYLESHEET
from ciphersentry.ui.window import MainWindow


def test_desktop_lab_explanation_filter_policy_and_export(tmp_path, monkeypatch):
    app = QApplication.instance() or QApplication([])
    app.setStyleSheet(STYLESHEET)
    controller = Controller(tmp_path / "data")
    window = MainWindow(controller)
    errors = []
    controller.error.connect(errors.append)
    window.show()
    try:
        QTest.mouseClick(window.nav_buttons[2], Qt.MouseButton.LeftButton)
        assert window.stack.currentIndex() == 2
        QTest.mouseClick(window.suspicious_button, Qt.MouseButton.LeftButton)
        deadline = time.monotonic() + 6
        while controller.lab["status"] not in {"Contained", "Failed"} and time.monotonic() < deadline:
            app.processEvents(QEventLoop.ProcessEventsFlag.AllEvents, 50)
            time.sleep(.01)
        assert controller.lab["status"] == "Contained", errors
        assert window.resume_button.isEnabled()
        assert not window.suspicious_button.isEnabled()

        QTest.mouseClick(window.nav_buttons[1], Qt.MouseButton.LeftButton)
        window.risk_filter.setCurrentText("High")
        window.refresh_tables()
        assert window.events_table.rowCount() > 0
        row = window.events_table.item(0, 0).data(Qt.ItemDataRole.UserRole)
        assert len(row["assessment"]["signals"]) == 5
        assert row["assessment"]["eligible_for_containment"]
        window.search.setText("file-that-is-not-in-the-evidence")
        window.refresh_tables()
        assert window.events_table.rowCount() == 0

        target = tmp_path / "export.json"
        monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *a, **k: (str(target), "JSON evidence (*.json)"))
        window.export_evidence()
        exported = json.loads(target.read_text(encoding="utf-8"))
        assert len(exported["events"]) == controller.session_events
        assert any(action["action"] == "worker_suspended" for action in exported["actions"])

        QTest.mouseClick(window.nav_buttons[3], Qt.MouseButton.LeftButton)
        window.threshold.setValue(90)
        window.auto_contain.setChecked(False)
        window.save_policy()
        assert controller.engine.containment_threshold == 90
        assert json.loads((controller.data_dir / "settings.json").read_text())["auto_contain"] is False
        assert errors == []
    finally:
        window.close()
        app.processEvents()
    assert not controller.lab_active
