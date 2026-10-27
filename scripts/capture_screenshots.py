"""Capture real Qt screens with fresh disposable demo state.

Run from the repository: python -m scripts.capture_screenshots
"""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QEventLoop
from PySide6.QtWidgets import QApplication

from ciphersentry.controller import Controller
from ciphersentry.ui.theme import STYLESHEET
from ciphersentry.ui.window import MainWindow


def main() -> int:
    app = QApplication.instance() or QApplication([])
    app.setStyle("Fusion")
    app.setStyleSheet(STYLESHEET)
    target = Path(__file__).resolve().parent.parent / "docs" / "screenshots"
    target.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="ciphersentry-capture-") as directory:
        controller = Controller(Path(directory) / "data")
        window = MainWindow(controller)
        window.resize(1480, 1160)
        window.show()
        try:
            controller.start_lab("suspicious")
            deadline = time.monotonic() + 6
            while controller.lab["status"] != "Contained" and time.monotonic() < deadline:
                app.processEvents(QEventLoop.ProcessEventsFlag.AllEvents, 50)
                time.sleep(.01)
            if controller.lab["status"] != "Contained":
                raise RuntimeError(f"Demo did not reach containment: {controller.lab}")
            controller._tick()
            window.refresh_tables()
            for index, name in [(0, "overview"), (1, "events"), (2, "lab"), (3, "settings")]:
                window.navigate(index)
                app.processEvents()
                if not window.grab().save(str(target / f"{name}.png")):
                    raise RuntimeError(f"Capture failed: {name}")
            print(f"Captured four real Qt screens in {target}")
        finally:
            window.close()
            app.processEvents()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
