"""Launch the desktop UI or the isolated, managed simulation worker."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys


def default_data_dir() -> Path:
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return base / "CipherSentry"


def main() -> int:
    # PyInstaller's executable doubles as the child worker; dispatch before Qt.
    if "--lab-worker" in sys.argv:
        sys.argv.remove("--lab-worker")
        from .lab_worker import main as worker_main
        return worker_main() or 0
    parser = argparse.ArgumentParser(description="CipherSentry native desktop prototype")
    parser.add_argument("--data-dir", type=Path, default=default_data_dir())
    parser.add_argument("--screenshot", type=Path, help="Save the window after startup and exit")
    parser.add_argument("--demo", choices=["suspicious", "benign"], help="Start a controlled lab run")
    args = parser.parse_args()

    from PySide6.QtCore import QTimer, Qt
    from PySide6.QtGui import QFont
    from PySide6.QtWidgets import QApplication
    from .controller import Controller
    from .ui.theme import STYLESHEET
    from .ui.window import MainWindow

    app = QApplication(sys.argv[:1])
    app.setApplicationName("CipherSentry")
    app.setOrganizationName("CipherSentry FYP")
    app.setFont(QFont("Segoe UI" if sys.platform == "win32" else "DejaVu Sans", 10))
    app.setStyle("Fusion")
    app.setStyleSheet(STYLESHEET)
    controller = Controller(args.data_dir)
    window = MainWindow(controller)
    window.show()
    app.aboutToQuit.connect(controller.close)
    if args.demo:
        QTimer.singleShot(250, lambda: controller.start_lab(args.demo))
    if args.screenshot:
        def capture() -> None:
            args.screenshot.parent.mkdir(parents=True, exist_ok=True)
            if not window.grab().save(str(args.screenshot)):
                print("Unable to save screenshot", file=sys.stderr)
                app.exit(1)
                return
            app.quit()
        QTimer.singleShot(4500 if args.demo else 600, capture)
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
