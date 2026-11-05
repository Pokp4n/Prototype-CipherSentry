"""Measure Event Explorer work using isolated synthetic evidence, not user data.

Run from the checkout with ``python -m scripts.profile_event_explorer --output
docs/validation/event-explorer-before.json``. Qt uses its offscreen platform by
default; measurements describe handler/layout cost, not perceived screen motion.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime
from importlib.metadata import version
import json
import hashlib
import os
from pathlib import Path
import platform
import statistics
import sys
import tempfile
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QEventLoop, Qt, QTimer
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import QApplication, QHeaderView, QScrollArea, QStyledItemDelegate, QTableWidgetItem

from ciphersentry.controller import Controller
from ciphersentry.engine import FileEvent, RiskEngine
from ciphersentry.ui.theme import STYLESHEET
from ciphersentry.ui.window import MainWindow


def timing_summary(samples):
    return {"calls": len(samples), "total_ms": round(sum(samples), 3),
            "median_ms": round(statistics.median(samples), 3) if samples else None,
            "maximum_ms": round(max(samples), 3) if samples else None}


class CountingDelegate(QStyledItemDelegate):
    def __init__(self, parent):
        super().__init__(parent)
        self.size_hint_calls = 0

    def sizeHint(self, option, index):
        self.size_hint_calls += 1
        return super().sizeHint(option, index)


class ProfiledWindow(MainWindow):
    def __init__(self, controller):
        self.timings = defaultdict(list)
        self.populated_rows = Counter()
        super().__init__(controller)

    def refresh_tables(self):
        started = time.perf_counter()
        try:
            return super().refresh_tables()
        finally:
            self.timings["refresh_tables"].append((time.perf_counter() - started) * 1000)

    def _populate_table(self, table, records):
        name = "explorer" if table is getattr(self, "events_table", None) else "overview"
        started = time.perf_counter()
        try:
            return super()._populate_table(table, records)
        finally:
            self.timings[f"populate_{name}"].append((time.perf_counter() - started) * 1000)
            self.populated_rows[name] += len(records)


def seed(controller, count, root):
    """Full RiskEngine assessments, stored directly without controller actions."""
    engine = RiskEngine()
    now = time.time()
    response = {"action": "alert_only", "allowed": False,
                "reason": "Synthetic UI measurement; no process action is authorized.",
                "checks": {}, "outcome": "not_attempted"}
    levels = set()
    for index in range(count):
        event = FileEvent(
            timestamp=now - (count - index) * .01,
            path=str(root / "synthetic-fixtures" / f"department-{index % 4 + 1}"
                     / f"sample-{index:04d}.locked-demo"),
            operation="moved", pid=43210, process_name="Synthetic profiling lab worker",
            entropy_before=4.1, entropy_after=7.9, source="lab", attribution="cooperative_lab",
            process_context={"pid": 43210, "create_time": now - 60, "parent_pid": 43209,
                             "executable": sys.executable, "name": "python.exe",
                             "identity_verified": True, "signature_status": "not_checked",
                             "note": "Synthetic metadata for UI profiling only; no such process is controlled."},
        )
        assessment = engine.ingest(event)
        controller.store.record_event(event, assessment, response=response)
        if assessment.level in {"High", "Uncertain"} and assessment.level not in levels:
            controller.store.record_alert(assessment, response)
            levels.add(assessment.level)
    for action in ("lab_started", "response_decision", "response_decision", "policy_updated"):
        controller.store.record_action(action, "Synthetic UI profiling audit entry. " * 5)
    controller.store.record_action("lab_finished", json.dumps(dict(scenario="suspicious", status="Completed", completed=count)))
    controller.total_events = count


def snapshot_geometry(window):
    page = window.stack.currentWidget()
    outer = page if isinstance(page, QScrollArea) else None
    table = window.events_table
    return {
        "window": [window.width(), window.height()],
        "table": [table.width(), table.height()],
        "table_vertical_scroll_range": [table.verticalScrollBar().minimum(), table.verticalScrollBar().maximum()],
        "table_horizontal_scroll_range": [table.horizontalScrollBar().minimum(), table.horizontalScrollBar().maximum()],
        "outer_vertical_scroll_range": ([outer.verticalScrollBar().minimum(), outer.verticalScrollBar().maximum()] if outer else None),
        "outer_scrollbar_visible": outer.verticalScrollBar().isVisible() if outer else False,
        "column_widths": [table.columnWidth(index) for index in range(table.columnCount())],
        "column_resize_modes": [table.horizontalHeader().sectionResizeMode(index).name for index in range(table.columnCount())],
    }


def first_column_only_populate(table, records):
    """Experimental equivalent of the original cell builder, record stored once."""
    table.setUpdatesEnabled(False)
    try:
        table.setRowCount(len(records))
        for index, record in enumerate(records):
            when = datetime.fromtimestamp(record["timestamp"]).strftime("%H:%M:%S")
            process = "Lab worker" if record["source"] == "lab" else "Unattributed activity"
            values = [when, process, Path(record["path"]).name, record["operation"].capitalize(),
                      f"{record['score']}  {record['level']}"]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(record["path"] if column == 2 else str(value))
                if column == 0:
                    item.setData(Qt.ItemDataRole.UserRole, record)
                if column == 4:
                    item.setForeground(QColor({"High": "#ff9398", "Uncertain": "#f0c978", "Elevated": "#f0c978", "Low": "#69e3bc"}.get(record["level"], "#8fa3b8")))
                table.setItem(index, column, item)
    finally:
        table.setUpdatesEnabled(True)


def measure_case(app, count, dimensions, root, idle_seconds, cycles, variants):
    print(f"Preparing {count} events at {dimensions[0]}x{dimensions[1]} ({cycles} timed repetitions)", flush=True)
    controller = Controller(root / f"events-{count}-{dimensions[0]}x{dimensions[1]}")
    seed(controller, count, root)
    window = ProfiledWindow(controller)
    window.resize(*dimensions)
    window.show()
    window.navigate(1)
    app.processEvents()
    delegate = CountingDelegate(window.events_table)
    window.events_table.setItemDelegate(delegate)
    app.processEvents()
    sql = Counter()
    query_samples = []
    real_recent = controller.store.recent_events

    def measured_recent(*args, **kwargs):
        started = time.perf_counter()
        try:
            return real_recent(*args, **kwargs)
        finally:
            query_samples.append((time.perf_counter() - started) * 1000)

    controller.store.recent_events = measured_recent

    def traced(statement):
        normalized = " ".join(statement.upper().split())
        if normalized.startswith("SELECT"):
            sql["all_selects"] += 1
            if "FROM EVENTS" in normalized:
                sql["event_selects"] += 1
            if normalized.startswith("SELECT * FROM EVENTS"):
                sql["event_record_selects"] += 1

    controller.store._connection.set_trace_callback(traced)

    def reset():
        sql.clear()
        query_samples.clear()
        window.timings.clear()
        window.populated_rows.clear()
        delegate.size_hint_calls = 0

    def collect():
        return dict(sql=dict(sql), recent_events=timing_summary(query_samples),
                    handler_timings={key: timing_summary(value) for key, value in window.timings.items()},
                    populated_rows=dict(window.populated_rows), size_hint_calls=delegate.size_hint_calls)

    try:
        print(f"Measuring idle: {count} events at {dimensions}", flush=True)
        reset()
        timer_gaps = []
        heartbeat = QTimer(window)
        previous = [time.perf_counter()]

        def beat():
            current = time.perf_counter()
            timer_gaps.append((current - previous[0]) * 1000)
            previous[0] = current

        heartbeat.timeout.connect(beat)
        heartbeat.start(16)
        started = time.perf_counter()
        pump_samples = []
        while time.perf_counter() - started < idle_seconds:
            pump_start = time.perf_counter()
            app.processEvents(QEventLoop.ProcessEventsFlag.AllEvents, 50)
            pump_samples.append((time.perf_counter() - pump_start) * 1000)
            time.sleep(.004)
        heartbeat.stop()
        idle = collect()
        idle.update(duration_seconds=round(time.perf_counter() - started, 3),
                    event_pump=timing_summary(pump_samples), heartbeat_16ms=timing_summary(timer_gaps))
        controller.timer.stop()
        window.refresh_timer.stop()
        print(f"Measuring unchanged refresh: {count} events at {dimensions}", flush=True)
        reset()
        forced_samples = []
        flush_samples = []
        for _ in range(cycles):
            started = time.perf_counter()
            window.refresh()
            window.refresh_tables()
            flushed = time.perf_counter()
            app.processEvents()
            flush_samples.append((time.perf_counter() - flushed) * 1000)
            forced_samples.append((time.perf_counter() - started) * 1000)
        forced = collect()
        forced.update(total_cycle=timing_summary(forced_samples), layout_event_flush=timing_summary(flush_samples))
        geometry = snapshot_geometry(window)
        query_only = []
        for _ in range(cycles):
            started = time.perf_counter()
            records = real_recent(500)
            query_only.append((time.perf_counter() - started) * 1000)
        isolated = {}
        builders = [("production_builder", MainWindow._populate_table)]
        if variants:
            builders.append(("experimental_record_once", first_column_only_populate))
            builders.append(("experimental_record_once_fixed_columns", first_column_only_populate))
        for name, builder in builders:
            print(f"Measuring {name}: {count} events at {dimensions}", flush=True)
            if name.endswith("fixed_columns"):
                header = window.events_table.horizontalHeader()
                header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
                for column, width in [(0, 85), (1, 180), (3, 115), (4, 110)]:
                    window.events_table.setColumnWidth(column, width)
                header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
                app.processEvents()
            delegate.size_hint_calls = 0
            build_samples, layout_samples = [], []
            for _ in range(cycles):
                started = time.perf_counter()
                builder(window.events_table, records)
                built = time.perf_counter()
                app.processEvents()
                build_samples.append((built - started) * 1000)
                layout_samples.append((time.perf_counter() - built) * 1000)
            isolated[name] = dict(populate=timing_summary(build_samples), layout_event_flush=timing_summary(layout_samples),
                                  size_hint_calls=delegate.size_hint_calls)
        return dict(events=count, dimensions=list(dimensions), idle=idle, unchanged_refresh_cycles=forced,
                    query_only=timing_summary(query_only), isolated_populate=isolated,
                    geometry=geometry, evidence_rows_after=controller.store.counts()["events"])
    finally:
        controller.store._connection.set_trace_callback(None)
        window.close()
        app.processEvents()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--idle-seconds", type=float, default=3.5)
    parser.add_argument("--cycles", type=int, default=10)
    parser.add_argument("--large-cycles", type=int, default=1,
                        help="Repetitions at 500 rows; old auto-sizing is quadratic and very slow")
    parser.add_argument("--variants", action="store_true", help="Also measure isolated in-memory candidate builders")
    args = parser.parse_args(argv)
    app = QApplication.instance() or QApplication([])
    app.setFont(QFont("Segoe UI" if sys.platform == "win32" else "DejaVu Sans", 10))
    app.setStyle("Fusion")
    app.setStyleSheet(STYLESHEET)
    base = Path(".ciphersentry").resolve()
    base.mkdir(exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix="event-explorer-profile-", dir=base))
    report = dict(purpose="Synthetic Event Explorer timing; no real endpoint evidence or process control",
                  window_source_sha256=hashlib.sha256(Path("ciphersentry/ui/window.py").read_bytes()).hexdigest(),
                  platform=platform.platform(), python=platform.python_version(),
                  dependencies={name: version(name) for name in ("PySide6", "psutil", "pytest")},
                  qt_platform=app.platformName(), style=app.style().objectName(),
                  recorded_at=datetime.now().astimezone().isoformat(), workspace=str(root),
                  settings=dict(idle_seconds=args.idle_seconds, cycles=args.cycles, large_cycles=args.large_cycles, experimental_variants=args.variants),
                  limitations=["Offscreen measurements do not establish perceived scroll smoothness or compositor frame rate.",
                               "Timing varies with host load; compare identical row counts, geometry and style.",
                               "The profiling delegate adds identical sizeHint-counting overhead to each run.",
                               "Isolated builders intentionally bypass production dirty checks."], cases=[])
    print(f"Loaded MainWindow source SHA256: {report['window_source_sha256']}", flush=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    for count in (60, 500):
        for dimensions in ((1480, 980), (1140, 760)):
            cycles = args.large_cycles if count >= 500 else args.cycles
            case = measure_case(app, count, dimensions, root, args.idle_seconds, cycles, args.variants)
            report["cases"].append(case)
            args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
            print(json.dumps(dict(events=count, dimensions=dimensions,
                                  idle_event_record_selects=case["idle"]["sql"].get("event_record_selects", 0),
                                  forced_refresh_median_ms=case["unchanged_refresh_cycles"]["total_cycle"]["median_ms"],
                                  isolated=case["isolated_populate"])), flush=True)
    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Profile saved: {args.output}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
