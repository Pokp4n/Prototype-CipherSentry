"""CipherSentry's native desktop dashboard and experiment controls."""
from __future__ import annotations

from datetime import datetime
import json
from pathlib import Path
import platform
import time

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor, QCloseEvent
from PySide6.QtWidgets import (
    QAbstractItemView, QCheckBox, QComboBox, QDialog, QDoubleSpinBox, QFileDialog, QFrame,
    QGridLayout, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMainWindow,
    QProgressBar, QPushButton, QScrollArea, QSpinBox,
    QStackedWidget, QTableWidget, QTableWidgetItem, QTextEdit, QVBoxLayout, QWidget,
)

from ..controller import Controller
from .widgets import Icon, RiskChart, RiskGauge, ShieldMark, SignalMeter, StatCard


def label(text: str, name: str = "", wrap: bool = False) -> QLabel:
    result = QLabel(text)
    result.setTextFormat(Qt.TextFormat.PlainText)
    if name:
        result.setObjectName(name)
    result.setWordWrap(wrap)
    return result


def button(text: str, slot=None, variant: str = "secondary") -> QPushButton:
    result = QPushButton(text)
    result.setProperty("variant", variant)
    result.setCursor(Qt.CursorShape.PointingHandCursor)
    result.setMinimumHeight(38)
    if slot:
        result.clicked.connect(slot)
    return result


def panel() -> tuple[QFrame, QVBoxLayout]:
    frame = QFrame()
    frame.setProperty("card", True)
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(22, 20, 22, 20)
    layout.setSpacing(12)
    return frame, layout


def row(*widgets: QWidget, stretch: bool = False) -> QHBoxLayout:
    result = QHBoxLayout()
    result.setSpacing(12)
    for widget in widgets:
        result.addWidget(widget)
    if stretch:
        result.addStretch()
    return result


class MainWindow(QMainWindow):
    TITLES = [("Endpoint overview", "Understand the signals. Act on the evidence."),
              ("Event explorer", "A traceable record of observed activity and decisions."),
              ("Simulation lab", "Observe, explain, and contain a controlled workload."),
              ("Settings", "Configure experimental rules and a separate response policy."),
              ("Security alerts", "Review evidence, missing information, and response decisions.")]
    INDICATORS = [("frequency", "File modification frequency", 30),
                  ("entropy", "Entropy change", 35),
                  ("operations", "Repeated operations", 25),
                  ("spread", "Directory spread", 10),
                  ("context", "Process context", 0)]

    def __init__(self, controller: Controller):
        super().__init__()
        self.controller = controller
        self.setWindowTitle("CipherSentry — Behavioural Security")
        self.resize(1480, 980)
        self.setMinimumSize(1140, 760)
        self._events_dirty = True
        self._last_chart_sample = 0.0
        self._last_chart_score = None
        self._build()
        controller.changed.connect(self.refresh)
        controller.event_received.connect(self.on_event)
        controller.assessment_changed.connect(self.on_assessment)
        controller.lab_changed.connect(self.refresh_lab)
        controller.message.connect(self.show_message)
        controller.error.connect(lambda text: self.show_message(text, error=True))
        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self.refresh_tables)
        self.refresh_timer.start(300)
        self.refresh()
        self.refresh_lab()
        self.refresh_tables()
        self.on_assessment(None)

    def _build(self) -> None:
        root = QWidget()
        self.setCentralWidget(root)
        outer = QHBoxLayout(root)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(230)
        side = QVBoxLayout(sidebar)
        side.setContentsMargins(20, 27, 20, 22)
        side.setSpacing(10)
        logo = row(ShieldMark(40), label("CipherSentry", "brand"))
        side.addLayout(logo)
        side.addWidget(label("BEHAVIOURAL SECURITY", "eyebrow"))
        side.addSpacing(36)
        side.addWidget(label("WORKSPACE", "eyebrow"))
        self.nav_buttons = []
        for index, (name, icon_name) in enumerate([
            ("Overview", "grid"), ("Event explorer", "activity"),
            ("Simulation lab", "flask"), ("Settings", "settings"),
            ("Security alerts", "shield"),
        ]):
            nav = button(f"    {name}", lambda checked=False, i=index: self.navigate(i), "nav")
            nav.setCheckable(True)
            nav.setMinimumHeight(48)
            nav.setStyleSheet("text-align: left; padding-left: 40px;")
            icon_widget = Icon(icon_name, 20, parent=nav)
            icon_widget.move(15, 14)
            side.addWidget(nav)
            self.nav_buttons.append(nav)
        side.addStretch()
        side.addWidget(label("RESEARCH ENVIRONMENT", "eyebrow"))
        endpoint, endpoint_layout = panel()
        endpoint_layout.setContentsMargins(14, 14, 14, 14)
        endpoint_layout.addWidget(label("●  Local endpoint", "bodyStrong"))
        endpoint_layout.addWidget(label(f"{platform.system()} · Python / Qt", "muted"))
        endpoint_layout.addWidget(label("User-mode prototype", "muted"))
        side.addWidget(endpoint)
        side.addSpacing(12)
        side.addWidget(label("FYP  /  v0.1.0", "eyebrow"))
        side.addWidget(label("Explainable by design.", "muted"))
        outer.addWidget(sidebar)

        main = QWidget()
        main_layout = QVBoxLayout(main)
        main_layout.setContentsMargins(30, 25, 30, 18)
        main_layout.setSpacing(16)
        breadcrumb = row(label("WORKSPACE   /   ENDPOINT SECURITY", "eyebrow"))
        breadcrumb.addStretch()
        self.status_badge = label("●  Monitor idle", "statusBadge")
        breadcrumb.addWidget(self.status_badge)
        main_layout.addLayout(breadcrumb)
        heading = QHBoxLayout()
        heading_text = QVBoxLayout()
        heading_text.setSpacing(5)
        self.page_title = label(self.TITLES[0][0], "title")
        self.page_subtitle = label(self.TITLES[0][1], "subtitle")
        heading_text.addWidget(self.page_title)
        heading_text.addWidget(self.page_subtitle)
        heading.addLayout(heading_text)
        heading.addStretch()
        heading.addWidget(button("Export evidence", self.export_evidence))
        main_layout.addLayout(heading)
        self.toast = label("", "toast", wrap=True)
        self.toast.hide()
        main_layout.addWidget(self.toast)

        self.stack = QStackedWidget()
        for build in [self._overview, self._events_page, self._lab_page, self._settings_page, self._alerts_page]:
            content = build()
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setFrameShape(QFrame.Shape.NoFrame)
            scroll.setWidget(content)
            self.stack.addWidget(scroll)
        main_layout.addWidget(self.stack, 1)
        footer = row(label("CIPHERSENTRY", "eyebrow"))
        footer.addWidget(label("/   Local evidence. Transparent decisions.", "muted"))
        footer.addStretch()
        self.resource_label = label("", "muted")
        footer.addWidget(self.resource_label)
        main_layout.addLayout(footer)
        outer.addWidget(main, 1)
        self.nav_buttons[0].setChecked(True)

    def _overview(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(18)

        hero, hero_layout = panel()
        hero.setObjectName("heroPanel")
        hero_top = QHBoxLayout()
        hero_top.setSpacing(20)
        hero_top.addWidget(ShieldMark(58))
        copy = QVBoxLayout()
        copy.setSpacing(5)
        copy.addWidget(label("Visibility starts with a folder.", "heroTitle"))
        copy.addWidget(label("Monitor file behaviour, review the evidence, and test your response.", "subtitle", True))
        self.folder_label = label("No folder selected", "muted")
        self.folder_label.setMaximumWidth(610)
        self.folder_label.setWordWrap(True)
        copy.addWidget(self.folder_label)
        hero_top.addLayout(copy, 1)
        controls = QVBoxLayout()
        self.choose_button = button("Choose folder", self.choose_folder)
        self.monitor_button = button("Start monitoring", self.toggle_monitor, "primary")
        self.choose_button.setFixedWidth(185)
        self.monitor_button.setFixedWidth(185)
        controls.addWidget(self.choose_button)
        controls.addWidget(self.monitor_button)
        hero_top.addLayout(controls)
        hero_layout.addLayout(hero_top)
        self.collector_health_label = label("Folder collector: path notifications only · writer PID unavailable", "muted", True)
        hero_layout.addWidget(self.collector_health_label)
        layout.addWidget(hero)

        stats = QHBoxLayout()
        stats.setSpacing(14)
        self.risk_card = StatCard("CURRENT RISK", "—", "Waiting for behavioural evidence", "shield")
        self.files_card = StatCard("FILES OBSERVED", "0", "Distinct event paths this session", "file")
        self.events_card = StatCard("EVIDENCE RECORDS", "0", "Persisted locally in SQLite", "activity")
        self.response_card = StatCard("RESPONSE MODE", "Alert-only", "Separate safety decision required", "pause")
        for card in [self.risk_card, self.files_card, self.events_card, self.response_card]:
            stats.addWidget(card, 1)
        layout.addLayout(stats)
        self.alert_summary = label("0 suspicious event assessments · 0 open alerts", "bodyStrong")
        summary = row(self.alert_summary)
        summary.addStretch()
        summary.addWidget(button("Review security alerts  →", lambda: self.navigate(4), "ghost"))
        layout.addLayout(summary)

        analysis = QHBoxLayout()
        analysis.setSpacing(18)
        trend, trend_layout = panel()
        trend_title = row(label("Behavioural risk", "sectionTitle"))
        trend_title.addStretch()
        self.window_badge = label("ROLLING 10s WINDOW", "eyebrow")
        trend_title.addWidget(self.window_badge)
        trend_layout.addLayout(trend_title)
        trend_layout.addWidget(label("Combined evidence over the last 60 seconds", "muted"))
        self.chart = RiskChart()
        self.chart.setMinimumHeight(200)
        trend_layout.addWidget(self.chart, 1)
        self.trend_note = label("Start monitoring or run a lab scenario to collect evidence.", "muted", True)
        trend_layout.addWidget(self.trend_note)
        analysis.addWidget(trend, 6)

        evidence, evidence_layout = panel()
        evidence_layout.addWidget(label("Why this score?", "sectionTitle"))
        self.assessment_source = label("No active assessment", "muted", True)
        evidence_layout.addWidget(self.assessment_source)
        self.signal_meters = {}
        for key, name, maximum in self.INDICATORS:
            meter = SignalMeter(name)
            meter.set_signal(0, maximum, "Waiting for observed events")
            self.signal_meters[name] = (meter, maximum)
            evidence_layout.addWidget(meter)
        evidence_layout.addWidget(label("Experimental weights · hover for measured evidence", "muted"))
        analysis.addWidget(evidence, 5)
        layout.addLayout(analysis)

        context, context_layout = panel()
        context_layout.addWidget(label("Process attribution and evidence coverage", "sectionTitle"))
        self.process_context_label = label("No attributed process. Folder monitoring cannot identify the writer.", "muted", True)
        self.process_context_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        context_layout.addWidget(self.process_context_label)
        self.missing_evidence_label = label("Missing evidence will be shown with each assessment.", "muted", True)
        context_layout.addWidget(self.missing_evidence_label)
        self.response_reason_label = label("Alert-only mode: high risk does not authorize process suspension.", "bodyStrong", True)
        context_layout.addWidget(self.response_reason_label)
        layout.addWidget(context)

        activity, activity_layout = panel()
        activity_head = row(label("Recent activity", "sectionTitle"))
        activity_head.addStretch()
        activity_head.addWidget(button("View all events  →", lambda: self.navigate(1), "ghost"))
        activity_layout.addLayout(activity_head)
        self.overview_table = self._event_table(compact=True)
        activity_layout.addWidget(self.overview_table)
        self.empty_activity = label("Your event timeline will appear here. Try a controlled scenario in the Simulation lab.", "muted", True)
        activity_layout.addWidget(self.empty_activity)
        layout.addWidget(activity)

        lab_banner = QHBoxLayout()
        lab_banner.addWidget(Icon("flask", 22, "#69e3bc"))
        lab_banner.addWidget(label("See the decision in action", "bodyStrong"))
        lab_banner.addWidget(label("Disposable files. Alert-only by default.", "muted"))
        lab_banner.addStretch()
        lab_banner.addWidget(button("Open simulation lab  →", lambda: self.navigate(2), "ghost"))
        layout.addLayout(lab_banner)
        layout.addStretch()
        return page

    def _event_table(self, compact=False) -> QTableWidget:
        table = QTableWidget(0, 5)
        table.setHorizontalHeaderLabels(["TIME", "PROCESS / SOURCE", "FILE", "OPERATION", "RISK"])
        table.verticalHeader().setVisible(False)
        table.setShowGrid(False)
        table.setAlternatingRowColors(False)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        table.verticalHeader().setDefaultSectionSize(38)
        table.setMinimumHeight(175 if compact else 390)
        if compact:
            table.setMaximumHeight(190)
        table.cellDoubleClicked.connect(lambda r, c, t=table: self.show_event_details(t, r))
        return table

    def _events_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(18)
        filters = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search file paths, processes, or operations…")
        self.search.setMinimumHeight(40)
        self.search.textChanged.connect(self.mark_tables_dirty)
        self.risk_filter = QComboBox()
        self.risk_filter.addItems(["All risk levels", "High", "Uncertain", "Low", "Elevated (legacy)"])
        self.risk_filter.currentTextChanged.connect(self.mark_tables_dirty)
        filters.addWidget(self.search, 1)
        filters.addWidget(self.risk_filter)
        filters.addWidget(button("Export JSON / CSV", self.export_evidence))
        layout.addLayout(filters)
        card, inner = panel()
        self.event_count_label = label("Observed events", "sectionTitle")
        inner.addWidget(self.event_count_label)
        inner.addWidget(label("Latest 500 records · double-click a row to inspect its evidence and explanation", "muted", True))
        self.events_table = self._event_table()
        inner.addWidget(self.events_table, 1)
        layout.addWidget(card, 1)
        actions, actions_layout = panel()
        actions_layout.addWidget(label("Response audit", "sectionTitle"))
        self.actions_label = label("No response actions recorded.", "muted", True)
        self.actions_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        actions_layout.addWidget(self.actions_label)
        layout.addWidget(actions)
        return page

    def _lab_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(18)
        introduction, intro = panel()
        intro.addLayout(row(Icon("flask", 26, "#69e3bc"), label("A safe place to test your hypothesis.", "heroTitle")))
        intro.addWidget(label("Each run creates 60 disposable fixtures in a new lab folder. Compare a high-entropy modification burst with ordinary bulk edits or legitimate ZIP creation, then inspect the evidence behind each decision.", "subtitle", True))
        intro.addWidget(label("Only CipherSentry's verified child worker can be paused. Existing user files are never used as simulation targets.", "muted", True))
        self.lab_mode_label = label("Alert-only mode · simulations run without automatic process actions.", "bodyStrong", True)
        intro.addWidget(self.lab_mode_label)
        layout.addWidget(introduction)
        scenarios = QHBoxLayout()
        scenarios.setSpacing(18)
        suspicious, suspicious_layout = panel()
        suspicious_layout.addWidget(label("01  /  SUSPICIOUS WORKLOAD", "eyebrow"))
        suspicious_layout.addWidget(label("Rapid modification burst", "sectionTitle"))
        suspicious_layout.addWidget(label("Generated files are rewritten with deterministic high-entropy bytes and renamed across four directories. This exercises multiple signals without malware or encryption.", "muted", True))
        self.suspicious_button = button("Run suspicious scenario  →", lambda: self.controller.start_lab("suspicious"), "primary")
        suspicious_layout.addWidget(self.suspicious_button)
        scenarios.addWidget(suspicious, 1)
        benign, benign_layout = panel()
        benign_layout.addWidget(label("02  /  BENIGN WORKLOAD", "eyebrow"))
        benign_layout.addWidget(label("Ordinary bulk text edits", "sectionTitle"))
        benign_layout.addWidget(label("Generated text files are updated rapidly across the same directories. High I/O alone should remain below the default containment threshold.", "muted", True))
        self.benign_button = button("Run benign scenario  →", lambda: self.controller.start_lab("benign"))
        benign_layout.addWidget(self.benign_button)
        scenarios.addWidget(benign, 1)
        layout.addLayout(scenarios)
        self.compression_button = button("Run benign ZIP creation", lambda: self.controller.start_lab("compression"))
        zip_controls = row(self.compression_button,
                           label("Creates real ZIP archives and retains the original generated text files.", "muted", True))
        zip_controls.addStretch()
        layout.addLayout(zip_controls)

        run, run_layout = panel()
        run_heading = row(label("Current experiment", "sectionTitle"))
        run_heading.addStretch()
        self.lab_status = label("IDLE", "statusBadge")
        run_heading.addWidget(self.lab_status)
        run_layout.addLayout(run_heading)
        run_body = QHBoxLayout()
        self.lab_gauge = RiskGauge()
        self.lab_gauge.setFixedSize(150, 150)
        run_body.addWidget(self.lab_gauge)
        progress_group = QVBoxLayout()
        self.lab_description = label("Choose a scenario to begin", "bodyStrong")
        progress_group.addWidget(self.lab_description)
        self.lab_progress = QProgressBar()
        self.lab_progress.setRange(0, 60)
        self.lab_progress.setValue(0)
        self.lab_progress.setTextVisible(False)
        self.lab_progress.setFixedHeight(5)
        progress_group.addWidget(self.lab_progress)
        self.lab_progress_label = label("0 / 60 generated files changed", "muted")
        progress_group.addWidget(self.lab_progress_label)
        self.lab_path_label = label("A new disposable workspace is created for every run.", "muted", True)
        self.lab_path_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        progress_group.addWidget(self.lab_path_label)
        run_body.addLayout(progress_group, 1)
        run_layout.addLayout(run_body)
        controls = QHBoxLayout()
        self.pause_button = button("Pause worker", lambda: self.controller.pause_lab())
        self.resume_button = button("Release worker", self.controller.resume_lab, "primary")
        self.stop_button = button("Stop experiment", self.controller.stop_lab, "danger")
        controls.addWidget(self.pause_button)
        controls.addWidget(self.resume_button)
        controls.addWidget(self.stop_button)
        controls.addStretch()
        run_layout.addLayout(controls)
        self.release_note = label("Manual pause is limited to this verified worker. Simulation mode is an explicit opt-in in Settings. Release bypasses automatic pause for the rest of the run.", "muted", True)
        run_layout.addWidget(self.release_note)
        layout.addWidget(run)

        metrics = QHBoxLayout()
        metrics.setSpacing(14)
        self.latency_card = StatCard("DETECTION LATENCY", "—", "First event → first high-risk result", "activity")
        self.impact_card = StatCard("CHANGES AT PAUSE", "—", "Completed fixture changes observed", "file")
        self.peak_card = StatCard("PEAK RISK", "—", "Highest score during this experiment", "shield")
        metrics.addWidget(self.latency_card, 1)
        metrics.addWidget(self.impact_card, 1)
        metrics.addWidget(self.peak_card, 1)
        layout.addLayout(metrics)
        layout.addWidget(label("These are functional demo measurements. Detection accuracy, false-positive rates, independent file impact, and Windows performance require the evaluation protocol in docs/EVALUATION_PLAN.md.", "muted", True))
        layout.addStretch()
        return page

    def _settings_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(18)
        policy, policy_layout = panel()
        policy_layout.addWidget(label("Experimental risk rules", "sectionTitle"))
        policy_layout.addWidget(label("All weights, thresholds, and time windows are development placeholders. They have not been scientifically validated. Low means the current rules found limited risk evidence; it does not certify that an application is safe.", "muted", True))
        config = self.controller.settings.get("risk_config", {})
        form = QGridLayout()
        form.setHorizontalSpacing(25)
        form.setVerticalSpacing(12)
        self.window_seconds = QDoubleSpinBox()
        self.window_seconds.setRange(.1, 300)
        self.window_seconds.setDecimals(1)
        self.window_seconds.setValue(config.get("window_seconds", 10))
        self.window_seconds.setSuffix(" seconds")
        self.uncertain_threshold = QSpinBox()
        self.uncertain_threshold.setRange(1, 99)
        self.uncertain_threshold.setValue(config.get("uncertain_threshold", 40))
        self.threshold = QSpinBox()
        self.threshold.setRange(2, 100)
        self.threshold.setValue(self.controller.settings["threshold"])
        self.threshold.setSuffix(" / 100")
        self.threshold.setMinimumWidth(130)
        for index, (text, control) in enumerate([
                ("Sliding evidence window", self.window_seconds),
                ("Uncertain risk begins at", self.uncertain_threshold),
                ("High risk begins at", self.threshold)]):
            form.addWidget(label(text, "bodyStrong"), index, 0)
            form.addWidget(control, index, 1)
        policy_layout.addLayout(form)
        policy_layout.addWidget(label("Indicator weights and ablation", "sectionTitle"))
        policy_layout.addWidget(label("Disable an indicator to compare the same workload without it. Scores are not rescaled when an indicator is disabled. Weights must total at most 100.", "muted", True))
        weights = QGridLayout()
        weights.setHorizontalSpacing(20)
        weights.setVerticalSpacing(10)
        self.weight_controls = {}
        self.indicator_enabled = {}
        enabled = config.get("enabled_indicators", [item[0] for item in self.INDICATORS])
        for index, (key, name, default) in enumerate(self.INDICATORS):
            include = QCheckBox(name)
            include.setChecked(key in enabled)
            weight = QSpinBox()
            weight.setRange(0, 100)
            weight.setValue(config.get("weights", {}).get(key, default))
            weight.setSuffix(" points")
            weights.addWidget(include, index, 0)
            weights.addWidget(weight, index, 1)
            self.weight_controls[key] = weight
            self.indicator_enabled[key] = include
        policy_layout.addLayout(weights)
        policy_layout.addWidget(label("Process context is descriptive in this version: no validated contextual risk rule is implemented, so it adds zero points even if a weight is configured. Unknown names and unchecked signatures are not evidence of malware.", "muted", True))
        policy_layout.addWidget(label("Response safety policy", "sectionTitle"))
        self.auto_contain = QCheckBox("Simulation mode: allow automatic pause of verified lab workers")
        self.auto_contain.setChecked(self.controller.settings.get("response_mode") == "simulation")
        policy_layout.addWidget(self.auto_contain)
        policy_layout.addWidget(label("Unchecked means alert-only. A high score is evaluated separately from action safety. Simulation response requires corroborating signals, cooperative lab attribution, a registered child, and identity revalidation. Arbitrary applications cannot be suspended.", "muted", True))
        self.save_policy_button = button("Save rules and response policy", self.save_policy, "primary")
        policy_layout.addLayout(row(self.save_policy_button, stretch=True))
        layout.addWidget(policy)

        capabilities, cap = panel()
        cap.addWidget(label("Prototype capabilities", "sectionTitle"))
        for title, text in [
            ("File monitoring", "User-mode folder notifications with sampled entropy before and after changes. Baseline is bounded to 5,000 files; each entropy read samples up to 64 KiB."),
            ("Process attribution", "The lab identifies its own worker through cooperative test instrumentation. Folder events remain unattributed. A controlled collector-versus-writer probe measures that gap; Windows ETW attribution is still a feasibility task."),
            ("Containment", "Alert-only is the default. Manual lab controls and opt-in simulation mode can suspend, resume, or stop the verified child. No arbitrary process actions."),
            ("Local evidence", "SQLite events, alerts, response reasons and action history, JSON / CSV export, and per-run lab results. Your data stays on this machine."),
            ("Research scope", "No ransomware decryption, file recovery, family identification, network detection, or production protection guarantees."),
        ]:
            cap.addWidget(label(title, "bodyStrong"))
            cap.addWidget(label(text, "muted", True))
        layout.addWidget(capabilities)
        data, data_layout = panel()
        data_layout.addWidget(label("Evidence location", "sectionTitle"))
        path = label(str(self.controller.data_dir), "muted", True)
        path.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        data_layout.addWidget(path)
        data_layout.addWidget(label("History and lab fixtures persist between launches. Close the app before archiving or removing this directory. Large monitoring runs need a retention policy in a future iteration.", "muted", True))
        layout.addWidget(data)
        layout.addStretch()
        return page

    def _alerts_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(18)
        intro, intro_layout = panel()
        intro_layout.addWidget(label("Review activity before deciding how to respond.", "heroTitle"))
        intro_layout.addWidget(label("High risk means the configured rules found ransomware-like activity. It is not a confirmed malware classification. Acknowledgement records that you reviewed an alert; it does not release a worker or mark a process safe.", "muted", True))
        layout.addWidget(intro)
        card, inner = panel()
        self.alert_count_label = label("Security alerts", "sectionTitle")
        inner.addWidget(self.alert_count_label)
        self.alerts_table = QTableWidget(0, 6)
        self.alerts_table.setHorizontalHeaderLabels(["TIME", "SOURCE / PROCESS", "RISK", "REASON", "RESPONSE", "STATUS"])
        self.alerts_table.verticalHeader().setVisible(False)
        self.alerts_table.setShowGrid(False)
        self.alerts_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.alerts_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.alerts_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.alerts_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.alerts_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.alerts_table.verticalHeader().setDefaultSectionSize(42)
        self.alerts_table.setMinimumHeight(280)
        self.alerts_table.itemSelectionChanged.connect(self.show_selected_alert)
        inner.addWidget(self.alerts_table)
        self.alert_details = QTextEdit()
        self.alert_details.setReadOnly(True)
        self.alert_details.setMinimumHeight(210)
        self.alert_details.setPlaceholderText("Select an alert to inspect evidence and the reason for its response.")
        inner.addWidget(self.alert_details)
        self.acknowledge_button = button("Acknowledge selected alert", self.acknowledge_selected_alert, "primary")
        self.acknowledge_button.setEnabled(False)
        inner.addLayout(row(self.acknowledge_button, stretch=True))
        layout.addWidget(card)
        layout.addStretch()
        return page

    def navigate(self, index: int) -> None:
        self.stack.setCurrentIndex(index)
        self.page_title.setText(self.TITLES[index][0])
        self.page_subtitle.setText(self.TITLES[index][1])
        for i, nav in enumerate(self.nav_buttons):
            nav.setChecked(index == i)
        if index in {1, 4}:
            self._events_dirty = True
            self.refresh_tables()

    def choose_folder(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Select a folder to observe")
        if path:
            try:
                self.controller.choose_folder(path)
            except (OSError, ValueError) as exc:
                self.show_message(str(exc), error=True)

    def toggle_monitor(self) -> None:
        if self.controller.monitoring:
            self.controller.stop_monitor()
        else:
            if self.controller.folder is None:
                self.choose_folder()
            if self.controller.folder is not None:
                self.controller.start_monitor()

    def refresh(self) -> None:
        c = self.controller
        self.status_badge.setText("●  Building baseline" if c.monitor_starting else "●  Monitor active" if c.monitoring else "●  Monitor idle")
        self.monitor_button.setText("Building baseline…" if c.monitor_starting else "Stop monitoring" if c.monitoring else "Start monitoring")
        self.monitor_button.setEnabled(not c.monitor_starting)
        self.choose_button.setEnabled(not c.monitoring and not c.monitor_starting)
        self.folder_label.setText(str(c.folder) if c.folder else "No folder selected")
        self.files_card.set_value(f"{len(c.observed_files):,}")
        self.events_card.set_value(f"{c.total_events:,}")
        state = c.lab["status"]
        mode = "Simulation" if c.settings.get("response_mode") == "simulation" else "Alert-only"
        self.response_card.set_value("Paused" if state == "Contained" else mode,
                                     f"{mode} · managed worker {state.lower()}")
        self.lab_mode_label.setText("Simulation mode · automatic pause may be considered after separate safety checks." if mode == "Simulation" else "Alert-only mode · simulations run without automatic process actions.")
        self.resource_label.setText(f"APP CPU  {c.cpu_percent:.1f}%    ·    MEMORY  {c.memory_mb:.0f} MB")
        self.chart.threshold = c.settings["threshold"]
        self.lab_gauge.high_threshold = c.settings["risk_config"]["high_threshold"]
        self.lab_gauge.uncertain_threshold = c.settings["risk_config"]["uncertain_threshold"]
        self.lab_gauge.update()
        self.window_badge.setText(f"ROLLING {c.engine.window_seconds:g}s WINDOW")
        health = c.monitor_health
        self.collector_health_label.setText(
            f"Folder collector: writer PID unavailable · {health['baseline_count']:,} baseline files · "
            f"{health['dropped_events']:,} application-queue drops reported"
            + (" · coverage incomplete" if health['dropped_events'] else " · zero reported drops does not prove complete coverage"))
        self._events_dirty = True

    def on_event(self, event, assessment) -> None:
        self._events_dirty = True

    def on_assessment(self, assessment) -> None:
        score = assessment.score if assessment else 0
        now = time.time()
        # Suppress zero-only samples until actual evidence has been received.
        if self.controller.session_events and (now - self._last_chart_sample >= .8 or score != self._last_chart_score):
            self.chart.add_point(score, now)
            self._last_chart_sample, self._last_chart_score = now, score
        self.risk_card.set_value(str(score) if assessment else "—", assessment.level + " · current evidence window" if assessment else "No events in the current window")
        signals = {signal.name: signal for signal in assessment.signals} if assessment else {}
        for name, (meter, maximum) in self.signal_meters.items():
            signal = signals.get(name)
            meter.set_signal(signal.points if signal else 0, getattr(signal, "maximum", maximum),
                             signal.explanation if signal else "No active evidence",
                             available=getattr(signal, "available", False) if signal else False,
                             value=getattr(signal, "value", ""))
        if assessment:
            attribution = f"PID {assessment.pid}" if assessment.pid is not None else "Process unknown"
            self.assessment_source.setText(f"{assessment.process_name} · {attribution}")
            self.trend_note.setText(f"{assessment.files_count} distinct paths · {assessment.directories_count} directories · {assessment.event_count} events in this window")
            features = getattr(assessment, "features", {})
            context = features.get("process_context") or {}
            if assessment.pid is not None and assessment.attribution == "cooperative_lab":
                created = context.get("create_time", context.get("start_time"))
                try:
                    started = datetime.fromtimestamp(created).isoformat(sep=" ", timespec="seconds") if created else "Unavailable"
                except (OSError, OverflowError, ValueError, TypeError):
                    started = "Unavailable"
                self.process_context_label.setText(
                    f"Cooperative lab identity · {context.get('name') or assessment.process_name} · PID {assessment.pid}\n"
                    f"Executable: {context.get('executable') or 'Unavailable'}\n"
                    f"Parent PID: {context.get('parent_pid', 'Unavailable')} · Started: {started} · Signature: {context.get('signature_status', 'not_checked')}\n"
                    "This is the owned test worker, not independently validated Windows file-operation attribution.")
            else:
                self.process_context_label.setText("Writer process unavailable. These folder events cannot be assigned to a process or used for automatic process containment.")
            missing = getattr(assessment, "missing_evidence", [])
            self.missing_evidence_label.setText("Missing / uncertain evidence: " + ("; ".join(missing) if missing else "None reported for these measured features; classifier validation is still pending."))
            response = getattr(self.controller, "current_response", {})
            self.response_reason_label.setText("Response decision: " + (getattr(assessment, "response_reason", "") or response.get("reason", "Continue monitoring and review the evidence.")))
        else:
            self.assessment_source.setText("No active assessment")
            self.trend_note.setText(f"Evidence expires after {self.controller.engine.window_seconds:g} seconds without activity. Historical decisions remain in Event explorer.")
            self.process_context_label.setText("No process has activity in the current evidence window. Historical identity and decisions remain in Event explorer.")
            self.missing_evidence_label.setText("Folder writer attribution and digital-signature verification are unavailable in this prototype.")
            self.response_reason_label.setText("No current risk evidence to assess. Process actions remain subject to the separate response safety policy.")

    def refresh_lab(self) -> None:
        c = self.controller
        lab = c.lab
        active = c.lab_active
        self.suspicious_button.setEnabled(not active)
        self.benign_button.setEnabled(not active)
        self.compression_button.setEnabled(not active)
        self.pause_button.setEnabled(active and lab["status"] == "Running")
        self.resume_button.setEnabled(active and lab["status"] == "Contained")
        self.stop_button.setEnabled(active)
        self.lab_status.setText(lab["status"].upper())
        self.lab_progress.setMaximum(lab["total"])
        self.lab_progress.setValue(lab["completed"])
        progress_unit = "ZIP archives created" if lab["scenario"] == "compression" else "generated files changed"
        self.lab_progress_label.setText(f"{lab['completed']} / {lab['total']} {progress_unit}")
        scenario = {"suspicious": "Rapid modification burst", "benign": "Ordinary bulk text edits",
                    "compression": "Legitimate ZIP creation"}.get(lab["scenario"], "Controlled workload")
        self.lab_description.setText(f"{scenario} · PID {lab['pid']}" if lab["pid"] else "Choose a scenario to begin")
        self.lab_path_label.setText(lab["root"] or "A new disposable workspace is created for every run.")
        peak = lab["peak_score"]
        self.lab_gauge.set_score(peak, "PEAK RISK" if lab["scenario"] else "AWAITING RUN")
        self.peak_card.set_value(str(peak) if lab["scenario"] else "—")
        latency = None
        if lab["first_event_at"] is not None and lab["first_high_at"] is not None:
            latency = max(0, lab["first_high_at"] - lab["first_event_at"])
        self.latency_card.set_value(f"{latency:.2f}s" if latency is not None else "—")
        impact = lab["files_at_containment"]
        self.impact_card.set_value(str(impact) if impact is not None else "—")
        self._events_dirty = True

    def mark_tables_dirty(self, *_args) -> None:
        self._events_dirty = True

    def refresh_tables(self) -> None:
        if not self._events_dirty or self.controller._closed:
            return
        self._events_dirty = False
        records = self.controller.store.recent_events(500)
        self._populate_table(self.overview_table, records[:4])
        self.empty_activity.setVisible(not records)
        query = self.search.text().casefold().strip()
        risk = self.risk_filter.currentText()
        if risk == "Elevated (legacy)":
            risk = "Elevated"
        filtered = [record for record in records
                    if (risk == "All risk levels" or record["level"] == risk)
                    and (not query or query in " ".join(str(record.get(key, "")) for key in ["path", "process_name", "operation", "source"]).casefold())]
        self._populate_table(self.events_table, filtered)
        self.event_count_label.setText(f"Observed events  ·  {len(filtered)} shown")
        actions = self.controller.store.recent_actions(5)
        lines = []
        for action in actions:
            when = datetime.fromtimestamp(action["timestamp"]).strftime("%H:%M:%S")
            detail = action["detail"]
            if action["action"] == "lab_finished":
                try:
                    summary = json.loads(detail)
                    detail = f"{summary['scenario']} · {summary['status']} · {summary['completed']} files changed"
                except (ValueError, KeyError):
                    detail = "Experiment finished"
            lines.append(f"{when}  ·  {action['action'].replace('_', ' ')}  —  {detail[:200]}")
        self.actions_label.setText("\n".join(lines) if lines else "No response actions recorded.")
        counts = self.controller.store.counts()
        self.alert_summary.setText(f"{counts.get('suspicious_events', 0):,} suspicious event assessments · {counts.get('open_alerts', 0):,} open alerts")
        self.refresh_alerts()

    def refresh_alerts(self) -> None:
        selected_id = None
        selected = self.alerts_table.item(self.alerts_table.currentRow(), 0)
        if selected:
            selected_id = selected.data(Qt.ItemDataRole.UserRole)["id"]
        records = self.controller.store.recent_alerts(100)
        self.alerts_table.blockSignals(True)
        self.alerts_table.setUpdatesEnabled(False)
        self.alerts_table.setRowCount(len(records))
        restored_row = None
        for index, record in enumerate(records):
            when = datetime.fromtimestamp(record["timestamp"]).strftime("%m-%d %H:%M:%S")
            identity = f"{record['process_name']} · {record['pid']}" if record.get("pid") else record.get("process_name", "Unattributed activity")
            values = [when, identity, f"{record['score']} {record['level']}", record["reason"],
                      record["response_action"].replace("_", " "), record["status"].capitalize()]
            for column, text in enumerate(values):
                item = QTableWidgetItem(text)
                item.setToolTip(text if column != 4 else record["response_reason"])
                item.setData(Qt.ItemDataRole.UserRole, record)
                self.alerts_table.setItem(index, column, item)
            if record["id"] == selected_id:
                restored_row = index
        if restored_row is not None:
            self.alerts_table.selectRow(restored_row)
        self.alerts_table.setUpdatesEnabled(True)
        self.alerts_table.blockSignals(False)
        self.alert_count_label.setText(f"Security alerts · latest {len(records)} shown")
        self.show_selected_alert()

    def show_selected_alert(self) -> None:
        item = self.alerts_table.item(self.alerts_table.currentRow(), 0)
        if item is None:
            self.acknowledge_button.setEnabled(False)
            self.alert_details.clear()
            return
        record = item.data(Qt.ItemDataRole.UserRole)
        assessment = record.get("assessment", {})
        lines = [record["reason"], "", f"Risk: {record['level']} ({record['score']} / 100)",
                 f"Response: {record['response_action'].replace('_', ' ')}", record["response_reason"], "",
                 "EVIDENCE"]
        for signal in assessment.get("signals", []):
            lines.extend([f"{signal['name']}: {signal['value']} (+{signal['points']})", signal["explanation"], ""])
        lines.append("MISSING / UNCERTAIN EVIDENCE")
        lines.extend(assessment.get("missing_evidence", []) or ["Not reported in this historical record."])
        self.alert_details.setPlainText("\n".join(lines))
        self.acknowledge_button.setEnabled(record["status"] == "open")

    def acknowledge_selected_alert(self) -> None:
        item = self.alerts_table.item(self.alerts_table.currentRow(), 0)
        if item is None:
            return
        record = item.data(Qt.ItemDataRole.UserRole)
        self.controller.acknowledge_alert(record["id"])
        self._events_dirty = True
        self.refresh_tables()

    @staticmethod
    def _populate_table(table: QTableWidget, records: list[dict]) -> None:
        table.setUpdatesEnabled(False)
        table.setRowCount(len(records))
        for i, record in enumerate(records):
            when = datetime.fromtimestamp(record["timestamp"]).strftime("%H:%M:%S")
            process = "Lab worker" if record["source"] == "lab" else "Unattributed activity"
            cells = [when, process, Path(record["path"]).name, record["operation"].capitalize(), f"{record['score']}  {record['level']}"]
            for j, text in enumerate(cells):
                item = QTableWidgetItem(text)
                item.setToolTip(record["path"] if j == 2 else str(text))
                item.setData(Qt.ItemDataRole.UserRole, record)
                if j == 4:
                    item.setForeground(QColor({"High": "#ff9398", "Uncertain": "#f0c978", "Elevated": "#f0c978", "Low": "#69e3bc"}.get(record["level"], "#8fa3b8")))
                table.setItem(i, j, item)
        table.setUpdatesEnabled(True)

    def show_event_details(self, table: QTableWidget, index: int) -> None:
        item = table.item(index, 0)
        if item is None:
            return
        record = item.data(Qt.ItemDataRole.UserRole)
        dialog = QDialog(self)
        dialog.setWindowTitle("Behavioural evidence")
        dialog.resize(760, 600)
        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.addWidget(label(f"{record['level']} risk · {record['score']} / 100", "sectionTitle"))
        details = QTextEdit()
        details.setReadOnly(True)
        content = [f"File: {record['path']}", f"Source: {record['source']}",
                   f"Process: {record['process_name']} (PID {record['pid'] or 'unknown'})",
                   f"Operation: {record['operation']}",
                   f"Entropy: {record['entropy_before']} → {record['entropy_after']}", "", "EXPLANATION", ""]
        for signal in record["assessment"]["signals"]:
            content.extend([f"{signal['name']} · +{signal['points']} points", signal["explanation"], ""])
        assessment = record["assessment"]
        content.extend(["ATTRIBUTION", assessment.get("attribution", "Unavailable in this historical record"), "",
                        "MISSING / UNCERTAIN EVIDENCE", *assessment.get("missing_evidence", []), "",
                        "RESPONSE DECISION", assessment.get("response_reason", "Not recorded in this historical record"), "",
                        "MEASURED FEATURES", json.dumps(assessment.get("features", {}), indent=2, ensure_ascii=False), "",
                        "EXPERIMENTAL CONFIGURATION", json.dumps(assessment.get("config", {}), indent=2, ensure_ascii=False)])
        content.append("Risk candidate for safety review: " + str(assessment["eligible_for_containment"]))
        details.setPlainText("\n".join(content))
        layout.addWidget(details)
        layout.addWidget(button("Close", dialog.accept, "primary"))
        dialog.exec()

    def export_evidence(self) -> None:
        path, selected_filter = QFileDialog.getSaveFileName(self, "Export local evidence", "ciphersentry-evidence.json", "JSON evidence (*.json);;CSV events (*.csv)")
        if not path:
            return
        target = Path(path)
        if not target.suffix:
            target = target.with_suffix(".csv" if "CSV" in selected_filter else ".json")
        try:
            self.controller.export(target)
        except (OSError, ValueError) as exc:
            self.show_message(f"Export failed: {exc}", error=True)

    def save_policy(self) -> None:
        try:
            config = {"window_seconds": self.window_seconds.value(),
                      "uncertain_threshold": self.uncertain_threshold.value(),
                      "high_threshold": self.threshold.value(),
                      "weights": {key: widget.value() for key, widget in self.weight_controls.items()},
                      "enabled_indicators": [key for key, widget in self.indicator_enabled.items() if widget.isChecked()]}
            self.controller.save_settings(self.threshold.value(), self.auto_contain.isChecked(), risk_config=config)
        except (OSError, ValueError) as exc:
            self.show_message(f"Could not save policy: {exc}", error=True)

    def show_message(self, text: str, error: bool = False) -> None:
        self.toast.setText(text)
        self.toast.setStyleSheet("color: #ffadb0; background: #30212c; border-radius: 8px; padding: 11px;" if error else "color: #a9eed5; background: #142d2c; border-radius: 8px; padding: 11px;")
        self.toast.show()

    def closeEvent(self, event: QCloseEvent) -> None:
        self.refresh_timer.stop()
        self.controller.close()
        event.accept()
